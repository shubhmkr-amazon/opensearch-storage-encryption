/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.CRC32C;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

/**
 * FRAME-AAD translog encryption engine (on-disk FORMAT_VERSION 1).
 *
 * <p>Stores a {@code .tlog} as an append-only sequence of self-describing AES-256-GCM <b>frames</b>. One
 * frame is sealed per core {@code write()} flush (split if larger than {@link #FRAME_MAX}); a frame is
 * never re-sealed, so a frame's {@code (key, nonce)} pair is used exactly once.
 *
 * <pre>
 * PHYSICAL LAYOUT
 *   [ core TranslogHeader            ]  physical [0, H)            plaintext, served 1:1 as logical [0,H)
 *   [ TLE1 super-header              ]  physical [H, H+SH)         plaintext, NOT in the logical map
 *   [ frame 0 ][ frame 1 ] ... [ N ]    physical [H+SH, EOF)
 *
 * one frame:
 *   [ frame header (24B, plaintext, AAD-bound) ][ ciphertext(ptLen) ][ 16B GCM tag ]
 *   frame header = u32 ptLen | u64 logicalOffset | u32 frameSeq | u32 keyEpoch | u32 headerCRC32C
 * </pre>
 *
 * <p><b>Security.</b> nonce = {@code baseIV[0:8] || BE32(frameSeq)}; {@code baseIV} is HKDF-derived per
 * {@code (translogUUID, generation, keyEpoch, fileSalt)}. The {@code fileSalt} is a random 64-bit value
 * generated when the file's super-header is first written and persisted in it — so two DISTINCT physical
 * files that share {@code (key, uuid, generation, epoch)} (e.g. an original generation and a remote-store
 * restore that re-encrypts the same generation from plaintext) derive DIFFERENT base IVs and therefore
 * never reuse a {@code (key, nonce)} pair. Within a file, {@code frameSeq} is strictly monotonic and never
 * reissued, so each frame's {@code (key, nonce)} is used exactly once. The 40-byte AAD =
 * {@code fileContext(16) || frameHeader(24)} (fileContext itself salted) binds length, logical offset,
 * frame sequence, epoch, and a per-file context — so tamper of any metadata fails the GCM tag (fail-closed).
 * See {@link #frameNonce}, {@link #frameAad}.
 *
 * <p><b>Concurrency.</b> This class holds NO locks of its own — the owning {@link CryptoFileChannelWrapper}
 * serializes every call under a {@code ReentrantReadWriteLock}: writes/seals under the write lock, positional
 * reads under the read lock (mutually exclusive with writes). All writer state ({@link #nextFrameSeq},
 * {@link #logicalDataWritten}, {@link #fileWritePosition}) is therefore mutated single-threaded under the
 * write lock, and the read-side {@link #index} is an <b>immutable snapshot</b> published via a single
 * {@code volatile} write — so concurrent readers observe either the old or the new index whole, never torn.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Channel operations required for frame-based encryption")
public final class TranslogFrameManager {

    // ---- Format constants ----
    /** Super-header magic: 'T','L','E','1'. */
    static final byte[] MAGIC = { 'T', 'L', 'E', '1' };
    /**
     * On-disk format version. Version 1 of the versioned format: the super-header carries this byte, so
     * versioning begins here. (The previously-deployed encryption had no super-header/version byte; it is
     * recognized by the absence of the {@code TLE1} magic, not version-matched.) A super-header whose version
     * byte is not {@code FORMAT_VERSION} fails closed at open.
     */
    public static final byte FORMAT_VERSION = 1;
    /** Plaintext per-frame header size: u32 ptLen + u64 logicalOffset + u32 frameSeq + u32 keyEpoch + u32 crc. */
    static final int FRAME_HEADER_SIZE = 4 + 8 + 4 + 4 + 4; // 24
    /** GCM tag size (16). */
    static final int TAG_SIZE = AesGcmCipherFactory.GCM_TAG_LENGTH;
    /** Max plaintext per frame (64 KiB); larger writes are split into multiple frames. */
    static final int FRAME_MAX = 64 * 1024;
    /** Super-header: magic(4)+ver(1)+flags(1)+frameHeaderLen(2)+generation(8)+keyEpoch(4)+baseIVCheck(4)+fileSalt(8)+crc(4). */
    static final int SUPER_HEADER_SIZE = 4 + 1 + 1 + 2 + 8 + 4 + 4 + 8 + 4; // 36
    private static final byte FLAG_AAD = 0x01;
    private static final int FILE_CONTEXT_SIZE = 16;
    /** Byte offset of the 8-byte fileSalt within the super-header (after magic|ver|flags|fhLen|gen|epoch|baseIVCheck). */
    private static final int SUPER_HEADER_SALT_OFFSET = 4 + 1 + 1 + 2 + 8 + 4 + 4; // 24
    /** CSPRNG for per-file salts (thread-safe). */
    private static final java.security.SecureRandom SALT_RNG = new java.security.SecureRandom();

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final String translogUUID;
    private final int actualHeaderSize;
    private final long generation;
    // Key-rotation epoch for THIS generation file. Like baseIV/fileContext/fileSalt it is finalized at
    // super-header write time (fresh file: the resolver's current epoch) or read time (existing file: the
    // on-disk epoch). A generation is pinned to its epoch for life, so appends after a rotation keep using
    // the original key; only a NEW generation adopts the rotated epoch. Mirrors the per-segment store path.
    private int keyEpoch;
    // baseIV / fileContext are LAZILY derived once the per-file salt is known: generated on the first
    // super-header write, or read from disk on the first read of an existing file. NOT set in the
    // constructor (the salt is not known yet). Funnel all access through ensureCryptoInitialized().
    private byte[] baseIV;
    private byte[] fileContext;     // SHA-256(uuid || BE64(generation) || BE64(salt))[0:16], unique per file
    private long fileSalt;          // random per-file salt; 0 only before initialization
    private boolean cryptoInitialized = false;

    /** Seal the open accumulator once it reaches this many plaintext bytes (also the per-frame cap). */
    private static final int SEAL_THRESHOLD = FRAME_MAX;

    // ---- Writer state (mutated only under the wrapper's write lock) ----
    private boolean superHeaderWritten = false;
    private int nextFrameSeq = 0;          // strictly monotonic; recovered from the index on reopen, never reset
    private long logicalDataWritten = 0;   // total plaintext bytes ACCEPTED (sealed + buffered) == logical length
    private long fileWritePosition = 0;    // physical write cursor (after the last sealed frame)

    // ---- Open accumulator (M2): plaintext buffered since the last seal, not yet on disk ----
    // Filled by writeToChunks, drained by sealFrame on threshold / flushSeal() (force) / close(). Realtime
    // reads of these not-yet-sealed bytes are served from this buffer (see readFromChunks open-frame branch),
    // so a GET of an uncommitted op never spins. Mutated only under the write lock.
    private final byte[] accumBuf = new byte[SEAL_THRESHOLD];
    private int accumLen = 0;               // valid bytes in accumBuf
    private long accumLogicalStart = 0;     // logical offset of accumBuf[0]

    // ---- Read-side index: immutable snapshot, published via a single volatile write ----
    private volatile FrameIndex index = FrameIndex.EMPTY;

    /**
     * Append-only snapshot of the sealed-frame index. Parallel primitive arrays keep memory tight
     * (~24 B/frame). Published whole via {@link TranslogFrameManager#index} so readers never tear.
     *
     * <p>M1: the backing arrays are <b>capacity-doubled</b> and the valid length is {@link #count} (NOT
     * {@code logicalStart.length}). {@link TranslogFrameManager#sealFrame} appends in place into spare
     * capacity and publishes a new snapshot that reuses the same arrays — so a frame append is amortized
     * O(1), not the O(F) {@code Arrays.copyOf} it used to be. <b>Safety:</b> the writer only ever writes
     * index slot {@code count} (spare capacity that no published snapshot exposes) before bumping
     * {@code count} via the volatile {@code index} publish; readers bound every loop by their snapshot's
     * {@code count}, so they never observe a slot mid-write. Growth allocates fresh, larger arrays.
     */
    private static final class FrameIndex {
        static final FrameIndex EMPTY = new FrameIndex(new long[0], new long[0], new int[0], new int[0], 0, -1, 0, 0);
        final long[] logicalStart;  // logical offset of each frame's first plaintext byte
        final long[] physicalStart; // physical offset of each frame's 24-byte header
        final int[] ptLen;          // plaintext length of each frame
        final int[] frameSeq;       // frame sequence number (for nonce + AAD)
        final int count;            // valid entries (<= array length, which is capacity)
        final long indexedFileSize; // delegate.size() this index was built for (cache key)
        final long scanResumePos;   // physical offset where the next unscanned frame would begin
        final long scannedPlain;    // cumulative plaintext bytes covered (sealed frames only)

        FrameIndex(long[] ls, long[] ps, int[] pl, int[] fs, int count, long size, long resume, long plain) {
            this.logicalStart = ls;
            this.physicalStart = ps;
            this.ptLen = pl;
            this.frameSeq = fs;
            this.count = count;
            this.indexedFileSize = size;
            this.scanResumePos = resume;
            this.scannedPlain = plain;
        }
    }

    /**
     * @param delegate the underlying FileChannel for physical I/O
     * @param keyResolver resolves the per-shard AES-256 data key
     * @param filePath the translog file path ({@code translog-N.tlog})
     * @param translogUUID the translog UUID (header-size + HKDF context)
     */
    public TranslogFrameManager(FileChannel delegate, KeyResolver keyResolver, Path filePath, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required");
        }
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.filePath = filePath;
        this.translogUUID = translogUUID;
        this.actualHeaderSize = filePath.getFileName().toString().endsWith(".tlog") ? calculateTranslogHeaderSize(translogUUID) : 0;
        this.generation = parseGenerationFromFileName(filePath);
        // keyEpoch is finalized in writeSuperHeader() (fresh file → current epoch) or
        // verifyAndReadSuperHeader() (existing file → on-disk epoch), alongside the per-file salt.
        // NOTE: baseIV / fileContext are NOT derived here — they depend on the per-file salt, which is only
        // known once this file's super-header is written (fresh file) or read (existing file). They are set
        // by initCryptoWithSalt(...) from writeSuperHeader()/verifyAndReadSuperHeader().
    }

    /**
     * Derives {@link #baseIV} and {@link #fileContext} from the now-known per-file salt. Idempotent within a
     * manager's life; the salt is fixed once a file's super-header exists. Folds (generation, epoch, salt)
     * into both the base-IV HKDF context and the AAD file-context so two physical files that share
     * (key, uuid, generation, epoch) — e.g. an original generation and its restore re-encryption — get
     * DISTINCT nonces and AAD (no cross-file GCM (key,nonce) reuse).
     */
    private void initCryptoWithSalt(long salt) {
        this.fileSalt = salt;
        // Derive from the master key for THIS file's epoch (set by the caller before invoking us), so a
        // generation written under an older epoch stays decryptable after a rotation to a newer epoch.
        byte[] dataKey = keyResolver.getDataKey(keyEpoch).getEncoded();
        this.baseIV = generation >= 0
            ? HkdfKeyDerivation.deriveTranslogBaseIV(dataKey, translogUUID, generation, keyEpoch, salt)
            : HkdfKeyDerivation.deriveTranslogBaseIV(dataKey, translogUUID); // legacy/no-gen fallback (no super-header)
        this.fileContext = computeFileContext(translogUUID, generation, salt);
        this.cryptoInitialized = true;
    }

    /** Guards every crypto use: baseIV/fileContext must have been initialized from this file's salt. */
    private void ensureCryptoInitialized() {
        if (!cryptoInitialized) {
            throw new IllegalStateException(
                "translog crypto not initialized (no super-header read/written yet) file:" + filePath
            );
        }
    }

    // ===================================================================================================
    // Header / format helpers
    // ===================================================================================================

    /** @return the plaintext core-header size in bytes. */
    public int determineHeaderSize() {
        return actualHeaderSize;
    }

    private long dataStartOffset() {
        return (long) actualHeaderSize + SUPER_HEADER_SIZE;
    }

    /** Public, instance-free core-header size (used by the download/re-encrypt path). */
    public static int calculateTranslogHeaderSizeStatic(String translogUUID) {
        return calculateTranslogHeaderSize(translogUUID);
    }

    private static int calculateTranslogHeaderSize(String translogUUID) {
        int uuidLength = translogUUID.getBytes(StandardCharsets.UTF_8).length;
        int size = CodecUtil.headerLength(TranslogHeader.TRANSLOG_CODEC);
        size += Integer.BYTES + uuidLength;
        if (TranslogHeader.CURRENT_VERSION >= TranslogHeader.VERSION_PRIMARY_TERM) {
            size += Long.BYTES;
            size += Integer.BYTES;
        }
        return size;
    }

    static long parseGenerationFromFileName(Path filePath) {
        if (filePath == null) {
            return -1;
        }
        String name = filePath.getFileName().toString();
        if (!name.startsWith("translog-") || !name.endsWith(".tlog")) {
            return -1;
        }
        try {
            return Long.parseLong(name.substring("translog-".length(), name.length() - ".tlog".length()));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * True iff the bytes carry the TLE1 super-header magic right after the core header. Magic-only (NOT
     * version) so an already-encrypted file — current, future, or corrupt-version — is never re-encrypted;
     * version is enforced fail-closed on the READ path ({@link #verifyAndReadSuperHeader}).
     */
    public static boolean hasSuperHeaderMagic(byte[] fileBytes, int headerSize) {
        if (fileBytes == null || (long) fileBytes.length < (long) headerSize + MAGIC.length) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (fileBytes[headerSize + i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] computeFileContext(String translogUUID, long generation, long fileSalt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(translogUUID.getBytes(StandardCharsets.UTF_8));
            ByteBuffer g = ByteBuffer.allocate(Long.BYTES + Long.BYTES);
            g.putLong(generation);
            g.putLong(fileSalt); // per-file salt → AAD file-context is unique per physical file too
            md.update(g.array());
            return Arrays.copyOf(md.digest(), FILE_CONTEXT_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private void writeSuperHeader() throws IOException {
        // Fresh file: bind this generation to the resolver's CURRENT epoch and persist it. Must be set
        // before initCryptoWithSalt() so the key is derived for this epoch.
        this.keyEpoch = keyResolver.getCurrentEpoch();
        // Generate this file's random salt ONCE, then derive baseIV/fileContext from it before persisting.
        long salt = SALT_RNG.nextLong();
        initCryptoWithSalt(salt);
        ByteBuffer sh = ByteBuffer.allocate(SUPER_HEADER_SIZE);
        sh.put(MAGIC);
        sh.put(FORMAT_VERSION);
        sh.put(FLAG_AAD);
        sh.putShort((short) FRAME_HEADER_SIZE);
        sh.putLong(generation);
        sh.putInt(keyEpoch);
        sh.putInt(baseIVCheck());
        sh.putLong(salt); // per-file salt (formerly the reserved field)
        int crcPos = sh.position();
        CRC32C crc = new CRC32C();
        crc.update(sh.array(), 0, crcPos);
        sh.putInt((int) crc.getValue());
        sh.flip();
        writeFully(sh, actualHeaderSize);
    }

    private int baseIVCheck() {
        ensureCryptoInitialized();
        return ((baseIV[0] & 0xFF) << 24) | ((baseIV[1] & 0xFF) << 16) | ((baseIV[2] & 0xFF) << 8) | (baseIV[3] & 0xFF);
    }

    /**
     * Reads + validates the super-header on the READ path. Fail-closed: present-but-malformed magic, a
     * CRC mismatch, a wrong baseIV check (wrong key/epoch), or an UNSUPPORTED version all throw. Returns
     * false only when the region is genuinely absent (header-only / empty data region).
     */
    private boolean verifyAndReadSuperHeader() throws IOException {
        if (delegate.size() < dataStartOffset()) {
            return false;
        }
        ByteBuffer sh = ByteBuffer.allocate(SUPER_HEADER_SIZE);
        if (readFully(sh, actualHeaderSize) < SUPER_HEADER_SIZE) {
            return false;
        }
        byte[] a = sh.array();
        for (int i = 0; i < MAGIC.length; i++) {
            if (a[i] != MAGIC[i]) {
                throw new IOException("not a TLE-encrypted translog (bad super-header magic) file:" + filePath);
            }
        }
        CRC32C crc = new CRC32C();
        crc.update(a, 0, SUPER_HEADER_SIZE - 4);
        int storedCrc = ((a[SUPER_HEADER_SIZE - 4] & 0xFF) << 24) | ((a[SUPER_HEADER_SIZE - 3] & 0xFF) << 16)
            | ((a[SUPER_HEADER_SIZE - 2] & 0xFF) << 8) | (a[SUPER_HEADER_SIZE - 1] & 0xFF);
        if ((int) crc.getValue() != storedCrc) {
            throw new IOException("corrupt super-header (CRC mismatch) file:" + filePath);
        }
        byte version = a[4];
        if (version != FORMAT_VERSION) {
            throw new IOException(
                "unsupported encrypted translog format version " + version + " (expected " + FORMAT_VERSION + ") file:" + filePath
            );
        }
        // Validate the persisted generation matches the one derived from the filename (review: it was
        // written but never checked). A mismatch means the file was relocated/renamed across generations —
        // its baseIV (HKDF over generation) would be wrong, so fail closed rather than mis-derive nonces.
        sh.position(4 + 1 + 1 + 2);
        long diskGeneration = sh.getLong();
        if (generation >= 0 && diskGeneration != generation) {
            throw new IOException(
                "translog generation mismatch (super-header " + diskGeneration + " != filename " + generation
                    + "); file relocated/renamed? file:" + filePath
            );
        }
        int diskEpoch = sh.getInt();
        int diskBaseIVCheck = sh.getInt();
        long diskSalt = sh.getLong(); // per-file salt persisted at write time
        // Adopt the ON-DISK epoch: this file was encrypted under whatever epoch was current when it was
        // written, and it must be decrypted with THAT epoch's key even if the shard has since rotated to a
        // newer epoch. Set keyEpoch first so initCryptoWithSalt() derives the correct per-epoch key.
        this.keyEpoch = diskEpoch;
        // Derive baseIV/fileContext from the ON-DISK salt (the value this file was actually encrypted with),
        // THEN validate. A wrong data key (wrong/absent epoch key, or tampered salt) yields a different
        // baseIV → baseIVCheck mismatch → fail closed. This must run before any frameNonce()/decrypt.
        initCryptoWithSalt(diskSalt);
        if (diskBaseIVCheck != baseIVCheck()) {
            throw new IOException("translog key/epoch mismatch (cannot decrypt with epoch " + diskEpoch + " key) file:" + filePath);
        }
        return true;
    }

    // ===================================================================================================
    // Per-frame crypto inputs
    // ===================================================================================================

    private byte[] frameNonce(int frameSeq) {
        ensureCryptoInitialized(); // baseIV depends on the per-file salt — never seal/read a frame without it
        return AesGcmCipherFactory.computeGcmNonce(baseIV, frameSeq);
    }

    /** AAD = fileContext(16) || frameHeader(24). Same bytes reconstructed on encrypt and decrypt. */
    private byte[] frameAad(byte[] frameHeader) {
        ensureCryptoInitialized();
        byte[] aad = new byte[FILE_CONTEXT_SIZE + FRAME_HEADER_SIZE];
        System.arraycopy(fileContext, 0, aad, 0, FILE_CONTEXT_SIZE);
        System.arraycopy(frameHeader, 0, aad, FILE_CONTEXT_SIZE, FRAME_HEADER_SIZE);
        return aad;
    }

    private static byte[] buildFrameHeader(int ptLen, long logicalOffset, int frameSeq, int keyEpoch) {
        ByteBuffer fh = ByteBuffer.allocate(FRAME_HEADER_SIZE);
        fh.putInt(ptLen);
        fh.putLong(logicalOffset);
        fh.putInt(frameSeq);
        fh.putInt(keyEpoch);
        CRC32C crc = new CRC32C();
        crc.update(fh.array(), 0, FRAME_HEADER_SIZE - 4);
        fh.putInt((int) crc.getValue());
        return fh.array();
    }

    // ===================================================================================================
    // Write path  (called under the wrapper's WRITE lock)
    // ===================================================================================================

    /**
     * Appends {@code src} as one or more frames. Header writes ({@code position < headerSize}) pass through
     * as plaintext. The first data write emits the super-header. Enforces append-only: {@code position}
     * must equal {@code headerSize + logicalDataWritten} (M4) — a non-append write fails closed.
     *
     * @return the number of logical (plaintext) bytes accepted (== {@code src} consumed)
     */
    public int writeToChunks(ByteBuffer src, long position) throws IOException {
        if (src.remaining() == 0) {
            return 0;
        }
        int headerSize = determineHeaderSize();

        if (position < headerSize) {
            return writeFully(src, position);
        }

        if (!superHeaderWritten) {
            // C6 guard: refuse to start appending to a NON-EMPTY encrypted translog (reopen-for-append would
            // reissue frameSeq 0 -> nonce reuse). A fresh translog has only the core header on disk.
            if (delegate.size() != headerSize) {
                throw new IOException(
                    "refusing to append to a non-empty encrypted translog (size=" + delegate.size() + ", headerSize=" + headerSize
                        + "): reopen-for-append would reuse a GCM nonce. file:" + filePath
                );
            }
            writeSuperHeader();
            superHeaderWritten = true;
            fileWritePosition = dataStartOffset();
        }

        long expected = headerSize + logicalDataWritten;
        if (position != expected) {
            throw new IOException(
                "encrypted translog is append-only: write at position " + position + " but logical write position is " + expected
                    + " file:" + filePath
            );
        }

        // M2: accumulate plaintext; seal a frame only when the open buffer fills to SEAL_THRESHOLD. The
        // remainder stays buffered (served to realtime reads from accumBuf) until the next force()/close()
        // or the next fill. This collapses the per-sync frame explosion + 40 B/frame amplification while
        // preserving per-frameSeq nonce uniqueness (each sealed frame still gets a fresh, monotonic seq).
        int totalAccepted = 0;
        while (src.hasRemaining()) {
            if (accumLen == 0) {
                accumLogicalStart = logicalDataWritten;
            }
            int take = Math.min(src.remaining(), SEAL_THRESHOLD - accumLen);
            src.get(accumBuf, accumLen, take);
            accumLen += take;
            logicalDataWritten += take;
            totalAccepted += take;
            if (accumLen == SEAL_THRESHOLD) {
                sealAccumulator();
            }
        }
        return totalAccepted;
    }

    /**
     * GCM-seals the open accumulator as one frame and appends it: writes {@code [frameHeader][ciphertext]
     * [tag]} fully, advances the physical cursor, and publishes an extended {@link FrameIndex} snapshot.
     * No-op if the accumulator is empty. Frames are never re-sealed, so {@code (key, nonce)} for this
     * {@code frameSeq} is used exactly once.
     */
    private void sealAccumulator() throws IOException {
        if (accumLen == 0) {
            return;
        }
        int frameSeq = nextFrameSeq;
        if (frameSeq < 0) { // wrapped past Integer.MAX_VALUE
            throw new IOException("translog frame sequence overflow for file:" + filePath);
        }
        int ptLen = accumLen;
        long logicalOffset = accumLogicalStart;
        byte[] frameHeader = buildFrameHeader(ptLen, logicalOffset, frameSeq, keyEpoch);
        byte[] nonce = frameNonce(frameSeq);
        byte[] aad = frameAad(frameHeader);

        byte[] cipherWithTag;
        try {
            // Seal under this file's epoch key — the nonce/baseIV above were derived for keyEpoch, so the
            // GCM key MUST be the same epoch or the pairing is inconsistent.
            Key key = keyResolver.getDataKey(keyEpoch);
            cipherWithTag = AesGcmCipherFactory.encryptWithTag(key, nonce, accumBuf, ptLen, aad);
        } catch (AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to seal translog frame " + frameSeq + " for file:" + filePath, e);
        }

        long framePhysicalStart = fileWritePosition;
        ByteBuffer record = ByteBuffer.allocate(FRAME_HEADER_SIZE + cipherWithTag.length);
        record.put(frameHeader);
        record.put(cipherWithTag);
        record.flip();
        int written = writeFully(record, framePhysicalStart);

        // Advance writer state, then publish an extended index snapshot (M1: amortized-O(1) append).
        fileWritePosition += written;
        nextFrameSeq = frameSeq + 1;
        accumLen = 0;

        FrameIndex prev = index;
        int n = prev.count;
        long[] ls, ps;
        int[] pl, fs;
        if (n < prev.logicalStart.length) {
            // Spare capacity: write slot n in place (no published snapshot exposes it yet), reuse arrays.
            ls = prev.logicalStart;
            ps = prev.physicalStart;
            pl = prev.ptLen;
            fs = prev.frameSeq;
        } else {
            // Grow: double capacity (min 16). Amortized O(1) appends, O(F) total for a generation.
            int newCap = Math.max(16, n * 2);
            ls = Arrays.copyOf(prev.logicalStart, newCap);
            ps = Arrays.copyOf(prev.physicalStart, newCap);
            pl = Arrays.copyOf(prev.ptLen, newCap);
            fs = Arrays.copyOf(prev.frameSeq, newCap);
        }
        ls[n] = logicalOffset;
        ps[n] = framePhysicalStart;
        pl[n] = ptLen;
        fs[n] = frameSeq;
        // scannedPlain advances to cover this sealed frame; indexedFileSize/scanResumePos track the disk.
        index = new FrameIndex(ls, ps, pl, fs, n + 1, delegate.size(), fileWritePosition, logicalOffset + ptLen);
    }

    /**
     * Seals any buffered (open) accumulator so all accepted ops are durable, complete, authenticated frames
     * on disk. Called by {@code CryptoFileChannelWrapper.force()} (before the delegate fsync) and by
     * {@link #close()}. After this returns, {@code logicalDataWritten == scannedPlain} (nothing buffered).
     */
    public void flushSeal() throws IOException {
        sealAccumulator();
    }

    // ===================================================================================================
    // Read path  (called under the wrapper's READ or WRITE lock)
    // ===================================================================================================

    /**
     * Reads decrypted plaintext at logical {@code position}. Header reads are served (capped at the header
     * boundary so a large buffer can't bleed into the super-header). Data reads map logical->frame via the
     * index (binary search), decrypt that one frame (verifying tag + AAD; fail-closed on mismatch), and copy
     * the requested slice. Returns 0 at/after logical EOF.
     */
    public int readFromChunks(ByteBuffer dst, long position) throws IOException {
        if (dst.remaining() == 0) {
            return 0;
        }
        int headerSize = determineHeaderSize();

        if (position < headerSize) {
            int headerRemaining = (int) (headerSize - position);
            int originalLimit = dst.limit();
            dst.limit(dst.position() + Math.min(dst.remaining(), headerRemaining));
            try {
                return readFully(dst, position);
            } finally {
                dst.limit(originalLimit);
            }
        }

        long dataPosition = position - headerSize;

        // Open-accumulator read (M2): bytes accepted but not yet sealed live only in accumBuf, covering
        // logical [accumLogicalStart, accumLogicalStart+accumLen). A realtime GET of an uncommitted op
        // lands here (core does not fsync before such a read), so serve it from memory or core's read loop
        // spins on a 0-byte return. Safe under the read lock: writes (which mutate accumBuf) hold the
        // mutually-exclusive write lock. Checked BEFORE the index so the freshest bytes win.
        if (accumLen > 0 && dataPosition >= accumLogicalStart && dataPosition < accumLogicalStart + accumLen) {
            int offsetInBuf = (int) (dataPosition - accumLogicalStart);
            int toRead = Math.min(dst.remaining(), accumLen - offsetInBuf);
            if (toRead <= 0) {
                return 0;
            }
            dst.put(accumBuf, offsetInBuf, toRead);
            return toRead;
        }

        FrameIndex idx = currentIndex();
        long logicalEnd = idx.scannedPlain;
        if (idx.count == 0 || dataPosition >= logicalEnd) {
            // End-of-stream: -1, not 0, per the FileChannel.read contract. Core's recovery read loop only
            // breaks on read < 0 and treats 0 as "retry", so returning 0 here spins it forever (hung shard)
            // when the translog ends before the checkpoint's length. (A zero-length dst returned 0 at entry.)
            return -1;
        }

        int f = findFrame(idx, dataPosition);
        if (f < 0) {
            return 0;
        }
        byte[] plain = decryptFrame(idx, f);
        int offsetInFrame = (int) (dataPosition - idx.logicalStart[f]);
        int available = plain.length - offsetInFrame;
        // Fail-closed (review): never return a negative count — that violates FileChannel.read's contract
        // and would corrupt a caller's position arithmetic. A non-positive available means nothing to serve.
        int toRead = Math.min(dst.remaining(), available);
        if (toRead <= 0) {
            return 0;
        }
        dst.put(plain, offsetInFrame, toRead);
        return toRead;
    }

    /** Binary search for the frame whose plaintext range contains {@code dataPosition}. */
    private static int findFrame(FrameIndex idx, long dataPosition) {
        int lo = 0, hi = idx.count - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            long start = idx.logicalStart[mid];
            long end = start + idx.ptLen[mid];
            if (dataPosition < start) {
                hi = mid - 1;
            } else if (dataPosition >= end) {
                lo = mid + 1;
            } else {
                return mid;
            }
        }
        return -1;
    }

    private byte[] decryptFrame(FrameIndex idx, int f) throws IOException {
        try {
            long recordPos = idx.physicalStart[f];
            int ptLen = idx.ptLen[f];
            int frameSeq = idx.frameSeq[f];

            // This frame is in the index, which means the scan already verified its full record fits within
            // the file (recordEnd <= size) and its header CRC passed. So a short read here is NOT a benign
            // torn-trailing-frame (the scan never indexes a torn tail) — it means the file shrank or was
            // corrupted under us. Fail closed (review): throw rather than silently return truncated/empty data.
            ByteBuffer fhBuf = ByteBuffer.allocate(FRAME_HEADER_SIZE);
            if (readFully(fhBuf, recordPos) < FRAME_HEADER_SIZE) {
                throw new IOException(
                    "indexed translog frame " + f + " (seq " + frameSeq + ") header truncated on disk at " + recordPos
                        + " file:" + filePath
                );
            }
            byte[] frameHeader = fhBuf.array();

            int ctWithTag = ptLen + TAG_SIZE;
            ByteBuffer ctBuf = ByteBuffer.allocate(ctWithTag);
            if (readFully(ctBuf, recordPos + FRAME_HEADER_SIZE) < ctWithTag) {
                throw new IOException(
                    "indexed translog frame " + f + " (seq " + frameSeq + ") ciphertext truncated on disk (expected "
                        + ctWithTag + "B at " + (recordPos + FRAME_HEADER_SIZE) + ") file:" + filePath
                );
            }
            // Decrypt under this file's epoch key (adopted from the on-disk super-header), matching the
            // epoch the nonce/baseIV were derived for.
            Key key = keyResolver.getDataKey(keyEpoch);
            byte[] nonce = frameNonce(frameSeq);
            byte[] aad = frameAad(frameHeader);
            return AesGcmCipherFactory.decryptWithTag(key, nonce, ctBuf.array(), aad);
        } catch (NonReadableChannelException e) {
            return new byte[0];
        } catch (IOException | AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to decrypt translog frame index " + f + " for file:" + filePath, e);
        }
    }

    /** Block-read buffer size for the cold-recovery scan (M3): read frame headers in big gulps, not per-24B. */
    private static final int SCAN_BUFFER_SIZE = 1 << 20; // 1 MiB

    /**
     * Returns an up-to-date frame index. If the on-disk size is unchanged, returns the cached snapshot.
     * Otherwise scans ONLY newly-appended frames (resuming from the prior scan position) by reading the
     * plaintext frame headers — no key, no decrypt, no full rescan.
     *
     * <p>Cost: this scan is <b>O(F) in the number of frames</b> (each header is parsed once); the "O(log F)"
     * claim applies only to the per-read binary search AFTER the index is built. To keep cold
     * peer-recovery/relocation cheap, headers are read in {@value #SCAN_BUFFER_SIZE}-byte blocks (M3) rather
     * than one {@code read()} syscall per 24-byte header.
     *
     * <p>Fail-closed (review): a frame whose full record fits within the file but fails CRC / frameSeq
     * continuity / logical-offset continuity is <b>mid-stream corruption</b> and throws. Only a record that
     * runs past EOF (or a short read at EOF) is the benign torn-trailing frame and stops the scan cleanly.
     */
    private FrameIndex currentIndex() throws IOException {
        long size = delegate.size();
        FrameIndex idx = index;
        if (idx.indexedFileSize == size) {
            return idx;
        }
        if (!verifyAndReadSuperHeader()) {
            FrameIndex empty = new FrameIndex(new long[0], new long[0], new int[0], new int[0], 0, size, dataStartOffset(), 0);
            index = empty;
            return empty;
        }
        // Resume from where the prior scan stopped; if there are no seed frames, start at the first frame
        // (right after the super-header). NOTE: EMPTY's scanResumePos is 0, so gate on seedCount, not >=0.
        int seedCount = idx.count;
        long pos = seedCount > 0 ? idx.scanResumePos : dataStartOffset();
        long plain = idx.scannedPlain;

        java.util.ArrayList<Long> nls = new java.util.ArrayList<>();
        java.util.ArrayList<Long> nps = new java.util.ArrayList<>();
        java.util.ArrayList<Integer> npl = new java.util.ArrayList<>();
        java.util.ArrayList<Integer> nfs = new java.util.ArrayList<>();
        int expectedSeq = seedCount > 0 ? idx.frameSeq[seedCount - 1] + 1 : 0;

        // M3: block-read the header region. We need only each frame's 24-byte header to index it, so we read
        // in chunks and walk header→(skip ciphertext+tag)→next header within the buffer, refilling when the
        // next header would straddle the buffer end. Cap the buffer at the remaining scan region so small
        // translogs don't allocate a full SCAN_BUFFER_SIZE (nit).
        int bufCap = (int) Math.min(SCAN_BUFFER_SIZE, Math.max(FRAME_HEADER_SIZE, size - pos));
        byte[] buf = new byte[bufCap];
        long bufFileStart = -1;
        int bufLen = 0;
        while (pos + FRAME_HEADER_SIZE <= size) {
            // Ensure [pos, pos+FRAME_HEADER_SIZE) is in buf.
            if (bufFileStart < 0 || pos < bufFileStart || pos + FRAME_HEADER_SIZE > bufFileStart + bufLen) {
                bufFileStart = pos;
                ByteBuffer bb = ByteBuffer.wrap(buf);
                bb.limit((int) Math.min(buf.length, size - pos));
                bufLen = readFully(bb, pos);
                if (bufLen < FRAME_HEADER_SIZE) {
                    break; // short read at EOF — benign torn tail
                }
            }
            int o = (int) (pos - bufFileStart);
            int ptLen = ((buf[o] & 0xFF) << 24) | ((buf[o + 1] & 0xFF) << 16) | ((buf[o + 2] & 0xFF) << 8) | (buf[o + 3] & 0xFF);
            long logicalOffset = readLongBE(buf, o + 4);
            int frameSeq = ((buf[o + 12] & 0xFF) << 24) | ((buf[o + 13] & 0xFF) << 16) | ((buf[o + 14] & 0xFF) << 8)
                | (buf[o + 15] & 0xFF);
            CRC32C crc = new CRC32C();
            crc.update(buf, o, FRAME_HEADER_SIZE - 4);
            int storedCrc = ((buf[o + 20] & 0xFF) << 24) | ((buf[o + 21] & 0xFF) << 16) | ((buf[o + 22] & 0xFF) << 8)
                | (buf[o + 23] & 0xFF);
            long recordEnd = pos + FRAME_HEADER_SIZE + (long) ptLen + TAG_SIZE;

            // Validate this record. A failure is MID-STREAM corruption (throw, fail-closed) ONLY if the
            // record is not the physical tail — i.e. more bytes follow it on disk (recordEnd < size), so a
            // well-formed frame was supposed to come after. A failure AT the physical tail (recordEnd >=
            // size, including a ptLen so large it runs past EOF) is the benign power-loss torn trailing
            // record: its bytes are beyond the last durable/checkpointed frame and core never reads them, so
            // we stop the scan cleanly rather than refuse to open the shard. (Review: rev2 over-fired here —
            // it threw on a fits-in-file-but-bad-CRC tail; only a record strictly inside the file is mid-stream.)
            boolean valid = ptLen > 0 && ptLen <= FRAME_MAX && (int) crc.getValue() == storedCrc && recordEnd <= size
                && frameSeq == expectedSeq && logicalOffset == plain;
            if (!valid) {
                // An out-of-range ptLen (<=0 from a flipped sign bit, or > FRAME_MAX) makes recordEnd
                // meaningless: a negative ptLen yields recordEnd < size, which a bare "recordEnd >= size"
                // test would misread as mid-stream corruption and refuse to open on a benign torn tail. No
                // valid frame can follow it, so treat it as the torn physical tail and recover the prefix.
                boolean ptLenOutOfRange = ptLen <= 0 || ptLen > FRAME_MAX;
                boolean atPhysicalTail = ptLenOutOfRange || recordEnd >= size; // nothing valid can follow within the file
                if (atPhysicalTail) {
                    break; // torn trailing record — stop, recover everything before it
                }
                // Strictly inside the file with an in-range ptLen: a valid frame was expected after this one,
                // so a remaining CRC / sequence / logical-offset failure is real mid-stream corruption => throw.
                if ((int) crc.getValue() != storedCrc) {
                    throw new IOException("corrupt mid-stream translog frame header CRC at " + pos + " file:" + filePath);
                }
                if (frameSeq != expectedSeq) {
                    throw new IOException(
                        "mid-stream translog frame sequence break at " + pos + " (got " + frameSeq + ", expected " + expectedSeq
                            + ") file:" + filePath
                    );
                }
                throw new IOException(
                    "mid-stream translog frame logical-offset break at " + pos + " (got " + logicalOffset + ", expected " + plain
                        + ") file:" + filePath
                );
            }
            nls.add(logicalOffset);
            nps.add(pos);
            npl.add(ptLen);
            nfs.add(frameSeq);
            plain += ptLen;
            expectedSeq++;
            pos = recordEnd; // next header may be beyond the buffer; the top-of-loop guard refills
        }

        int added = nls.size();
        int total = seedCount + added;
        // Capacity for the rebuilt snapshot: keep the prior arrays' capacity if it already holds `total`,
        // else grow to exactly `total` (this scan path is the cold/recovery rebuild, not the hot append, so
        // exact sizing is fine — the amortized-O(1) doubling matters on sealAccumulator's write path).
        int cap = Math.max(idx.logicalStart.length, total);
        long[] oLs = Arrays.copyOf(idx.logicalStart, cap);
        long[] oPs = Arrays.copyOf(idx.physicalStart, cap);
        int[] oPl = Arrays.copyOf(idx.ptLen, cap);
        int[] oFs = Arrays.copyOf(idx.frameSeq, cap);
        for (int i = 0; i < added; i++) {
            oLs[seedCount + i] = nls.get(i);
            oPs[seedCount + i] = nps.get(i);
            oPl[seedCount + i] = npl.get(i);
            oFs[seedCount + i] = nfs.get(i);
        }
        FrameIndex rebuilt = new FrameIndex(oLs, oPs, oPl, oFs, total, size, pos, plain);
        index = rebuilt;
        // Keep the writer cursors consistent if this manager is also the writer reopening an existing file.
        if (!superHeaderWritten && rebuilt.count > 0) {
            nextFrameSeq = rebuilt.frameSeq[rebuilt.count - 1] + 1;
            logicalDataWritten = rebuilt.scannedPlain;
            fileWritePosition = rebuilt.scanResumePos;
        }
        return rebuilt;
    }

    private static long readLongBE(byte[] a, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (a[off + i] & 0xFFL);
        }
        return v;
    }

    // ===================================================================================================
    // Transfer paths (remote upload / recovery). Decrypt-on-egress / encrypt-on-ingress through the frames.
    // ===================================================================================================

    public long transferFromChunks(long position, long count, java.nio.channels.WritableByteChannel target) throws IOException {
        long transferred = 0;
        ByteBuffer buffer = ByteBuffer.allocate(FRAME_MAX);
        while (transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), count - transferred);
            buffer.limit(toRead);
            int bytesRead = readFromChunks(buffer, position + transferred);
            if (bytesRead <= 0) {
                break;
            }
            buffer.flip();
            int written = target.write(buffer);
            transferred += written;
            if (written < bytesRead) {
                break;
            }
        }
        return transferred;
    }

    public long transferToChunks(java.nio.channels.ReadableByteChannel src, long position, long count) throws IOException {
        long transferred = 0;
        ByteBuffer buffer = ByteBuffer.allocate(FRAME_MAX);
        while (transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), count - transferred);
            buffer.limit(toRead);
            int bytesRead = src.read(buffer);
            if (bytesRead <= 0) {
                break;
            }
            buffer.flip();
            int written = writeToChunks(buffer, position + transferred);
            transferred += written;
            if (written < bytesRead) {
                break;
            }
        }
        return transferred;
    }

    /** Seal-per-write means close has nothing buffered to flush. */
    public void close() throws IOException {
        flushSeal();
    }

    // ===================================================================================================
    // Fully-looping I/O (closes the partial-write / partial-read corruption class)
    // ===================================================================================================

    private int writeFully(ByteBuffer buffer, long position) throws IOException {
        int total = 0;
        while (buffer.hasRemaining()) {
            int n = delegate.write(buffer, position + total);
            if (n <= 0) {
                throw new IOException(
                    "Short write to translog: wrote " + total + " of " + (total + buffer.remaining()) + " at position "
                        + (position + total) + " file:" + filePath
                );
            }
            total += n;
        }
        return total;
    }

    private int readFully(ByteBuffer dst, long position) throws IOException {
        int total = 0;
        while (dst.hasRemaining()) {
            int n = delegate.read(dst, position + total);
            if (n <= 0) {
                break; // genuine EOF
            }
            total += n;
        }
        return total;
    }
}
