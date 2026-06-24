/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

/**
 * Manages AES-GCM encryption of translog data as a sequence of self-describing blocks.
 *
 * <p>On-disk layout of a {@code .tlog} written by this class:
 * <pre>
 *   [ plaintext TranslogHeader ]            written by OpenSearch core
 *   [ 4-byte plaintext TLE super-header ]   magic 'T','L','E' + format version
 *   [ block 0 ] [ block 1 ] ... [ block N ] each: [u16 ptLen][ciphertext(ptLen)][16B GCM tag]
 * </pre>
 *
 * <p>The writer buffers one block's plaintext in memory and SEALS it (one-shot GCM encrypt + write the
 * length-prefixed record) when the block fills, on {@code force()}, or on {@code close()} — so every
 * fsync/checkpoint is backed by complete, authenticated chunks (durability). Each block uses a distinct
 * GCM nonce {@code baseIV[0:8] || BE32(blockIndex)} with a per-(generation) base IV. The reader scans the
 * length prefixes into an immutable block index and serves logical reads (incl. from the open, unsealed
 * block for realtime reads of uncommitted ops).
 *
 * <p>This class separates chunking logic from FileChannel delegation, making the code more maintainable
 * and testable. "block" and "chunk" are used interchangeably (one block == one chunk).
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Channel operations required for chunk-based encryption")
@SuppressWarnings("preview")
public class TranslogChunkManager {

    // GCM block constants ("block" and "chunk" are used interchangeably here: one block == one chunk).
    /** Maximum plaintext bytes per block (8KB). The final block of a generation may be shorter. */
    public static final int GCM_CHUNK_SIZE = 8192;

    /** Size of the GCM authentication tag in bytes (16 bytes). */
    public static final int GCM_TAG_SIZE = AesGcmCipherFactory.GCM_TAG_LENGTH;

    // Thread-local buffer pool for reducing allocations on the transfer path.
    private static final ThreadLocal<ByteBuffer> TRANSFER_BUFFER_POOL = ThreadLocal.withInitial(() -> ByteBuffer.allocate(GCM_CHUNK_SIZE));

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final String translogUUID;

    // Header size - calculated exactly using TranslogHeader.headerSizeInBytes()
    private final int actualHeaderSize;

    // Base IV derived using HKDF for deterministic translog encryption
    private final byte[] baseIV;

    // ---- v2 seal-on-force format ----
    // Each on-disk block is: [u16 ptLen big-endian][ptLen bytes ciphertext][16 byte GCM tag].
    // Blocks are buffered in memory and SEALED (encrypted + tag written) when full, on force(), or on
    // close() — so a force()/checkpoint is always backed by complete, tagged, durable chunks (C2 fix).
    /** Length-prefix size in bytes (u16 big-endian plaintext length, 1..8192). */
    public static final int LENGTH_PREFIX_SIZE = 2;
    private static final int BLOCK_SIZE_SHIFT = 13;
    private static final int BLOCK_SIZE = 1 << BLOCK_SIZE_SHIFT; // 8KB max plaintext per block

    // ---- Encryption-layer super-header (written once after the core TranslogHeader, before the blocks) ----
    // Makes the on-disk encryption format self-describing so it can evolve (algorithm/chunk-size/nonce
    // scheme/KDF) without another silent on-disk break: the reader dispatches on (magic, version).
    private static final byte[] SUPER_HEADER_MAGIC = { 'T', 'L', 'E' };
    /** Current encryption-layer format version: variable-length seal-on-force blocks. */
    public static final byte FORMAT_VERSION = 2;
    /** Size of the plaintext super-header: 3-byte magic + 1-byte version. */
    public static final int SUPER_HEADER_SIZE = SUPER_HEADER_MAGIC.length + 1;

    // Write-side state
    private final byte[] blockBuf = new byte[BLOCK_SIZE]; // accumulates the open (unsealed) block's plaintext
    private int blockBufLen = 0;                          // bytes currently buffered in the open block
    private long currentBlockNumber = 0;                  // index of the open block (== sealed blocks so far)
    private long fileWritePosition = 0;                   // disk write cursor (after the last sealed block)
    // Total plaintext bytes accepted so far (sealed + buffered). Enforces append-only (M4).
    private long logicalDataWritten = 0;
    private boolean superHeaderWritten = false;           // whether this writer has emitted the super-header

    /**
     * Helper class for chunk position mapping
     */
    public static class ChunkInfo {
        /** The chunk index (0, 1, 2, ...). */
        public final int chunkIndex;

        /** The byte position within the 8KB chunk. */
        public final int offsetInChunk;

        /** The actual file position where the chunk starts on disk. */
        public final long diskPosition;

        /**
         * Constructs a new ChunkInfo with the specified chunk coordinates.
         *
         * @param chunkIndex the chunk index (0, 1, 2, ...)
         * @param offsetInChunk the byte position within the 8KB chunk
         * @param diskPosition the actual file position where the chunk starts on disk
         */
        public ChunkInfo(int chunkIndex, int offsetInChunk, long diskPosition) {
            this.chunkIndex = chunkIndex;
            this.offsetInChunk = offsetInChunk;
            this.diskPosition = diskPosition;
        }
    }

    /**
     * Creates a new TranslogChunkManager for managing encrypted chunks.
     *
     * @param delegate the underlying FileChannel for actual I/O operations
     * @param keyResolver the key resolver for encryption operations
     * @param filePath the file path (used for logging and debugging)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public TranslogChunkManager(FileChannel delegate, KeyResolver keyResolver, Path filePath, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.filePath = filePath;
        this.translogUUID = translogUUID;
        // Non-translog files (.ckp) don't need encryption anyway
        this.actualHeaderSize = filePath.getFileName().toString().endsWith(".tlog") ? calculateTranslogHeaderSize(translogUUID) : 0;

        // Derive base IV using HKDF. The generation (parsed from the translog-N.tlog filename) is folded
        // into the derivation so each generation gets a DISTINCT base IV — otherwise chunk 0 of every
        // generation file would reuse the same (key, nonce) on different plaintext (catastrophic GCM
        // nonce reuse). The generation is reconstructable identically at write and read time.
        long generation = parseGenerationFromFileName(filePath);
        byte[] dataKey = keyResolver.getDataKey().getEncoded();
        this.baseIV = generation >= 0
            ? HkdfKeyDerivation.deriveTranslogBaseIV(dataKey, translogUUID, generation)
            : HkdfKeyDerivation.deriveTranslogBaseIV(dataKey, translogUUID);
    }

    /**
     * Determines the exact header size using local calculation to avoid cross-classloader access.
     * This replicates the exact same logic as TranslogHeader.headerSizeInBytes() method.
     *
     * @return the calculated header size in bytes
     */
    public int determineHeaderSize() {
        return actualHeaderSize;
    }

    /**
     * Disk offset where the encrypted block stream begins: after the core TranslogHeader and the
     * encryption-layer super-header. Block records are written/read from here; the core header region
     * [0, headerSize) is still served as plaintext passthrough.
     *
     * @return the disk offset of the first block record
     */
    private long dataStartOffset() {
        return (long) actualHeaderSize + SUPER_HEADER_SIZE;
    }

    /**
     * Writes the 3-byte magic + 1-byte version super-header at {@code actualHeaderSize}. Called once, on
     * the first data write to a fresh translog, before any block. Idempotent within a writer's lifetime
     * (guarded by {@code superHeaderWritten}).
     */
    private void writeSuperHeader() throws IOException {
        ByteBuffer sh = ByteBuffer.allocate(SUPER_HEADER_SIZE);
        sh.put(SUPER_HEADER_MAGIC);
        sh.put(FORMAT_VERSION);
        sh.flip();
        writeFully(sh, actualHeaderSize);
    }

    /**
     * Reads and validates the super-header. Fail-closed: a missing/wrong magic or unknown version means
     * this is not a v2 encrypted translog (or a future format), so we refuse rather than misparse.
     *
     * @return true if a valid current-version super-header is present; false if the region is absent
     *         (e.g. a header-only file with no data yet)
     * @throws IOException if the magic is present but malformed/unsupported, or on a read error
     */
    private boolean verifySuperHeader() throws IOException {
        if (delegate.size() < dataStartOffset()) {
            return false; // no super-header yet (header-only / empty data region)
        }
        ByteBuffer sh = ByteBuffer.allocate(SUPER_HEADER_SIZE);
        int n = readFully(sh, actualHeaderSize);
        if (n < SUPER_HEADER_SIZE) {
            return false;
        }
        sh.flip();
        byte[] magic = new byte[SUPER_HEADER_MAGIC.length];
        sh.get(magic);
        byte version = sh.get();
        if (!Arrays.equals(magic, SUPER_HEADER_MAGIC)) {
            throw new IOException("not a TLE-encrypted translog (bad super-header magic) file:" + filePath);
        }
        if (version != FORMAT_VERSION) {
            throw new IOException(
                "unsupported encrypted translog format version " + version + " (expected " + FORMAT_VERSION + ") file:" + filePath
            );
        }
        return true;
    }

    /**
     * Local implementation of TranslogHeader.headerSizeInBytes() to avoid cross-classloader access issues.
     * This replicates the exact same calculation as the original method.
     *
     * @param translogUUID the translog UUID used for calculating the UUID field size in the header
     * @return the calculated header size in bytes including codec header, UUID field, and version-specific fields
     */
    private static int calculateTranslogHeaderSize(String translogUUID) {
        int uuidLength = translogUUID.getBytes(StandardCharsets.UTF_8).length;

        // Calculate header size using official TranslogHeader constants
        int size = CodecUtil.headerLength(TranslogHeader.TRANSLOG_CODEC); // Lucene codec header
        size += Integer.BYTES + uuidLength; // uuid length field + uuid bytes

        if (TranslogHeader.CURRENT_VERSION >= TranslogHeader.VERSION_PRIMARY_TERM) {
            size += Long.BYTES;    // primary term
            size += Integer.BYTES; // checksum
        }

        return size;
    }

    /**
     * Parses the generation number from a translog filename of the form {@code translog-<N>.tlog}.
     *
     * <p>Used to derive a per-generation base IV (see the constructor). The generation is part of the
     * filename written by OpenSearch core and is therefore available identically when the file is
     * written and when it is later reopened for read/recovery — no runtime state is required.
     *
     * @param filePath the translog file path
     * @return the generation number, or {@code -1} if the name is not a {@code translog-N.tlog} file
     */
    static long parseGenerationFromFileName(Path filePath) {
        if (filePath == null) {
            return -1;
        }
        String name = filePath.getFileName().toString();
        if (!name.startsWith("translog-") || !name.endsWith(".tlog")) {
            return -1;
        }
        String gen = name.substring("translog-".length(), name.length() - ".tlog".length());
        try {
            return Long.parseLong(gen);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ---- Read-side variable-length block index (v2) ----
    // Built by scanning the [u16 ptLen][ct][tag] records from the header to EOF. For block i:
    //   blockDiskOffset[i] = byte offset of its u16 length prefix
    //   blockPlainOffset[i] = cumulative plaintext bytes before block i (logical offset of its first byte)
    //   blockPtLen[i] = plaintext length of block i
    /**
     * Immutable snapshot of the sealed-block index, published atomically via a single volatile reference so
     * concurrent readers never observe torn arrays. Built by scanning the length-prefixed records on disk.
     */
    private static final class BlockIndex {
        final long[] diskOffset;   // byte offset of each block's u16 length prefix
        final long[] plainOffset;  // cumulative plaintext bytes before each block (its first logical byte)
        final int[] ptLen;         // plaintext length of each block
        final int count;
        final long indexedFileSize; // delegate.size() this index was built for
        final long scanResumePos;   // disk offset where the next (not-yet-sealed) record would start
        final long scannedPlain;    // cumulative plaintext bytes covered by the indexed blocks

        BlockIndex(long[] diskOffset, long[] plainOffset, int[] ptLen, long indexedFileSize, long scanResumePos, long scannedPlain) {
            this.diskOffset = diskOffset;
            this.plainOffset = plainOffset;
            this.ptLen = ptLen;
            this.count = diskOffset.length;
            this.indexedFileSize = indexedFileSize;
            this.scanResumePos = scanResumePos;
            this.scannedPlain = scannedPlain;
        }
    }

    private static final BlockIndex EMPTY_INDEX = new BlockIndex(new long[0], new long[0], new int[0], -1, -1, 0);
    // Rebuilt incrementally as the on-disk size grows (a concurrent/continuing writer seals more blocks).
    private volatile BlockIndex blockIndex = EMPTY_INDEX;

    /**
     * Returns an up-to-date sealed-block index. Because the format is append-only and sealed blocks are
     * never rewritten, this scans ONLY the newly-appended records (resuming from the previous index's
     * scanResumePos) rather than rescanning the whole file — O(new blocks) per read, not O(N). The result
     * is an immutable snapshot published via a single volatile write, so a concurrent reader sees either
     * the old or the new index whole — never a torn mix of fields.
     */
    private BlockIndex currentIndex() throws IOException {
        long size = delegate.size();
        BlockIndex idx = blockIndex;
        if (idx.indexedFileSize == size) {
            return idx; // up to date
        }
        // Validate the self-describing super-header before trusting any block bytes (fail-closed on a
        // foreign/old/future format). Absent super-header => no data yet => empty index.
        if (!verifySuperHeader()) {
            BlockIndex empty = new BlockIndex(new long[0], new long[0], new int[0], size, dataStartOffset(), 0);
            blockIndex = empty;
            return empty;
        }
        // Resume from where the last scan stopped (append-only => prior blocks are immutable); the first
        // block starts right after the super-header.
        long pos = idx.scanResumePos >= 0 ? idx.scanResumePos : dataStartOffset();
        long plain = idx.scannedPlain;
        ArrayList<Long> diskOffs = new ArrayList<>();
        ArrayList<Long> plainOffs = new ArrayList<>();
        ArrayList<Integer> ptLens = new ArrayList<>();
        // seed with the already-indexed blocks
        for (int i = 0; i < idx.count; i++) {
            diskOffs.add(idx.diskOffset[i]);
            plainOffs.add(idx.plainOffset[i]);
            ptLens.add(idx.ptLen[i]);
        }
        ByteBuffer lenBuf = ByteBuffer.allocate(LENGTH_PREFIX_SIZE);
        while (pos + LENGTH_PREFIX_SIZE <= size) {
            lenBuf.clear();
            int n = readFully(lenBuf, pos);
            if (n < LENGTH_PREFIX_SIZE) {
                break; // torn trailing length prefix — ignore (beyond last durable block)
            }
            lenBuf.flip();
            int ptLen = lenBuf.getShort() & 0xFFFF;
            long recordEnd = pos + LENGTH_PREFIX_SIZE + (long) ptLen + GCM_TAG_SIZE;
            if (ptLen == 0 || ptLen > GCM_CHUNK_SIZE || recordEnd > size) {
                break; // torn/partial trailing record — ignore
            }
            diskOffs.add(pos);
            plainOffs.add(plain);
            ptLens.add(ptLen);
            plain += ptLen;
            pos = recordEnd;
        }
        BlockIndex rebuilt = new BlockIndex(
            diskOffs.stream().mapToLong(Long::longValue).toArray(),
            plainOffs.stream().mapToLong(Long::longValue).toArray(),
            ptLens.stream().mapToInt(Integer::intValue).toArray(),
            size,
            pos,
            plain
        );
        blockIndex = rebuilt; // single volatile publish
        return rebuilt;
    }

    /**
     * Maps a logical file position to the block that contains it (block index + offset within the block's
     * decrypted plaintext + the disk offset of the block record). Uses the variable-length block index.
     *
     * @param filePosition the logical file position to map
     * @return chunk info, or a chunkIndex of -1 if the position is at/after the end of indexed data
     * @throws IOException if the index cannot be built
     */
    public ChunkInfo getChunkInfo(long filePosition) throws IOException {
        return getChunkInfo(filePosition, currentIndex());
    }

    private ChunkInfo getChunkInfo(long filePosition, BlockIndex idx) {
        long dataPosition = filePosition - determineHeaderSize();
        if (idx.count == 0 || dataPosition < 0) {
            return new ChunkInfo(-1, 0, determineHeaderSize());
        }
        // binary search for the block whose plaintext range contains dataPosition
        int lo = 0, hi = idx.count - 1, found = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            long start = idx.plainOffset[mid];
            long end = start + idx.ptLen[mid];
            if (dataPosition < start) {
                hi = mid - 1;
            } else if (dataPosition >= end) {
                lo = mid + 1;
            } else {
                found = mid;
                break;
            }
        }
        if (found < 0) {
            return new ChunkInfo(-1, 0, determineHeaderSize());
        }
        int offsetInChunk = (int) (dataPosition - idx.plainOffset[found]);
        return new ChunkInfo(found, offsetInChunk, idx.diskOffset[found]);
    }

    /**
     * Reads and decrypts the block at the given index. Returns empty if the index is out of range or the
     * channel is write-only.
     *
     * @param chunkIndex the block index to read and decrypt
     * @return the decrypted block plaintext, or empty array if not present
     * @throws IOException if reading or decryption fails
     */
    public byte[] readAndDecryptChunk(int chunkIndex) throws IOException {
        return readAndDecryptChunk(chunkIndex, currentIndex());
    }

    private byte[] readAndDecryptChunk(int chunkIndex, BlockIndex idx) throws IOException {
        try {
            if (chunkIndex < 0 || chunkIndex >= idx.count) {
                return new byte[0];
            }
            long recordPos = idx.diskOffset[chunkIndex];
            int ptLen = idx.ptLen[chunkIndex];
            int ctWithTag = ptLen + GCM_TAG_SIZE;

            // skip the u16 length prefix, read ciphertext+tag fully
            ByteBuffer buffer = ByteBuffer.allocate(ctWithTag);
            int bytesRead = readFully(buffer, recordPos + LENGTH_PREFIX_SIZE);
            if (bytesRead < ctWithTag) {
                // torn trailing block beyond the last durable record — treat as absent
                return new byte[0];
            }
            byte[] encryptedWithTag = buffer.array();

            Key key = keyResolver.getDataKey();
            // Per-block nonce MUST match the write path: baseIV[0:8] || BE32(blockIndex).
            byte[] chunkIV = AesGcmCipherFactory.computeGcmNonce(baseIV, chunkIndex);
            return AesGcmCipherFactory.decryptWithTag(key, chunkIV, encryptedWithTag);

        } catch (NonReadableChannelException e) {
            return new byte[0];
        } catch (IOException | AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to decrypt chunk " + chunkIndex, e);
        }
    }

    /**
     * Reads data from encrypted chunks at the specified position.
     * This method handles chunk boundary crossing and decryption.
     *
     * @param dst the buffer to read data into
     * @param position the file position to read from
     * @return the number of bytes read
     * @throws IOException if reading fails
     */
    public int readFromChunks(ByteBuffer dst, long position) throws IOException {
        if (dst.remaining() == 0) {
            return 0;
        }

        int headerSize = determineHeaderSize();

        // Header reads: read fully (guard against partial reads being mistaken for EOF)
        if (position < headerSize) {
            return readFully(dst, position);
        }

        long dataPosition = position - headerSize;

        // Open-block read: the bytes between the last SEALED block and logicalDataWritten live only in the
        // in-memory blockBuf (not yet sealed to disk). A realtime GET of an uncommitted op lands here — core
        // does not fsync before such a read, so we must serve it from memory or core's read loop spins on a
        // 0-byte return. The buffered region covers logical [sealedPlainBytes, logicalDataWritten).
        long sealedPlainBytes = logicalDataWritten - blockBufLen;
        if (blockBufLen > 0 && dataPosition >= sealedPlainBytes && dataPosition < logicalDataWritten) {
            int offsetInBuf = (int) (dataPosition - sealedPlainBytes);
            int available = blockBufLen - offsetInBuf;
            int toRead = Math.min(dst.remaining(), available);
            if (toRead > 0) {
                dst.put(blockBuf, offsetInBuf, toRead);
            }
            return toRead;
        }

        // Sealed-block read: map the logical position to a sealed on-disk block and decrypt it. Build the
        // index once and reuse it for both the lookup and the decrypt (avoids a double rebuild per read).
        BlockIndex idx = currentIndex();
        ChunkInfo chunkInfo = getChunkInfo(position, idx);

        // Read and decrypt the needed chunk
        byte[] decryptedChunk = readAndDecryptChunk(chunkInfo.chunkIndex, idx);

        // Extract requested data from decrypted chunk
        int available = Math.max(0, decryptedChunk.length - chunkInfo.offsetInChunk);
        int toRead = Math.min(dst.remaining(), available);

        if (toRead > 0) {
            dst.put(decryptedChunk, chunkInfo.offsetInChunk, toRead);
        }

        return toRead;
    }

    /**
     * Writes data using streaming cipher with auto block management.
     * Handles block boundaries by finalizing cipher and writing tag inline.
     *
     * @param src the buffer containing data to write
     * @param position the file position to write to
     * @return the number of bytes written
     * @throws IOException if writing fails
     */
    public int writeToChunks(ByteBuffer src, long position) throws IOException {
        if (src.remaining() == 0) {
            return 0;
        }

        int headerSize = determineHeaderSize();

        // Header writes: write fully (partial writes here also corrupt the file)
        if (position < headerSize) {
            return writeFully(src, position);
        }

        if (!superHeaderWritten) {
            // C6 guard: refuse to start appending to a NON-EMPTY encrypted translog. A fresh manager
            // resets block numbering to 0; appending to an existing file would re-encrypt block 0 under a
            // reused (key, nonce). Core only ever opens a brand-new generation for write (CREATE_NEW) and
            // reopens existing generations read-only, so this never fires in practice — it fails closed if
            // that ever changes, before any nonce reuse can occur. A fresh translog has only the core
            // header on disk (no super-header, no blocks yet).
            if (delegate.size() != headerSize) {
                throw new IOException(
                    "refusing to append to a non-empty encrypted translog (size="
                        + delegate.size()
                        + ", headerSize="
                        + headerSize
                        + "): reopen-for-append would reuse a GCM nonce. file:"
                        + filePath
                );
            }
            // Emit the self-describing encryption super-header before the first block.
            writeSuperHeader();
            superHeaderWritten = true;
            fileWritePosition = dataStartOffset();
        }

        // M4: the encrypted translog is append-only. The data-write path always continues the stream at
        // the internal logical cursor and derives nonces from the running block index; a positional write
        // at a different offset would silently misplace bytes / reuse a nonce. Fail closed on mismatch.
        long expectedLogicalPosition = headerSize + logicalDataWritten;
        if (position != expectedLogicalPosition) {
            throw new IOException(
                "encrypted translog is append-only: write at position "
                    + position
                    + " but current logical write position is "
                    + expectedLogicalPosition
                    + " file:"
                    + filePath
            );
        }

        int totalWritten = 0;

        // Buffer plaintext into the open block; seal whenever the block fills to BLOCK_SIZE.
        while (src.hasRemaining()) {
            int toWrite = Math.min(src.remaining(), BLOCK_SIZE - blockBufLen);
            src.get(blockBuf, blockBufLen, toWrite);
            blockBufLen += toWrite;
            totalWritten += toWrite;
            logicalDataWritten += toWrite;

            if (blockBufLen == BLOCK_SIZE) {
                sealCurrentBlock();
            }
        }

        return totalWritten;
    }

    /**
     * Seals the open block: GCM-encrypts the buffered plaintext under this block's per-block nonce and
     * writes {@code [u16 ptLen][ciphertext][16B tag]} to disk, then advances to the next block.
     *
     * <p>No-op if the open block is empty. After a successful seal the on-disk file ends on a complete,
     * authenticated chunk — this is what makes {@link #flushSeal()} (called from {@code force()}) able to
     * make every checkpoint durable (the C2 fix).
     *
     * @throws IOException if encryption or writing fails
     */
    private void sealCurrentBlock() throws IOException {
        if (blockBufLen == 0) {
            return;
        }
        if (currentBlockNumber > Integer.MAX_VALUE) {
            throw new IOException("translog block index " + currentBlockNumber + " exceeds maximum addressable block for file:" + filePath);
        }
        try {
            Key key = keyResolver.getDataKey();
            byte[] nonce = AesGcmCipherFactory.computeGcmNonce(baseIV, (int) currentBlockNumber);
            byte[] cipherWithTag = AesGcmCipherFactory.encryptWithTag(key, nonce, blockBuf, blockBufLen);

            ByteBuffer record = ByteBuffer.allocate(LENGTH_PREFIX_SIZE + cipherWithTag.length);
            record.putShort((short) blockBufLen); // 1..8192 fits in u16
            record.put(cipherWithTag);
            record.flip();
            int written = writeFully(record, fileWritePosition);
            fileWritePosition += written;

            currentBlockNumber++;
            blockBufLen = 0;
        } catch (AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to seal translog block " + currentBlockNumber + " for file:" + filePath, e);
        }
    }

    /**
     * Seals any buffered (open) block so its ciphertext+tag are on disk. Called by
     * {@code CryptoFileChannelWrapper.force()} before {@code delegate.force()} and by {@link #close()} —
     * guaranteeing every fsynced/checkpointed byte belongs to a complete, authenticated chunk (C2).
     *
     * @throws IOException if sealing fails
     */
    public void flushSeal() throws IOException {
        sealCurrentBlock();
    }

    /**
     * Transfers data from encrypted chunks to a target channel.
     * This method decrypts data during transfer.
     *
     * @param position the starting position in the source
     * @param count the number of bytes to transfer
     * @param target the target channel to write to
     * @return the number of bytes transferred
     * @throws IOException if transfer fails
     */
    public long transferFromChunks(long position, long count, WritableByteChannel target) throws IOException {
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = TRANSFER_BUFFER_POOL.get();
        buffer.clear();

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = readFromChunks(buffer, position + transferred);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = target.write(buffer);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    /**
     * Transfers data from a source channel to encrypted chunks.
     * This method encrypts data during transfer.
     *
     * @param src the source channel to read from
     * @param position the starting position in the target
     * @param count the number of bytes to transfer
     * @return the number of bytes transferred
     * @throws IOException if transfer fails
     */
    public long transferToChunks(ReadableByteChannel src, long position, long count) throws IOException {
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = TRANSFER_BUFFER_POOL.get();
        buffer.clear();

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = src.read(buffer);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = writeToChunks(buffer, position + transferred);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    /**
     * Seals any buffered (open) block, so the final partial block's ciphertext+tag are durable on disk.
     *
     * @throws IOException if sealing fails
     */
    public void close() throws IOException {
        flushSeal();
    }

    /**
     * Writes the entire buffer to the delegate at the given position, looping until no bytes remain.
     *
     * <p>{@link FileChannel#write(ByteBuffer, long)} is permitted to write fewer bytes than requested
     * (a partial write), which happens under I/O load. A single unchecked {@code write} can therefore
     * silently drop the tail of an encrypted chunk, leaving a hole that misaligns every subsequent
     * fixed-stride chunk and surfaces later as an {@code AEADBadTagException} during recovery. This
     * mirrors OpenSearch core's {@code TranslogWriter.writeToFile}, which loops for the same reason.
     *
     * @param buffer the bytes to write fully
     * @param position the starting file position
     * @return the total number of bytes written (equal to the buffer's initial remaining)
     * @throws IOException if a write returns a non-positive count or the channel fails
     */
    private int writeFully(ByteBuffer buffer, long position) throws IOException {
        int total = 0;
        while (buffer.hasRemaining()) {
            int n = delegate.write(buffer, position + total);
            if (n <= 0) {
                throw new IOException(
                    "Short write to translog: wrote " + total + " of " + (total + buffer.remaining()) + " bytes at position "
                        + (position + total) + " file:" + filePath
                );
            }
            total += n;
        }
        return total;
    }

    /**
     * Reads into the buffer from the delegate at the given position, looping until the buffer is
     * filled or a real EOF is reached. Guards the header path against partial reads being mistaken
     * for end-of-data.
     *
     * @param dst the destination buffer
     * @param position the starting file position
     * @return the number of bytes read (less than requested only at genuine EOF)
     * @throws IOException if the channel fails
     */
    private int readFully(ByteBuffer dst, long position) throws IOException {
        int total = 0;
        while (dst.hasRemaining()) {
            int n = delegate.read(dst, position + total);
            if (n <= 0) {
                break; // genuine EOF or no more bytes currently available
            }
            total += n;
        }
        return total;
    }
}
