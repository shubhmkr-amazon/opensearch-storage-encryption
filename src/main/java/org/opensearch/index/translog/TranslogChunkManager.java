/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;


import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Key;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.cipher.OpenSslNativeCipher;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

/**
 * Manages 8KB encrypted chunks for translog files using AES-GCM authentication.
 * Handles chunk positioning, encryption, decryption, and I/O operations.
 *
 * This class separates chunking logic from FileChannel delegation, making the code
 * more maintainable and testable.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Channel operations required for chunk-based encryption")
@SuppressWarnings("preview")
public class TranslogChunkManager {

    // GCM chunk constants
    /** Size of each data chunk in bytes (8KB). */
    public static final int GCM_CHUNK_SIZE = 8192;

    /** Size of GCM authentication tag in bytes (16 bytes). */
    public static final int GCM_TAG_SIZE = AesGcmCipherFactory.GCM_TAG_LENGTH;

    /** Total size of chunk plus authentication tag in bytes (8208 bytes maximum). */
    public static final int CHUNK_WITH_TAG_SIZE = GCM_CHUNK_SIZE + GCM_TAG_SIZE;

    // Thread-local buffer pool for reducing allocations
    private static final ThreadLocal<ByteBuffer> CHUNK_BUFFER_POOL = ThreadLocal
        .withInitial(() -> ByteBuffer.allocate(CHUNK_WITH_TAG_SIZE));
    private static final ThreadLocal<ByteBuffer> TRANSFER_BUFFER_POOL = ThreadLocal.withInitial(() -> ByteBuffer.allocate(GCM_CHUNK_SIZE));
    private static final ThreadLocal<byte[]> TEMP_ARRAY_POOL = ThreadLocal.withInitial(() -> new byte[GCM_CHUNK_SIZE]);

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final String translogUUID;

    // Header size - calculated exactly using TranslogHeader.headerSizeInBytes()
    private final int actualHeaderSize;

    // Base IV derived using HKDF for deterministic translog encryption
    private final byte[] baseIV;

    // Streaming cipher state for write operations
    private MemorySegment currentCipher;
    private long currentBlockNumber = 0;
    private int currentBlockBytesWritten = 0;
    private static final int BLOCK_SIZE_SHIFT = 13;
    private static final int BLOCK_SIZE = 1 << BLOCK_SIZE_SHIFT; // 8KB blocks
    private long fileWritePosition = 0;

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

    /**
     * Maps a file position to chunk information including chunk index and offset within chunk.
     *
     * @param filePosition the logical file position to map to chunk coordinates
     * @return chunk information containing index, offset, and disk position
     */
    public ChunkInfo getChunkInfo(long filePosition) {
        long dataPosition = filePosition - determineHeaderSize();
        int chunkIndex = (int) (dataPosition / GCM_CHUNK_SIZE);
        int offsetInChunk = (int) (dataPosition % GCM_CHUNK_SIZE);
        long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);
        return new ChunkInfo(chunkIndex, offsetInChunk, diskPosition);
    }

    /**
     * Checks if we can read a chunk at the given disk position.
     * Returns false for write-only channels or if chunk doesn't exist.
     *
     * @param diskPosition the disk position where the chunk should be located
     * @return true if the chunk exists and can be read, false otherwise
     */
    public boolean canReadChunk(long diskPosition) {
        try {
            // Check if position is beyond current file size (new chunk)
            if (diskPosition >= delegate.size()) {
                return false;
            }

            // Test if channel is readable by attempting a zero-byte read
            ByteBuffer testBuffer = ByteBuffer.allocate(0);
            delegate.read(testBuffer, diskPosition);
            return true;

        } catch (NonReadableChannelException | IOException e) {
            // Channel is write-only
            return false;
        }
        // Other read errors - assume can't read

    }

    /**
     * Reads and decrypts a complete chunk from disk.
     * Returns empty array if chunk doesn't exist or channel is write-only.
     *
     * @param chunkIndex the index of the chunk to read and decrypt
     * @return the decrypted chunk data, or empty array if chunk doesn't exist
     * @throws IOException if reading or decryption fails
     */
    public byte[] readAndDecryptChunk(int chunkIndex) throws IOException {
        try {
            // Calculate disk position for this chunk
            long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);

            // Check if position is beyond current file size (new chunk)
            if (diskPosition >= delegate.size()) {
                return new byte[0];
            }

            // Read encrypted chunk + tag from disk using pooled buffer.
            // Must read fully: a single delegate.read may return a partial count, which would feed a
            // truncated buffer to GCM and fail authentication. The pooled buffer caps at
            // CHUNK_WITH_TAG_SIZE, so this reads exactly one chunk (or up to EOF for a short last chunk).
            ByteBuffer buffer = CHUNK_BUFFER_POOL.get();
            buffer.clear();
            int bytesRead = readFully(buffer, diskPosition);

            if (bytesRead <= GCM_TAG_SIZE) {
                return new byte[0]; // Empty or invalid chunk
            }

            // Extract encrypted data with tag
            byte[] encryptedWithTag = new byte[bytesRead];
            buffer.flip();
            buffer.get(encryptedWithTag);

            // Use existing key management
            Key key = keyResolver.getDataKey();

            // Per-block 12-byte GCM nonce (baseIV[0:8] || BE32(chunkIndex)). MUST match the write path's
            // nonce for the same block index, or decryption fails. See AesGcmCipherFactory.computeGcmNonce.
            byte[] chunkIV = AesGcmCipherFactory.computeGcmNonce(baseIV, chunkIndex);

            // Use existing GCM decryption with authentication
            byte[] decrypted = AesGcmCipherFactory.decryptWithTag(key, chunkIV, encryptedWithTag);
            return decrypted;

        } catch (NonReadableChannelException e) {
            // Channel is write-only
            return new byte[0];
        } catch (IOException | AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to decrypt chunk " + chunkIndex, e);
        }
    }

    /**
     * Encrypts and writes a complete chunk to disk.
     *
     * @param chunkIndex the index of the chunk to encrypt and write
     * @param plainData the plain data to encrypt and write to the chunk
     * @throws IOException if encryption or writing fails
     */
    public void encryptAndWriteChunk(int chunkIndex, byte[] plainData) throws IOException {
        try {
            // Use existing key management
            Key key = keyResolver.getDataKey();

            // Per-block 12-byte GCM nonce (baseIV[0:8] || BE32(chunkIndex)) — unique per block.
            byte[] chunkIV = AesGcmCipherFactory.computeGcmNonce(baseIV, chunkIndex);

            // Use existing GCM encryption (includes authentication tag)
            byte[] encryptedWithTag = AesGcmCipherFactory.encryptWithTag(key, chunkIV, plainData, plainData.length);

            // Write to disk at chunk position
            long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);
            ByteBuffer buffer = ByteBuffer.wrap(encryptedWithTag);
            writeFully(buffer, diskPosition);

        } catch (IOException | AesGcmCipherFactory.JavaCryptoException e) {
            throw new IOException("Failed to encrypt chunk " + chunkIndex + " in file " + filePath, e);
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

        // Chunk-based reading for encrypted data
        ChunkInfo chunkInfo = getChunkInfo(position);

        // Read and decrypt the needed chunk
        byte[] decryptedChunk = readAndDecryptChunk(chunkInfo.chunkIndex);

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

        if (fileWritePosition == 0) {
            fileWritePosition = headerSize;
        }

        int totalWritten = 0;

        // Initialize new cipher
        if (currentCipher == null) {
            initializeBlockCipher(currentBlockNumber++);
        }

        while (src.hasRemaining()) {
            // Finalize cipher when block is full and initialize new cipher
            if (currentCipher != null && currentBlockBytesWritten >= BLOCK_SIZE) {
                finalizeCurrentBlock();
                initializeBlockCipher(currentBlockNumber++);
            }

            // Write what fits in current block
            int toWrite = Math.min(src.remaining(), BLOCK_SIZE - currentBlockBytesWritten);

            // Use pooled array to avoid allocation
            byte[] plainData = TEMP_ARRAY_POOL.get();
            src.get(plainData, 0, toWrite);

            // Stream encrypt using current cipher (no tag yet)
            byte[] encrypted;
            try {
                encrypted = OpenSslNativeCipher.encryptUpdate(currentCipher, java.util.Arrays.copyOf(plainData, toWrite));
            } catch (Throwable e) {
                OpenSslNativeCipher.freeCipherContext(currentCipher);
                throw new IOException("Failed to encrypt translog data at offset:" + fileWritePosition + " file:" + filePath, e);
            }

            // Write encrypted data immediately at tracked position
            int written = writeFully(ByteBuffer.wrap(encrypted), fileWritePosition);
            fileWritePosition += written;

            currentBlockBytesWritten += toWrite;
            totalWritten += toWrite;
        }

        return totalWritten;
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
     * Initialize GCM cipher for a new block
     */
    private void initializeBlockCipher(long blockNumber) throws IOException {
        Key key = keyResolver.getDataKey();

        // Per-block GCM nonce: baseIV[0:8] || BE32(blockNumber). blockNumber == the chunk index of the
        // block (both count 8192-byte blocks from 0), so this matches readAndDecryptChunk's nonce exactly.
        // Guard the 32-bit block-index domain (M3): beyond 2^31-1 blocks the nonce counter would alias.
        if (blockNumber > Integer.MAX_VALUE) {
            throw new IOException("translog block index " + blockNumber + " exceeds maximum addressable block for file:" + filePath);
        }
        byte[] nonce = AesGcmCipherFactory.computeGcmNonce(baseIV, (int) blockNumber);
        // initGCMCipher requires a 16-byte IV but uses only the first 12 bytes (the GCM nonce); pad it.
        byte[] iv16 = new byte[16];
        System.arraycopy(nonce, 0, iv16, 0, nonce.length);

        try {
            this.currentCipher = OpenSslNativeCipher.initGCMCipher(key.getEncoded(), iv16, 0L);
        } catch (Throwable e) {
            throw new IOException("Failed to initialize cipher for blockNumber:" + blockNumber + " for file:" + filePath, e);
        }

        // NOTE: do NOT reassign currentBlockNumber here. The caller (writeToChunks) advances it via
        // currentBlockNumber++ when selecting the block to initialize; reassigning it to blockNumber
        // would undo that increment and pin every block to the same nonce index (GCM nonce reuse).
        this.currentBlockBytesWritten = 0;
    }

    /**
     * Finalize current block and write tag inline
     */
    private void finalizeCurrentBlock() throws IOException {
        if (currentCipher == null) {
            return;
        }
        byte[] tag;
        try {
            tag = OpenSslNativeCipher.finalizeAndGetTag(currentCipher);
        } catch (Throwable e) {
            throw new IOException("Failed to finalize cipher for file:" + filePath, e);
        } finally {
            currentCipher = null;
        }
        int written = writeFully(ByteBuffer.wrap(tag), fileWritePosition);
        fileWritePosition += written;
    }

    /**
     * Close and finalize last block
     */
    public void close() throws IOException {
        if (currentCipher != null) {
            finalizeCurrentBlock();
            currentCipher = null;
        }
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
