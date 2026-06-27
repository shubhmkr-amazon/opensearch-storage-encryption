/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A FileChannel wrapper that provides transparent AES-GCM encryption/decryption for translog files using
 * the FRAME-AAD format.
 *
 * <p>This implementation delegates all framing/crypto to {@link TranslogFrameManager} while handling the
 * FileChannel lifecycle and logical position tracking. The wrapper owns the concurrency contract: writes,
 * scatter-reads, {@code force()} and {@code transferFrom()} take the write lock; positional reads and
 * {@code transferTo()} take the read lock — so the frame manager itself holds no locks and its writer state
 * is mutated single-threaded.
 *
 * <p>On-disk format (see {@link TranslogFrameManager}):
 * [plaintext TranslogHeader][TLE1 super-header][frame...], each frame = [24B header][ciphertext][16B tag].
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "FileChannel operations required for encrypted translog implementation")
public class CryptoFileChannelWrapper extends FileChannel {

    private final FileChannel delegate;
    private final TranslogFrameManager chunkManager;
    private final AtomicLong position;
    private final ReentrantReadWriteLock positionLock;
    private volatile boolean closed = false;
    private final Path filePath;

    /**
     * Creates a new CryptoFileChannelWrapper that wraps the provided FileChannel.
     *
     * @param delegate the underlying FileChannel to wrap
     * @param keyResolver the key and IV resolver for encryption (unified with index files)
     * @param path the file path (used for logging and debugging)
     * @param options the file open options (used for logging and debugging)
     * @param translogUUID the translog UUID for exact header size calculation
     * @throws IOException if there is an error setting up the channel
     */
    public CryptoFileChannelWrapper(FileChannel delegate, KeyResolver keyResolver, Path path, Set<OpenOption> options, String translogUUID)
        throws IOException {
        this.delegate = delegate;
        this.filePath = path;
        this.chunkManager = new TranslogFrameManager(delegate, keyResolver, path, translogUUID);
        this.position = new AtomicLong(delegate.position());
        this.positionLock = new ReentrantReadWriteLock();
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        ensureOpen();
        if (dst.remaining() == 0) {
            return 0;
        }

        // updates channel position, needs writeLock for position update
        positionLock.writeLock().lock();
        try {
            long currentPosition = position.get();
            int bytesRead = readAtPosition(dst, currentPosition);
            if (bytesRead > 0) {
                position.addAndGet(bytesRead);
            }
            return bytesRead;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        ensureOpen();
        if (dst.remaining() == 0) {
            return 0;
        }

        // Positional read: does NOT update channel position, can use readLock for better concurrency
        positionLock.readLock().lock();
        try {
            return readAtPosition(dst, position);
        } finally {
            positionLock.readLock().unlock();
        }
    }

    /**
     * Internal method to read from a specific position without updating the channel position.
     * This method is used by both stateful and positional read methods.
     */
    private int readAtPosition(ByteBuffer dst, long position) throws IOException {
        // Delegate to chunk manager for all read operations
        return chunkManager.readFromChunks(dst, position);
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        ensureOpen();

        // L6: this scatter read mutates the channel position, so it must hold the same writeLock as the
        // single-buffer stateful read — otherwise a concurrent read/write can tear the position. Call the
        // unlocked readAtPosition() inside the lock (ReentrantReadWriteLock is not re-entrant write->read).
        positionLock.writeLock().lock();
        try {
            long totalBytesRead = 0;
            long currentPosition = position.get();

            for (int i = offset; i < offset + length && i < dsts.length; i++) {
                ByteBuffer dst = dsts[i];
                if (dst.remaining() > 0) {
                    int bytesRead = readAtPosition(dst, currentPosition + totalBytesRead);
                    if (bytesRead <= 0) {
                        break;
                    }
                    totalBytesRead += bytesRead;
                }
            }

            if (totalBytesRead > 0) {
                position.addAndGet(totalBytesRead);
            }

            return totalBytesRead;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        long currentPosition = position.get();
        int bytesWritten = write(src, currentPosition);
        if (bytesWritten > 0) {
            position.addAndGet(bytesWritten);
        }
        return bytesWritten;
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        ensureOpen();
        if (src.remaining() == 0) {
            return 0;
        }

        positionLock.writeLock().lock();
        try {
            // Delegate to chunk manager for all write operations
            return chunkManager.writeToChunks(src, position);
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        ensureOpen();

        long totalBytesWritten = 0;
        long currentPosition = position.get();

        for (int i = offset; i < offset + length && i < srcs.length; i++) {
            ByteBuffer src = srcs[i];
            if (src.remaining() > 0) {
                int bytesWritten = write(src, currentPosition + totalBytesWritten);
                if (bytesWritten <= 0) {
                    break;
                }
                totalBytesWritten += bytesWritten;
            }
        }

        if (totalBytesWritten > 0) {
            position.addAndGet(totalBytesWritten);
        }

        return totalBytesWritten;
    }

    @Override
    public long position() throws IOException {
        ensureOpen();
        return position.get();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        ensureOpen();
        delegate.position(newPosition);
        position.set(newPosition);
        return this;
    }

    @Override
    public long size() throws IOException {
        ensureOpen();
        return delegate.size();
    }

    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen();
        delegate.truncate(size);
        long currentPosition = position.get();
        if (currentPosition > size) {
            position.set(size);
        }
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        ensureOpen();
        // C2: seal the open GCM block (write its ciphertext + tag) BEFORE forcing, so every byte that a
        // subsequent checkpoint references — and any concurrent read of just-written ops — sees a complete,
        // authenticated chunk on disk. Without this, the open block's tag lives only in memory and a
        // realtime read / crash hits an un-tagged chunk -> AEADBadTagException.
        positionLock.writeLock().lock();
        try {
            chunkManager.flushSeal();
        } finally {
            positionLock.writeLock().unlock();
        }
        delegate.force(metaData);
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        ensureOpen();
        // L6: positional read of encrypted chunks — guard with the read lock so it cannot interleave with
        // a concurrent write that is mutating the open-block buffer/index state.
        positionLock.readLock().lock();
        try {
            return chunkManager.transferFromChunks(position, count, target);
        } finally {
            positionLock.readLock().unlock();
        }
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        ensureOpen();
        // L6: mutates write state (blockBuf/fileWritePosition/currentBlockNumber) — must hold the write
        // lock, same as write().
        positionLock.writeLock().lock();
        try {
            return chunkManager.transferToChunks(src, position, count);
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.lock(position, size, shared);
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.tryLock(position, size, shared);
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        ensureOpen();

        // For encrypted files, we cannot support memory mapping directly
        // because the mapped memory would contain encrypted data
        throw new UnsupportedOperationException(
            "Memory mapping is not supported for encrypted translog files. "
                + "Encrypted files require data to be decrypted during read operations."
        );
    }

    @Override
    protected void implCloseChannel() throws IOException {
        if (closed) {
            return;
        }
        // Always close the delegate even if the final seal fails (e.g. disk-full throws inside
        // chunkManager.close() -> flushSeal() -> writeFully). Otherwise the delegate fd leaks, and latching
        // `closed` before the seal would make every retry a no-op (permanent leak). Mark closed only after
        // the delegate is actually released. (Review: M2 fd-leak fix.)
        try {
            chunkManager.close(); // seals the open accumulator (real I/O — may throw)
        } finally {
            try {
                delegate.close();
            } finally {
                closed = true;
            }
        }
    }

    private void ensureOpen() throws ClosedChannelException {
        if (closed || !delegate.isOpen()) {
            throw new ClosedChannelException();
        }
    }

    /**
     * Gets the {@link TranslogFrameManager} for this channel.
     * This allows access to finalize the cipher before upload.
     *
     * @return the TranslogFrameManager instance
     */
    public TranslogFrameManager getChunkManager() {
        return chunkManager;
    }
}
