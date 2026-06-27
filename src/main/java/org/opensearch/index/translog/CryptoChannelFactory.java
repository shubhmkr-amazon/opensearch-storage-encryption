/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.opensearch.index.store.key.KeyResolver;

/**
 * A ChannelFactory implementation that creates FileChannels with transparent
 * AES-GCM encryption/decryption for translog files.
 *
 * This factory determines whether to apply encryption based on the file extension:
 * - .tlog files: Encrypted using AES-GCM with 8KB authenticated chunks
 * - .ckp files: Not encrypted (checkpoint metadata)
 *
 * Updated to use unified KeyResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * The factory also tracks the current writer's wrapper to enable cipher finalization
 * before remote upload (decrypt-before-upload flow).
 *
 * @opensearch.internal
 */
public class CryptoChannelFactory implements ChannelFactory {

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final Map<Path, CryptoFileChannelWrapper> wrappers = new ConcurrentHashMap<>();

    /**
     * Creates a new CryptoChannelFactory.
     *
     * @param keyResolver the key and IV resolver for encryption keys (unified with index files)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public CryptoChannelFactory(KeyResolver keyResolver, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        // Fail fast on a null key resolver. Since the base-IV derivation is LAZY (deferred to the
        // first super-header write/read), the constructor no longer dereferences the resolver, so without
        // this check a null resolver would slip past construction and only NPE later at the first frame
        // crypto op — a worse, deferred failure. Validate eagerly at the earliest common point instead.
        if (keyResolver == null) {
            throw new IllegalArgumentException("keyResolver is required for translog encryption");
        }
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
    }

    @Override
    public FileChannel open(Path path, OpenOption... options) throws IOException {
        if (!path.getFileName().toString().endsWith(".tlog")) {
            return FileChannel.open(path, options);
        }

        // Restore-from-plaintext safety: a remote-store restore downloads decrypted .tlog bytes to disk,
        // and OpenSearch core opens recovery readers (caching the FileChannel as a final field) during the
        // RemoteFsTranslog constructor — i.e. through THIS open() — before CryptoRemoteFsTranslog's
        // post-constructor re-encrypt sweep runs. If we returned a decrypting wrapper over plaintext here,
        // that cached reader would later try to decrypt plaintext and fail (shard red), and a subsequent
        // Files.move of an encrypted file over the name would not help the already-open fd (POSIX rename
        // leaves it on the old inode). So convert plaintext -> the encrypted frame format IN PLACE before
        // opening, so the channel core caches is already bound to the encrypted inode. No-op for files that
        // already carry the TLE1 super-header.
        //
        // ONLY for an open of an EXISTING file that is NOT creating a fresh writer: a CREATE/CREATE_NEW
        // open is core making a brand-new translog generation (the file does not exist yet) — there is
        // nothing to convert, and touching the not-yet-created path here would break new-translog creation.
        if (!isCreatingNewFile(options) && Files.exists(path)) {
            ensureEncryptedOnDisk(path);
        }

        FileChannel baseChannel = FileChannel.open(path, options);
        Set<OpenOption> optionsSet = Set.of(options);
        CryptoFileChannelWrapper wrapper = new CryptoFileChannelWrapper(baseChannel, keyResolver, path, optionsSet, translogUUID);

        // Track wrapper by path for later finalization
        wrappers.put(path, wrapper);
        return wrapper;
    }

    /**
     * Returns true if {@code options} indicate the caller is creating a brand-new file (CREATE or
     * CREATE_NEW). A fresh translog generation is opened this way and has no existing bytes to convert.
     */
    private static boolean isCreatingNewFile(OpenOption... options) {
        for (OpenOption o : options) {
            if (o == StandardOpenOption.CREATE || o == StandardOpenOption.CREATE_NEW) {
                return true;
            }
        }
        return false;
    }

    /**
     * Ensures the on-disk {@code .tlog} at {@code path} is in the encrypted frame format, converting it in
     * place if it is genuinely-plaintext downloaded data. Idempotent: a file already carrying the TLE1
     * super-header (or a header-only/empty file with no data region) is left untouched.
     *
     * <p>This runs synchronously before the FileChannel is created so that any reader OpenSearch core
     * caches over this path is bound to the encrypted inode, never to plaintext. The conversion is
     * crash-safe (write to a temp sibling, then atomically rename over the original).
     *
     * @param path the translog file path
     * @throws IOException if the file cannot be read, converted, or atomically replaced
     */
    private void ensureEncryptedOnDisk(Path path) throws IOException {
        int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(translogUUID);

        long fileSize = Files.size(path);
        if (fileSize <= headerSize) {
            // Header-only / empty data region: nothing to encrypt yet, and not a magic-detectable file.
            return;
        }

        byte[] fileBytes = Files.readAllBytes(path);

        // Already an encrypted translog (carries the TLE magic): leave it alone. Check MAGIC ONLY, not the
        // version — a current file, a future-version file, or a file with a corrupted version byte all carry
        // the magic and must NOT be re-encrypted (that would double-encrypt/corrupt them, and would also mask
        // a format/corruption error the reader is supposed to fail closed on). Only a file WITHOUT the magic
        // is genuinely-plaintext downloaded data eligible for conversion.
        if (TranslogFrameManager.hasSuperHeaderMagic(fileBytes, headerSize)) {
            return;
        }

        // Genuinely-plaintext downloaded data: convert to the encrypted frame format in place via a crash-safe
        // temp+rename. The conversion runs BEFORE this open() returns the channel, so any reader OpenSearch
        // core caches over this path binds to the encrypted inode (never the plaintext one).
        byte[] header = Arrays.copyOf(fileBytes, headerSize);
        byte[] data = Arrays.copyOfRange(fileBytes, headerSize, fileBytes.length);

        Path tempFile = path.resolveSibling(path.getFileName().toString() + ".enc.tmp");
        try {
            try (
                FileChannel out = FileChannel.open(
                    tempFile,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.READ,
                    StandardOpenOption.TRUNCATE_EXISTING
                )
            ) {
                // Plaintext core-header passthrough, then the TLE1 super-header + length-prefixed GCM frames.
                out.write(ByteBuffer.wrap(header), 0);
                TranslogFrameManager tfm = new TranslogFrameManager(out, keyResolver, path, translogUUID);
                tfm.writeToChunks(ByteBuffer.wrap(data), headerSize);
                tfm.close();
                out.force(true);
            }
            Files.move(tempFile, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException ex) {
            // Never leave an orphan temp behind on a mid-conversion failure (the original file is untouched
            // until the atomic rename, so deleting the temp is always safe).
            Files.deleteIfExists(tempFile);
            throw ex;
        }
    }

    /**
     * Finalizes the cipher for a specific file path.
     * This writes authentication tags to disk so the file can be decrypted.
     * 
     * This is for the decrypt-before-upload flow:
     * 1. Called before upload for the specific file being uploaded
     * 2. Writes authentication tags to complete encryption
     * 3. Enables successful decryption during snapshot read
     * 
     * @param path the path of the file to finalize
     * @throws IOException if finalization fails
     */
    public void finalizeForPath(Path path) throws IOException {
        CryptoFileChannelWrapper wrapper = wrappers.get(path);
        if (wrapper != null) {
            wrapper.getChunkManager().close();
        }
    }

    /**
     * Removes a wrapper from tracking when it's no longer needed.
     * 
     * @param path the path of the wrapper to remove
     */
    public void removeWrapper(Path path) {
        wrappers.remove(path);
    }
}
