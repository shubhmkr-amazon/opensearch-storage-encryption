/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.opensearch.index.remote.RemoteStoreEnums.DataCategory.TRANSLOG;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.DATA;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.METADATA;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.remote.RemoteStorePathStrategy;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.BlobStoreTransferService;
import org.opensearch.index.translog.transfer.FileTransferTracker;
import org.opensearch.index.translog.transfer.TranslogTransferManager;
import org.opensearch.indices.RemoteStoreSettings;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.threadpool.ThreadPool;

/**
 * A RemoteFsTranslog implementation that provides AES-GCM encryption capabilities
 * with decrypt-before-upload for remote store.
 *
 * @opensearch.internal
 */
public class CryptoRemoteFsTranslog extends RemoteFsTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoRemoteFsTranslog.class);

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;

    public CryptoRemoteFsTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        BooleanSupplier startedPrimarySupplier,
        RemoteTranslogTransferTracker remoteTranslogTransferTracker,
        RemoteStoreSettings remoteStoreSettings,
        TranslogOperationHelper translogOperationHelper,
        KeyResolver keyResolver
    )
        throws IOException {
        super(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            blobStoreRepository,
            threadPool,
            startedPrimarySupplier,
            remoteTranslogTransferTracker,
            remoteStoreSettings,
            translogOperationHelper,
            createCryptoChannelFactory(keyResolver, translogUUID),
            true // isServerSideEncryptionEnabled
        );

        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = (CryptoChannelFactory) this.channelFactory;

        // Re-encrypt downloaded plaintext translog files with the new key.
        // After remote store restore, S3 has plaintext translog data (AES-GCM was stripped
        // during upload by DecryptingTranslogTransferManager). The download writes these raw
        // plaintext bytes to disk. But CryptoChannelFactory expects AES-GCM encrypted files
        // on disk. We re-encrypt old generation files so the decrypt-before-upload path works
        // and the encryption-at-rest invariant is maintained.
        reEncryptDownloadedTranslogFiles(config.getTranslogPath(), current.getGeneration());

        try {
            TranslogTransferManager decryptingManager = createDecryptingTranslogTransferManager(
                blobStoreRepository,
                threadPool,
                config.getShardId(),
                fileTransferTracker,
                remoteTranslogTransferTracker,
                config.getIndexSettings().getRemoteStorePathStrategy(),
                remoteStoreSettings,
                config.getIndexSettings().isTranslogMetadataEnabled(),
                keyResolver,
                translogUUID,
                cryptoFactory
            );

            // Use reflection to replace the final field
            Field transferManagerField = RemoteFsTranslog.class.getDeclaredField("translogTransferManager");
            transferManagerField.setAccessible(true);
            transferManagerField.set(this, decryptingManager);
        } catch (Exception e) {
            logger.error("Failed to replace TranslogTransferManager with decrypting version", e);
            throw new IOException("Failed to initialize decrypt-before-upload capability", e);
        }
    }

    /**
     * Creates a DecryptingTranslogTransferManager to replace parent's manager.
     */
    private static TranslogTransferManager createDecryptingTranslogTransferManager(
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        ShardId shardId,
        FileTransferTracker fileTransferTracker,
        RemoteTranslogTransferTracker tracker,
        RemoteStorePathStrategy pathStrategy,
        RemoteStoreSettings remoteStoreSettings,
        boolean isTranslogMetadataEnabled,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        String indexUUID = shardId.getIndex().getUUID();
        String shardIdStr = String.valueOf(shardId.id());

        RemoteStorePathStrategy.ShardDataPathInput dataPathInput = RemoteStorePathStrategy.ShardDataPathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(DATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath dataPath = pathStrategy.generatePath(dataPathInput);

        RemoteStorePathStrategy.ShardDataPathInput mdPathInput = RemoteStorePathStrategy.ShardDataPathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(METADATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath mdPath = pathStrategy.generatePath(mdPathInput);

        BlobStoreTransferService transferService = new BlobStoreTransferService(
            blobStoreRepository.blobStore(true), // SSE-KMS enabled
            threadPool
        );

        return new DecryptingTranslogTransferManager(
            shardId,
            transferService,
            dataPath,
            mdPath,
            fileTransferTracker,
            tracker,
            remoteStoreSettings,
            isTranslogMetadataEnabled,
            keyResolver,
            translogUUID,
            cryptoFactory
        );
    }

    /**
     * Re-encrypts downloaded plaintext translog files with the current key, in the self-describing
     * on-disk frame format (plaintext core header + TLE1 super-header + length-prefixed AES-GCM frames).
     *
     * <p>Only processes old generation {@code .tlog} files (not the current writer). Files that already
     * carry the TLE1 super-header are skipped — re-encrypting them would double-encrypt and corrupt them.
     * Genuinely-plaintext files are re-encrypted by streaming their data region through a
     * {@link TranslogFrameManager}, which emits the super-header and per-block chunks under the
     * generation-bound base IV — the exact format the reader/recovery path expects.
     *
     * <p>Note: recovery readers opened during the parent constructor are already converted in place by
     * {@link CryptoChannelFactory#open} before their channel is cached, so this sweep is a belt-and-braces
     * pass over any downloaded {@code .tlog} that recovery did not open. It is fail-closed: any conversion
     * failure is rethrown so the shard fails to initialize rather than silently running on a corrupt or
     * still-plaintext translog.
     *
     * @throws IOException if a downloaded file cannot be converted to the encrypted frame format
     */
    private void reEncryptDownloadedTranslogFiles(java.nio.file.Path translogDir, long currentGeneration) throws IOException {
        try (DirectoryStream<java.nio.file.Path> stream = Files.newDirectoryStream(translogDir, "*.tlog")) {
            for (java.nio.file.Path file : stream) {
                String name = file.getFileName().toString();
                // Extract generation number from filename like "translog-4.tlog"
                String genStr = name.replace("translog-", "").replace(".tlog", "");
                long gen;
                try { gen = Long.parseLong(genStr); } catch (NumberFormatException e) { continue; }

                // Skip current writer generation (already created encrypted by CryptoChannelFactory)
                if (gen >= currentGeneration) continue;

                long fileSize = Files.size(file);
                int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(translogUUID);

                // Skip header-only files (no data to re-encrypt)
                if (fileSize <= headerSize) {
                    continue;
                }

                // Read the entire downloaded file
                byte[] plainBytes = Files.readAllBytes(file);

                // Already an encrypted translog? Detect by the self-describing super-header MAGIC (not the
                // version) — skip to avoid double-encryption/corruption and to avoid masking a format error
                // the reader is supposed to fail closed on. Same predicate as CryptoChannelFactory.open().
                if (TranslogFrameManager.hasSuperHeaderMagic(plainBytes, headerSize)) {
                    continue;
                }

                byte[] header = java.util.Arrays.copyOf(plainBytes, headerSize);
                byte[] data = java.util.Arrays.copyOfRange(plainBytes, headerSize, plainBytes.length);

                // Re-encrypt into the frame format by streaming the plaintext data region through a frame
                // manager. The TFM uses `file` only for header-size and generation parsing (its IV is keyed
                // to this generation); the temp channel is the actual I/O target.
                java.nio.file.Path tempFile = file.resolveSibling(name + ".tmp");
                try {
                    try (FileChannel out = FileChannel.open(tempFile,
                            StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ,
                            StandardOpenOption.TRUNCATE_EXISTING)) {
                        // Plaintext core header passthrough.
                        out.write(ByteBuffer.wrap(header), 0);
                        // TLE1 super-header + length-prefixed GCM frames, sealed on close().
                        TranslogFrameManager tfm = new TranslogFrameManager(out, keyResolver, file, translogUUID);
                        tfm.writeToChunks(ByteBuffer.wrap(data), headerSize);
                        tfm.close();
                        // Flush the converted bytes to stable storage BEFORE the atomic rename. Without this a
                        // power-loss after the rename is visible but before the page cache is flushed could
                        // expose a partial/zero-length file under the real translog name. Mirrors the open()
                        // conversion path (CryptoChannelFactory.ensureEncryptedOnDisk).
                        out.force(true);
                    }
                    Files.move(
                        tempFile,
                        file,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING
                    );
                } catch (IOException | RuntimeException ex) {
                    // Never leave an orphan temp behind on a mid-conversion failure (the original downloaded
                    // file is untouched until the atomic rename, so deleting the temp is always safe).
                    Files.deleteIfExists(tempFile);
                    throw ex;
                }
            }
        } catch (IOException e) {
            // Fail closed: do NOT let the shard start on a corrupt/plaintext translog.
            logger.error("Failed to re-encrypt downloaded translog files in {}", translogDir, e);
            throw e;
        }
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     */
    private static CryptoChannelFactory createCryptoChannelFactory(KeyResolver keyResolver, String translogUUID) throws IOException {
        try {
            return new CryptoChannelFactory(keyResolver, translogUUID);
        } catch (Exception e) {
            throw new IOException(
                "Failed to initialize crypto channel factory for translog encryption. Cannot proceed without encryption!",
                e
            );
        }
    }
}
