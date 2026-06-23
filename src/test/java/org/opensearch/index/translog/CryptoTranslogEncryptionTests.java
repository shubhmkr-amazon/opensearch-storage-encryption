/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.ShardCacheKey;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

/**
 * Verify that translog data encryption actually works.
 */
public class CryptoTranslogEncryptionTests extends OpenSearchTestCase {

    private static final Logger logger = LogManager.getLogger(CryptoTranslogEncryptionTests.class);

    private Path tempDir;
    private KeyResolver keyResolver;
    private MasterKeyProvider keyProvider;
    private String testIndexUuid;

    /**
     * Helper method to register the resolver in the ShardKeyResolverRegistry
     */
    @SuppressForbidden(reason = "Test needs to register resolver in ShardKeyResolverRegistry")
    private void registerResolver(String indexUuid, int shardId, KeyResolver resolver) throws Exception {
        Field resolverCacheField = ShardKeyResolverRegistry.class.getDeclaredField("resolverCache");
        resolverCacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentMap<ShardCacheKey, KeyResolver> resolverCache = (ConcurrentMap<ShardCacheKey, KeyResolver>) resolverCacheField.get(null);
        resolverCache.put(new ShardCacheKey(indexUuid, shardId, "test-index"), resolver);
    }

    @Override
    @SuppressForbidden(reason = "Creating temp directory for test purposes")
    public void setUp() throws Exception {
        super.setUp();
        tempDir = Files.createTempDirectory("crypto-translog-encryption-test");

        // Clear the ShardKeyResolverRegistry cache before each test
        ShardKeyResolverRegistry.clearCache();

        // Initialize NodeLevelKeyCache with test settings
        Settings nodeSettings = Settings
            .builder()
            .put("node.store.crypto.key_refresh_interval", "5m") // 5 minutes for tests
            .build();

        // Create mock Client and ClusterService for testing
        Client mockClient = mock(Client.class);
        ClusterService mockClusterService = mock(ClusterService.class);

        // Setup mock Client chain for block operations
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        @SuppressWarnings("unchecked")
        ActionFuture<AcknowledgedResponse> mockFuture = (ActionFuture<AcknowledgedResponse>) mock(ActionFuture.class);

        when(mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);
        when(mockIndicesAdminClient.updateSettings(any())).thenReturn(mockFuture);
        when(mockFuture.actionGet()).thenReturn(mock(AcknowledgedResponse.class));

        MasterKeyHealthMonitor.initialize(nodeSettings, mockClient, mockClusterService);
        NodeLevelKeyCache.initialize(nodeSettings, MasterKeyHealthMonitor.getInstance());

        Provider cryptoProvider = Security.getProvider("SunJCE");

        // Create a mock key provider for testing
        keyProvider = new MasterKeyProvider() {
            @Override
            public java.util.Map<String, String> getEncryptionContext() {
                return java.util.Collections.singletonMap("test-key", "test-value");
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                return new byte[32]; // 256-bit key
            }

            @Override
            public String getKeyId() {
                return "test-key-id";
            }

            @Override
            public org.opensearch.common.crypto.DataKeyPair generateDataPair() {
                byte[] rawKey = new byte[32];
                byte[] encryptedKey = new byte[32];
                return new org.opensearch.common.crypto.DataKeyPair(rawKey, encryptedKey);
            }

            @Override
            public void close() {
                // No resources to close
            }
        };

        // Use a test index UUID
        testIndexUuid = "test-index-uuid-" + System.currentTimeMillis();
        org.apache.lucene.store.Directory directory = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        // keyResolver = new DefaultKeyResolver(directory, cryptoProvider, keyProvider);
        keyResolver = new DefaultKeyResolver(testIndexUuid, "test-index", directory, cryptoProvider, keyProvider, 0);

        // Register the resolver with ShardKeyResolverRegistry so cache can find it
        registerResolver(testIndexUuid, 0, keyResolver);
    }

    @Override
    public void tearDown() throws Exception {
        // Reset singletons to prevent test pollution
        MasterKeyHealthMonitor.reset();
        NodeLevelKeyCache.reset();
        // Clear the ShardKeyResolverRegistry cache
        ShardKeyResolverRegistry.clearCache();
        super.tearDown();
    }

    public void testTranslogDataIsActuallyEncrypted() throws IOException {
        String testTranslogUUID = "test-encryption-uuid";
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyResolver, testTranslogUUID);

        Path translogPath = tempDir.resolve("test-encryption.tlog");

        // Test data that should be encrypted
        String sensitiveData =
            "{\"@timestamp\": 894069207, \"clientip\":\"192.168.1.1\", \"request\": \"GET /secret/data HTTP/1.1\", \"status\": 200}";
        byte[] testData = sensitiveData.getBytes(StandardCharsets.UTF_8);

        // Write header + data using our crypto channel (with READ permission for round-trip verification)
        try (
            FileChannel cryptoChannel = channelFactory
                .open(translogPath, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)
        ) {

            // First write the header
            TranslogHeader header = new TranslogHeader(testTranslogUUID, 1L);
            header.write(cryptoChannel, false);
            int headerSize = header.sizeInBytes();

            logger.info("Header size: {} bytes", headerSize);

            // Now write data that should be encrypted (beyond header)
            ByteBuffer dataBuffer = ByteBuffer.wrap(testData);
            int bytesWritten = cryptoChannel.write(dataBuffer, headerSize);

            assertEquals("Should write all test data", testData.length, bytesWritten);
        }

        // CRITICAL: Read raw file content and verify data is encrypted (NOT readable)
        byte[] fileContent = Files.readAllBytes(translogPath);
        String fileContentString = new String(fileContent, StandardCharsets.UTF_8);
        String fileContentISO = new String(fileContent, StandardCharsets.ISO_8859_1);

        logger.info("File size: {} bytes", fileContent.length);
        logger.info("File content UTF-8 (first 200 chars): {}", fileContentString.substring(0, Math.min(200, fileContentString.length())));
        logger.info("File content ISO-8859-1 (first 200 chars): {}", fileContentISO.substring(0, Math.min(200, fileContentISO.length())));
        logger.info("UUID in UTF-8: {}", fileContentString.contains(testTranslogUUID));
        logger.info("UUID in ISO-8859-1: {}", fileContentISO.contains(testTranslogUUID));

        // Debug: print first 53 bytes (header) as hex
        StringBuilder hexHeader = new StringBuilder();
        for (int i = 0; i < Math.min(53, fileContent.length); i++) {
            hexHeader.append(String.format("%02X ", fileContent[i]));
        }
        logger.info("Header bytes (hex): {}", hexHeader.toString());

        assertFalse("Sensitive data found in plain text! File content: " + fileContentString, fileContentString.contains("192.168.1.1"));

        assertFalse("Sensitive data found in plain text! File content: " + fileContentString, fileContentString.contains("/secret/data"));

        assertFalse("JSON structure found in plain text! File content: " + fileContentString, fileContentString.contains("\"clientip\""));

        // Verify header is still readable (should be unencrypted)
        assertTrue(
            "Header should contain translog UUID",
            fileContentString.contains(testTranslogUUID) || fileContentISO.contains(testTranslogUUID)
        );
    }

    /**
     * Verify read/write round trip works correctly.
     */
    public void testTranslogEncryptionDecryptionRoundTrip() throws IOException {
        String testTranslogUUID = "test-roundtrip-uuid";
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyResolver, testTranslogUUID);

        Path translogPath = tempDir.resolve("test-roundtrip.tlog");

        String originalData = "{\"test\": \"sensitive document data that must be encrypted\"}";
        byte[] testData = originalData.getBytes(StandardCharsets.UTF_8);

        int headerSize;

        // Write data
        try (FileChannel writeChannel = channelFactory.open(translogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            // Write header
            TranslogHeader header = new TranslogHeader(testTranslogUUID, 1L);
            header.write(writeChannel, false);
            headerSize = header.sizeInBytes();

            // Write data beyond header
            ByteBuffer writeBuffer = ByteBuffer.wrap(testData);
            writeChannel.write(writeBuffer, headerSize);
        }

        // Read data back
        try (FileChannel readChannel = channelFactory.open(translogPath, StandardOpenOption.READ)) {
            // Skip header
            readChannel.position(headerSize);

            // Read encrypted data
            ByteBuffer readBuffer = ByteBuffer.allocate(testData.length);
            int bytesRead = readChannel.read(readBuffer);

            assertEquals("Should read same amount as written", testData.length, bytesRead);

            // Verify decrypted data matches original
            String decryptedData = new String(readBuffer.array(), StandardCharsets.UTF_8);
            assertEquals("Decrypted data should match original", originalData, decryptedData);
        }

        // Verify file content is still encrypted on disk
        byte[] rawFileContent = Files.readAllBytes(translogPath);
        String rawContent = new String(rawFileContent, StandardCharsets.UTF_8);

        assertFalse("Data should be encrypted on disk", rawContent.contains("sensitive document data"));
    }

    /**
     * Regression test for the partial-write corruption (P0).
     *
     * <p>{@link FileChannel#write(ByteBuffer, long)} may write fewer bytes than requested under load.
     * Before the fix, {@code TranslogChunkManager} issued a single unchecked {@code write} and advanced
     * its position by only the partial count, dropping the tail of an encrypted chunk and permanently
     * misaligning every later chunk — surfacing during recovery as {@code AEADBadTagException: Tag mismatch!}
     * (observed ~chunk 35834 deep in a large file). This test forces short writes on every call and asserts
     * the file still decrypts byte-for-byte across multiple 8KB chunks.
     */
    @SuppressForbidden(reason = "Test needs a real FileChannel to wrap with a short-write delegate")
    public void testPartialWritesDoNotCorruptTranslog() throws IOException {
        String testTranslogUUID = "test-partial-write-uuid";

        // ~3.5 chunks of data so the partial-write hole would land mid-stream and misalign later chunks.
        int dataLen = (TranslogChunkManager.GCM_CHUNK_SIZE * 3) + 1234;
        byte[] testData = new byte[dataLen];
        random().nextBytes(testData);

        Path translogPath = tempDir.resolve("test-partial-write.tlog");

        int headerSize;
        // Open the real channel, then wrap the delegate so every write() reports only a few bytes written.
        try (FileChannel realChannel = FileChannel.open(translogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            FileChannel shortWriteChannel = new ShortWriteFileChannel(realChannel, 7);
            try (
                CryptoFileChannelWrapper cryptoChannel = new CryptoFileChannelWrapper(
                    shortWriteChannel,
                    keyResolver,
                    translogPath,
                    java.util.Set.of(StandardOpenOption.WRITE),
                    testTranslogUUID
                )
            ) {
                TranslogHeader header = new TranslogHeader(testTranslogUUID, 1L);
                header.write(cryptoChannel, false);
                headerSize = header.sizeInBytes();

                int written = cryptoChannel.write(ByteBuffer.wrap(testData), headerSize);
                assertEquals("writeToChunks must report all logical bytes despite short delegate writes", dataLen, written);
            }
        }

        // Read back through a normal crypto channel (no short writes) and verify exact decryption.
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyResolver, testTranslogUUID);
        try (FileChannel readChannel = channelFactory.open(translogPath, StandardOpenOption.READ)) {
            ByteBuffer readBuffer = ByteBuffer.allocate(dataLen);
            int pos = headerSize;
            while (readBuffer.hasRemaining()) {
                int n = readChannel.read(readBuffer, pos);
                if (n <= 0) {
                    break;
                }
                pos += n;
            }
            assertEquals("Should decrypt all bytes back", dataLen, readBuffer.position());
            assertArrayEquals("Decrypted data must match original despite partial writes", testData, readBuffer.array());
        }
    }

    /**
     * Reads {@code len} bytes starting at {@code pos}, looping because {@code readFromChunks} returns at
     * most one chunk per call. Fails the test on a stalled loop.
     */
    private static byte[] readFullyLoop(FileChannel ch, long pos, int len) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(len);
        int done = 0;
        int guard = 0;
        int maxIters = (len / TranslogChunkManager.GCM_CHUNK_SIZE) + 4;
        while (buf.hasRemaining()) {
            int n = ch.read(buf, pos + done);
            if (n <= 0) {
                break;
            }
            done += n;
            if (++guard > maxIters) {
                fail("read loop stalled at " + done + "/" + len);
            }
        }
        assertEquals("short read-back", len, done);
        return buf.array();
    }

    /**
     * On-disk size of an encrypted translog. The streaming write format does NOT pad chunks: each block
     * stores {@code ciphertext (== plaintext length for the GCM stream) + a 16-byte tag}. So the data
     * region is {@code len + 16 * numBlocks}, where numBlocks = ceil(len / 8192).
     */
    private static long expectedFileSize(int headerSize, int len) {
        int blocks = (len + TranslogChunkManager.GCM_CHUNK_SIZE - 1) / TranslogChunkManager.GCM_CHUNK_SIZE;
        return headerSize + (long) len + (long) blocks * TranslogChunkManager.GCM_TAG_SIZE;
    }

    /**
     * P0-2: isolate the inline tag-write site (finalizeCurrentBlock). A short write of just the 16-byte
     * tag must still be fully flushed, or the file is short by 16 bytes and every later chunk misaligns.
     */
    public void testShortWriteAtTagBoundary() throws IOException {
        String uuid = "tag-boundary-uuid";
        int rest = 300;
        int len = TranslogChunkManager.GCM_CHUNK_SIZE + rest; // crosses one block boundary -> finalize tag
        byte[] data = randomByteArrayOfLength(len);
        Path path = tempDir.resolve("tag.tlog");

        int headerSize;
        // maxBytesPerWrite=8 forces even the 16-byte tag write to be split into two calls.
        try (FileChannel real = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            FileChannel faulty = new ShortWriteFileChannel(real, 8);
            try (
                FileChannel ch = new CryptoFileChannelWrapper(
                    faulty,
                    keyResolver,
                    path,
                    java.util.Set.of(StandardOpenOption.WRITE),
                    uuid
                )
            ) {
                TranslogHeader h = new TranslogHeader(uuid, 1L);
                h.write(ch, false);
                headerSize = h.sizeInBytes();
                ch.write(ByteBuffer.wrap(data), headerSize);
            }
        }

        // Two chunks (8192 + rest), each + 16B tag, both fully present.
        assertEquals(headerSize + TranslogChunkManager.GCM_CHUNK_SIZE + 16 + rest + 16, Files.size(path));
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            assertArrayEquals(data, readFullyLoop(rc, headerSize, len));
        }
    }

    /**
     * P0-5: a single bit flipped anywhere in the ciphertext/tag region must cause decryption to throw
     * ("Failed to decrypt chunk N") or return non-equal bytes — never silently return the original.
     */
    public void testTamperedChunkNeverDecryptsToOriginal() throws IOException {
        String uuid = "tamper-uuid";
        int len = randomIntBetween(TranslogChunkManager.GCM_CHUNK_SIZE, 2 * TranslogChunkManager.GCM_CHUNK_SIZE);
        byte[] data = randomByteArrayOfLength(len);
        Path path = tempDir.resolve("tamper.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }

        byte[] raw = Files.readAllBytes(path);
        int trials = scaledRandomIntBetween(30, 120);
        for (int t = 0; t < trials; t++) {
            byte[] bad = raw.clone();
            int idx = randomIntBetween(headerSize, bad.length - 1); // never touch the plaintext header
            bad[idx] ^= (byte) (1 << randomIntBetween(0, 7));
            Path bp = tempDir.resolve("tamper-" + t + ".tlog");
            Files.write(bp, bad);
            try (FileChannel rc = factory.open(bp, StandardOpenOption.READ)) {
                try {
                    byte[] got = readFullyLoop(rc, headerSize, len);
                    assertFalse("GCM auth bypassed: tampered file decrypted to original", java.util.Arrays.equals(data, got));
                } catch (IOException e) {
                    assertTrue("unexpected error: " + e.getMessage(), e.getMessage().contains("Failed to decrypt chunk"));
                } catch (AssertionError shortReadBack) {
                    // A <=16B truncation path returns fewer bytes; acceptable as long as it is never silently equal.
                }
            }
        }
    }

    /**
     * P0-10: a delegate that never accepts bytes must make writeFully throw a clear IOException, not hang.
     */
    public void testWriteFullyThrowsOnStuckChannel() throws IOException {
        String uuid = "stuck-uuid";
        Path path = tempDir.resolve("stuck.tlog");
        try (FileChannel real = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            FileChannel faulty = new ShortWriteFileChannel(real, 0); // accepts 0 bytes per call
            try (
                FileChannel ch = new CryptoFileChannelWrapper(
                    faulty,
                    keyResolver,
                    path,
                    java.util.Set.of(StandardOpenOption.WRITE),
                    uuid
                )
            ) {
                TranslogHeader h = new TranslogHeader(uuid, 1L);
                IOException e = expectThrows(IOException.class, () -> {
                    h.write(ch, false);
                    ch.write(ByteBuffer.wrap(new byte[100]), h.sizeInBytes());
                });
                assertTrue("expected short-write message, got: " + e.getMessage(), e.getMessage().contains("Short write to translog"));
            }
        }
    }

    /**
     * PROP-1/PROP-6: write-then-read byte-identity across many random lengths and explicit boundary values
     * (0, 1, around the 8192 chunk size, multi-chunk). Guards nonce/stride/finalize regressions.
     */
    public void testRoundTripLengthsAndBoundaries() throws IOException {
        java.util.List<Integer> lengths = new java.util.ArrayList<>();
        for (int b : new int[] { 1, 100, 8191, 8192, 8193, 16384, 16385 }) {
            lengths.add(b);
        }
        int randomCases = scaledRandomIntBetween(20, 80);
        for (int i = 0; i < randomCases; i++) {
            lengths.add(randomIntBetween(1, 40000));
        }

        for (int idx = 0; idx < lengths.size(); idx++) {
            int len = lengths.get(idx);
            String uuid = "rt-" + idx + "-" + len;
            Path path = tempDir.resolve("rt-" + idx + ".tlog");
            byte[] data = randomByteArrayOfLength(len);
            CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

            int headerSize;
            try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                TranslogHeader h = new TranslogHeader(uuid, 1L);
                h.write(ch, false);
                headerSize = h.sizeInBytes();
                assertEquals("len=" + len, len, ch.write(ByteBuffer.wrap(data), headerSize));
            }
            assertEquals("size len=" + len, expectedFileSize(headerSize, len), Files.size(path));
            try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
                assertArrayEquals("len=" + len, data, readFullyLoop(rc, headerSize, len));
            }
        }
    }

    /**
     * C1 regression: chunk 0 of two DIFFERENT generation files (same translogUUID, same data key, same
     * plaintext) must encrypt to DIFFERENT ciphertext on disk. Before the generation-bound base-IV fix,
     * the base IV depended only on (dataKey, translogUUID) and chunkIndex restarted at 0 per file, so
     * chunk 0 of translog-1.tlog and translog-2.tlog reused the same (key, nonce) — catastrophic GCM
     * reuse. Identical ciphertext for the same plaintext across generations means the nonce was reused.
     */
    public void testDifferentGenerationsProduceDifferentCiphertext() throws IOException {
        String uuid = "gen-nonce-uuid";
        byte[] data = randomByteArrayOfLength(4096);
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        java.util.function.Function<Integer, byte[]> writeGen = gen -> {
            try {
                Path path = tempDir.resolve("translog-" + gen + ".tlog");
                int headerSize;
                try (
                    FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)
                ) {
                    TranslogHeader h = new TranslogHeader(uuid, 1L);
                    h.write(ch, false);
                    headerSize = h.sizeInBytes();
                    ch.write(ByteBuffer.wrap(data), headerSize);
                }
                // return the ciphertext region only (skip the plaintext header, which is identical anyway)
                byte[] all = Files.readAllBytes(path);
                return java.util.Arrays.copyOfRange(all, headerSize, all.length);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        };

        byte[] ctGen1 = writeGen.apply(1);
        byte[] ctGen2 = writeGen.apply(2);

        assertFalse(
            "chunk-0 ciphertext must differ across generations (same nonce => GCM reuse)",
            java.util.Arrays.equals(ctGen1, ctGen2)
        );

        // and each generation must still decrypt back to the original through its own filename
        for (int gen : new int[] { 1, 2 }) {
            Path path = tempDir.resolve("translog-" + gen + ".tlog");
            int headerSize = new TranslogHeader(uuid, 1L).sizeInBytes();
            try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
                assertArrayEquals("gen " + gen + " must round-trip", data, readFullyLoop(rc, headerSize, data.length));
            }
        }
    }

    /**
     * M4: the encrypted translog is append-only. A data write whose position does not equal the current
     * logical write cursor must fail closed rather than silently misplace bytes / reuse a nonce.
     */
    public void testNonAppendWriteRejected() throws IOException {
        String uuid = "append-only-uuid";
        Path path = tempDir.resolve("translog-3.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        byte[] first = randomByteArrayOfLength(4096);
        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            // sequential append at the logical cursor: OK
            assertEquals(first.length, ch.write(ByteBuffer.wrap(first), headerSize));
            // append continues fine
            byte[] more = randomByteArrayOfLength(1000);
            assertEquals(more.length, ch.write(ByteBuffer.wrap(more), headerSize + first.length));
            // a write at the WRONG (earlier) position must be rejected
            IOException e = expectThrows(IOException.class, () -> ch.write(ByteBuffer.wrap(new byte[10]), headerSize));
            assertTrue("expected append-only message, got: " + e.getMessage(), e.getMessage().contains("append-only"));
        }
    }

    /**
     * C6: reopening a non-empty encrypted translog for write must fail closed (reopen-for-append would
     * reuse block-0's nonce). Core never does this (CREATE_NEW + read-only reopen); this is a safety net.
     */
    public void testReopenForAppendRejected() throws IOException {
        String uuid = "reopen-guard-uuid";
        Path path = tempDir.resolve("translog-9.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(randomByteArrayOfLength(TranslogChunkManager.GCM_CHUNK_SIZE)), headerSize);
        }
        // reopen the populated file for WRITE and attempt to append at headerSize
        try (FileChannel ch = factory.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            IOException e = expectThrows(IOException.class, () -> ch.write(ByteBuffer.wrap(new byte[10]), headerSize));
            assertTrue("expected non-empty-translog message, got: " + e.getMessage(), e.getMessage().contains("non-empty encrypted translog"));
        }
    }

    /**
     * Intra-generation nonce regression: two blocks within the SAME file that hold identical plaintext
     * must encrypt to different ciphertext. Before the per-block nonce fix, every block in a file used
     * the same nonce baseIV[0:12] (the per-block "offset" only touched IV bytes 12-15, which GCM ignores),
     * so two equal 8192-byte plaintext blocks produced identical ciphertext — catastrophic GCM reuse
     * within one translog file. Different ciphertext for equal blocks proves the nonce now varies per block.
     */
    public void testSameFileBlocksUseDistinctNonces() throws IOException {
        String uuid = "intragen-nonce-uuid";
        int chunk = TranslogChunkManager.GCM_CHUNK_SIZE;
        // two identical full blocks back-to-back
        byte[] block = randomByteArrayOfLength(chunk);
        byte[] data = new byte[chunk * 2];
        System.arraycopy(block, 0, data, 0, chunk);
        System.arraycopy(block, 0, data, chunk, chunk);

        Path path = tempDir.resolve("translog-7.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }

        byte[] all = Files.readAllBytes(path);
        // on-disk block 0 = [headerSize, headerSize+8208); block 1 = [headerSize+8208, headerSize+2*8208)
        int stride = TranslogChunkManager.CHUNK_WITH_TAG_SIZE;
        byte[] ct0 = java.util.Arrays.copyOfRange(all, headerSize, headerSize + stride);
        byte[] ct1 = java.util.Arrays.copyOfRange(all, headerSize + stride, headerSize + 2 * stride);
        assertFalse(
            "two identical plaintext blocks in one file must NOT produce identical ciphertext (nonce reuse)",
            java.util.Arrays.equals(ct0, ct1)
        );

        // and the file must still decrypt back to the original two identical blocks
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            assertArrayEquals(data, readFullyLoop(rc, headerSize, data.length));
        }
    }

    /**
     * Edge case (READ-LOOP): symmetric read-side guard for the readFully loop. Writes a multi-chunk file
     * normally, then reads it back through a channel that returns at most 7 bytes per read. A reverted
     * readFully would feed a truncated chunk to GCM and throw "Failed to decrypt chunk N".
     */
    @SuppressForbidden(reason = "Test needs a real FileChannel to wrap with a short-read delegate")
    public void testPartialReadsDoNotCorruptTranslog() throws IOException {
        String uuid = "partial-read-uuid";
        int len = (TranslogChunkManager.GCM_CHUNK_SIZE * 3) + 1234;
        byte[] data = randomByteArrayOfLength(len);
        Path path = tempDir.resolve("partial-read.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }

        try (FileChannel real = FileChannel.open(path, StandardOpenOption.READ)) {
            FileChannel shortReads = new ShortWriteFileChannel(real, Integer.MAX_VALUE, 7);
            try (
                FileChannel ch = new CryptoFileChannelWrapper(shortReads, keyResolver, path, java.util.Set.of(StandardOpenOption.READ), uuid)
            ) {
                ByteBuffer hdr = ByteBuffer.allocate(headerSize);
                int hpos = 0;
                while (hdr.hasRemaining()) {
                    int n = ch.read(hdr, hpos);
                    if (n <= 0) break;
                    hpos += n;
                }
                assertEquals("header must read fully under short reads", headerSize, hdr.position());
                assertArrayEquals("partial reads must not corrupt decryption", data, readFullyLoop(ch, headerSize, len));
            }
        }
    }

    /**
     * Edge case (MULTI-CALL-APPEND): the real TranslogWriter appends via many sequential write() calls.
     * Writing a payload in several calls (one seam exactly on the 8192 block boundary, one mid-block) must
     * decrypt to the same bytes and produce the same file size as a single write — proving the on-disk
     * layout is independent of caller chunking. (Stress-validated over 200 iterations during development.)
     */
    public void testMultiCallAppendMatchesSingleWrite() throws IOException {
        int len = 20000;
        byte[] data = randomByteArrayOfLength(len);

        String uuidA = "append-single";
        Path pathA = tempDir.resolve("append-single.tlog");
        CryptoChannelFactory fA = new CryptoChannelFactory(keyResolver, uuidA);
        int headerSize;
        try (FileChannel ch = fA.open(pathA, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuidA, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }
        try (FileChannel rcA = fA.open(pathA, StandardOpenOption.READ)) {
            assertArrayEquals("single-write must round-trip", data, readFullyLoop(rcA, headerSize, len));
        }

        String uuidB = "append-multi";
        Path pathB = tempDir.resolve("append-multi.tlog");
        CryptoChannelFactory fB = new CryptoChannelFactory(keyResolver, uuidB);
        int[] seams = { 0, 8192, 12345, len };
        try (FileChannel ch = fB.open(pathB, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuidB, 1L);
            h.write(ch, false);
            long pos = headerSize;
            for (int s = 0; s < seams.length - 1; s++) {
                int written = ch.write(ByteBuffer.wrap(data, seams[s], seams[s + 1] - seams[s]), pos);
                assertEquals("each append writes its full slice", seams[s + 1] - seams[s], written);
                pos += written;
            }
        }
        try (FileChannel rc = fB.open(pathB, StandardOpenOption.READ)) {
            assertArrayEquals("multi-call append must decrypt to original", data, readFullyLoop(rc, headerSize, len));
        }
        // identical header size (same-length UUID) + identical data layout => identical file size
        assertEquals("file size must be call-boundary independent", Files.size(pathA), Files.size(pathB));
    }

    /**
     * Edge case (TRANSFER-ROUNDTRIP): transferFrom (encrypt-on-ingest) then transferTo (decrypt-on-egress)
     * must round-trip across multiple chunks — the real remote-upload / recovery I/O paths.
     */
    @SuppressForbidden(reason = "Test uses FileChannel transfer to/from temp files")
    public void testTransferRoundTripAcrossChunks() throws IOException {
        String uuid = "transfer-uuid";
        int len = TranslogChunkManager.GCM_CHUNK_SIZE * 3;
        byte[] data = randomByteArrayOfLength(len);
        Path src = tempDir.resolve("transfer-src.bin");
        Files.write(src, data);
        Path path = tempDir.resolve("transfer.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        try (
            FileChannel srcCh = FileChannel.open(src, StandardOpenOption.READ);
            FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)
        ) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            long transferred = ch.transferFrom(srcCh, headerSize, len);
            assertEquals("transferFrom must ingest all bytes", len, transferred);
        }
        assertEquals("encrypted size after transferFrom", expectedFileSize(headerSize, len), Files.size(path));

        Path sink = tempDir.resolve("transfer-sink.bin");
        try (
            FileChannel ch = factory.open(path, StandardOpenOption.READ);
            FileChannel sinkCh = FileChannel.open(sink, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        ) {
            long out = 0;
            while (out < len) {
                long n = ch.transferTo(headerSize + out, len - out, sinkCh);
                if (n <= 0) break;
                out += n;
            }
            assertEquals("transferTo must emit all decrypted bytes", len, out);
        }
        assertArrayEquals("transfer round-trip must preserve bytes", data, Files.readAllBytes(sink));
    }

    /**
     * Edge case (EOF): reads at and past EOF return no bytes and write nothing. (Pins FileChannel contract.)
     */
    public void testReadAtAndPastEof() throws IOException {
        String uuid = "eof-uuid";
        int len = 9000;
        byte[] data = randomByteArrayOfLength(len);
        Path path = tempDir.resolve("eof.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }
        long fileSize = Files.size(path);
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            ByteBuffer atEof = ByteBuffer.allocate(64);
            assertTrue("read at EOF returns <=0", rc.read(atEof, fileSize) <= 0);
            assertEquals("nothing written at EOF", 0, atEof.position());
            ByteBuffer pastEof = ByteBuffer.allocate(64);
            assertTrue("read past EOF returns <=0", rc.read(pastEof, fileSize + 5000) <= 0);
            assertEquals("nothing written past EOF", 0, pastEof.position());
        }
    }

    /**
     * Edge case (LIFECYCLE): map() is unsupported; ops after close throw ClosedChannelException; a
     * header-only file is exactly headerSize (no phantom chunk/tag); double-close is a no-op.
     */
    public void testChannelLifecycleAndHeaderOnly() throws IOException {
        String uuid = "lifecycle-uuid";
        Path path = tempDir.resolve("lifecycle.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        TranslogHeader h = new TranslogHeader(uuid, 1L);
        h.write(ch, false);
        int headerSize = h.sizeInBytes();
        expectThrows(UnsupportedOperationException.class, () -> ch.map(FileChannel.MapMode.READ_ONLY, 0, headerSize));
        ch.close();
        assertEquals("header-only file must be exactly headerSize", headerSize, Files.size(path));
        expectThrows(java.nio.channels.ClosedChannelException.class, () -> ch.read(ByteBuffer.allocate(8), 0));
        expectThrows(java.nio.channels.ClosedChannelException.class, () -> ch.write(ByteBuffer.allocate(8), headerSize));
        ch.close(); // idempotent
        assertEquals("double-close must not change the file", headerSize, Files.size(path));
    }

    /**
     * A FileChannel decorator whose positional write() always reports at most {@code maxBytesPerWrite}
     * bytes written, simulating the OS partial-write behavior that caused the P0 corruption.
     */
    @SuppressForbidden(reason = "Test helper wrapping FileChannel to simulate partial writes/reads")
    private static final class ShortWriteFileChannel extends FileChannel {
        private final FileChannel delegate;
        private final int maxBytesPerWrite;
        private final int maxBytesPerRead; // 0 == unlimited (pass-through)

        ShortWriteFileChannel(FileChannel delegate, int maxBytesPerWrite) {
            this(delegate, maxBytesPerWrite, 0);
        }

        ShortWriteFileChannel(FileChannel delegate, int maxBytesPerWrite, int maxBytesPerRead) {
            this.delegate = delegate;
            this.maxBytesPerWrite = maxBytesPerWrite;
            this.maxBytesPerRead = maxBytesPerRead;
        }

        @Override
        public int write(ByteBuffer src, long position) throws IOException {
            if (src.remaining() <= maxBytesPerWrite) {
                return delegate.write(src, position);
            }
            int oldLimit = src.limit();
            src.limit(src.position() + maxBytesPerWrite);
            int n = delegate.write(src, position);
            src.limit(oldLimit);
            return n;
        }

        @Override
        public int read(ByteBuffer dst, long position) throws IOException {
            if (maxBytesPerRead <= 0 || dst.remaining() <= maxBytesPerRead) {
                return delegate.read(dst, position);
            }
            int oldLimit = dst.limit();
            dst.limit(dst.position() + maxBytesPerRead);
            int n = delegate.read(dst, position);
            dst.limit(oldLimit);
            return n;
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (maxBytesPerRead <= 0 || dst.remaining() <= maxBytesPerRead) {
                return delegate.read(dst);
            }
            int oldLimit = dst.limit();
            dst.limit(dst.position() + maxBytesPerRead);
            int n = delegate.read(dst);
            dst.limit(oldLimit);
            return n;
        }

        @Override
        public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
            return delegate.read(dsts, offset, length);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            return write(src, position());
        }

        @Override
        public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
            return delegate.write(srcs, offset, length);
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public FileChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }

        @Override
        public FileChannel truncate(long newSize) throws IOException {
            delegate.truncate(newSize);
            return this;
        }

        @Override
        public void force(boolean metaData) throws IOException {
            delegate.force(metaData);
        }

        @Override
        public long transferTo(long position, long count, java.nio.channels.WritableByteChannel target) throws IOException {
            return delegate.transferTo(position, count, target);
        }

        @Override
        public long transferFrom(java.nio.channels.ReadableByteChannel src, long position, long count) throws IOException {
            return delegate.transferFrom(src, position, count);
        }

        @Override
        public java.nio.MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
            return delegate.map(mode, position, size);
        }

        @Override
        public java.nio.channels.FileLock lock(long position, long size, boolean shared) throws IOException {
            return delegate.lock(position, size, shared);
        }

        @Override
        public java.nio.channels.FileLock tryLock(long position, long size, boolean shared) throws IOException {
            return delegate.tryLock(position, size, shared);
        }

        @Override
        protected void implCloseChannel() throws IOException {
            delegate.close();
        }
    }
}
