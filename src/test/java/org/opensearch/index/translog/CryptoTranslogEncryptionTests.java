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
     * A FileChannel decorator whose positional write() always reports at most {@code maxBytesPerWrite}
     * bytes written, simulating the OS partial-write behavior that caused the P0 corruption.
     */
    @SuppressForbidden(reason = "Test helper wrapping FileChannel to simulate partial writes")
    private static final class ShortWriteFileChannel extends FileChannel {
        private final FileChannel delegate;
        private final int maxBytesPerWrite;

        ShortWriteFileChannel(FileChannel delegate, int maxBytesPerWrite) {
            this.delegate = delegate;
            this.maxBytesPerWrite = maxBytesPerWrite;
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
            return delegate.read(dst, position);
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            return delegate.read(dst);
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
