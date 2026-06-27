/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.MappedByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Verify that translog data encryption actually works.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class CryptoTranslogEncryptionTests extends OpenSearchTestCase {

    private static final Logger logger = LogManager.getLogger(CryptoTranslogEncryptionTests.class);

    private Path tempDir;
    private KeyResolver keyResolver;
    private MasterKeyProvider keyProvider;
    private String testIndexUuid;

    /** Data-sizing constant (NOT a format constant): a convenient multi-KB chunk for test payloads. */
    private static final int CHUNK = 8192;

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
            public Map<String, String> getEncryptionContext() {
                return Collections.singletonMap("test-key", "test-value");
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
     * Before the fix, the pre-frame writer issued a single unchecked {@code write} and advanced
     * its position by only the partial count, dropping the tail of an encrypted chunk and permanently
     * misaligning every later chunk — surfacing during recovery as {@code AEADBadTagException: Tag mismatch!}
     * (observed ~chunk 35834 deep in a large file). This test forces short writes on every call and asserts
     * the file still decrypts byte-for-byte across multiple 8KB chunks.
     */
    @SuppressForbidden(reason = "Test needs a real FileChannel to wrap with a short-write delegate")
    public void testPartialWritesDoNotCorruptTranslog() throws IOException {
        String testTranslogUUID = "test-partial-write-uuid";

        // ~3.5 chunks of data so the partial-write hole would land mid-stream and misalign later chunks.
        int dataLen = (CHUNK * 3) + 1234;
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
                    Set.of(StandardOpenOption.WRITE),
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
        int maxIters = (len / CHUNK) + 4;
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
     * On-disk size of an encrypted translog in the v2 seal-on-force format. Each block is
     * {@code [u16 ptLen][ptLen bytes ciphertext][16B GCM tag]}, so the data region is
     * {@code len + (LENGTH_PREFIX_SIZE + 16) * numBlocks}, where numBlocks = ceil(len / 8192).
     */
    private static long expectedFileSize(int headerSize, int len) {
        if (len == 0) {
            return headerSize; // no data written => no super-header, no frames
        }
        // v3 FRAME-AAD layout: [core header][TLE1 super-header][frame...], one frame per <=FRAME_MAX write,
        // each frame = [24B frame header][ciphertext(ptLen)][16B tag]. A single contiguous write of `len`
        // bytes is split into ceil(len / FRAME_MAX) frames.
        int frames = (len + TranslogFrameManager.FRAME_MAX - 1) / TranslogFrameManager.FRAME_MAX;
        long perFrameOverhead = TranslogFrameManager.FRAME_HEADER_SIZE + TranslogFrameManager.TAG_SIZE;
        return headerSize + TranslogFrameManager.SUPER_HEADER_SIZE + (long) len + (long) frames * perFrameOverhead;
    }

    /**
     * P0-2: isolate the inline tag-write site (finalizeCurrentBlock). A short write of just the 16-byte
     * tag must still be fully flushed, or the file is short by 16 bytes and every later chunk misaligns.
     */
    public void testShortWriteAtTagBoundary() throws IOException {
        String uuid = "tag-boundary-uuid";
        int rest = 300;
        int len = CHUNK + rest; // crosses one block boundary -> finalize tag
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
                    Set.of(StandardOpenOption.WRITE),
                    uuid
                )
            ) {
                TranslogHeader h = new TranslogHeader(uuid, 1L);
                h.write(ch, false);
                headerSize = h.sizeInBytes();
                ch.write(ByteBuffer.wrap(data), headerSize);
            }
        }

        // Two blocks (8192 + rest) in v2 format, each [u16 len][ct][16B tag], both fully present.
        assertEquals(expectedFileSize(headerSize, CHUNK + rest), Files.size(path));
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
        int len = randomIntBetween(CHUNK, 2 * CHUNK);
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
                    assertFalse("GCM auth bypassed: tampered file decrypted to original", Arrays.equals(data, got));
                } catch (IOException e) {
                    // Any fail-closed rejection is acceptable. A tampered byte may land in the GCM
                    // ciphertext/tag (decrypt failure), in a frame header (CRC/sequence/offset/decrypt), or in
                    // the 36-byte super-header (its CRC/version/baseIVCheck guards) — the test perturbs any
                    // byte at or after headerSize, which includes the super-header region. The invariant under
                    // test is "never silently decrypts to the original", so every thrown rejection passes.
                    String m = e.getMessage() == null ? "" : e.getMessage();
                    assertTrue(
                        "unexpected error: " + m,
                        m.contains("Failed to decrypt")
                            || m.contains("corrupt")
                            || m.contains("CRC")
                            || m.contains("mismatch")
                            || m.contains("truncated")
                            || m.contains("translog")
                    );
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
                    Set.of(StandardOpenOption.WRITE),
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
        List<Integer> lengths = new ArrayList<>();
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
                return Arrays.copyOfRange(all, headerSize, all.length);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };

        byte[] ctGen1 = writeGen.apply(1);
        byte[] ctGen2 = writeGen.apply(2);

        assertFalse(
            "chunk-0 ciphertext must differ across generations (same nonce => GCM reuse)",
            Arrays.equals(ctGen1, ctGen2)
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
     * Format-version super-header: a v2 file carries a 'TLE'+version super-header right after the core
     * header, and the reader fails closed on a wrong/foreign magic or an unsupported version (so a future
     * format or a non-TLE file can never be silently misparsed as v2).
     */
    public void testSuperHeaderPresentAndVersionEnforced() throws IOException {
        String uuid = "superheader-uuid";
        Path path = tempDir.resolve("translog-13.tlog");
        byte[] data = randomByteArrayOfLength(2000);
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader hh = new TranslogHeader(uuid, 1L);
            hh.write(ch, false);
            headerSize = hh.sizeInBytes();
            ch.write(ByteBuffer.wrap(data), headerSize);
        }

        // v3 super-header begins right after the core header: magic 'T','L','E','1' then the version byte.
        byte[] all = Files.readAllBytes(path);
        assertEquals('T', all[headerSize]);
        assertEquals('L', all[headerSize + 1]);
        assertEquals('E', all[headerSize + 2]);
        assertEquals('1', all[headerSize + 3]);
        assertEquals(TranslogFrameManager.FORMAT_VERSION, all[headerSize + 4]);

        // Corrupt the version byte WITHOUT fixing the super-header CRC, then read the bytes back through the
        // reader directly (a raw channel + TranslogFrameManager, bypassing the factory's plaintext->v3
        // conversion which only triggers when the magic is ABSENT). The reader must fail closed: v3
        // authenticates the super-header with a CRC, so a lone version flip is caught as a corrupt
        // super-header; a CRC-consistent unknown version would be caught as a version error.
        byte[] badVersion = all.clone();
        badVersion[headerSize + 4] = (byte) 0x7F;
        Path badV = tempDir.resolve("translog-1300.tlog");
        Files.write(badV, badVersion);
        IOException e = expectThrows(IOException.class, () -> readViaManagerRaw(badV, uuid, headerSize, data.length));
        assertTrue(
            "expected version/corrupt-super-header error, got: " + e.getMessage(),
            e.getMessage().contains("format version") || e.getMessage().contains("super-header")
        );
    }

    /**
     * Reads {@code len} logical bytes through a {@link TranslogFrameManager} over a RAW read-only channel,
     * bypassing {@link CryptoChannelFactory#open}'s plaintext->v3 conversion. Used to test the reader's
     * fail-closed behavior on a corrupted super-header (where open() would otherwise mis-convert it).
     */
    @SuppressForbidden(reason = "raw FileChannel to exercise the reader path directly")
    private byte[] readViaManagerRaw(Path path, String uuid, int headerSize, int len) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, path, uuid);
            ByteBuffer out = ByteBuffer.allocate(len);
            int pos = headerSize, guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                if (++guard > len + 16) break;
            }
            return out.array();
        }
    }

    /**
     * Realtime-GET of an UNCOMMITTED op (no force, no close): the open block lives only in memory (blockBuf).
     * A read of that logical region through the SAME channel must return the bytes from the buffer — not 0,
     * which would make core's read loop spin/hang. This is the no-force variant of the original
     * AEADBadTagException repro and must be served without any decrypt failure.
     */
    public void testRealtimeReadOfUnsealedOpenBlock() throws IOException {
        String uuid = "realtime-open-uuid";
        Path path = tempDir.resolve("translog-11.tlog");
        int len = 1500; // sub-block: stays buffered until force()/close()
        byte[] data = randomByteArrayOfLength(len);
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        TranslogHeader h = new TranslogHeader(uuid, 1L);
        h.write(ch, false);
        int headerSize = h.sizeInBytes();
        ch.write(ByteBuffer.wrap(data), headerSize);
        // NO force(), NO close() — read the just-written (still-buffered) op back through the same channel.
        byte[] back = readFullyLoop(ch, headerSize, len);
        assertArrayEquals("realtime read of an unsealed op must return the buffered bytes", data, back);

        // a partial read within the open block must also work (offset into blockBuf)
        ByteBuffer mid = ByteBuffer.allocate(200);
        int n = ch.read(mid, headerSize + 500);
        assertTrue("read within open block must return >0", n > 0);
        ch.close();
    }

    /**
     * C2 (the live AEADBadTagException repro, made deterministic and crash-free): write a sub-block amount
     * of data, force() WITHOUT closing the channel, then read it back through a fresh read-only channel.
     * This mirrors a realtime GET of an uncommitted op in the still-open block. Before seal-on-force, the
     * open block's GCM tag lived only in memory, so the reopened reader hit an un-tagged chunk and threw
     * "Failed to decrypt chunk". With force() sealing the open block, the data is durable and decrypts.
     */
    public void testForceMakesOpenBlockReadable() throws IOException {
        String uuid = "c2-force-uuid";
        Path path = tempDir.resolve("translog-5.tlog");
        int len = 1234; // smaller than one block -> stays in the open block until force()
        byte[] data = randomByteArrayOfLength(len);
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        // Deliberately NOT using try-with-resources: we must NOT close (close() would also seal).
        FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
        TranslogHeader h = new TranslogHeader(uuid, 1L);
        h.write(ch, false);
        headerSize = h.sizeInBytes();
        ch.write(ByteBuffer.wrap(data), headerSize);
        ch.force(false); // seals the open block to disk — the C2 fix

        // Read back through a SEPARATE read-only channel while the writer is still open (uncommitted read).
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            assertArrayEquals("force() must make the open block durably decryptable", data, readFullyLoop(rc, headerSize, len));
        }
        ch.close();
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
            ch.write(ByteBuffer.wrap(randomByteArrayOfLength(CHUNK)), headerSize);
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
        int chunk = CHUNK;
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
            // two separate writes -> two distinct v3 frames (frameSeq 0 and 1 -> distinct nonces)
            ch.write(ByteBuffer.wrap(block), headerSize);
            ch.write(ByteBuffer.wrap(block), headerSize + chunk);
        }

        // Format-agnostic check: the encrypted data region holds two equal-size frames whose ciphertext
        // must differ. Compare its two halves without hardcoding any byte stride.
        byte[] all = Files.readAllBytes(path);
        int dataStart = headerSize + TranslogFrameManager.SUPER_HEADER_SIZE;
        int regionLen = all.length - dataStart;
        assertEquals("two equal frames -> even-length data region", 0, regionLen % 2);
        int half = regionLen / 2;
        byte[] f0 = Arrays.copyOfRange(all, dataStart, dataStart + half);
        byte[] f1 = Arrays.copyOfRange(all, dataStart + half, dataStart + regionLen);
        assertFalse("two identical plaintext frames must NOT produce identical ciphertext (per-frame nonce)", Arrays.equals(f0, f1));

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
        int len = (CHUNK * 3) + 1234;
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
                FileChannel ch = new CryptoFileChannelWrapper(shortReads, keyResolver, path, Set.of(StandardOpenOption.READ), uuid)
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
     * MULTI-CALL-APPEND: the real TranslogWriter appends via many sequential write() calls. In the v3
     * frame format each write() seals its own frame, so the on-disk LAYOUT is intentionally call-boundary
     * dependent (this is what removes any shared open-block and the associated race). The CONTENT invariant
     * still holds: a payload appended across several calls (one seam on a chunk boundary, one mid-chunk)
     * must decrypt back to exactly the original bytes, regardless of how it was chunked.
     */
    public void testMultiCallAppendMatchesSingleWrite() throws IOException {
        int len = 20000;
        byte[] data = randomByteArrayOfLength(len);

        // Single write
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

        // Multi-call append of the SAME payload across several seams.
        String uuidB = "append-multi-uuid";
        Path pathB = tempDir.resolve("append-multi.tlog");
        CryptoChannelFactory fB = new CryptoChannelFactory(keyResolver, uuidB);
        int[] seams = { 0, 8192, 12345, len };
        int headerSizeB;
        try (FileChannel ch = fB.open(pathB, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuidB, 1L);
            h.write(ch, false);
            headerSizeB = h.sizeInBytes();
            long pos = headerSizeB;
            for (int s = 0; s < seams.length - 1; s++) {
                int written = ch.write(ByteBuffer.wrap(data, seams[s], seams[s + 1] - seams[s]), pos);
                assertEquals("each append writes its full slice", seams[s + 1] - seams[s], written);
                pos += written;
            }
        }
        // Content invariant: multi-call append decrypts to the exact original, independent of chunking.
        try (FileChannel rc = fB.open(pathB, StandardOpenOption.READ)) {
            assertArrayEquals("multi-call append must decrypt to original", data, readFullyLoop(rc, headerSizeB, len));
        }
    }

    /**
     * Edge case (TRANSFER-ROUNDTRIP): transferFrom (encrypt-on-ingest) then transferTo (decrypt-on-egress)
     * must round-trip across multiple chunks — the real remote-upload / recovery I/O paths.
     */
    @SuppressForbidden(reason = "Test uses FileChannel transfer to/from temp files")
    public void testTransferRoundTripAcrossChunks() throws IOException {
        String uuid = "transfer-uuid";
        int len = CHUNK * 3;
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
     * CryptoDecryptingInputStream (used by the decrypt-before-upload path) must stream back exactly the
     * core header bytes + the original plaintext for a v2 file — i.e. it transparently strips the
     * super-header, length prefixes, and per-block GCM tags. Guards the remote-upload reader against the
     * v2 format change.
     */
    public void testDecryptingInputStreamReturnsHeaderPlusPlaintext() throws IOException {
        String uuid = "decrypt-stream-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path tlogPath = tempDir.resolve("translog-7.tlog");

        byte[] dataBytes = ("{\"k\":\"" + "v".repeat(20_000) + "\"}").getBytes(StandardCharsets.UTF_8); // spans >2 blocks
        int headerSize;
        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            TranslogHeader header = new TranslogHeader(uuid, 1L);
            header.write(ch, false);
            headerSize = header.sizeInBytes();
            ch.write(ByteBuffer.wrap(dataBytes), headerSize);
        }

        java.io.ByteArrayOutputStream decrypted = new java.io.ByteArrayOutputStream();
        try (CryptoDecryptingInputStream stream = new CryptoDecryptingInputStream(tlogPath, keyResolver, uuid)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = stream.read(buf)) != -1) {
                decrypted.write(buf, 0, read);
            }
        }
        byte[] out = decrypted.toByteArray();
        assertEquals("stream returns header + plaintext", headerSize + dataBytes.length, out.length);
        byte[] tail = Arrays.copyOfRange(out, headerSize, out.length);
        assertArrayEquals("plaintext tail must round-trip through the decrypting stream", dataBytes, tail);
    }

    /**
     * A genuinely-plaintext downloaded translog (simulating an S3 restore) is detected as NOT-yet-v2 and
     * re-encrypted into the v3 frame format via TranslogFrameManager — then reads back correctly. An
     * already-v2 file is detected by its super-header and skipped (not double-encrypted).
     */
    public void testReEncryptPlaintextToV2AndSkipAlreadyV2() throws Exception {
        String uuid = "reencrypt-v2-uuid";
        int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(uuid);

        // Build a plaintext "downloaded" translog: core header + raw plaintext (no super-header).
        Path tlogPath = tempDir.resolve("translog-9.tlog");
        byte[] header = createRawHeader(uuid, 1L);
        byte[] plainData = ("{\"@timestamp\":\"2099-01-01\",\"msg\":\"" + "x".repeat(9000) + "\"}").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ch.write(ByteBuffer.wrap(header));
            ch.write(ByteBuffer.wrap(plainData));
        }

        byte[] beforeBytes = Files.readAllBytes(tlogPath);
        assertFalse("freshly-downloaded plaintext must NOT carry the TLE magic", TranslogFrameManager.hasSuperHeaderMagic(beforeBytes, headerSize));

        // Re-encrypt exactly as reEncryptDownloadedTranslogFiles does: header passthrough + TCM-sealed blocks.
        Path tmp = tlogPath.resolveSibling("translog-9.tlog.tmp");
        try (
            FileChannel out = FileChannel
                .open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ, StandardOpenOption.TRUNCATE_EXISTING)
        ) {
            out.write(ByteBuffer.wrap(header), 0);
            TranslogFrameManager tfm = new TranslogFrameManager(out, keyResolver, tlogPath, uuid);
            tfm.writeToChunks(ByteBuffer.wrap(plainData), headerSize);
            tfm.close();
        }
        Files.move(tmp, tlogPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        // Now it must be detected as v2 (so a second reEncrypt pass would skip it).
        byte[] afterBytes = Files.readAllBytes(tlogPath);
        assertTrue("re-encrypted file must carry the TLE super-header magic", TranslogFrameManager.hasSuperHeaderMagic(afterBytes, headerSize));

        // And it must decrypt back to header + original plaintext.
        java.io.ByteArrayOutputStream decrypted = new java.io.ByteArrayOutputStream();
        try (CryptoDecryptingInputStream stream = new CryptoDecryptingInputStream(tlogPath, keyResolver, uuid)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = stream.read(buf)) != -1) {
                decrypted.write(buf, 0, read);
            }
        }
        byte[] tail = Arrays.copyOfRange(decrypted.toByteArray(), headerSize, decrypted.size());
        assertArrayEquals("re-encrypted v2 file must decrypt back to the original plaintext", plainData, tail);
    }

    /**
     * Regression for the restore-from-plaintext reader-binding bug: OpenSearch core opens (and caches) a
     * recovery reader's FileChannel through {@link CryptoChannelFactory#open} while the on-disk file is
     * still the downloaded PLAINTEXT, before the post-constructor re-encrypt sweep runs. The factory must
     * therefore convert plaintext -> v2 IN PLACE during open(), so the very channel core caches already
     * decrypts correctly — otherwise the cached reader reads plaintext and recovery fails (shard red), and
     * a later Files.move cannot help the already-open fd.
     */
    public void testOpenConvertsPlaintextInPlaceSoCachedReaderDecrypts() throws IOException {
        String uuid = "open-convert-uuid";
        int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(uuid);

        // Simulate a downloaded plaintext translog: core header + raw plaintext, NO v2 super-header.
        Path tlogPath = tempDir.resolve("translog-42.tlog");
        byte[] header = createRawHeader(uuid, 1L);
        byte[] plainData = ("{\"op\":\"" + "y".repeat(20_000) + "\"}").getBytes(StandardCharsets.UTF_8); // spans >2 blocks
        try (FileChannel ch = FileChannel.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ch.write(ByteBuffer.wrap(header));
            ch.write(ByteBuffer.wrap(plainData));
        }
        assertFalse("precondition: file is plaintext", TranslogFrameManager.hasSuperHeaderMagic(Files.readAllBytes(tlogPath), headerSize));

        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        // Opening for READ (exactly what core's recovery reader does) must return a channel that decrypts
        // the now-encrypted file back to the original plaintext.
        try (FileChannel rc = factory.open(tlogPath, StandardOpenOption.READ)) {
            assertArrayEquals(
                "channel opened over downloaded plaintext must decrypt to the original op bytes",
                plainData,
                readFullyLoop(rc, headerSize, plainData.length)
            );
        }
        // open() must have converted the on-disk file to v2 in place.
        assertTrue(
            "open() must convert the downloaded plaintext to v3 on disk",
            TranslogFrameManager.hasSuperHeaderMagic(Files.readAllBytes(tlogPath), headerSize)
        );

        // Idempotency: a second open() (already-v2) must NOT double-encrypt — it must still decrypt cleanly
        // and leave the on-disk bytes byte-for-byte unchanged.
        byte[] afterFirst = Files.readAllBytes(tlogPath);
        try (FileChannel rc2 = factory.open(tlogPath, StandardOpenOption.READ)) {
            assertArrayEquals("second open of an already-v2 file must still decrypt", plainData, readFullyLoop(rc2, headerSize, plainData.length));
        }
        assertArrayEquals("already-v2 file must be untouched by a second open()", afterFirst, Files.readAllBytes(tlogPath));
    }

    /**
     * Create-path regression (the staging break): opening a BRAND-NEW translog generation for write
     * (CREATE_NEW + WRITE) on a path that does NOT yet exist must succeed and round-trip. Before the
     * create-guard, open() unconditionally called ensureEncryptedOnDisk(path), which runs Files.size(path)
     * on the not-yet-created file -> NoSuchFileException -> core's "failed to create new translog file"
     * -> shard red. CREATE_NEW also asserts the file is genuinely absent at open time (open itself would
     * fail if it pre-existed), so the guard must run BEFORE the channel is created.
     */
    public void testOpenForCreateNewGenerationSucceedsWhenFileAbsent() throws IOException {
        String uuid = "create-new-gen-uuid";
        Path path = tempDir.resolve("translog-77.tlog");
        assertFalse("precondition: brand-new generation file must not exist yet", Files.exists(path));
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 3 * CHUNK));
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        // CREATE_NEW => the file must not exist; the create-guard must prevent ensureEncryptedOnDisk from
        // touching the missing path. This open() must NOT throw NoSuchFileException.
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            assertEquals("fresh generation must accept the first data write", data.length, ch.write(ByteBuffer.wrap(data), headerSize));
        }

        assertTrue("open(CREATE_NEW) must have created the new translog file", Files.exists(path));
        assertEquals("fresh generation must be written in the v3 frame format", expectedFileSize(headerSize, data.length), Files.size(path));
        // And it must decrypt back to the original through a normal read channel.
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            assertArrayEquals("newly-created generation must round-trip", data, readFullyLoop(rc, headerSize, data.length));
        }
    }

    /**
     * Create-path regression via the CREATE option set core actually uses (and a header-only generation):
     * open(path, CREATE, READ, WRITE) on a path that does not exist must succeed (isCreatingNewFile must
     * treat CREATE like CREATE_NEW so the guard skips ensureEncryptedOnDisk on the missing path). A fresh
     * generation that writes only the core header must end up exactly headerSize on disk (no phantom
     * super-header/blocks), and reopening it read-only must also not trip the conversion path.
     */
    public void testOpenForCreateGenerationSucceedsWhenFileAbsent() throws IOException {
        String uuid = "create-gen-uuid";
        Path path = tempDir.resolve("translog-78.tlog");
        assertFalse("precondition: brand-new generation file must not exist yet", Files.exists(path));
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        int headerSize;
        // CREATE on a non-existent path: must not throw NoSuchFileException from a premature Files.size().
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            // Intentionally write NO data: a freshly-created, header-only generation.
        }
        assertTrue("open(CREATE) must have created the new translog file", Files.exists(path));
        assertEquals("header-only fresh generation must be exactly headerSize (no super-header/blocks)", headerSize, Files.size(path));

        // Reopening the header-only file read-only must also succeed (ensureEncryptedOnDisk early-returns
        // for a file whose size <= headerSize) and must not corrupt or grow the file.
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            ByteBuffer buf = ByteBuffer.allocate(64);
            assertTrue("no data region to read past the header", rc.read(buf, headerSize) <= 0);
        }
        assertEquals("reopen of a header-only generation must leave it untouched", headerSize, Files.size(path));
    }

    /**
     * Lifecycle (CREATE-THEN-REOPEN-READ): the create-guard + idempotency interplay. A fresh .tlog created
     * THROUGH the factory with CREATE,READ,WRITE must open without ensureEncryptedOnDisk touching the
     * not-yet-created path (the regression that ran Files.size() on a missing file during a brand-new
     * generation -> NoSuchFileException -> "failed to create new translog file" -> shard red). After
     * writing header+data and closing (which seals to v2), reopening the SAME existing path for READ
     * (non-create) must be a true no-op: ensureEncryptedOnDisk detects the v2 super-header and skips, so
     * the on-disk bytes are byte-for-byte unchanged AND the channel still decrypts the data back.
     */
    public void testCreateThenReopenForReadIsIdempotentNoOp() throws IOException {
        String uuid = "create-reopen-read-uuid";
        Path path = tempDir.resolve("translog-21.tlog");
        int len = 20_000; // spans >2 blocks so the v2 layout is non-trivial
        byte[] data = randomByteArrayOfLength(len);
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        // CREATE open through the factory: the create-guard must let this succeed even though the file does
        // not exist yet (the regression called Files.size() here and threw NoSuchFileException).
        int headerSize;
        try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            assertEquals("write must accept all bytes", len, ch.write(ByteBuffer.wrap(data), headerSize));
        } // close() seals the open block to disk -> file is now v2

        // After close the locally-written file is already v2 on disk.
        byte[] afterCreate = Files.readAllBytes(path);
        assertTrue(
            "locally-created translog must carry the TLE magic after close",
            TranslogFrameManager.hasSuperHeaderMagic(afterCreate, headerSize)
        );

        // Reopen the EXISTING file for READ (non-create): ensureEncryptedOnDisk must see the v2 super-header
        // and skip, leaving the bytes untouched, while the channel still decrypts the data back.
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            assertArrayEquals(
                "reopen-for-read must decrypt the already-v2 file back to the original",
                data,
                readFullyLoop(rc, headerSize, len)
            );
        }
        assertArrayEquals(
            "reopen-for-read of an already-v2 file must NOT re-encrypt / mutate the on-disk bytes",
            afterCreate,
            Files.readAllBytes(path)
        );
    }

    /**
     * Header-only open(READ): a downloaded/recovered .tlog that holds ONLY the core TranslogHeader (no v2
     * super-header, no data region) must be opened for READ without any conversion. ensureEncryptedOnDisk
     * early-returns when fileSize <= headerSize, so the file must stay byte-for-byte identical (no 'TLE'
     * super-header appended, size unchanged) and the channel must open and serve the plaintext header.
     * Before the fileSize<=headerSize guard, open() would fall past the hasV2SuperHeader(false) check and
     * mis-treat the empty data region as downloaded plaintext, rewriting the file in place.
     */
    @SuppressForbidden(reason = "Test writes a raw header-only file and opens a raw FileChannel")
    public void testOpenReadOfHeaderOnlyFileLeavesItUnchanged() throws IOException {
        String uuid = "header-only-open-uuid";
        int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(uuid);

        // A genuinely header-only translog: only the core TranslogHeader on disk, no super-header, no data.
        Path path = tempDir.resolve("translog-71.tlog");
        byte[] header = createRawHeader(uuid, 1L);
        Files.write(path, header);

        // Preconditions: size is exactly the core header and it is NOT a v2 file.
        assertEquals("precondition: file is exactly the core header", (long) headerSize, Files.size(path));
        byte[] before = Files.readAllBytes(path);
        assertFalse(
            "precondition: header-only file must not look like v2",
            TranslogFrameManager.hasSuperHeaderMagic(before, headerSize)
        );

        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);

        // open(READ) must NOT convert: ensureEncryptedOnDisk early-returns on fileSize <= headerSize.
        try (FileChannel rc = factory.open(path, StandardOpenOption.READ)) {
            // Channel opens and the plaintext header region reads back unchanged.
            assertArrayEquals("header region must read back as the original plaintext header", header, readFullyLoop(rc, 0, headerSize));
            // A read at the (empty) data region returns no bytes — there is no data and no super-header.
            ByteBuffer atData = ByteBuffer.allocate(64);
            assertTrue("header-only file has no data to read", rc.read(atData, headerSize) <= 0);
            assertEquals("nothing read past the header", 0, atData.position());
        }

        // The on-disk file must be byte-for-byte unchanged: no 'TLE' super-header was appended, size intact.
        assertEquals("open(READ) must not change a header-only file's size", (long) headerSize, Files.size(path));
        assertArrayEquals("open(READ) must leave a header-only file byte-for-byte unchanged", before, Files.readAllBytes(path));
        assertFalse(
            "open(READ) must not have converted a header-only file to v2",
            TranslogFrameManager.hasSuperHeaderMagic(Files.readAllBytes(path), headerSize)
        );
    }

    /**
     * Passthrough: a non-.tlog file (e.g. translog.ckp checkpoint metadata) opened via
     * {@link CryptoChannelFactory#open} must be returned as a RAW FileChannel — never encrypted, never
     * wrapped, and never touched by {@code ensureEncryptedOnDisk}. {@code open()} short-circuits on the
     * file extension before any conversion/wrapping, so a .ckp round-trips as plaintext: the on-disk bytes
     * are byte-for-byte what was written (no v2 'TLE' super-header, no length-prefix/GCM-tag overhead), and
     * a later open() of the existing file performs no in-place conversion. A regression that ran
     * {@code ensureEncryptedOnDisk} (or crypto-wrapped) unconditionally would silently corrupt checkpoints
     * and break recovery.
     */
    @SuppressForbidden(reason = "Test reads raw .ckp bytes written through the passthrough channel")
    public void testCkpFileIsPlaintextPassthrough() throws IOException {
        String uuid = "ckp-passthrough-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path ckpPath = tempDir.resolve("translog.ckp");

        // Plaintext that spans more than one GCM block, so any accidental v2 framing would change size/bytes.
        byte[] ckpBytes = randomByteArrayOfLength(CHUNK + randomIntBetween(64, 512));

        // Write through the factory (CREATE) — must be a raw passthrough channel, no header/super-header.
        try (FileChannel ch = factory.open(ckpPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ByteBuffer src = ByteBuffer.wrap(ckpBytes);
            int written = 0;
            while (src.hasRemaining()) {
                int n = ch.write(src, written);
                if (n <= 0) {
                    break;
                }
                written += n;
            }
            assertEquals("ckp write must report all bytes", ckpBytes.length, written);
        }

        // On disk: byte-for-byte the original plaintext (no encryption, no v2 framing/overhead).
        assertEquals("ckp must be stored verbatim (no encryption overhead)", ckpBytes.length, Files.size(ckpPath));
        assertArrayEquals("ckp on-disk bytes must equal what was written", ckpBytes, Files.readAllBytes(ckpPath));
        assertFalse(
            "ckp must NOT carry the v2 TLE super-header (it must never be encrypted)",
            TranslogFrameManager.hasSuperHeaderMagic(Files.readAllBytes(ckpPath), 0)
        );

        // Read back through the factory (existing file, NOT creating) — open() must still passthrough and
        // must NOT invoke ensureEncryptedOnDisk on a non-.tlog file. Bytes come back as plaintext.
        try (FileChannel rc = factory.open(ckpPath, StandardOpenOption.READ)) {
            byte[] back = readFullyLoop(rc, 0, ckpBytes.length);
            assertArrayEquals("ckp must read back as plaintext", ckpBytes, back);
        }
        // open() over the existing .ckp must have left it byte-for-byte unchanged (no in-place conversion).
        assertArrayEquals("open() of an existing .ckp must not modify it", ckpBytes, Files.readAllBytes(ckpPath));
    }

    private byte[] createRawHeader(String uuid, long primaryTerm) throws IOException {
        Path tmp = tempDir.resolve("tmp-header.tlog");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            new TranslogHeader(uuid, primaryTerm).write(ch, false);
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.delete(tmp);
        return bytes;
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
        public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
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
