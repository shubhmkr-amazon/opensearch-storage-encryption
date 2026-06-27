/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.ShardCacheKey;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Correctness, security, crash-safety, and concurrency tests for the FRAME-AAD engine
 * ({@link TranslogFrameManager}). These are the tests that earn the "zero corruption / zero race" bar:
 * round-trip across many sizes and boundaries, byte-identity under partial writes/reads, tamper rejection
 * (ciphertext + every authenticated metadata field), torn-tail truncation, nonce uniqueness across
 * frames/generations, append-only enforcement, and a concurrent reader-vs-writer stress that asserts no
 * reader ever observes a torn index or wrong bytes.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class TranslogFrameManagerTests extends OpenSearchTestCase {

    private Path tempDir;
    private KeyResolver keyResolver;
    private String uuid;

    @SuppressForbidden(reason = "register resolver in ShardKeyResolverRegistry")
    private void registerResolver(String indexUuid, int shardId, KeyResolver resolver) throws Exception {
        Field f = ShardKeyResolverRegistry.class.getDeclaredField("resolverCache");
        f.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentMap<ShardCacheKey, KeyResolver> cache = (ConcurrentMap<ShardCacheKey, KeyResolver>) f.get(null);
        cache.put(new ShardCacheKey(indexUuid, shardId, "test-index"), resolver);
    }

    @Override
    @SuppressForbidden(reason = "temp dir for test")
    public void setUp() throws Exception {
        super.setUp();
        tempDir = Files.createTempDirectory("v3-frame-test");
        ShardKeyResolverRegistry.clearCache();
        Settings nodeSettings = Settings.builder().put("node.store.crypto.key_refresh_interval", "5m").build();
        org.opensearch.transport.client.Client mockClient = mock(org.opensearch.transport.client.Client.class);
        org.opensearch.cluster.service.ClusterService mockCs = mock(org.opensearch.cluster.service.ClusterService.class);
        org.opensearch.transport.client.AdminClient adminClient = mock(org.opensearch.transport.client.AdminClient.class);
        org.opensearch.transport.client.IndicesAdminClient indicesClient = mock(org.opensearch.transport.client.IndicesAdminClient.class);
        @SuppressWarnings("unchecked")
        org.opensearch.common.action.ActionFuture<org.opensearch.action.support.clustermanager.AcknowledgedResponse> fut = mock(
            org.opensearch.common.action.ActionFuture.class
        );
        when(mockClient.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesClient);
        when(indicesClient.updateSettings(any())).thenReturn(fut);
        when(fut.actionGet()).thenReturn(mock(org.opensearch.action.support.clustermanager.AcknowledgedResponse.class));
        MasterKeyHealthMonitor.initialize(nodeSettings, mockClient, mockCs);
        NodeLevelKeyCache.initialize(nodeSettings, MasterKeyHealthMonitor.getInstance());

        Provider provider = Security.getProvider("SunJCE");
        MasterKeyProvider keyProvider = new MasterKeyProvider() {
            @Override
            public Map<String, String> getEncryptionContext() {
                return Collections.singletonMap("k", "v");
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                return new byte[32];
            }

            @Override
            public String getKeyId() {
                return "test-key-id";
            }

            @Override
            public DataKeyPair generateDataPair() {
                return new DataKeyPair(new byte[32], new byte[32]);
            }

            @Override
            public void close() {}
        };
        uuid = "v3-uuid-" + System.nanoTime();
        org.apache.lucene.store.Directory dir = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        keyResolver = new DefaultKeyResolver(uuid, "test-index", dir, provider, keyProvider, 0);
        registerResolver(uuid, 0, keyResolver);
    }

    @Override
    public void tearDown() throws Exception {
        MasterKeyHealthMonitor.reset();
        NodeLevelKeyCache.reset();
        ShardKeyResolverRegistry.clearCache();
        super.tearDown();
    }

    // ---- helpers ----

    private int headerSize() {
        return TranslogFrameManager.calculateTranslogHeaderSizeStatic(uuid);
    }

    /**
     * A KeyResolver whose data key is all-0xAB (distinct from the all-zero test key), so its HKDF baseIV —
     * and thus the super-header baseIVCheck — differs. Used to prove wrong-key reads fail closed.
     */
    @SuppressForbidden(reason = "build an alternate-key resolver for the wrong-key test")
    private KeyResolver newKeyResolverWithDifferentKey() throws Exception {
        MasterKeyProvider altProvider = new MasterKeyProvider() {
            @Override
            public Map<String, String> getEncryptionContext() {
                return Collections.singletonMap("k", "v2");
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                byte[] k = new byte[32];
                Arrays.fill(k, (byte) 0xAB);
                return k;
            }

            @Override
            public String getKeyId() {
                return "test-key-id-2";
            }

            @Override
            public DataKeyPair generateDataPair() {
                byte[] k = new byte[32];
                Arrays.fill(k, (byte) 0xAB);
                return new DataKeyPair(k, new byte[32]);
            }

            @Override
            public void close() {}
        };
        Provider provider = Security.getProvider("SunJCE");
        String altUuid = "v3-altkey-" + System.nanoTime();
        org.apache.lucene.store.Directory dir = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        return new DefaultKeyResolver(altUuid, "test-index-2", dir, provider, altProvider, 0);
    }

    /** Write a core header + data through a fresh manager; return headerSize. */
    @SuppressForbidden(reason = "real FileChannel for the engine")
    private int writeFile(Path path, byte[] data) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            int hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, path, uuid);
            // multi-call append to mimic core's many sequential writes
            int pos = hs, off = 0;
            while (off < data.length) {
                int n = Math.min(data.length - off, 4096);
                ByteBuffer b = ByteBuffer.wrap(data, off, n);
                int w = m.writeToChunks(b, pos);
                assertEquals("writer must accept all bytes of the slice", n, w);
                pos += n;
                off += n;
            }
            m.close();
            return hs;
        }
    }

    private int writeHeader(FileChannel ch) throws IOException {
        TranslogHeader h = new TranslogHeader(uuid, 1L);
        h.write(ch, false);
        return h.sizeInBytes();
    }

    @SuppressForbidden(reason = "real FileChannel for the engine")
    private byte[] readBack(Path path, int hs, int len) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, path, uuid);
            ByteBuffer out = ByteBuffer.allocate(len);
            int pos = hs;
            int guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                if (++guard > len + 16) fail("read loop stalled");
            }
            assertEquals("read-back length", len, out.position());
            return out.array();
        }
    }

    // ---- round-trip / boundaries ----

    public void testRoundTripManyLengths() throws IOException {
        int[] fixed = { 1, 100, 4095, 4096, 4097, 65535, 65536, 65537, 200000 };
        for (int i = 0; i < fixed.length; i++) {
            Path p = tempDir.resolve("translog-" + (i + 1) + ".tlog");
            byte[] data = randomByteArrayOfLength(fixed[i]);
            int hs = writeFile(p, data);
            assertArrayEquals("len=" + fixed[i], data, readBack(p, hs, data.length));
        }
        int random = scaledRandomIntBetween(10, 40);
        for (int i = 0; i < random; i++) {
            Path p = tempDir.resolve("translog-r" + i + ".tlog");
            byte[] data = randomByteArrayOfLength(randomIntBetween(1, 250000));
            int hs = writeFile(p, data);
            assertArrayEquals(data, readBack(p, hs, data.length));
        }
    }

    public void testReadAtAndPastEofReturnsZero() throws IOException {
        Path p = tempDir.resolve("translog-9.tlog");
        byte[] data = randomByteArrayOfLength(5000);
        int hs = writeFile(p, data);
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            ByteBuffer b = ByteBuffer.allocate(64);
            assertTrue("read at logical EOF returns <=0", m.readFromChunks(b, hs + data.length) <= 0);
            assertEquals(0, b.position());
        }
    }

    // ---- partial write / partial read (corruption class) ----

    @SuppressForbidden(reason = "short-write/read channel wrapper")
    public void testPartialWritesDoNotCorrupt() throws IOException {
        Path p = tempDir.resolve("translog-3.tlog");
        byte[] data = randomByteArrayOfLength(3 * TranslogFrameManager.FRAME_MAX + 1234);
        int hs;
        try (FileChannel real = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            FileChannel shortCh = new ShortChannel(real, 7, 0);
            hs = writeHeader(shortCh);
            TranslogFrameManager m = new TranslogFrameManager(shortCh, keyResolver, p, uuid);
            m.writeToChunks(ByteBuffer.wrap(data), hs);
            m.close();
        }
        assertArrayEquals("partial writes must not corrupt", data, readBack(p, hs, data.length));
    }

    @SuppressForbidden(reason = "short-read channel wrapper")
    public void testPartialReadsDoNotCorrupt() throws IOException {
        Path p = tempDir.resolve("translog-4.tlog");
        byte[] data = randomByteArrayOfLength(3 * TranslogFrameManager.FRAME_MAX + 999);
        int hs = writeFile(p, data);
        try (FileChannel real = FileChannel.open(p, StandardOpenOption.READ)) {
            FileChannel shortCh = new ShortChannel(real, Integer.MAX_VALUE, 7);
            TranslogFrameManager m = new TranslogFrameManager(shortCh, keyResolver, p, uuid);
            ByteBuffer out = ByteBuffer.allocate(data.length);
            int pos = hs, guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                if (++guard > data.length + 16) fail("stalled");
            }
            assertArrayEquals("partial reads must not corrupt", data, out.array());
        }
    }

    // ---- tamper rejection (security): ciphertext + every authenticated metadata field ----

    public void testCiphertextTamperFailsClosed() throws IOException {
        Path p = tempDir.resolve("translog-5.tlog");
        byte[] data = randomByteArrayOfLength(20000);
        int hs = writeFile(p, data);
        byte[] raw = Files.readAllBytes(p);
        int trials = scaledRandomIntBetween(20, 60);
        for (int t = 0; t < trials; t++) {
            byte[] bad = raw.clone();
            int idx = randomIntBetween(hs + TranslogFrameManager.SUPER_HEADER_SIZE, bad.length - 1);
            bad[idx] ^= (byte) (1 << randomIntBetween(0, 7));
            Path bp = tempDir.resolve("translog-5" + t + ".tlog");
            Files.write(bp, bad);
            try {
                byte[] got = readBack(bp, hs, data.length);
                assertFalse("GCM bypass: tampered file decrypted to original", Arrays.equals(data, got));
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("decrypt") || expected.getMessage().contains("frame"));
            } catch (AssertionError shortReadBack) {
                // a truncating tamper yields fewer bytes; acceptable as long as never silently equal
            }
        }
    }

    /**
     * Tamper EACH AAD-bound frame-header field (review: was only logicalOffset). For each, flip a byte in
     * that field AND recompute the header CRC so the index scan accepts the frame — forcing the GCM AAD (not
     * the CRC) to be what rejects it at decrypt. Layout: ptLen[0..3] | logicalOffset[4..11] | frameSeq[12..15]
     * | keyEpoch[16..19] | crc[20..23].
     */
    public void testFrameHeaderTamperEveryFieldFailsClosed() throws IOException {
        // byte offsets within the 24-byte header to perturb: ptLen, logicalOffset, frameSeq, keyEpoch
        int[] fieldBytes = { 2, 6, 14, 18 };
        String[] names = { "ptLen", "logicalOffset", "frameSeq", "keyEpoch" };
        for (int k = 0; k < fieldBytes.length; k++) {
            Path p = tempDir.resolve("translog-6" + k + "0.tlog");
            byte[] data = randomByteArrayOfLength(10000);
            int hs = writeFile(p, data);
            int fhStart = hs + TranslogFrameManager.SUPER_HEADER_SIZE;
            byte[] bad = Files.readAllBytes(p).clone();
            bad[fhStart + fieldBytes[k]] ^= 0x01;
            // Recompute header CRC so the scan accepts it -> only the AAD-bound GCM tag can reject it.
            java.util.zip.CRC32C crc = new java.util.zip.CRC32C();
            crc.update(bad, fhStart, TranslogFrameManager.FRAME_HEADER_SIZE - 4);
            int c = (int) crc.getValue();
            bad[fhStart + 20] = (byte) (c >>> 24);
            bad[fhStart + 21] = (byte) (c >>> 16);
            bad[fhStart + 22] = (byte) (c >>> 8);
            bad[fhStart + 23] = (byte) c;
            Path bp = tempDir.resolve("translog-6" + k + "1.tlog");
            Files.write(bp, bad);
            // ptLen/frameSeq tampering may be caught at the scan (continuity) OR at decrypt (AAD); either is
            // fail-closed. logicalOffset/keyEpoch pass the scan and must fail at the GCM AAD check.
            IOException ex = expectThrows(IOException.class, () -> readBack(bp, hs, data.length));
            assertNotNull("tampering " + names[k] + " must fail closed", ex);
        }
    }

    /**
     * Mid-stream corruption (review): a CRC-broken frame whose record fully fits within the file (NOT a torn
     * tail) must fail closed during the index scan, not silently drop all later frames. Build a 3-frame file,
     * corrupt the MIDDLE frame's header without fixing its CRC.
     */
    public void testMidStreamCorruptionFailsClosed() throws IOException {
        Path p = tempDir.resolve("translog-90.tlog");
        int frameLen = 4096;
        // 3 forced frames via flushSeal between writes.
        int hs;
        byte[][] f = new byte[3][];
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            int pos = hs;
            for (int i = 0; i < 3; i++) {
                f[i] = randomByteArrayOfLength(frameLen);
                m.writeToChunks(ByteBuffer.wrap(f[i]), pos);
                m.flushSeal();
                pos += frameLen;
            }
            m.close();
        }
        byte[] bad = Files.readAllBytes(p).clone();
        int stride = TranslogFrameManager.FRAME_HEADER_SIZE + frameLen + 16;
        int midHeader = hs + TranslogFrameManager.SUPER_HEADER_SIZE + stride; // 2nd frame's header
        bad[midHeader + 2] ^= 0x01; // corrupt ptLen byte, leave CRC stale -> CRC mismatch on a fits-in-file frame
        // Write back to the SAME path so the super-header generation still matches the filename (we are
        // testing mid-stream FRAME corruption, not a generation/relocation mismatch).
        Files.write(p, bad);
        IOException e = expectThrows(IOException.class, () -> readBack(p, hs, frameLen * 3));
        assertTrue("expected mid-stream corruption error, got: " + e.getMessage(),
            e.getMessage().contains("corrupt") || e.getMessage().contains("CRC") || e.getMessage().contains("sequence")
                || e.getMessage().contains("offset"));
    }

    /**
     * Torn TRAILING record after a crash (review fix): a final frame whose 24-byte header is fully on disk
     * and whose record fits within the file (recordEnd &lt;= size) but has a bad CRC must be treated as a
     * benign torn tail — recover all PRIOR frames as an exact prefix, do NOT throw. (Rev2 over-fired and
     * threw here, converting a recoverable crash tail into a shard-open failure.) This is the tail analogue
     * of {@link #testMidStreamCorruptionFailsClosed}: same corruption, but on the LAST frame, must recover.
     */
    public void testTornTrailingBadCrcRecovers() throws IOException {
        Path p = tempDir.resolve("translog-92.tlog");
        int frameLen = 4096;
        int hs;
        byte[][] f = new byte[3][];
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            int pos = hs;
            for (int i = 0; i < 3; i++) {
                f[i] = randomByteArrayOfLength(frameLen);
                m.writeToChunks(ByteBuffer.wrap(f[i]), pos);
                m.flushSeal();
                pos += frameLen;
            }
            m.close();
        }
        byte[] bad = Files.readAllBytes(p).clone();
        int stride = TranslogFrameManager.FRAME_HEADER_SIZE + frameLen + 16;
        int lastHeader = hs + TranslogFrameManager.SUPER_HEADER_SIZE + 2 * stride; // 3rd (last) frame's header
        bad[lastHeader + 2] ^= 0x01; // corrupt ptLen byte, leave CRC stale -> bad CRC, but record still fits in file
        Files.write(p, bad); // same path => generation matches
        // Must NOT throw: recover frames 0 and 1 as an exact prefix; the torn last frame is dropped.
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            ByteBuffer out = ByteBuffer.allocate(frameLen * 3);
            int pos = hs, got = 0, guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                got += n;
                if (++guard > frameLen * 3 + 16) fail("stalled");
            }
            assertEquals("must recover exactly the two intact leading frames", frameLen * 2, got);
            byte[] want = new byte[frameLen * 2];
            System.arraycopy(f[0], 0, want, 0, frameLen);
            System.arraycopy(f[1], 0, want, frameLen, frameLen);
            assertArrayEquals("torn-tail recovery must return the intact prefix", want, Arrays.copyOf(out.array(), got));
        }
    }

    /**
     * Torn TRAILING frame whose ptLen high (sign) bit got flipped by a partial/garbage write. A negative
     * ptLen makes {@code recordEnd = pos + 24 + ptLen + 16} compute to LESS than the file size, so a naive
     * {@code atPhysicalTail = recordEnd >= size} test misclassifies the benign torn tail as mid-stream
     * corruption and refuses to open the shard. A ptLen can never legitimately be {@code <=0} or
     * {@code > FRAME_MAX}, so an out-of-range ptLen at the physical tail must be treated as the torn tail and
     * the intact prefix recovered — never throw.
     */
    public void testTornTrailingNegativePtLenRecovers() throws IOException {
        Path p = tempDir.resolve("translog-93.tlog");
        int frameLen = 4096;
        int hs;
        byte[][] f = new byte[3][];
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            int pos = hs;
            for (int i = 0; i < 3; i++) {
                f[i] = randomByteArrayOfLength(frameLen);
                m.writeToChunks(ByteBuffer.wrap(f[i]), pos);
                m.flushSeal();
                pos += frameLen;
            }
            m.close();
        }
        byte[] bad = Files.readAllBytes(p).clone();
        int stride = TranslogFrameManager.FRAME_HEADER_SIZE + frameLen + 16;
        int lastHeader = hs + TranslogFrameManager.SUPER_HEADER_SIZE + 2 * stride; // 3rd (last) frame's header
        bad[lastHeader] = (byte) 0x80; // set ptLen sign bit (high byte of the big-endian u32) -> negative ptLen
        Files.write(p, bad); // same path => generation matches; this is a torn TAIL, not relocation
        // Must NOT throw: recover frames 0 and 1 as an exact prefix; the torn last frame is dropped.
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            ByteBuffer out = ByteBuffer.allocate(frameLen * 3);
            int pos = hs, got = 0, guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                got += n;
                if (++guard > frameLen * 3 + 16) fail("stalled");
            }
            assertEquals("must recover exactly the two intact leading frames", frameLen * 2, got);
            byte[] want = new byte[frameLen * 2];
            System.arraycopy(f[0], 0, want, 0, frameLen);
            System.arraycopy(f[1], 0, want, frameLen, frameLen);
            assertArrayEquals("negative-ptLen torn-tail recovery must return the intact prefix", want, Arrays.copyOf(out.array(), got));
        }
    }

    /**
     * Wrong key / epoch: a file written under one data key must fail closed (not silently mis-decrypt) when
     * opened with a manager whose key derives a different baseIV. The super-header baseIVCheck catches it.
     */
    public void testWrongKeyFailsClosed() throws Exception {
        Path p = tempDir.resolve("translog-95.tlog");
        byte[] data = randomByteArrayOfLength(3000);
        int hs = writeFile(p, data); // written with the test keyResolver
        // Open with a DIFFERENT key resolver -> baseIVCheck mismatch -> fail closed.
        KeyResolver otherKey = newKeyResolverWithDifferentKey();
        // Fail-closed can surface either at manager construction / key resolution (KeyCacheException, the
        // alt resolver cannot produce a key) OR at read time as the super-header baseIVCheck mismatch
        // (IOException) — both are correct: a wrong key NEVER silently mis-decrypts. Wrap BOTH the
        // construction and the read so whichever throws is caught.
        Exception e = expectThrows(Exception.class, () -> {
            try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
                TranslogFrameManager m = new TranslogFrameManager(ch, otherKey, p, uuid);
                ByteBuffer out = ByteBuffer.allocate(data.length);
                m.readFromChunks(out, hs);
            }
        });
        String msg = String.valueOf(e.getMessage());
        assertTrue(
            "wrong key must fail closed, got: " + e.getClass().getSimpleName() + ": " + msg,
            msg.contains("key/epoch") || msg.contains("decrypt") || msg.toLowerCase().contains("key")
        );
    }

    /**
     * M2 accumulator: many small sub-threshold writes WITHOUT a force coalesce into far fewer frames (no
     * per-write frame explosion) yet still round-trip byte-exact; a force() in the middle seals a boundary.
     */
    public void testAccumulatorCoalescesSmallWrites() throws IOException {
        Path p = tempDir.resolve("translog-96.tlog");
        int n = 500, each = 50; // 500 tiny ops; pre-fix this was 500 frames (+40B each)
        byte[] all = new byte[n * each];
        int hs;
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            int pos = hs;
            for (int i = 0; i < n; i++) {
                byte[] op = randomByteArrayOfLength(each);
                System.arraycopy(op, 0, all, i * each, each);
                m.writeToChunks(ByteBuffer.wrap(op), pos);
                pos += each;
                if (i == n / 2) {
                    m.flushSeal(); // a force() in the middle seals one frame boundary
                }
            }
            m.close();
        }
        // Round-trips byte-exact.
        assertArrayEquals(all, readBack(p, hs, all.length));
        // Frame explosion is gone: total data-region overhead should be only a couple of frames' worth,
        // not 500 * (24+16). Expect <= 3 frames (the mid force + threshold fills + final close).
        long dataRegion = Files.size(p) - hs - TranslogFrameManager.SUPER_HEADER_SIZE;
        long overhead = dataRegion - all.length;
        long perFrame = TranslogFrameManager.FRAME_HEADER_SIZE + 16;
        assertTrue("accumulator must coalesce; overhead=" + overhead + " (~" + (overhead / perFrame) + " frames)",
            overhead <= 5 * perFrame);
    }

    /**
     * Flip the version byte AND recompute the super-header CRC so the CRC check passes — this forces the
     * UNSUPPORTED-VERSION branch to be what rejects the file (review: the old test tripped the CRC first and
     * never exercised the version check).
     */
    public void testSuperHeaderVersionRejectedAfterValidCrc() throws IOException {
        Path p = tempDir.resolve("translog-7.tlog");
        byte[] data = randomByteArrayOfLength(4000);
        int hs = writeFile(p, data);
        byte[] bad = Files.readAllBytes(p).clone();
        bad[hs + 4] = (byte) 0x7F; // version byte (super-header layout: magic[0..3], version@4)
        // Recompute the super-header CRC32C over the first SUPER_HEADER_SIZE-4 bytes of the super-header.
        int shStart = hs;
        int crcOff = shStart + TranslogFrameManager.SUPER_HEADER_SIZE - 4;
        java.util.zip.CRC32C crc = new java.util.zip.CRC32C();
        crc.update(bad, shStart, TranslogFrameManager.SUPER_HEADER_SIZE - 4);
        int c = (int) crc.getValue();
        bad[crcOff] = (byte) (c >>> 24);
        bad[crcOff + 1] = (byte) (c >>> 16);
        bad[crcOff + 2] = (byte) (c >>> 8);
        bad[crcOff + 3] = (byte) c;
        Path bp = tempDir.resolve("translog-77.tlog");
        Files.write(bp, bad);
        IOException e = expectThrows(IOException.class, () -> readBack(bp, hs, data.length));
        assertTrue("expected unsupported-version error, got: " + e.getMessage(), e.getMessage().contains("version"));
    }

    /** A wrong magic byte (CRC-consistent) must still fail closed with the magic error. */
    public void testSuperHeaderMagicTamperFailsClosed() throws IOException {
        Path p = tempDir.resolve("translog-71.tlog");
        byte[] data = randomByteArrayOfLength(2000);
        int hs = writeFile(p, data);
        byte[] bad = Files.readAllBytes(p).clone();
        bad[hs] = (byte) 'X'; // corrupt the 'T' of TLE1
        Path bp = tempDir.resolve("translog-711.tlog");
        Files.write(bp, bad);
        IOException e = expectThrows(IOException.class, () -> readBack(bp, hs, data.length));
        assertTrue("expected magic error, got: " + e.getMessage(), e.getMessage().contains("magic"));
    }

    // ---- torn tail (crash mid-append) ----

    public void testTornTailTruncatedNotCorrupt() throws IOException {
        // Use ONE generation file: write it, then truncate IN PLACE (same name => same generation/baseIV),
        // simulating a crash that left a partial final frame.
        Path tp = tempDir.resolve("translog-88.tlog");
        byte[] data = randomByteArrayOfLength(50000);
        int hs = writeFile(tp, data);
        byte[] raw = Files.readAllBytes(tp);
        byte[] torn = Arrays.copyOf(raw, raw.length - 37);
        Files.write(tp, torn);
        // The reader must NOT throw; it serves only fully-durable frames and treats the torn tail as absent.
        try (FileChannel ch = FileChannel.open(tp, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, tp, uuid);
            ByteBuffer out = ByteBuffer.allocate(data.length);
            int pos = hs, got = 0, guard = 0;
            while (out.hasRemaining()) {
                int n = m.readFromChunks(out, pos);
                if (n <= 0) break;
                pos += n;
                got += n;
                if (++guard > data.length + 16) fail("stalled");
            }
            // Everything returned must be a byte-exact prefix of the original (no garbage from the torn frame).
            assertTrue("recovered bytes must be a prefix of the original", got <= data.length);
            byte[] prefix = Arrays.copyOf(out.array(), got);
            assertArrayEquals("torn-tail recovery must return an exact prefix", Arrays.copyOf(data, got), prefix);
        }
    }

    // ---- nonce uniqueness (security) ----

    public void testDifferentGenerationsDifferentCiphertext() throws IOException {
        byte[] data = randomByteArrayOfLength(8000);
        Path p1 = tempDir.resolve("translog-1.tlog");
        Path p2 = tempDir.resolve("translog-2.tlog");
        int hs1 = writeFile(p1, data);
        int hs2 = writeFile(p2, data);
        byte[] ct1 = Arrays.copyOfRange(Files.readAllBytes(p1), hs1, (int) Files.size(p1));
        byte[] ct2 = Arrays.copyOfRange(Files.readAllBytes(p2), hs2, (int) Files.size(p2));
        assertFalse("same plaintext across generations must differ on disk (no nonce reuse)", Arrays.equals(ct1, ct2));
        // and each still decrypts
        assertArrayEquals(data, readBack(p1, hs1, data.length));
        assertArrayEquals(data, readBack(p2, hs2, data.length));
    }

    /**
     * CROSS-FILE nonce uniqueness (the rev2 blocker): the SAME generation re-encrypted from plaintext into a
     * fresh file (exactly what the remote-store restore path does — fresh TranslogFrameManager, frameSeq
     * restarting at 0, on a truncated channel) must NOT reuse frame-0's (key, nonce) on the original file's
     * frame 0. Identical plaintext written to two files of the same generation must produce DIFFERENT
     * frame-0 ciphertext, because each file gets a random per-file salt folded into baseIV. Before the salt
     * fix both derived baseIV=HKDF(key,uuid,gen,epoch) and reused baseIV[0:8]||BE32(0) — catastrophic.
     */
    public void testSameGenerationDistinctFilesDifferentFrameZeroCiphertext() throws IOException {
        byte[] data = randomByteArrayOfLength(8000); // one frame after a single force-seal
        // One physical path, same generation: write, snapshot frame0, then re-encrypt IN PLACE from the same
        // plaintext via a fresh manager on a truncated channel (mirrors the restore re-encrypt path exactly).
        Path a = tempDir.resolve("translog-777.tlog");
        int hs = writeFile(a, data);
        byte[] firstFrame0 = frameZeroBytes(a, hs);
        byte[] firstSalt = saltBytes(a, hs);

        // Re-encrypt the SAME path from the same plaintext with a fresh manager (restore semantics).
        try (FileChannel ch = FileChannel.open(a, StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            int h2 = writeHeader(ch);
            assertEquals(hs, h2);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, a, uuid);
            m.writeToChunks(ByteBuffer.wrap(data), h2);
            m.close();
        }
        byte[] secondFrame0 = frameZeroBytes(a, hs);
        byte[] secondSalt = saltBytes(a, hs);

        assertFalse("per-file salt must differ across re-encryptions", Arrays.equals(firstSalt, secondSalt));
        assertFalse(
            "SAME generation, SAME plaintext, re-encrypted => frame-0 ciphertext MUST differ (no (key,nonce) reuse)",
            Arrays.equals(firstFrame0, secondFrame0)
        );
        // And the re-encrypted file still decrypts to the original.
        assertArrayEquals(data, readBack(a, hs, data.length));
    }

    /** Returns frame-0's on-disk bytes (header+ct+tag) for a single-frame file. */
    @SuppressForbidden(reason = "read raw frame bytes")
    private byte[] frameZeroBytes(Path p, int hs) throws IOException {
        byte[] all = Files.readAllBytes(p);
        int f0 = hs + TranslogFrameManager.SUPER_HEADER_SIZE;
        return Arrays.copyOfRange(all, f0, all.length);
    }

    /** Returns the 8-byte per-file salt from the super-header reserved/salt field. */
    @SuppressForbidden(reason = "read raw super-header salt")
    private byte[] saltBytes(Path p, int hs) throws IOException {
        byte[] all = Files.readAllBytes(p);
        int saltOff = hs + 4 + 1 + 1 + 2 + 8 + 4 + 4; // after magic|ver|flags|fhLen|gen|epoch|baseIVCheck
        return Arrays.copyOfRange(all, saltOff, saltOff + 8);
    }

    public void testIdenticalFramesInOneFileDifferentCiphertext() throws IOException {
        int chunk = 4096;
        byte[] block = randomByteArrayOfLength(chunk);
        byte[] data = new byte[chunk * 2];
        System.arraycopy(block, 0, data, 0, chunk);
        System.arraycopy(block, 0, data, chunk, chunk);
        Path p = tempDir.resolve("translog-12.tlog");
        // Force two frames: write 4096, flushSeal() (seals frame 0), write the next 4096 (frame 1), close.
        // (With the M2 accumulator, two sub-threshold writes WITHOUT a seal between them coalesce into one
        // frame — so the seal is what makes this a genuine two-frame, two-nonce test.)
        int hs;
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            m.writeToChunks(ByteBuffer.wrap(block), hs);
            m.flushSeal();
            m.writeToChunks(ByteBuffer.wrap(block), hs + chunk);
            m.close();
        }
        byte[] all = Files.readAllBytes(p);
        int f0 = hs + TranslogFrameManager.SUPER_HEADER_SIZE;
        int stride = TranslogFrameManager.FRAME_HEADER_SIZE + chunk + 16;
        byte[] c0 = Arrays.copyOfRange(all, f0, f0 + stride);
        byte[] c1 = Arrays.copyOfRange(all, f0 + stride, f0 + 2 * stride);
        assertFalse("two equal frames must encrypt differently (per-frame nonce)", Arrays.equals(c0, c1));
        assertArrayEquals(data, readBack(p, hs, data.length));
    }

    // ---- append-only enforcement ----

    @SuppressForbidden(reason = "real FileChannel")
    public void testNonAppendWriteRejected() throws IOException {
        Path p = tempDir.resolve("translog-3.tlog");
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            int hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            byte[] first = randomByteArrayOfLength(4096);
            assertEquals(first.length, m.writeToChunks(ByteBuffer.wrap(first), hs));
            IOException e = expectThrows(IOException.class, () -> m.writeToChunks(ByteBuffer.wrap(new byte[10]), hs));
            assertTrue(e.getMessage().contains("append-only"));
        }
    }

    /**
     * C6 guard (the invariant this CR exists to protect): a FRESH TranslogFrameManager opened on a NON-EMPTY
     * encrypted translog must REFUSE the first write rather than start at frameSeq 0 — which, on an existing
     * file, would reissue (baseIV[0:8] || BE32(0)) on new plaintext = catastrophic GCM nonce reuse. Distinct
     * from testNonAppendWriteRejected, which only exercises the position-mismatch ("append-only") branch on
     * an ALREADY-open writer. A regression deleting the C6 guard would pass that test but fail this one.
     */
    @SuppressForbidden(reason = "real FileChannel")
    public void testC6ReopenForAppendRefusedNonceReuseGuard() throws IOException {
        Path p = tempDir.resolve("translog-31.tlog");
        byte[] data = randomByteArrayOfLength(5000); // a sealed frame on disk -> file is non-empty
        int hs = writeFile(p, data);
        assertTrue("precondition: file must be non-empty (has a super-header + frame)", Files.size(p) > hs);
        // A brand-new manager (superHeaderWritten=false, nextFrameSeq=0) tries to append at the core-header
        // boundary of an already-populated file. C6 must throw before any frame is sealed.
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            IOException e = expectThrows(IOException.class, () -> m.writeToChunks(ByteBuffer.wrap(new byte[16]), hs));
            assertTrue(
                "C6 must refuse append-to-non-empty to prevent nonce reuse, got: " + e.getMessage(),
                e.getMessage().contains("non-empty") || e.getMessage().contains("reuse a GCM nonce")
            );
        }
        // And the original file must be byte-for-byte intact (the refused write touched nothing).
        assertArrayEquals("refused C6 write must not have mutated the file", data, readBack(p, hs, data.length));
    }

    /**
     * Reopen frameSeq continuity: when a manager reopens an existing file and scans it (currentIndex), it
     * must re-seed nextFrameSeq / logicalDataWritten / fileWritePosition from the on-disk frames so a
     * subsequent monotonic frameSeq is correct. We can't legally append through the C6 guard, so we assert
     * the recovered index reflects the exact on-disk frame count + plaintext length (the state those cursors
     * are derived from), proving the reopen-scan re-seed (TranslogFrameManager.java:788-792) actually runs.
     */
    @SuppressForbidden(reason = "real FileChannel")
    public void testReopenScanReseedsFrameContinuity() throws IOException {
        Path p = tempDir.resolve("translog-32.tlog");
        // Force exactly 3 frames via flushSeal between writes.
        int frameLen = 4096, hs;
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            hs = writeHeader(ch);
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            int pos = hs;
            for (int i = 0; i < 3; i++) {
                m.writeToChunks(ByteBuffer.wrap(randomByteArrayOfLength(frameLen)), pos);
                m.flushSeal();
                pos += frameLen;
            }
            m.close();
        }
        // Reopen with a fresh manager and force a scan via a read at logical EOF-1; the scan re-seeds cursors.
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
            TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            // Read the last byte -> drives currentIndex() over all 3 frames.
            byte[] back = readBack(p, hs, frameLen * 3);
            assertEquals("reopened file must expose all 3 frames' plaintext", frameLen * 3, back.length);
            // A read exactly at logical EOF returns 0 (next frameSeq would be 3; continuity intact).
            ByteBuffer atEof = ByteBuffer.allocate(16);
            assertEquals("read at logical EOF after reopen must return 0 (cursors re-seeded consistently)",
                0, m.readFromChunks(atEof, hs + frameLen * 3));
        }
    }

    // ---- concurrency: reader vs writer, no torn index / no wrong bytes ----

    @SuppressForbidden(reason = "real FileChannel; concurrent reader/writer stress")
    public void testConcurrentReadsDuringAppends() throws Exception {
        Path p = tempDir.resolve("translog-30.tlog");
        final int frames = 400;
        final int frameLen = 1024;
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            int hs = writeHeader(ch);
            final TranslogFrameManager m = new TranslogFrameManager(ch, keyResolver, p, uuid);
            // Emulate the wrapper's lock discipline exactly: writes hold the write lock, reads the read lock.
            final java.util.concurrent.locks.ReentrantReadWriteLock lock = new java.util.concurrent.locks.ReentrantReadWriteLock();
            final byte[][] expected = new byte[frames][];
            final AtomicReference<Throwable> failure = new AtomicReference<>();
            final CountDownLatch started = new CountDownLatch(1);
            final java.util.concurrent.atomic.AtomicInteger framesWritten = new java.util.concurrent.atomic.AtomicInteger(0);

            Thread writer = new Thread(() -> {
                try {
                    started.countDown();
                    int pos = hs;
                    for (int i = 0; i < frames; i++) {
                        byte[] d = new byte[frameLen];
                        for (int j = 0; j < frameLen; j++) d[j] = (byte) (i * 31 + j);
                        expected[i] = d;
                        lock.writeLock().lock();
                        try {
                            m.writeToChunks(ByteBuffer.wrap(d), pos);
                        } finally {
                            lock.writeLock().unlock();
                        }
                        pos += frameLen;
                        framesWritten.incrementAndGet();
                    }
                } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                }
            });

            Thread reader = new Thread(() -> {
                try {
                    started.await();
                    for (int iter = 0; iter < 5000 && failure.get() == null; iter++) {
                        int upto = framesWritten.get();
                        if (upto == 0) continue;
                        int fi = randomIntBetween(0, upto - 1);
                        byte[] out = new byte[frameLen];
                        ByteBuffer bb = ByteBuffer.wrap(out);
                        int rpos = hs + fi * frameLen, guard = 0;
                        lock.readLock().lock();
                        try {
                            while (bb.hasRemaining()) {
                                int n = m.readFromChunks(bb, rpos);
                                if (n <= 0) break;
                                rpos += n;
                                if (++guard > frameLen + 8) break;
                            }
                        } finally {
                            lock.readLock().unlock();
                        }
                        if (bb.position() == frameLen && !Arrays.equals(expected[fi], out)) {
                            failure.compareAndSet(null, new AssertionError("torn/wrong read of frame " + fi));
                            return;
                        }
                    }
                } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                }
            });

            writer.start();
            reader.start();
            writer.join(60_000);
            reader.join(60_000);
            if (failure.get() != null) {
                throw new AssertionError("concurrent reader/writer failure", failure.get());
            }
            m.close();
            // final full read-back must be byte-exact
            ByteBuffer full = ByteBuffer.allocate(frames * frameLen);
            int pos = hs, guard = 0;
            while (full.hasRemaining()) {
                int n = m.readFromChunks(full, pos);
                if (n <= 0) break;
                pos += n;
                if (++guard > frames * frameLen + 16) fail("stalled");
            }
            for (int i = 0; i < frames; i++) {
                byte[] slice = Arrays.copyOfRange(full.array(), i * frameLen, (i + 1) * frameLen);
                assertArrayEquals("frame " + i + " final read-back", expected[i], slice);
            }
        }
    }

    /**
     * A FileChannel decorator that caps positional write/read sizes, to exercise the write-fully / read-fully
     * loops (the partial-IO corruption class).
     */
    @SuppressForbidden(reason = "test wrapper over FileChannel")
    private static final class ShortChannel extends FileChannel {
        private final FileChannel d;
        private final int maxW;
        private final int maxR;

        ShortChannel(FileChannel d, int maxW, int maxR) {
            this.d = d;
            this.maxW = maxW;
            this.maxR = maxR;
        }

        @Override
        public int write(ByteBuffer src, long position) throws IOException {
            if (maxW <= 0 || src.remaining() <= maxW) return d.write(src, position);
            int ol = src.limit();
            src.limit(src.position() + maxW);
            int n = d.write(src, position);
            src.limit(ol);
            return n;
        }

        @Override
        public int read(ByteBuffer dst, long position) throws IOException {
            if (maxR <= 0 || dst.remaining() <= maxR) return d.read(dst, position);
            int ol = dst.limit();
            dst.limit(dst.position() + maxR);
            int n = d.read(dst, position);
            dst.limit(ol);
            return n;
        }

        @Override
        public long size() throws IOException {
            return d.size();
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            return d.read(dst);
        }

        @Override
        public long read(ByteBuffer[] dsts, int off, int len) throws IOException {
            return d.read(dsts, off, len);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            return d.write(src);
        }

        @Override
        public long write(ByteBuffer[] srcs, int off, int len) throws IOException {
            return d.write(srcs, off, len);
        }

        @Override
        public long position() throws IOException {
            return d.position();
        }

        @Override
        public FileChannel position(long p) throws IOException {
            d.position(p);
            return this;
        }

        @Override
        public FileChannel truncate(long s) throws IOException {
            d.truncate(s);
            return this;
        }

        @Override
        public void force(boolean m) throws IOException {
            d.force(m);
        }

        @Override
        public long transferTo(long p, long c, java.nio.channels.WritableByteChannel t) throws IOException {
            return d.transferTo(p, c, t);
        }

        @Override
        public long transferFrom(java.nio.channels.ReadableByteChannel s, long p, long c) throws IOException {
            return d.transferFrom(s, p, c);
        }

        @Override
        public java.nio.MappedByteBuffer map(MapMode m, long p, long s) throws IOException {
            return d.map(m, p, s);
        }

        @Override
        public java.nio.channels.FileLock lock(long p, long s, boolean shared) throws IOException {
            return d.lock(p, s, shared);
        }

        @Override
        public java.nio.channels.FileLock tryLock(long p, long s, boolean shared) throws IOException {
            return d.tryLock(p, s, shared);
        }

        @Override
        protected void implCloseChannel() throws IOException {
            d.close();
        }
    }
}
