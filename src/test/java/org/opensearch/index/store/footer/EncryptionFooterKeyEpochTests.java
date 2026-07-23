/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.footer;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.function.IntFunction;

import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Proves the online key-rotation mechanism at the footer level: each segment is stamped with the
 * key-rotation epoch that encrypted it, and a reader selects the matching master key from that stamp
 * BEFORE authenticating the footer. This is what allows segments written under an old epoch to remain
 * readable after rotation (online dual-key reads), while the wrong epoch's key is rejected.
 */
public class EncryptionFooterKeyEpochTests extends OpenSearchTestCase {

    private static final short ALG = (short) EncryptionMetadataTrailer.ALGORITHM_AES_256_GCM;
    private static final long FRAME_SIZE = EncryptionMetadataTrailer.DEFAULT_FRAME_SIZE;

    /** Deterministic distinct 32-byte master key per epoch, for the test. */
    private static byte[] masterKeyForEpoch(int epoch) {
        try {
            byte[] seed = ("test-master-key-epoch-" + epoch).getBytes(StandardCharsets.UTF_8);
            return MessageDigest.getInstance("SHA-256").digest(seed); // 32 bytes
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void testEpochZeroIsBackwardCompatibleEmptyKeyMetadata() {
        EncryptionFooter legacy = EncryptionFooter.generateNew(FRAME_SIZE, ALG); // no epoch => 0
        assertEquals(0, legacy.getKeyEpoch());
        assertEquals("epoch 0 must not add bytes to the footer", 0, legacy.getKeyMetadata().length);

        EncryptionFooter explicitZero = EncryptionFooter.generateNew(FRAME_SIZE, ALG, 0);
        assertEquals(0, explicitZero.getKeyMetadata().length);
    }

    public void testNonZeroEpochStampedInKeyMetadata() {
        EncryptionFooter footer = EncryptionFooter.generateNew(FRAME_SIZE, ALG, 7);
        assertEquals(7, footer.getKeyEpoch());
        assertEquals("epoch > 0 occupies the 4-byte keyMetadata slot", EncryptionFooter.KEY_EPOCH_SIZE, footer.getKeyMetadata().length);
    }

    public void testEpochSurvivesSerializeDeserialize() throws IOException {
        for (int epoch : new int[] { 0, 1, 2, 42 }) {
            EncryptionFooter footer = EncryptionFooter.generateNew(FRAME_SIZE, ALG, epoch);
            byte[] fileKey = HkdfKeyDerivation.deriveFileKey(masterKeyForEpoch(epoch), footer.getMessageId());

            byte[] serialized = footer.serialize(null, fileKey);

            // The epoch must be recoverable WITHOUT the key (pre-auth), for key selection.
            assertEquals("extractKeyEpoch (pre-auth) mismatch", epoch, EncryptionFooter.extractKeyEpoch(serialized));

            // And after full authenticated deserialize.
            EncryptionFooter roundTripped = EncryptionFooter.deserialize(serialized, fileKey);
            assertEquals("epoch after deserialize mismatch", epoch, roundTripped.getKeyEpoch());
            assertArrayEquals(footer.getMessageId(), roundTripped.getMessageId());
        }
    }

    /**
     * Adversarial: a tampered (pre-auth) keyMetadataLength must fail closed with an IOException, never
     * an unchecked NegativeArraySize / ArrayIndexOutOfBounds from offset arithmetic.
     */
    public void testTamperedKeyMetadataLengthFailsClosed() throws IOException {
        EncryptionFooter footer = EncryptionFooter.generateNew(FRAME_SIZE, ALG, 3);
        byte[] fileKey = HkdfKeyDerivation.deriveFileKey(masterKeyForEpoch(3), footer.getMessageId());
        byte[] serialized = footer.serialize(null, fileKey);

        // keyMetadataLength sits at: end - MAGIC(4) - FOOTER_LENGTH(4) - ALGORITHM_ID(2) - KEY_METADATA_LENGTH(2)
        int kmLenPos = serialized.length - 4 - 4 - 2 - 2;

        // (a) Negative length (0x8000 = -32768 as signed short).
        byte[] neg = serialized.clone();
        neg[kmLenPos] = (byte) 0x80;
        neg[kmLenPos + 1] = (byte) 0x00;
        IOException e1 = expectThrows(IOException.class, () -> EncryptionFooter.extractKeyEpoch(neg));
        assertTrue("negative length must be reported as malformed: " + e1.getMessage(),
            e1.getMessage() != null && e1.getMessage().toLowerCase(java.util.Locale.ROOT).contains("keymetadata"));

        // (b) Oversized length that runs past the buffer start.
        byte[] big = serialized.clone();
        big[kmLenPos] = (byte) 0x7F;
        big[kmLenPos + 1] = (byte) 0xFF;
        IOException e2 = expectThrows(IOException.class, () -> EncryptionFooter.extractKeyEpoch(big));
        assertNotNull(e2.getMessage());
    }

    /**
     * The core dual-key property: two segments stamped with different epochs each authenticate under
     * their OWN epoch key when read through the epoch-aware resolver — even though both live in the
     * same directory at the same time.
     */
    public void testTwoEpochsReadableSimultaneouslyViaResolver() throws IOException {
        Path dir = createTempDir();
        IntFunction<byte[]> resolver = EncryptionFooterKeyEpochTests::masterKeyForEpoch;

        Path segEpoch1 = writeFooterOnlyFile(dir.resolve("seg_epoch1.osef"), 1);
        Path segEpoch2 = writeFooterOnlyFile(dir.resolve("seg_epoch2.osef"), 2);

        EncryptionFooter f1 = readFooter(segEpoch1, resolver);
        EncryptionFooter f2 = readFooter(segEpoch2, resolver);

        assertEquals("epoch-1 segment must resolve under epoch 1", 1, f1.getKeyEpoch());
        assertEquals("epoch-2 segment must resolve under epoch 2", 2, f2.getKeyEpoch());
    }

    /**
     * A resolver that hands back the WRONG epoch's key (e.g. an old node that never learned the new
     * epoch) must fail footer authentication rather than silently mis-decrypt.
     */
    public void testWrongEpochKeyFailsAuthentication() throws IOException {
        Path dir = createTempDir();
        Path seg = writeFooterOnlyFile(dir.resolve("seg_epoch2.osef"), 2);

        // Resolver always returns epoch-1's key regardless of the requested epoch.
        IntFunction<byte[]> wrongResolver = epoch -> masterKeyForEpoch(1);

        IOException ex = expectThrows(IOException.class, () -> readFooter(seg, wrongResolver));
        assertTrue(
            "expected authentication failure, got: " + ex.getMessage(),
            ex.getMessage() != null && ex.getMessage().contains("authentication")
        );
    }

    /** A resolver with no key for the stamped epoch must fail loudly, not NPE. */
    public void testMissingEpochKeyFailsCleanly() throws IOException {
        Path dir = createTempDir();
        Path seg = writeFooterOnlyFile(dir.resolve("seg_epoch5.osef"), 5);

        IntFunction<byte[]> emptyResolver = epoch -> null;

        IOException ex = expectThrows(IOException.class, () -> readFooter(seg, emptyResolver));
        assertTrue("expected epoch-5 in message, got: " + ex.getMessage(), ex.getMessage().contains("epoch 5"));
    }

    // --- helpers ---

    /** Writes a file whose entire content is a valid footer stamped with the given epoch. */
    private Path writeFooterOnlyFile(Path path, int epoch) throws IOException {
        EncryptionFooter footer = EncryptionFooter.generateNew(FRAME_SIZE, ALG, epoch);
        byte[] fileKey = HkdfKeyDerivation.deriveFileKey(masterKeyForEpoch(epoch), footer.getMessageId());
        byte[] serialized = footer.serialize(path, fileKey);
        Files.write(path, serialized, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return path;
    }

    private EncryptionFooter readFooter(Path path, IntFunction<byte[]> resolver) throws IOException {
        String normalized = EncryptionMetadataCache.normalizePath(path);
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            return EncryptionFooter.readViaFileChannel(normalized, ch, resolver, cache);
        }
    }
}
