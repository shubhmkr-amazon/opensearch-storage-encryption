/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import static org.junit.Assert.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the AAD-capable AES-GCM overloads (the v3 translog primitive):
 * {@link AesGcmCipherFactory#encryptWithTag(java.security.Key, byte[], byte[], int, byte[])} and
 * {@link AesGcmCipherFactory#decryptWithTag(java.security.Key, byte[], byte[], byte[])}.
 *
 * <p>The security property under test: the AAD is authenticated (not encrypted), so a round-trip with the
 * SAME aad succeeds, while ANY mismatch of the aad on decrypt — or any tamper of the ciphertext — fails
 * closed with a {@link AesGcmCipherFactory.JavaCryptoException}. This is what lets v3 bind frame metadata
 * (length, logical offset, frame sequence, epoch, file context) so it cannot be altered undetected.
 */
public class AesGcmAadTests extends OpenSearchTestCase {

    private static final byte[] KEY = new byte[32];
    private static final byte[] IV = new byte[16];
    private static final byte[] DATA = "v3 frame plaintext payload — opaque op bytes".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "ptLen=44|logicalOffset=4096|frameSeq=7|epoch=0".getBytes(StandardCharsets.UTF_8);

    static {
        Arrays.fill(KEY, (byte) 0x11);
        Arrays.fill(IV, (byte) 0x22);
    }

    /** Round-trip with matching AAD must return the original plaintext. */
    public void testAadRoundTrip() {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        byte[] ct = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, AAD);
        byte[] pt = AesGcmCipherFactory.decryptWithTag(key, IV, ct, AAD);
        assertArrayEquals("matching AAD must round-trip", DATA, pt);
    }

    /** Decrypting with a DIFFERENT aad than was bound must fail closed (tamper of authenticated metadata). */
    public void testWrongAadFailsClosed() {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        byte[] ct = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, AAD);

        byte[] tamperedAad = AAD.clone();
        tamperedAad[0] ^= 0x01; // flip one bit of the authenticated metadata (e.g. pretend ptLen differs)
        expectThrows(
            AesGcmCipherFactory.JavaCryptoException.class,
            () -> AesGcmCipherFactory.decryptWithTag(key, IV, ct, tamperedAad)
        );
    }

    /** Decrypting AAD-bound ciphertext with NO aad (or empty) must also fail closed. */
    public void testMissingAadFailsClosed() {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        byte[] ct = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, AAD);
        expectThrows(
            AesGcmCipherFactory.JavaCryptoException.class,
            () -> AesGcmCipherFactory.decryptWithTag(key, IV, ct, new byte[0])
        );
        expectThrows(
            AesGcmCipherFactory.JavaCryptoException.class,
            () -> AesGcmCipherFactory.decryptWithTag(key, IV, ct, null)
        );
    }

    /** Tampering the ciphertext body must fail closed even when the AAD is correct. */
    public void testCiphertextTamperFailsClosed() {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        byte[] ct = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, AAD);
        ct[0] ^= 0x01;
        expectThrows(
            AesGcmCipherFactory.JavaCryptoException.class,
            () -> AesGcmCipherFactory.decryptWithTag(key, IV, ct, AAD)
        );
    }

    /**
     * AAD-bound ciphertext must NOT be decryptable by the non-AAD overload (which binds no AAD), and a
     * no-AAD/empty-AAD encryption must round-trip through both the new overload (empty aad) and the
     * original non-AAD method — proving the new path is a clean superset, symmetric with the old behavior.
     */
    public void testAadAndNonAadInterop() {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");

        // AAD-bound ciphertext is not authenticatable without the AAD (old overload passes no AAD).
        byte[] ctWithAad = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, AAD);
        expectThrows(
            AesGcmCipherFactory.JavaCryptoException.class,
            () -> AesGcmCipherFactory.decryptWithTag(key, IV, ctWithAad)
        );

        // Empty-AAD encryption equals the no-AAD path: decryptable by BOTH the old and new (empty) overload.
        byte[] ctNoAad = AesGcmCipherFactory.encryptWithTag(key, IV, DATA, DATA.length, new byte[0]);
        assertArrayEquals("empty-AAD must match the legacy non-AAD decrypt", DATA, AesGcmCipherFactory.decryptWithTag(key, IV, ctNoAad));
        assertArrayEquals("empty-AAD must round-trip the new overload", DATA, AesGcmCipherFactory.decryptWithTag(key, IV, ctNoAad, new byte[0]));
    }
}
