/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;

import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.plugins.CryptoKeyProviderPlugin;
import org.opensearch.plugins.Plugin;

/**
 * Test key provider that mints a DISTINCT random data key on every {@link MasterKeyProvider#generateDataPair()}
 * call, while {@code decryptKey} is the identity function.
 *
 * <p>This is essential for key-rotation tests. The default {@link MockCryptoKeyProviderPlugin} returns a
 * FIXED pair, so {@code keyfile.0} and {@code keyfile.1} hold identical bytes and {@code getDataKey(0)} equals
 * {@code getDataKey(1)} — meaning a wrong-epoch decryption would still succeed and a rotation test could pass
 * without actually exercising epoch isolation. Here each epoch's keyfile holds different bytes, so decrypting a
 * segment with the wrong epoch's key fails, exactly as it would under a real KMS.
 *
 * <p>Model of reality: {@code keyfile.N} stores the (here, plaintext-equivalent) wrapped data key for epoch N;
 * {@code decryptKey} is deterministic given the keyfile bytes — so any node that has the SAME {@code keyfile.N}
 * derives the SAME master key (mirrors a shared KMS). Cross-node correctness therefore hinges on whether
 * {@code keyfile.N} is propagated to every shard copy — which is exactly what the multi-node rotation test probes.
 */
public class DistinctKeyPerEpochProviderPlugin extends Plugin implements CryptoKeyProviderPlugin {

    @Override
    public MasterKeyProvider createKeyProvider(CryptoMetadata cryptoMetadata) {
        MasterKeyProvider keyProvider = mock(MasterKeyProvider.class);
        SecureRandom rnd = new SecureRandom();
        when(keyProvider.generateDataPair()).thenAnswer(inv -> {
            byte[] rawKey = new byte[32];
            byte[] encryptedKey = new byte[32];
            rnd.nextBytes(rawKey);
            rnd.nextBytes(encryptedKey);
            // decryptKey is identity, so the stored (encrypted) bytes ARE the master key used on read.
            // Make them equal to rawKey so encrypt-side and read-side agree deterministically per epoch.
            System.arraycopy(rawKey, 0, encryptedKey, 0, 32);
            return new DataKeyPair(rawKey, encryptedKey);
        });
        when(keyProvider.decryptKey(any(byte[].class))).then(returnsFirstArg());
        return keyProvider;
    }

    @Override
    public String type() {
        return "distinct";
    }
}
