/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.security.Key;

/**
 * An abstraction for resolving the symmetric encryption key used for encrypting and decrypting
 * index files in an OpenSearch Directory implementation.
 *
 * Implementations of this interface are responsible for securely retrieving or generating
 * the key used in symmetric encryption (e.g., AES-GCM).
 *
 * Note: IVs are derived deterministically using HKDF based on file-specific metadata,
 * not stored or retrieved through this interface.
 *
 * @opensearch.internal
 */
public interface KeyResolver {

    /**
     * Returns the symmetric encryption key for the current (write) key-rotation epoch.
     *
     * @return the decrypted symmetric {@link Key}, typically AES
     */
    Key getDataKey();

    /**
     * Returns the symmetric encryption key for a specific key-rotation epoch.
     *
     * <p>Reads resolve the epoch from a segment's footer and ask for exactly that epoch's key, so
     * that segments written under an older epoch stay decryptable after rotation (online dual-key
     * reads). Epoch 0 is the pre-rotation key.
     *
     * @param epoch the key-rotation epoch (>= 0)
     * @return the decrypted symmetric {@link Key} for that epoch
     */
    Key getDataKey(int epoch);

    /**
     * Returns the current (highest) key-rotation epoch. New writes are encrypted under this epoch.
     *
     * @return the current epoch (>= 0)
     */
    int getCurrentEpoch();
}
