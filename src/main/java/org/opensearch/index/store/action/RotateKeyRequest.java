/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import java.io.IOException;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.broadcast.BroadcastRequest;
import org.opensearch.core.common.io.stream.StreamInput;

/**
 * Request to rotate the encryption key epoch for the primary shards of the given indices.
 *
 * <p>Extends {@link BroadcastRequest} so the transport layer fans the operation out to every node
 * holding a targeted primary shard. {@link #validate()} rejects a null/empty index list to prevent
 * an accidental cluster-wide rotation.
 */
public class RotateKeyRequest extends BroadcastRequest<RotateKeyRequest> {

    public RotateKeyRequest(String... indices) {
        super(indices);
    }

    public RotateKeyRequest(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = super.validate();
        if (indices == null || indices.length == 0) {
            if (validationException == null) {
                validationException = new ActionRequestValidationException();
            }
            validationException
                .addValidationError("at least one index must be specified for key rotation; refusing to rotate all indices");
        }
        return validationException;
    }
}
