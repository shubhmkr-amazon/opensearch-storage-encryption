/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import java.io.IOException;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.index.shard.ShardId;

/**
 * Per-shard result of a key rotation: the {@link ShardId} whose key was rotated and the new
 * key-rotation epoch that primary shard now writes under.
 */
public class RotateKeyShardResponse implements Writeable {

    private final ShardId shardId;
    private final int newEpoch;

    public RotateKeyShardResponse(ShardId shardId, int newEpoch) {
        this.shardId = shardId;
        this.newEpoch = newEpoch;
    }

    public RotateKeyShardResponse(StreamInput in) throws IOException {
        this.shardId = new ShardId(in);
        this.newEpoch = in.readVInt();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        shardId.writeTo(out);
        out.writeVInt(newEpoch);
    }

    public ShardId getShardId() {
        return shardId;
    }

    public int getNewEpoch() {
        return newEpoch;
    }
}
