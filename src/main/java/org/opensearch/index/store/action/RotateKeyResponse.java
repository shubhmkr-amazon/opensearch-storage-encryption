/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import java.io.IOException;
import java.util.List;

import org.opensearch.action.support.broadcast.BroadcastResponse;
import org.opensearch.core.action.support.DefaultShardOperationFailedException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Response for {@link RotateKeyAction}. Aggregates the standard broadcast counters (total /
 * successful / failed shards, plus shard failures) and carries the per-shard new epochs produced by
 * the rotation on each node.
 */
public class RotateKeyResponse extends BroadcastResponse {

    private final List<RotateKeyShardResponse> shardResponses;

    public RotateKeyResponse(
        int totalShards,
        int successfulShards,
        int failedShards,
        List<RotateKeyShardResponse> shardResponses,
        List<DefaultShardOperationFailedException> shardFailures
    ) {
        super(totalShards, successfulShards, failedShards, shardFailures);
        this.shardResponses = shardResponses;
    }

    public RotateKeyResponse(StreamInput in) throws IOException {
        super(in);
        this.shardResponses = in.readList(RotateKeyShardResponse::new);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeList(shardResponses);
    }

    /**
     * @return the per-shard rotation results (shard id + new epoch) for every successfully rotated
     *         primary shard.
     */
    public List<RotateKeyShardResponse> getShardResponses() {
        return shardResponses;
    }

    @Override
    protected void addCustomXContentFields(XContentBuilder builder, Params params) throws IOException {
        builder.startArray("rotated_shards");
        for (RotateKeyShardResponse shardResponse : shardResponses) {
            builder.startObject();
            builder.field("index", shardResponse.getShardId().getIndexName());
            builder.field("shard", shardResponse.getShardId().id());
            builder.field("new_epoch", shardResponse.getNewEpoch());
            builder.endObject();
        }
        builder.endArray();
    }
}
