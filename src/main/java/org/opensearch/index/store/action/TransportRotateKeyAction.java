/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.broadcast.node.TransportBroadcastByNodeAction;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.block.ClusterBlockLevel;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.routing.IndexShardRoutingTable;
import org.opensearch.cluster.routing.PlainShardsIterator;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.cluster.routing.ShardsIterator;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.support.DefaultShardOperationFailedException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

/**
 * Broadcast-by-node transport action that rotates the encryption key epoch for the primary shards of
 * the requested indices.
 *
 * <p>Rotation mutates node-local resolver state ({@link ShardKeyResolverRegistry}), so the operation
 * MUST run on each node that hosts a targeted primary shard — hence {@link TransportBroadcastByNodeAction}
 * rather than a coordinator-only {@code HandledTransportAction}. For each primary shard the node owns,
 * {@link #shardOperation} resolves the shard's {@link DefaultKeyResolver} and calls
 * {@link DefaultKeyResolver#rotate()}, returning the new epoch.
 */
public class TransportRotateKeyAction extends TransportBroadcastByNodeAction<RotateKeyRequest, RotateKeyResponse, RotateKeyShardResponse> {

    @Inject
    public TransportRotateKeyAction(
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters,
        IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        super(
            RotateKeyAction.NAME,
            clusterService,
            transportService,
            actionFilters,
            indexNameExpressionResolver,
            RotateKeyRequest::new,
            ThreadPool.Names.MANAGEMENT
        );
    }

    @Override
    protected RotateKeyShardResponse readShardResult(StreamInput in) throws IOException {
        return new RotateKeyShardResponse(in);
    }

    @Override
    protected RotateKeyResponse newResponse(
        RotateKeyRequest request,
        int totalShards,
        int successfulShards,
        int failedShards,
        List<RotateKeyShardResponse> results,
        List<DefaultShardOperationFailedException> shardFailures,
        ClusterState clusterState
    ) {
        return new RotateKeyResponse(totalShards, successfulShards, failedShards, results, shardFailures);
    }

    @Override
    protected RotateKeyRequest readRequestFrom(StreamInput in) throws IOException {
        return new RotateKeyRequest(in);
    }

    @Override
    protected RotateKeyShardResponse shardOperation(RotateKeyRequest request, ShardRouting shardRouting) throws IOException {
        String indexUuid = shardRouting.index().getUUID();
        String indexName = shardRouting.getIndexName();
        ShardId shardId = shardRouting.shardId();

        KeyResolver resolver = ShardKeyResolverRegistry.getResolver(indexUuid, shardId.id(), indexName);
        if (resolver == null) {
            throw new IllegalStateException(
                "No key resolver found for shard " + shardId + " (indexUuid=" + indexUuid + "); cannot rotate key"
            );
        }
        if (!(resolver instanceof DefaultKeyResolver)) {
            throw new IllegalStateException(
                "Key resolver for shard " + shardId + " is not a DefaultKeyResolver; cannot rotate key"
            );
        }

        int newEpoch = ((DefaultKeyResolver) resolver).rotate();
        return new RotateKeyShardResponse(shardId, newEpoch);
    }

    /**
     * Selects the primary shards of the resolved concrete indices. The broadcast framework groups the
     * returned shards by node so each primary is rotated exactly once, on the node that hosts it.
     */
    @Override
    protected ShardsIterator shards(ClusterState clusterState, RotateKeyRequest request, String[] concreteIndices) {
        List<ShardRouting> shards = new ArrayList<>();
        for (String index : concreteIndices) {
            IndexRoutingTable indexRoutingTable = clusterState.routingTable().index(index);
            if (indexRoutingTable == null) {
                continue;
            }
            for (IndexShardRoutingTable shardRoutingTable : indexRoutingTable.getShards().values()) {
                ShardRouting primary = shardRoutingTable.primaryShard();
                if (primary != null) {
                    shards.add(primary);
                }
            }
        }
        return new PlainShardsIterator(shards);
    }

    @Override
    protected ClusterBlockException checkGlobalBlock(ClusterState state, RotateKeyRequest request) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }

    @Override
    protected ClusterBlockException checkRequestBlock(ClusterState state, RotateKeyRequest request, String[] concreteIndices) {
        return state.blocks().indicesBlockedException(ClusterBlockLevel.METADATA_WRITE, concreteIndices);
    }
}
