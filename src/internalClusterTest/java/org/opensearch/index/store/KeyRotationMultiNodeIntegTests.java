/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.opensearch.index.query.QueryBuilders.matchAllQuery;

import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.routing.allocation.command.MoveAllocationCommand;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.index.Index;
import org.opensearch.index.IndexService;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.indices.IndicesService;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * MULTI-NODE key-rotation integration tests.
 *
 * <p>Unlike {@link KeyRotationUnderTrafficIntegTests} (single node), these run a real multi-node cluster
 * with replicas and shard relocation, using {@link DistinctKeyPerEpochProviderPlugin} so each epoch's key
 * is genuinely distinct (a wrong-epoch key fails to decrypt — the single-node dummy provider could not
 * catch that).
 *
 * <p>These tests probe the cross-node key-agreement question: {@code keyfile.N} is written to a node-local
 * directory, and (with the distinct provider) each node's {@code generateDataPair()} mints DIFFERENT bytes.
 * If a rotation is driven per-node without agreeing on the epoch key, a replica or relocated shard on
 * another node cannot decrypt data written under the new epoch. This is the Step-5 cross-node gap; these
 * tests are the live-cluster reproduction of it.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class KeyRotationMultiNodeIntegTests extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        // NOTE: DistinctKeyPerEpochProviderPlugin (type "distinct") instead of the fixed-key dummy.
        return Arrays.asList(CryptoDirectoryPlugin.class, DistinctKeyPerEpochProviderPlugin.class, MockCryptoPlugin.class);
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings
            .builder()
            .put(super.nodeSettings(nodeOrdinal))
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .build();
    }

    @Override
    protected boolean addMockInternalEngine() {
        return false;
    }

    private Settings cryptoIndexSettings(int shards, int replicas) {
        return Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "distinct")
            .put("index.store.crypto.kms.key_arn", "distinctArn")
            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, shards)
            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, replicas)
            .put("index.unassigned.node_left.delayed_timeout", "0")
            .build();
    }

    private void indexDocs(String index, int from, int count, String tag) {
        for (int i = from; i < from + count; i++) {
            index(index, "_doc", String.valueOf(i), "field", tag + "-" + i, "number", i);
        }
    }

    private long searchAll(String index) {
        return client().prepareSearch(index).setSize(0).setQuery(matchAllQuery()).get().getHits().getTotalHits().value();
    }

    /** Rotate every primary shard's resolver on whatever node hosts it. Returns the max epoch reached. */
    private int rotateAllPrimaries(String index) throws Exception {
        String uuid = client().admin().cluster().prepareState().get().getState().metadata().index(index).getIndexUUID();
        Index resolved = new Index(index, uuid);
        int maxEpoch = 0;
        int rotated = 0;
        for (String node : internalCluster().getNodeNames()) {
            IndicesService indicesService = internalCluster().getInstance(IndicesService.class, node);
            IndexService indexService = indicesService.indexService(resolved);
            if (indexService == null) {
                continue;
            }
            for (IndexShard shard : indexService) {
                KeyResolver resolver = ShardKeyResolverRegistry.getResolver(uuid, shard.shardId().id(), index);
                if (resolver == null) {
                    continue;
                }
                int epoch = ((DefaultKeyResolver) resolver).rotate();
                maxEpoch = Math.max(maxEpoch, epoch);
                rotated++;
            }
        }
        assertThat("at least one shard resolver must have rotated", rotated, greaterThan(0));
        return maxEpoch;
    }

    /**
     * Rotate with a replica present: after rotation, new writes go to the primary under the new epoch and
     * are replicated to the replica on ANOTHER node. The replica must be able to serve/recover that data,
     * which requires it to hold the new epoch's key. Probes cross-node key agreement.
     */
    public void testRotateWithReplicaPeerRecovery() throws Exception {
        internalCluster().startNodes(2);
        final String index = "rotate-replica";
        createIndex(index, cryptoIndexSettings(1, 1));
        ensureGreen(index);

        final int base = 300;
        indexDocs(index, 0, base, "epoch0");
        refresh(index);
        flush(index);
        assertThat(searchAll(index), equalTo((long) base));

        rotateAllPrimaries(index);

        final int more = 300;
        indexDocs(index, base, more, "epoch1");
        refresh(index);
        flush(index);

        final long total = base + more;
        // Search hits primary AND replica copies round-robin; if the replica can't decrypt epoch-1 data,
        // this surfaces as missing hits or a shard failure.
        assertThat("primary+replica must both serve all docs across epochs", searchAll(index), equalTo(total));

        // Force a fresh peer recovery of the replica by restarting one node, then require full data.
        internalCluster().fullRestart();
        ensureGreen(TimeValue.timeValueSeconds(60), index);
        refresh(index);
        assertThat("all docs survive restart + peer recovery across epochs", searchAll(index), equalTo(total));
    }

    /**
     * Rotate, then RELOCATE the primary to another node. The target node must decrypt segments written
     * under the new epoch — i.e. it must have the same epoch key the source used. Probes cross-node key
     * agreement directly via segment-copy relocation.
     */
    public void testRotateThenRelocatePrimary() throws Exception {
        internalCluster().startNodes(3);
        final String index = "rotate-relocate";
        createIndex(index, cryptoIndexSettings(1, 0));
        ensureGreen(index);

        final int base = 300;
        indexDocs(index, 0, base, "epoch0");
        refresh(index);
        flush(index);

        rotateAllPrimaries(index);
        indexDocs(index, base, 200, "epoch1");
        refresh(index);
        flush(index);
        final long total = base + 200;
        assertThat(searchAll(index), equalTo(total));

        // Relocate shard 0 to a different node.
        String uuid = client().admin().cluster().prepareState().get().getState().metadata().index(index).getIndexUUID();
        Index resolved = new Index(index, uuid);
        String hostNode = null;
        for (String node : internalCluster().getNodeNames()) {
            IndexService is = internalCluster().getInstance(IndicesService.class, node).indexService(resolved);
            if (is != null && is.hasShard(0)) {
                hostNode = node;
                break;
            }
        }
        assertNotNull("must find the node hosting shard 0", hostNode);
        String target = null;
        for (String node : internalCluster().getNodeNames()) {
            if (!node.equals(hostNode)) {
                target = node;
                break;
            }
        }

        client()
            .admin()
            .cluster()
            .prepareReroute()
            .add(new MoveAllocationCommand(index, 0, hostNode, target))
            .execute()
            .actionGet(TimeValue.timeValueSeconds(60));

        ensureGreen(TimeValue.timeValueSeconds(60), index);

        final long expected = total;
        assertBusy(() -> {
            assertThat("relocated shard on the target node must decrypt all epochs", searchAll(index), equalTo(expected));
        }, 30, TimeUnit.SECONDS);
    }
}
