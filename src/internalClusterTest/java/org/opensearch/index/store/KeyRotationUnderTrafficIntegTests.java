/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.opensearch.index.query.QueryBuilders.matchAllQuery;
import static org.opensearch.index.query.QueryBuilders.termQuery;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.action.admin.indices.forcemerge.ForceMergeResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
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
 * Live-traffic key-rotation integration test.
 *
 * <p>Exercises BOTH encryption paths on a real node while traffic flows:
 * <ul>
 *   <li>Lucene segments — footer-stamped epoch, per-segment key selection on read.</li>
 *   <li>Translog — per-generation epoch stamped in the super-header.</li>
 * </ul>
 *
 * <p>Flow: index under epoch 0 -> rotate every shard's resolver mid-life -> index MORE (epoch 1) ->
 * flush (rolls a new translog generation under epoch 1) -> search across both epochs -> force-merge
 * (rewrites mixed-epoch segments) -> full cluster restart (translog replay across epochs). Every stage
 * asserts full doc counts and zero shard failures, proving old-epoch data stays readable after rotation
 * (online dual-key) while new writes use the new epoch.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class KeyRotationUnderTrafficIntegTests extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays.asList(CryptoDirectoryPlugin.class, MockCryptoKeyProviderPlugin.class, MockCryptoPlugin.class);
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

    private Settings cryptoIndexSettings(int shards) {
        return Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "dummy")
            .put("index.store.crypto.kms.key_arn", "dummyArn")
            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, shards)
            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
            // "request" durability so ops hit the encrypted translog; large flush threshold so we control
            // generation rolls explicitly via flush().
            .put("index.translog.durability", "request")
            .put("index.translog.flush_threshold_size", "1gb")
            .build();
    }

    /** Rotates the key for every primary shard of the index. Returns the new epoch (asserts all agree). */
    private int rotateAllShards(String index) throws Exception {
        String uuid = client().admin().cluster().prepareState().get().getState().metadata().index(index).getIndexUUID();
        Index resolved = new Index(index, uuid);

        AtomicReference<Integer> newEpoch = new AtomicReference<>(null);
        int rotatedShards = 0;

        for (String node : internalCluster().getNodeNames()) {
            IndicesService indicesService = internalCluster().getInstance(IndicesService.class, node);
            IndexService indexService = indicesService.indexService(resolved);
            if (indexService == null) {
                continue;
            }
            for (IndexShard shard : indexService) {
                int shardId = shard.shardId().id();
                KeyResolver resolver = ShardKeyResolverRegistry.getResolver(uuid, shardId, index);
                assertNotNull("resolver must exist for live shard " + shardId, resolver);
                assertTrue("resolver should be a DefaultKeyResolver", resolver instanceof DefaultKeyResolver);

                int epoch = ((DefaultKeyResolver) resolver).rotate();
                logger.info("rotated index={} shard={} -> epoch {}", index, shardId, epoch);
                newEpoch.compareAndSet(null, epoch);
                assertThat("all shards should rotate to the same epoch", epoch, equalTo(newEpoch.get()));
                assertThat("epoch must advance past 0", ((DefaultKeyResolver) resolver).getCurrentEpoch(), equalTo(epoch));
                rotatedShards++;
            }
        }
        assertThat("at least one shard must have been rotated", rotatedShards, greaterThan(0));
        return newEpoch.get();
    }

    private void indexDocs(String index, int from, int count, String tag) {
        for (int i = from; i < from + count; i++) {
            client()
                .prepareIndex(index)
                .setId(Integer.toString(i))
                .setSource("n", i, "tag", tag, "payload", tag + "-doc-" + i + "-" + "x".repeat(200))
                .get();
        }
    }

    private long searchAll(String index) {
        return client().prepareSearch(index).setSize(0).setQuery(matchAllQuery()).get().getHits().getTotalHits().value();
    }

    /**
     * The headline live-traffic test: rotate mid-traffic, then keep ingesting and searching across both
     * epochs, force-merge the mixed-epoch segments, and restart to replay a multi-epoch translog.
     */
    public void testRotateUnderTrafficBothPaths() throws Exception {
        internalCluster().startNode();
        final String index = "rotate-traffic";
        createIndex(index, cryptoIndexSettings(2));
        ensureGreen(index);

        // --- Phase 0: write under epoch 0 (segments + translog) ---
        final int epoch0Docs = 400;
        indexDocs(index, 0, epoch0Docs, "epoch0");
        refresh(index);
        flush(index); // commit epoch-0 segments and roll the epoch-0 translog generation
        assertThat("epoch-0 docs searchable", searchAll(index), equalTo((long) epoch0Docs));

        // --- Rotate every shard mid-life ---
        int newEpoch = rotateAllShards(index);
        assertThat("expected first rotation to reach epoch 1", newEpoch, equalTo(1));

        // Old epoch-0 segments must STILL be readable after rotation (online dual-key read).
        assertThat("epoch-0 data readable after rotation", searchAll(index), equalTo((long) epoch0Docs));
        SearchResponse oldHit = client().prepareSearch(index).setQuery(termQuery("n", 42)).get();
        assertThat("specific epoch-0 doc still decrypts", oldHit.getHits().getTotalHits().value(), equalTo(1L));

        // --- Phase 1: write MORE under epoch 1 ---
        final int epoch1Docs = 400;
        indexDocs(index, epoch0Docs, epoch1Docs, "epoch1");
        refresh(index);
        flush(index); // new segments + a NEW translog generation, both stamped epoch 1

        final long totalDocs = epoch0Docs + epoch1Docs;
        assertThat("both epochs searchable together", searchAll(index), equalTo(totalDocs));

        // A doc from each epoch resolves under its own key.
        assertThat(client().prepareSearch(index).setQuery(termQuery("tag", "epoch0")).get().getHits().getTotalHits().value(),
            equalTo((long) epoch0Docs));
        assertThat(client().prepareSearch(index).setQuery(termQuery("tag", "epoch1")).get().getHits().getTotalHits().value(),
            equalTo((long) epoch1Docs));

        // --- Force-merge: rewrites epoch-0 + epoch-1 segments into new segments (current epoch). ---
        ForceMergeResponse merge = client().admin().indices().prepareForceMerge(index).setMaxNumSegments(1).setFlush(true).get();
        assertThat("force-merge across epochs must not fail any shard", merge.getFailedShards(), equalTo(0));
        assertThat("all docs survive cross-epoch merge", searchAll(index), equalTo(totalDocs));

        // --- Full restart: recover a translog that spans epoch-0 and epoch-1 generations. ---
        internalCluster().fullRestart();
        ensureGreen(index);
        refresh(index);
        assertThat("all docs survive restart + multi-epoch translog replay", searchAll(index), equalTo(totalDocs));

        // Spot-check integrity of one doc from each epoch after recovery.
        var g0 = client().prepareGet(index, "10").get();
        assertTrue("epoch-0 doc exists after recovery", g0.isExists());
        assertTrue("epoch-0 source intact", g0.getSourceAsString().contains("epoch0-doc-10-"));
        var g1 = client().prepareGet(index, Integer.toString(epoch0Docs + 10)).get();
        assertTrue("epoch-1 doc exists after recovery", g1.isExists());
        assertTrue("epoch-1 source intact", g1.getSourceAsString().contains("epoch1-doc-" + (epoch0Docs + 10) + "-"));
    }

    /**
     * Multiple sequential rotations: each new batch lands under a distinct epoch; all remain readable and
     * survive restart. Proves N simultaneously-resident epochs, not just two.
     */
    public void testMultipleSequentialRotations() throws Exception {
        internalCluster().startNode();
        final String index = "rotate-multi";
        createIndex(index, cryptoIndexSettings(1));
        ensureGreen(index);

        final int perEpoch = 150;
        int total = 0;
        List<Integer> epochs = new ArrayList<>();

        for (int round = 0; round < 3; round++) {
            indexDocs(index, total, perEpoch, "round" + round);
            total += perEpoch;
            refresh(index);
            flush(index);
            if (round < 2) {
                int e = rotateAllShards(index);
                epochs.add(e);
            }
        }
        // Rotations should have produced strictly increasing epochs 1, 2.
        assertThat(epochs, equalTo(Arrays.asList(1, 2)));

        assertThat("all docs across 3 epochs searchable", searchAll(index), equalTo((long) total));

        internalCluster().fullRestart();
        ensureGreen(index);
        refresh(index);
        assertThat("all docs across epochs survive restart", searchAll(index), equalTo((long) total));
    }

    /**
     * Sanity: writes under an epoch remain writable/searchable while a background searcher hammers the
     * index during the rotation, catching any transient read failure introduced by the epoch flip.
     */
    public void testConcurrentSearchDuringRotation() throws Exception {
        internalCluster().startNode();
        final String index = "rotate-concurrent";
        createIndex(index, cryptoIndexSettings(1));
        ensureGreen(index);

        final int baseDocs = 300;
        indexDocs(index, 0, baseDocs, "base");
        refresh(index);
        flush(index);

        final AtomicBoolean stop = new AtomicBoolean(false);
        final AtomicReference<Throwable> searchError = new AtomicReference<>(null);
        Thread searcher = new Thread(() -> {
            while (!stop.get()) {
                try {
                    long hits = searchAll(index);
                    if (hits < baseDocs) {
                        searchError.compareAndSet(null, new AssertionError("search saw fewer than base docs during rotation: " + hits));
                    }
                } catch (Throwable t) {
                    searchError.compareAndSet(null, t);
                    return;
                }
            }
        }, "rotation-searcher");
        searcher.start();

        try {
            // Rotate a few times while the searcher runs.
            for (int i = 0; i < 3; i++) {
                rotateAllShards(index);
                indexDocs(index, baseDocs + i * 50, 50, "post" + i);
                refresh(index);
            }
        } finally {
            stop.set(true);
            searcher.join(30_000);
        }

        assertNull("concurrent search must not fail during rotation", searchError.get());
        refresh(index);
        assertThat("all docs present after concurrent rotation", searchAll(index), equalTo((long) (baseDocs + 150)));
    }
}
