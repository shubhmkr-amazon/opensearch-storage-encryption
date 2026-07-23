/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.index.query.QueryBuilders.matchAllQuery;
import static org.opensearch.index.query.QueryBuilders.termQuery;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;

import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotResponse;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;
import org.opensearch.index.IndexService;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.index.store.action.RotateKeyAction;
import org.opensearch.index.store.action.RotateKeyRequest;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.indices.IndicesService;
import org.opensearch.plugins.Plugin;
import org.opensearch.snapshots.SnapshotState;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Verifies that key-rotation state survives a repository round-trip (snapshot -> restore to a NEW
 * index). This is the same file-transfer question as remote-store / segment-replication: the restored
 * index has a different UUID, so it cannot regenerate the source's keys — every epoch's keyfile.N and
 * the epoch-stamped segments must have been captured by the snapshot and reconstituted on restore.
 *
 * <p>Uses {@link DistinctKeyPerEpochProviderPlugin} so a lost/regenerated keyfile.N would produce a
 * DIFFERENT key and fail decryption — the test would catch it rather than silently pass.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class KeyRotationSnapshotRestoreIntegTests extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
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

    private Settings cryptoIndexSettings(int shards) {
        return Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "distinct")
            .put("index.store.crypto.kms.key_arn", "distinctArn")
            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, shards)
            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
            .build();
    }

    private long searchAll(String index) {
        return client().prepareSearch(index).setSize(0).setQuery(matchAllQuery()).get().getHits().getTotalHits().value();
    }

    private void rotateViaAction(String index) {
        var resp = client().execute(RotateKeyAction.INSTANCE, new RotateKeyRequest(index)).actionGet();
        assertThat("rotation must not fail any shard", resp.getShardFailures().length, equalTo(0));
    }

    /**
     * Rotate mid-life so the source index holds BOTH epoch-0 and epoch-1 segments, then snapshot and
     * restore to a new index. The restored index must decrypt data from both epochs.
     */
    public void testRotatedIndexSurvivesSnapshotRestore() throws Exception {
        internalCluster().startNodes(2);

        Path repoPath = randomRepoPath();
        client()
            .admin()
            .cluster()
            .preparePutRepository("rotate-repo")
            .setType("fs")
            .setSettings(Settings.builder().put("location", repoPath).put("compress", false))
            .get();

        final String src = "src-rotated";
        createIndex(src, cryptoIndexSettings(2));
        ensureGreen(src);

        // Epoch 0 data.
        final int epoch0 = 200;
        for (int i = 0; i < epoch0; i++) {
            index(src, "_doc", String.valueOf(i), "field", "epoch0-" + i, "number", i);
        }
        refresh(src);
        flush(src);

        // Rotate, then epoch 1 data.
        rotateViaAction(src);
        final int epoch1 = 200;
        for (int i = epoch0; i < epoch0 + epoch1; i++) {
            index(src, "_doc", String.valueOf(i), "field", "epoch1-" + i, "number", i);
        }
        refresh(src);
        flush(src);

        final long total = epoch0 + epoch1;
        assertThat("source has both epochs", searchAll(src), equalTo(total));

        // Snapshot.
        CreateSnapshotResponse snap = client()
            .admin()
            .cluster()
            .prepareCreateSnapshot("rotate-repo", "snap-1")
            .setWaitForCompletion(true)
            .setIndices(src)
            .get();
        assertThat(snap.getSnapshotInfo().state(), equalTo(SnapshotState.SUCCESS));

        // Restore to a NEW index (new UUID -> cannot reuse the source's in-memory/on-node keys).
        RestoreSnapshotResponse restore = client()
            .admin()
            .cluster()
            .prepareRestoreSnapshot("rotate-repo", "snap-1")
            .setWaitForCompletion(true)
            .setRenamePattern("src-rotated")
            .setRenameReplacement("restored-rotated")
            .get();
        assertThat("all shards restored", restore.getRestoreInfo().successfulShards(), equalTo(2));
        ensureGreen("restored-rotated");

        // The decisive assertions: both epochs decrypt on the restored index.
        assertThat("restored index serves ALL docs across epochs", searchAll("restored-rotated"), equalTo(total));
        assertThat(
            "restored epoch-0 doc decrypts",
            client().prepareSearch("restored-rotated").setQuery(termQuery("number", 10)).get().getHits().getTotalHits().value(),
            equalTo(1L)
        );
        assertThat(
            "restored epoch-1 doc decrypts",
            client().prepareSearch("restored-rotated").setQuery(termQuery("number", epoch0 + 10)).get().getHits().getTotalHits().value(),
            equalTo(1L)
        );

        // Diagnostic: what keyfiles + epoch does the restored shard actually see on disk?
        String uuid = client().admin().cluster().prepareState().get().getState().metadata().index("restored-rotated").getIndexUUID();
        Index resolved = new Index("restored-rotated", uuid);
        for (String node : internalCluster().getNodeNames()) {
            IndexService is = internalCluster().getInstance(IndicesService.class, node).indexService(resolved);
            if (is == null) {
                continue;
            }
            for (IndexShard shard : is) {
                // Keyfiles live at the INDEX level: indices/<uuid>/ = resolveIndex().getParent().getParent()
                java.nio.file.Path idxDir = shard.shardPath().resolveIndex().getParent().getParent();
                java.util.List<String> keyfiles = new java.util.ArrayList<>();
                try (var stream = java.nio.file.Files.list(idxDir)) {
                    stream.map(p -> p.getFileName().toString())
                        .filter(n -> n.startsWith("keyfile"))
                        .forEach(keyfiles::add);
                }
                KeyResolver r = ShardKeyResolverRegistry.getResolver(uuid, shard.shardId().id(), "restored-rotated");
                int epoch = r != null ? ((DefaultKeyResolver) r).getCurrentEpoch() : -1;
                logger.info("RESTORED-DIAG shard={} dir={} keyfiles={} currentEpoch={}", shard.shardId().id(), idxDir, keyfiles, epoch);
            }
        }

        // And the restored index can itself be rotated further (its resolver discovered the restored epoch).
        rotateViaAction("restored-rotated");
        int maxEpoch = 0;
        for (String node : internalCluster().getNodeNames()) {
            IndexService is = internalCluster().getInstance(IndicesService.class, node).indexService(resolved);
            if (is == null) {
                continue;
            }
            for (IndexShard shard : is) {
                KeyResolver r = ShardKeyResolverRegistry.getResolver(uuid, shard.shardId().id(), "restored-rotated");
                if (r != null) {
                    maxEpoch = Math.max(maxEpoch, ((DefaultKeyResolver) r).getCurrentEpoch());
                }
            }
        }
        assertThat("restored index rotated beyond the snapshotted epoch", maxEpoch, equalTo(2));
    }
}
