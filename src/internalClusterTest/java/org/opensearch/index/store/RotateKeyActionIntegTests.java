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

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.action.RotateKeyAction;
import org.opensearch.index.store.action.RotateKeyRequest;
import org.opensearch.index.store.action.RotateKeyResponse;
import org.opensearch.index.store.action.RotateKeyShardResponse;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * End-to-end tests for the {@code POST /{index}/_rotate_key} admin action, driven through the real
 * transport layer on a live cluster (not a direct resolver call). Uses the distinct-per-epoch provider
 * so rotation genuinely changes the key.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class RotateKeyActionIntegTests extends OpenSearchIntegTestCase {

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

    /** Drive the transport action and require every primary shard to rotate to a new epoch. */
    public void testRotateKeyActionRotatesAllPrimaries() throws Exception {
        internalCluster().startNode();
        final String index = "rotate-action";
        createIndex(index, cryptoIndexSettings(3));
        ensureGreen(index);

        final int docs = 300;
        for (int i = 0; i < docs; i++) {
            index(index, "_doc", String.valueOf(i), "field", "v" + i, "number", i);
        }
        refresh(index);
        flush(index);
        assertThat(searchAll(index), equalTo((long) docs));

        RotateKeyResponse resp = client().execute(RotateKeyAction.INSTANCE, new RotateKeyRequest(index)).actionGet();

        assertThat("no shard should fail rotation", resp.getShardFailures().length, equalTo(0));
        assertThat("all 3 primaries rotated", resp.getSuccessfulShards(), equalTo(3));
        assertThat("shard responses present", resp.getShardResponses().size(), equalTo(3));
        for (RotateKeyShardResponse sr : resp.getShardResponses()) {
            assertThat("epoch advanced to 1", sr.getNewEpoch(), equalTo(1));
        }

        // Old-epoch data still readable after rotation via the action.
        assertThat("epoch-0 data readable post-rotation", searchAll(index), equalTo((long) docs));

        // New writes land under epoch 1; everything still searchable together.
        for (int i = docs; i < docs + 100; i++) {
            index(index, "_doc", String.valueOf(i), "field", "v" + i, "number", i);
        }
        refresh(index);
        assertThat(searchAll(index), equalTo((long) (docs + 100)));

        // A second rotation must advance to epoch 2.
        RotateKeyResponse resp2 = client().execute(RotateKeyAction.INSTANCE, new RotateKeyRequest(index)).actionGet();
        assertThat(resp2.getShardFailures().length, equalTo(0));
        for (RotateKeyShardResponse sr : resp2.getShardResponses()) {
            assertThat("epoch advanced to 2", sr.getNewEpoch(), equalTo(2));
        }
    }

    /** The request must refuse an empty index list (guards against accidental all-index rotation). */
    public void testRotateKeyRequestRejectsNoIndices() {
        RotateKeyRequest req = new RotateKeyRequest(new String[0]);
        ActionRequestValidationException ex = req.validate();
        assertNotNull("empty-index request must fail validation", ex);
        assertThat(ex.validationErrors().size(), greaterThan(0));
    }
}
