/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.opensearch.index.query.QueryBuilders.matchAllQuery;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.opensearch.action.admin.indices.stats.IndicesStatsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.niofs.CryptoDirectoryIntegTestCases;
import org.opensearch.test.OpenSearchIntegTestCase;

/**
 * Integration tests for translog encryption recovery: a full-cluster restart must replay the encrypted
 * translog and recover every acknowledged operation, with no AEADBadTagException / "Failed to decrypt
 * chunk" failures. This is the cluster-level counterpart to the unit-level partial-write/read tests and
 * the guard against the original chunk-misalignment regression surfacing during shard recovery.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 1, numClientNodes = 0)
public class CryptoTranslogRecoveryIntegTests extends CryptoDirectoryIntegTestCases {

    /** cryptofs + dummy provider (from the base class) plus request durability and a high flush threshold
     *  so indexed docs stay in the encrypted translog (not folded into a Lucene commit) until we restart. */
    private Settings translogIndexSettings() {
        return Settings
            .builder()
            .put(indexSettings())
            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
            .put("index.translog.durability", "request")
            .put("index.translog.flush_threshold_size", "1gb")
            .put("index.refresh_interval", "-1")
            .build();
    }

    private long uncommittedTranslogOps(String index) {
        IndicesStatsResponse stats = client().admin().indices().prepareStats(index).clear().setTranslog(true).get();
        return stats.getIndex(index).getPrimaries().translog.getUncommittedOperations();
    }

    /**
     * The headline test: index many docs that live only in the encrypted translog (spanning dozens of
     * 8208-byte chunks), then full-restart the cluster to force translog replay. Every op must come back.
     * A reintroduced partial-write/chunk-misalignment bug makes recovery throw and the shard stays red.
     */
    public void testFullRestartRecoversEncryptedTranslog() throws Exception {
        final String index = "tlog-recovery";
        createIndex(index, translogIndexSettings());
        ensureGreen(index);

        final int nbDocs = 5000;
        for (int i = 0; i < nbDocs; i++) {
            // ~400-byte source so 5000 docs span many chunks in one generation
            client()
                .prepareIndex(index)
                .setId(Integer.toString(i))
                .setSource("n", i, "payload", "translog-doc-" + i + "-" + "x".repeat(380))
                .get();
        }

        // The docs must still be in the translog (not committed) for this to actually exercise replay.
        assertThat("docs should be uncommitted in the translog before restart", uncommittedTranslogOps(index), greaterThanOrEqualTo((long) nbDocs));

        internalCluster().fullRestart();
        ensureGreen(index);

        refresh(index);
        SearchResponse resp = client().prepareSearch(index).setSize(0).setQuery(matchAllQuery()).get();
        assertThat("all translog ops must be recovered after restart", resp.getHits().getTotalHits().value(), is((long) nbDocs));

        // spot-check a few decrypted sources are intact
        for (int id : new int[] { 0, nbDocs / 2, nbDocs - 1 }) {
            var get = client().prepareGet(index, Integer.toString(id)).get();
            assertTrue("doc " + id + " must exist after recovery", get.isExists());
            assertTrue("doc " + id + " source intact", get.getSourceAsString().contains("translog-doc-" + id + "-"));
        }
    }

    /**
     * Roll multiple translog generations via explicit flush, indexing into each, then restart. Exercises
     * per-generation translog files (each with its own baseIV) recovering together.
     */
    public void testMultiGenerationRecovery() throws Exception {
        final String index = "tlog-multigen";
        createIndex(index, translogIndexSettings());
        ensureGreen(index);

        int total = 0;
        for (int gen = 0; gen < 3; gen++) {
            for (int i = 0; i < 500; i++, total++) {
                client().prepareIndex(index).setId(Integer.toString(total)).setSource("n", total, "g", gen).get();
            }
            // force a new translog generation
            client().admin().indices().prepareFlush(index).get();
        }
        // a final batch that stays in the live (un-flushed) generation
        for (int i = 0; i < 250; i++, total++) {
            client().prepareIndex(index).setId(Integer.toString(total)).setSource("n", total, "g", 99).get();
        }

        internalCluster().fullRestart();
        ensureGreen(index);
        refresh(index);

        SearchResponse resp = client().prepareSearch(index).setSize(0).setQuery(matchAllQuery()).get();
        assertThat("all docs across generations must survive restart", resp.getHits().getTotalHits().value(), is((long) total));
    }

    /**
     * Confirms the on-disk encryption invariants: the .tlog data is ciphertext (no plaintext sentinel),
     * while the .ckp checkpoint is intentionally left plaintext.
     */
    public void testTranslogEncryptedOnDiskCheckpointPlaintext() throws Exception {
        final String index = "tlog-ondisk";
        createIndex(index, translogIndexSettings());
        ensureGreen(index);

        final String sentinel = "SENSITIVE-TRANSLOG-SENTINEL-PAYLOAD";
        for (int i = 0; i < 200; i++) {
            client().prepareIndex(index).setId(Integer.toString(i)).setSource("secret", sentinel + "-" + i).get();
        }
        // do NOT refresh/flush: keep it in the translog

        boolean sawTlog = false;
        boolean sawCkp = false;
        for (Path shardPath : translogDirs(index)) {
            try (Stream<Path> files = Files.list(shardPath)) {
                for (Path f : (Iterable<Path>) files::iterator) {
                    String name = f.getFileName().toString();
                    byte[] bytes = Files.readAllBytes(f);
                    String asText = new String(bytes, StandardCharsets.ISO_8859_1);
                    if (name.endsWith(".tlog")) {
                        sawTlog = true;
                        assertFalse(".tlog must not contain plaintext sentinel: " + name, asText.contains(sentinel));
                    } else if (name.endsWith(".ckp")) {
                        sawCkp = true; // checkpoint is intentionally plaintext; just assert it exists/readable
                    }
                }
            }
        }
        assertTrue("expected at least one .tlog file", sawTlog);
        assertTrue("expected at least one .ckp file", sawCkp);
    }

    /** Locate the translog directories of the index's shards via the live IndexShard's ShardPath. */
    private List<Path> translogDirs(String index) {
        List<Path> dirs = new ArrayList<>();
        String uuid = client()
            .admin()
            .cluster()
            .prepareState()
            .get()
            .getState()
            .metadata()
            .index(index)
            .getIndexUUID();
        org.opensearch.core.index.Index resolved = new org.opensearch.core.index.Index(index, uuid);
        for (String node : internalCluster().getNodeNames()) {
            org.opensearch.indices.IndicesService indicesService = internalCluster().getInstance(
                org.opensearch.indices.IndicesService.class,
                node
            );
            org.opensearch.index.IndexService indexService = indicesService.indexService(resolved);
            if (indexService == null) {
                continue;
            }
            for (org.opensearch.index.shard.IndexShard shard : indexService) {
                Path tlog = shard.shardPath().resolveTranslog();
                if (Files.isDirectory(tlog)) {
                    dirs.add(tlog);
                }
            }
        }
        return dirs;
    }
}
