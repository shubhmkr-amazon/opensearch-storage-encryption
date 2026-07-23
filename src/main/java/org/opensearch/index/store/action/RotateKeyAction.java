/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import org.opensearch.action.ActionType;

/**
 * Admin action that rotates the encryption key epoch for every primary shard of the target
 * index/indices. This is a broadcast-by-node action: it runs on each node hosting a targeted
 * primary shard, mutating node-local resolver state via {@code ShardKeyResolverRegistry}.
 */
public class RotateKeyAction extends ActionType<RotateKeyResponse> {

    public static final RotateKeyAction INSTANCE = new RotateKeyAction();
    public static final String NAME = "cluster:admin/opensearch/storage_encryption/rotate_key";

    private RotateKeyAction() {
        super(NAME, RotateKeyResponse::new);
    }
}
