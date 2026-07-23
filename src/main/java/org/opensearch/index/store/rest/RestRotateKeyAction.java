/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.rest;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

import java.io.IOException;
import java.util.List;

import org.opensearch.core.common.Strings;
import org.opensearch.index.store.action.RotateKeyAction;
import org.opensearch.index.store.action.RotateKeyRequest;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

/**
 * REST handler for {@code POST /_plugins/_opensearch_storage_encryption/{index}/_rotate_key}.
 *
 * <p>Rotates the encryption key epoch for the primary shards of the given index/indices. The
 * {@code {index}} path parameter may be a comma-separated list of index names or patterns.
 */
public class RestRotateKeyAction extends BaseRestHandler {

    private static final String ACTION_NAME = "rotate_key_action";
    private static final String ROUTE_PATH = "/_plugins/_opensearch_storage_encryption/{index}/_rotate_key";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, ROUTE_PATH));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String[] indices = Strings.splitStringByCommaToArray(request.param("index"));
        RotateKeyRequest rotateKeyRequest = new RotateKeyRequest(indices);
        return channel -> client.execute(RotateKeyAction.INSTANCE, rotateKeyRequest, new RestToXContentListener<>(channel));
    }
}
