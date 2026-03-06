/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest.action;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;

/**
 * A REST action listener that builds an {@link XContentBuilder} based response.
 */
public abstract class RestBuilderListener<Response> extends RestResponseListener<Response> {

    public RestBuilderListener(RestChannel channel) {
        super(channel);
    }

    @Override
    public final RestResponse buildResponse(Response response) throws Exception {
        try (XContentBuilder builder = channel.newBuilder()) {
            final RestResponse restResponse = buildResponse(response, builder);
            assert assertBuilderClosed(builder);
            return restResponse;
        }
    }

    public abstract RestResponse buildResponse(Response response, XContentBuilder builder) throws Exception;

    boolean assertBuilderClosed(XContentBuilder xContentBuilder) {
        assert xContentBuilder.generator().isClosed() : "callers should ensure the XContentBuilder is closed themselves";
        return true;
    }
}
