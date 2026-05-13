/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.rest;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.http.HttpRequest;
import org.opensearch.python.action.PythonEvalAction;
import org.opensearch.python.action.PythonEvalRequest;
import org.opensearch.python.action.PythonEvalResponse;
import org.opensearch.rest.spi.BaseRestHandler;
import org.opensearch.rest.spi.BytesRestResponse;
import org.opensearch.rest.spi.RestBuilderListener;
import org.opensearch.rest.spi.RestRequest;
import org.opensearch.rest.spi.RestResponse;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

public class RestPythonAction extends BaseRestHandler {
    @Override
    public String getName() {
        return "python_eval";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(HttpRequest.Method.POST, "/_python"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String source = request.getHttpRequest().content().utf8ToString();
        PythonEvalRequest evalRequest = new PythonEvalRequest(source);
        return channel -> client.execute(PythonEvalAction.INSTANCE, evalRequest, new RestBuilderListener<>(channel) {
            @Override
            public RestResponse buildResponse(PythonEvalResponse response, XContentBuilder builder) throws Exception {
                if (request.hasParam("pretty") == false) {
                    builder.prettyPrint().lfAtEnd();
                }
                response.toXContent(builder, request);
                return new BytesRestResponse(RestStatus.OK, builder);
            }
        });
    }
}
