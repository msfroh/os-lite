/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.core.xcontent.NamedXContentRegistry;

/**
 * Placeholder {@link HttpServerTransport.Dispatcher} used when no rest controller is wired.
 * Sends 503 Service Unavailable for requests, 400 for bad requests. Uses only server types.
 *
 * @opensearch.internal
 */
public final class NoOpDispatcher implements HttpServerTransport.Dispatcher {

    @Override
    public DispatchRequest createRequest(
        org.opensearch.http.HttpRequest httpRequest,
        HttpChannel httpChannel,
        NamedXContentRegistry xContentRegistry
    ) {
        return new HttpDispatchRequestAdapter(httpRequest);
    }

    @Override
    public DispatchChannel createChannel(
        HttpChannel httpChannel,
        org.opensearch.http.HttpRequest httpRequest,
        DispatchRequest dispatchRequest,
        DispatchChannelContext context
    ) {
        return new HttpDispatchChannelAdapter(httpChannel, httpRequest);
    }

    @Override
    public void dispatchRequest(DispatchRequest request, DispatchChannel channel, ThreadContext threadContext) {
        channel.sendResponse(RestStatus.SERVICE_UNAVAILABLE, new BytesArray("{\"error\":\"REST controller not configured\",\"status\":503}"));
    }

    @Override
    public void dispatchBadRequest(DispatchChannel channel, ThreadContext threadContext, Throwable cause) {
        String message = cause != null ? cause.getMessage() : "Bad request";
        if (message == null) message = "Bad request";
        channel.sendResponse(RestStatus.BAD_REQUEST, new BytesArray("{\"error\":\"" + escapeJson(message) + "\",\"status\":400}"));
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
