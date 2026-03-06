/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpRequest;

/**
 * Minimal {@link DispatchChannel} that wraps {@link HttpChannel} and {@link HttpRequest}.
 * Used by the server's NoOpDispatcher.
 *
 * @opensearch.internal
 */
final class HttpDispatchChannelAdapter implements DispatchChannel {

    private final HttpChannel httpChannel;
    private final HttpRequest httpRequest;

    HttpDispatchChannelAdapter(HttpChannel httpChannel, HttpRequest httpRequest) {
        this.httpChannel = httpChannel;
        this.httpRequest = httpRequest;
    }

    @Override
    public void sendResponse(RestStatus status, BytesReference content) {
        try {
            var response = httpRequest.createResponse(status, content);
            httpChannel.sendResponse(response, ActionListener.wrap(() -> {}));
        } finally {
            httpRequest.release();
        }
    }
}
