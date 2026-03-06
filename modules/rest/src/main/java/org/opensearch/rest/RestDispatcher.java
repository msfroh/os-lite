/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

import java.util.Map;
import java.util.Optional;

/**
 * Dispatches REST requests to handlers. The HTTP transport's dispatcher extends this interface.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestDispatcher {

    /**
     * Finds the matching handler for the request, if any.
     */
    default Optional<RestHandler> dispatchHandler(String uri, String rawPath, RestRequest.Method method, Map<String, String> params) {
        return Optional.empty();
    }

    /**
     * Dispatches the request to the relevant handler or responds with an error.
     */
    void dispatchRequest(RestRequest request, RestChannel channel, RestRequestContext requestContext);

    /**
     * Dispatches a bad request (e.g. malformed) with the given cause.
     */
    void dispatchBadRequest(RestChannel channel, RestRequestContext requestContext, Throwable cause);

    /**
     * Minimal context for copying headers into the request (e.g. from rest to transport).
     * Server adapts {@code ThreadContext} to this interface.
     */
    @PublicApi(since = "1.0.0")
    interface RestRequestContext {
        void putHeader(String name, String value);
    }
}
