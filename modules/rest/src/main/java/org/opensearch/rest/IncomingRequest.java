/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.http.HttpMethod;

import java.util.List;
import java.util.Map;

/**
 * Abstraction over an incoming HTTP request used to build a {@link RestRequest}.
 * Allows the rest layer to be decoupled from the HTTP transport types.
 * The transport provides an implementation that wraps its HTTP types.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface IncomingRequest {

    HttpMethod method();

    String uri();

    Map<String, List<String>> getHeaders();

    BytesReference content();

    List<String> strictCookies();

    /**
     * If this instance uses pooled resources, creates a copy that does not and releases
     * resources. Otherwise returns this instance.
     */
    IncomingRequest releaseAndCopy();
}
