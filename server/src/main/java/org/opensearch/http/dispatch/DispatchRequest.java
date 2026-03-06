/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.http.HttpMethod;

import java.util.List;
import java.util.Map;

/**
 * Server-level abstraction of a request to be dispatched. Used by the HTTP transport and dispatcher
 * without depending on the rest module. The rest module's {@code RestRequest} implements this interface.
 *
 * @opensearch.internal
 */
public interface DispatchRequest {

    HttpMethod method();

    String uri();

    String rawPath();

    Map<String, String> params();

    BytesReference content();

    Map<String, List<String>> getHeaders();

    default String header(String name) {
        List<String> v = getHeaders().get(name);
        return (v != null && !v.isEmpty()) ? v.get(0) : null;
    }

    /** Request id for tracing; default 0 if not tracked. */
    default long getRequestId() {
        return 0L;
    }

    /**
     * If this instance uses pooled resources, creates a copy that does not and releases
     * resources. Otherwise returns this instance.
     */
    DispatchRequest releaseAndCopy();
}
