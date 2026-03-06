/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.http.HttpRequest;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal {@link DispatchRequest} that wraps {@link HttpRequest}. Used by the server's NoOpDispatcher.
 * Parses params from the URI so no rest dependency is needed.
 *
 * @opensearch.internal
 */
final class HttpDispatchRequestAdapter implements DispatchRequest {

    private final HttpRequest httpRequest;
    private final String rawPath;
    private final Map<String, String> params;
    private final long requestId;

    private static final java.util.concurrent.atomic.AtomicLong requestIdGen = new java.util.concurrent.atomic.AtomicLong(0);

    HttpDispatchRequestAdapter(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
        String uri = httpRequest.uri();
        int q = uri.indexOf('?');
        if (q >= 0) {
            this.rawPath = uri.substring(0, q);
            this.params = new HashMap<>();
            parseQueryString(uri, q + 1, params);
        } else {
            this.rawPath = uri;
            this.params = Collections.emptyMap();
        }
        this.requestId = requestIdGen.incrementAndGet();
    }

    @Override
    public org.opensearch.http.HttpMethod method() {
        return httpRequest.method();
    }

    @Override
    public String uri() {
        return httpRequest.uri();
    }

    @Override
    public String rawPath() {
        return rawPath;
    }

    @Override
    public Map<String, String> params() {
        return params;
    }

    @Override
    public BytesReference content() {
        return httpRequest.content();
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return httpRequest.getHeaders();
    }

    @Override
    public long getRequestId() {
        return requestId;
    }

    @Override
    public DispatchRequest releaseAndCopy() {
        return new HttpDispatchRequestAdapter(httpRequest.releaseAndCopy());
    }

    private static void parseQueryString(String s, int fromIndex, Map<String, String> params) {
        if (fromIndex >= s.length()) return;
        int end = s.indexOf('#');
        if (end < 0) end = s.length();
        String name = null;
        int pos = fromIndex;
        for (int i = fromIndex; i < end; i++) {
            char c = s.charAt(i);
            if (c == '=' && name == null) {
                if (pos != i) name = decodeComponent(s.substring(pos, i));
                pos = i + 1;
            } else if (c == '&' || c == ';') {
                if (name == null && pos != i) {
                    params.put(decodeComponent(s.substring(pos, i)), "");
                } else if (name != null) {
                    params.put(name, decodeComponent(s.substring(pos, i)));
                    name = null;
                }
                pos = i + 1;
            }
        }
        if (pos != end) {
            if (name == null) {
                params.put(decodeComponent(s.substring(pos, end)), "");
            } else {
                params.put(name, decodeComponent(s.substring(pos, end)));
            }
        }
    }

    private static String decodeComponent(String s) {
        return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
