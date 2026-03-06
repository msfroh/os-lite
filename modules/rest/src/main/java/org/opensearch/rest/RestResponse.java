/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OpenSearch REST response
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public abstract class RestResponse {

    private Map<String, List<String>> customHeaders;

    public abstract String contentType();

    /**
     * The response content. If the content is releasable it should be released when done by the channel.
     */
    public abstract BytesReference content();

    public abstract RestStatus status();

    public void copyHeaders(RestExceptionHeaders ex) {
        Set<String> headerKeySet = ex.getHeaderKeys();
        if (customHeaders == null) {
            customHeaders = new HashMap<>(headerKeySet.size());
        }
        for (String key : headerKeySet) {
            List<String> values = customHeaders.get(key);
            if (values == null) {
                values = new ArrayList<>();
                customHeaders.put(key, values);
            }
            values.addAll(ex.getHeader(key));
        }
    }

    public void addHeader(String name, String value) {
        if (customHeaders == null) {
            customHeaders = new HashMap<>(2);
        }
        List<String> header = customHeaders.get(name);
        if (header == null) {
            header = new ArrayList<>();
            customHeaders.put(name, header);
        }
        header.add(value);
    }

    public Map<String, List<String>> getHeaders() {
        if (customHeaders == null) {
            return Collections.emptyMap();
        } else {
            return customHeaders;
        }
    }
}
