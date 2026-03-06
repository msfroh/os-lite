/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

/**
 * A definition for an http header that should be copied to the thread context when
 * reading the request on the rest layer.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public final class RestHeaderDefinition {
    private final String name;
    private final boolean multiValueAllowed;

    public RestHeaderDefinition(String name, boolean multiValueAllowed) {
        this.name = name;
        this.multiValueAllowed = multiValueAllowed;
    }

    public String getName() {
        return name;
    }

    public boolean isMultiValueAllowed() {
        return multiValueAllowed;
    }
}
