/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.action.rest;

/**
 * Definition for an HTTP header copied to thread context. The rest module may use or extend this.
 *
 * @opensearch.internal
 */
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
