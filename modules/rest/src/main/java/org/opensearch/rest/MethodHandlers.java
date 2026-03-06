/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.Nullable;
import org.opensearch.http.HttpMethod;

import java.util.Set;

/**
 * A collection of REST method handlers.
 *
 * @opensearch.api
 */
@PublicApi(since = "2.12.0")
public interface MethodHandlers {

    /**
     * Returns the handler for the given method or {@code null} if none exists.
     */
    @Nullable
    RestHandler getHandler(HttpMethod method);

    /**
     * Return a set of all valid HTTP methods for the particular path.
     */
    Set<HttpMethod> getValidMethods();

    /**
     * Returns the relative HTTP path of the set of method handlers.
     */
    String getPath();
}
