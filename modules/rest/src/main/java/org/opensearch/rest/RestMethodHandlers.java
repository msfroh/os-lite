/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.Nullable;
import org.opensearch.http.HttpMethod;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Encapsulate multiple handlers for the same path, allowing different handlers for different HTTP verbs.
 */
public final class RestMethodHandlers implements MethodHandlers {

    private final String path;
    private final Map<HttpMethod, RestHandler> methodHandlers;

    RestMethodHandlers(String path, RestHandler handler, HttpMethod... methods) {
        this.path = path;
        this.methodHandlers = new HashMap<>(methods.length);
        for (HttpMethod method : methods) {
            methodHandlers.put(method, handler);
        }
    }

    public RestMethodHandlers addMethods(RestHandler handler, HttpMethod... methods) {
        for (HttpMethod method : methods) {
            RestHandler existing = methodHandlers.putIfAbsent(method, handler);
            if (existing != null) {
                throw new IllegalArgumentException("Cannot replace existing handler for [" + path + "] for method: " + method);
            }
        }
        return this;
    }

    @Override
    @Nullable
    public RestHandler getHandler(HttpMethod method) {
        return methodHandlers.get(method);
    }

    @Override
    public Set<HttpMethod> getValidMethods() {
        return methodHandlers.keySet();
    }

    @Override
    public String getPath() {
        return path;
    }
}
