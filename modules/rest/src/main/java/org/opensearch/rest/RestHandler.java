/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Handler for REST requests
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
@FunctionalInterface
public interface RestHandler {

    void handleRequest(RestRequest request, RestChannel channel, RestClient client) throws Exception;

    default boolean canTripCircuitBreaker() {
        return true;
    }

    default boolean supportsContentStream() {
        return false;
    }

    default boolean supportsStreaming() {
        return false;
    }

    default boolean allowsUnsafeBuffers() {
        return false;
    }

    default List<Route> routes() {
        return Collections.emptyList();
    }

    default List<DeprecatedRoute> deprecatedRoutes() {
        return Collections.emptyList();
    }

    default List<ReplacedRoute> replacedRoutes() {
        return Collections.emptyList();
    }

    default boolean allowSystemIndexAccessByDefault() {
        return false;
    }

    default boolean isActionPaginated() {
        return false;
    }

    static RestHandler wrapper(RestHandler delegate) {
        return new Wrapper(delegate);
    }

    class Wrapper implements RestHandler {
        private final RestHandler delegate;

        public Wrapper(RestHandler delegate) {
            this.delegate = Objects.requireNonNull(delegate, "RestHandler delegate can not be null");
        }

        @Override
        public void handleRequest(RestRequest request, RestChannel channel, RestClient client) throws Exception {
            delegate.handleRequest(request, channel, client);
        }

        @Override
        public boolean canTripCircuitBreaker() {
            return delegate.canTripCircuitBreaker();
        }

        @Override
        public boolean supportsContentStream() {
            return delegate.supportsContentStream();
        }

        @Override
        public boolean allowsUnsafeBuffers() {
            return delegate.allowsUnsafeBuffers();
        }

        @Override
        public List<Route> routes() {
            return delegate.routes();
        }

        @Override
        public List<DeprecatedRoute> deprecatedRoutes() {
            return delegate.deprecatedRoutes();
        }

        @Override
        public List<ReplacedRoute> replacedRoutes() {
            return delegate.replacedRoutes();
        }

        @Override
        public boolean allowSystemIndexAccessByDefault() {
            return delegate.allowSystemIndexAccessByDefault();
        }

        @Override
        public boolean isActionPaginated() {
            return delegate.isActionPaginated();
        }

        @Override
        public boolean supportsStreaming() {
            return delegate.supportsStreaming();
        }
    }

    @PublicApi(since = "1.0.0")
    class Route {
        protected final String path;
        protected final RestRequest.Method method;

        public Route(RestRequest.Method method, String path) {
            this.path = path;
            this.method = method;
        }

        public String getPath() {
            return path;
        }

        public String getPathWithPathParamsReplaced() {
            return path.replaceAll("(?<=\\{).*?(?=\\})", "path_param");
        }

        public RestRequest.Method getMethod() {
            return method;
        }

        @Override
        public int hashCode() {
            return ("Route [method=" + method + ", path=" + getPathWithPathParamsReplaced() + "]").hashCode();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Route that = (Route) o;
            return Objects.equals(method, that.method) && Objects.equals(getPathWithPathParamsReplaced(), that.getPathWithPathParamsReplaced());
        }
    }

    @PublicApi(since = "1.0.0")
    class DeprecatedRoute extends Route {
        private final String deprecationMessage;

        public DeprecatedRoute(RestRequest.Method method, String path, String deprecationMessage) {
            super(method, path);
            this.deprecationMessage = deprecationMessage;
        }

        public String getDeprecationMessage() {
            return deprecationMessage;
        }
    }

    @PublicApi(since = "1.0.0")
    class ReplacedRoute extends Route {
        private final String deprecatedPath;
        private final RestRequest.Method deprecatedMethod;

        public ReplacedRoute(RestRequest.Method method, String path, RestRequest.Method deprecatedMethod, String deprecatedPath) {
            super(method, path);
            this.deprecatedMethod = deprecatedMethod;
            this.deprecatedPath = deprecatedPath;
        }

        public ReplacedRoute(RestRequest.Method method, String path, String deprecatedPath) {
            this(method, path, method, deprecatedPath);
        }

        public ReplacedRoute(Route route, String prefix, String deprecatedPrefix) {
            this(route.getMethod(), prefix + route.getPath(), deprecatedPrefix + route.getPath());
        }

        public String getDeprecatedPath() {
            return deprecatedPath;
        }

        public RestRequest.Method getDeprecatedMethod() {
            return deprecatedMethod;
        }
    }

    static List<ReplacedRoute> replaceRoutes(List<Route> routes, String prefix, String deprecatedPrefix) {
        return routes.stream().map(route -> new ReplacedRoute(route, prefix, deprecatedPrefix)).collect(Collectors.toList());
    }
}
