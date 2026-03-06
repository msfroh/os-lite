/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.CollectionUtil;
import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

/**
 * Base handler for REST requests.
 */
@PublicApi(since = "1.0.0")
public abstract class BaseRestHandler implements RestHandler {

    /** Setting name for allowing explicit index in multi requests. The server registers the actual setting. */
    public static final String MULTI_ALLOW_EXPLICIT_INDEX_KEY = "rest.action.multi.allow_explicit_index";

    private final LongAdder usageCount = new LongAdder();

    @Deprecated
    protected Logger logger = LogManager.getLogger(getClass());

    public final long getUsageCount() {
        return usageCount.sum();
    }

    public abstract String getName();

    @Override
    public final void handleRequest(RestRequest request, RestChannel channel, RestClient client) throws Exception {
        final RestChannelConsumer action = prepareRequest(request, client);
        final SortedSet<String> unconsumedParams = request.unconsumedParams()
            .stream()
            .filter(p -> !responseParams().contains(p))
            .collect(Collectors.toCollection(TreeSet::new));

        if (!unconsumedParams.isEmpty()) {
            final Set<String> candidateParams = new HashSet<>();
            candidateParams.addAll(request.consumedParams());
            candidateParams.addAll(responseParams());
            throw new IllegalArgumentException(unrecognized(request, unconsumedParams, candidateParams, "parameter"));
        }

        usageCount.increment();
        action.accept(channel);
    }

    public static String unrecognizedStrings(
        final RestRequest request,
        final Set<String> invalids,
        final Set<String> candidates,
        final String detail
    ) {
        StringBuilder message = new StringBuilder(
            String.format(Locale.ROOT, "request [%s] contains unrecognized %s%s: ", request.path(), detail, invalids.size() > 1 ? "s" : "")
        );
        boolean first = true;
        for (final String invalid : invalids) {
            final List<Tuple<Float, String>> scoredParams = new ArrayList<>();
            CollectionUtil.timSort(scoredParams, (a, b) -> {
                int compare = a.v1().compareTo(b.v1());
                if (compare != 0) return -compare;
                return a.v2().compareTo(b.v2());
            });
            if (first == false) {
                message.append(", ");
            }
            message.append("[").append(invalid).append("]");
            final List<String> keys = scoredParams.stream().map(Tuple::v2).collect(Collectors.toList());
            if (!keys.isEmpty()) {
                message.append(" -> did you mean ");
                if (keys.size() == 1) {
                    message.append("[").append(keys.get(0)).append("]");
                } else {
                    message.append("any of ").append(keys.toString()).append("?");
                }
            }
            first = false;
        }
        return message.toString();
    }

    protected final String unrecognized(
        final RestRequest request,
        final Set<String> invalids,
        final Set<String> candidates,
        final String detail
    ) {
        return unrecognizedStrings(request, invalids, candidates, detail);
    }

    @FunctionalInterface
    @PublicApi(since = "1.0.0")
    protected interface RestChannelConsumer extends CheckedConsumer<RestChannel, Exception> {}

    @FunctionalInterface
    @ExperimentalApi
    protected interface StreamingRestChannelConsumer extends CheckedConsumer<StreamingRestChannel, Exception> {}

    protected abstract RestChannelConsumer prepareRequest(RestRequest request, RestClient client) throws IOException;

    protected Set<String> responseParams() {
        return Collections.emptySet();
    }

    public static class Wrapper extends BaseRestHandler {

        protected final BaseRestHandler delegate;

        public Wrapper(BaseRestHandler delegate) {
            this.delegate = Objects.requireNonNull(delegate, "BaseRestHandler delegate can not be null");
        }

        @Override
        public String getName() {
            return delegate.getName();
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
        protected RestChannelConsumer prepareRequest(RestRequest request, RestClient client) throws IOException {
            return delegate.prepareRequest(request, client);
        }

        @Override
        protected Set<String> responseParams() {
            return delegate.responseParams();
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
        public boolean allowSystemIndexAccessByDefault() {
            return delegate.allowSystemIndexAccessByDefault();
        }

        @Override
        public boolean supportsStreaming() {
            return delegate.supportsStreaming();
        }
    }

    /**
     * Return a task immediately when executing some long-running operations asynchronously (e.g. reindex, resize).
     */
    protected RestChannelConsumer sendTask(String nodeId, String taskId) {
        return channel -> {
            try (XContentBuilder builder = channel.newBuilder()) {
                builder.startObject();
                builder.field("task", nodeId + ":" + taskId);
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
            }
        };
    }
}
