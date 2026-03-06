/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.BoundTransportAddress;
import org.opensearch.core.service.ReportingService;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.dispatch.DispatchChannel;
import org.opensearch.http.dispatch.DispatchChannelContext;
import org.opensearch.http.dispatch.DispatchRequest;

import java.util.Map;
import java.util.Optional;

/**
 * HTTP Transport server
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface HttpServerTransport extends LifecycleComponent, ReportingService<HttpInfo> {

    String HTTP_SERVER_WORKER_THREAD_NAME_PREFIX = "http_server_worker";

    BoundTransportAddress boundAddress();

    @Override
    HttpInfo info();

    HttpStats stats();

    /**
     * Dispatches HTTP requests. Uses only server types ({@link DispatchRequest}, {@link DispatchChannel}, {@link HttpMethod})
     * so that server does not depend on the rest module. The rest module implements this interface.
     */
    interface Dispatcher {
        /**
         * Creates a dispatch request from the HTTP request. May throw if the request is malformed.
         */
        DispatchRequest createRequest(HttpRequest httpRequest, HttpChannel httpChannel, NamedXContentRegistry xContentRegistry);

        /**
         * Creates a dispatch channel for the response. {@code dispatchRequest} may be null when creating a channel for error responses only.
         */
        DispatchChannel createChannel(
            HttpChannel httpChannel,
            HttpRequest httpRequest,
            DispatchRequest dispatchRequest,
            DispatchChannelContext context
        );

        /**
         * Finds a matching handler, if any. Default returns empty.
         */
        default Optional<?> dispatchHandler(String uri, String rawPath, HttpMethod method, Map<String, String> params) {
            return Optional.empty();
        }

        /**
         * Dispatches the request to the relevant handler.
         */
        void dispatchRequest(DispatchRequest request, DispatchChannel channel, ThreadContext threadContext);

        /**
         * Dispatches a bad request (e.g. malformed) with the given cause.
         */
        void dispatchBadRequest(DispatchChannel channel, ThreadContext threadContext, Throwable cause);
    }
}
