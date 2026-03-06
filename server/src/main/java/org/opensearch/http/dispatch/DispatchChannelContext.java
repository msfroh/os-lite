/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.common.Nullable;
import org.opensearch.common.util.BigArrays;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.http.CorsHandler;
import org.opensearch.http.HttpHandlingSettings;

/**
 * Context passed from the HTTP transport to the dispatcher when creating a channel.
 * Allows the rest module to build its channel implementation without the transport depending on rest.
 *
 * @opensearch.internal
 */
public final class DispatchChannelContext {

    private final BigArrays bigArrays;
    private final HttpHandlingSettings handlingSettings;
    private final ThreadContext threadContext;
    private final CorsHandler corsHandler;
    private final Object tracer;

    public DispatchChannelContext(
        BigArrays bigArrays,
        HttpHandlingSettings handlingSettings,
        ThreadContext threadContext,
        CorsHandler corsHandler,
        @Nullable Object tracer
    ) {
        this.bigArrays = bigArrays;
        this.handlingSettings = handlingSettings;
        this.threadContext = threadContext;
        this.corsHandler = corsHandler;
        this.tracer = tracer;
    }

    public BigArrays getBigArrays() {
        return bigArrays;
    }

    public HttpHandlingSettings getHandlingSettings() {
        return handlingSettings;
    }

    public ThreadContext getThreadContext() {
        return threadContext;
    }

    public CorsHandler getCorsHandler() {
        return corsHandler;
    }

    @Nullable
    public Object getTracer() {
        return tracer;
    }
}
