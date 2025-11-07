/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.action.support;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;

/**
 * This class can be used to provide metadata about action requests to ActionFilter implementations.
 * At the moment, this class provides information about the requested indices of a request, but it can be
 * extended to transport further metadata.
 */
public class ActionRequestMetadata<Request extends ActionRequest, Response extends ActionResponse> {

    /**
     * Returns an empty meta data object which will just report unknown results.
     */
    public static <Request extends ActionRequest, Response extends ActionResponse> ActionRequestMetadata<Request, Response> empty() {
        @SuppressWarnings("unchecked")
        ActionRequestMetadata<Request, Response> result = (ActionRequestMetadata<Request, Response>) EMPTY;
        return result;
    }

    private static final ActionRequestMetadata<?, ?> EMPTY = new ActionRequestMetadata<>(null, null);

    private final TransportAction<Request, Response> transportAction;
    private final Request request;

    ActionRequestMetadata(TransportAction<Request, Response> transportAction, Request request) {
        this.transportAction = transportAction;
        this.request = request;
    }
}
