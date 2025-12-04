/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.helloworld.transport;

import org.opensearch.Build;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.helloworld.action.HelloWorldAction;
import org.opensearch.helloworld.action.HelloWorldRequest;
import org.opensearch.helloworld.action.HelloWorldResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class HelloWorldTransportAction extends HandledTransportAction<HelloWorldRequest, HelloWorldResponse> {
    private final TransportService transportService;

    @Inject
    public HelloWorldTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(HelloWorldAction.NAME, transportService, actionFilters, HelloWorldRequest::new);
        this.transportService = transportService;
    }

    @Override
    protected void doExecute(Task task, HelloWorldRequest request, ActionListener<HelloWorldResponse> listener) {
        listener.onResponse(new HelloWorldResponse(transportService.getLocalNode(), Build.CURRENT));
    }
}
