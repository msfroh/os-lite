/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.helloworld;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.helloworld.action.HelloWorldAction;
import org.opensearch.helloworld.transport.HelloWorldTransportAction;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;

import java.util.List;

public class HelloWorldPlugin extends Plugin implements ActionPlugin {

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(new ActionHandler<>(HelloWorldAction.INSTANCE, HelloWorldTransportAction.class));
    }
}
