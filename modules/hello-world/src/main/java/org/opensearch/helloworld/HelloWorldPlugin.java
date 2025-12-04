/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.helloworld;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.helloworld.action.HelloWorldAction;
import org.opensearch.helloworld.rest.RestHelloWorldAction;
import org.opensearch.helloworld.transport.HelloWorldTransportAction;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;

import java.util.List;
import java.util.function.Supplier;

public class HelloWorldPlugin extends Plugin implements ActionPlugin {

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        SettingsFilter settingsFilter,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return List.of(new RestHelloWorldAction());
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(new ActionHandler<>(HelloWorldAction.INSTANCE, HelloWorldTransportAction.class));
    }
}
