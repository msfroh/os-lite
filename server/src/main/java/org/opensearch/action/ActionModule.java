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
 *     http://www.apache.org/licenses/LICENSE-2.0
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

package org.opensearch.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.TransportAction;
import org.opensearch.common.NamedRegistry;
import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.inject.AbstractModule;
import org.opensearch.common.inject.multibindings.MapBinder;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ActionPlugin.ActionHandler;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;

import static java.util.Collections.unmodifiableMap;

/**
 * Builds and binds the generic action map, all {@link TransportAction}s, and {@link ActionFilters}.
 *
 * @opensearch.internal
 */
public class ActionModule extends AbstractModule {

    // The unmodifiable map containing OpenSearch and Plugin actions
    // This is initialized at node bootstrap and contains same-JVM actions
    // It will be wrapped in the Dynamic Action Registry but otherwise
    // remains unchanged from its prior purpose, and registered actions
    // will remain accessible.
    private final Map<String, ActionHandler<?, ?>> actions;
    // A dynamic action registry which includes the above immutable actions
    // and also registers dynamic actions which may be unregistered. Usually
    // associated with remote action execution on extensions, possibly in
    // a different JVM and possibly on a different server.
    private final DynamicActionRegistry dynamicActionRegistry;
    private final ActionFilters actionFilters;

    public ActionModule(List<ActionPlugin> actionPlugins) {
        actions = setupActions(actionPlugins);
        actionFilters = setupActionFilters(actionPlugins);
        dynamicActionRegistry = new DynamicActionRegistry();
    }

    public Map<String, ActionHandler<?, ?>> getActions() {
        return actions;
    }

    static Map<String, ActionHandler<?, ?>> setupActions(List<ActionPlugin> actionPlugins) {
        // Subclass NamedRegistry for easy registration
        class ActionRegistry extends NamedRegistry<ActionHandler<?, ?>> {
            ActionRegistry() {
                super("action");
            }

            public void register(ActionHandler<?, ?> handler) {
                register(handler.getAction().name(), handler);
            }

            public <Request extends ActionRequest, Response extends ActionResponse> void register(
                ActionType<Response> action,
                Class<? extends TransportAction<Request, Response>> transportAction,
                Class<?>... supportTransportActions
            ) {
                register(new ActionHandler<>(action, transportAction, supportTransportActions));
            }
        }
        ActionRegistry actions = new ActionRegistry();
        actionPlugins.stream().flatMap(p -> p.getActions().stream()).forEach(actions::register);
        return unmodifiableMap(actions.getRegistry());
    }

    private ActionFilters setupActionFilters(List<ActionPlugin> actionPlugins) {
        return new ActionFilters(
            Collections.unmodifiableSet(actionPlugins.stream().flatMap(p -> p.getActionFilters().stream()).collect(Collectors.toSet()))
        );
    }

    public ActionFilters getActionFilters() {
        return actionFilters;
    }

    public DynamicActionRegistry getDynamicActionRegistry() {
        return dynamicActionRegistry;
    }

    @Override
    protected void configure() {
        bind(ActionFilters.class).toInstance(actionFilters);

        // register ActionType -> transportAction Map used by NodeClient
        @SuppressWarnings("rawtypes")
        MapBinder<ActionType, TransportAction> transportActionsBinder = MapBinder.newMapBinder(
            binder(),
            ActionType.class,
            TransportAction.class
        );
        for (ActionHandler<?, ?> action : actions.values()) {
            // bind the action as eager singleton, so the map binder one will reuse it
            bind(action.getTransportAction()).asEagerSingleton();
            transportActionsBinder.addBinding(action.getAction()).to(action.getTransportAction()).asEagerSingleton();
            for (Class<?> supportAction : action.getSupportTransportActions()) {
                bind(supportAction).asEagerSingleton();
            }
        }

        // register dynamic ActionType -> transportAction Map used by NodeClient
        bind(DynamicActionRegistry.class).toInstance(dynamicActionRegistry);
    }

    /**
     * The DynamicActionRegistry maintains a registry mapping {@link ActionType} instances to {@link TransportAction} instances.
     * <p>
     * This class is modeled after {@link NamedRegistry} but provides both register and unregister capabilities.
     *
     * @opensearch.api
     */
    @PublicApi(since = "2.7.0")
    public static class DynamicActionRegistry {
        // This is the unmodifiable actions map created during node bootstrap, which
        // will continue to link ActionType and TransportAction pairs from core and plugin
        // action handler registration.
        private Map<ActionType, TransportAction> actions = Collections.emptyMap();
        // A dynamic registry to add or remove ActionType / TransportAction pairs
        // at times other than node bootstrap.
        private final Map<ActionType<?>, TransportAction<?, ?>> registry = new ConcurrentHashMap<>();

        private final Set<String> registeredActionNames = new ConcurrentSkipListSet<>();

        /**
         * Register the immutable actions in the registry.
         *
         * @param actions The injected map of {@link ActionType} to {@link TransportAction}
         */
        public void registerUnmodifiableActionMap(Map<ActionType, TransportAction> actions) {
            this.actions = actions;
            for (ActionType action : actions.keySet()) {
                registeredActionNames.add(action.name());
            }
        }

        /**
         * Checks to see if an action is registered provided an action name
         *
         * @param actionName The name of the action to check
         */
        public boolean isActionRegistered(String actionName) {
            return registeredActionNames.contains(actionName);
        }

        /**
         * Gets the {@link TransportAction} instance corresponding to the {@link ActionType} instance.
         *
         * @param action The {@link ActionType}.
         * @return the corresponding {@link TransportAction} if it is registered, null otherwise.
         */
        @SuppressWarnings("unchecked")
        public TransportAction<? extends ActionRequest, ? extends ActionResponse> get(ActionType<?> action) {
            if (actions.containsKey(action)) {
                return actions.get(action);
            }
            return registry.get(action);
        }
    }
}
