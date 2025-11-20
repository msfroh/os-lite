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

package org.opensearch.plugins;

import org.opensearch.bootstrap.BootstrapCheck;
import org.opensearch.cluster.node.DiscoveryNodeRole;
import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.inject.Module;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.SettingUpgrader;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteable;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ExecutorBuilder;
import org.opensearch.threadpool.ThreadPool;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * An extension point allowing to plug in custom functionality. This class has a number of extension points that are available to all
 * plugins, in addition you can implement any of the following interfaces to further customize OpenSearch:
 * <ul>
 * <li>{@link ActionPlugin}
 * </ul>
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public abstract class Plugin implements Closeable {

    /**
     * A feature exposed by the plugin. This should be used if a plugin exposes ClusterState.Custom or  Metadata.Custom; see
     * also ClusterState.FeatureAware.
     *
     * @return a feature set represented by this plugin, or the empty optional if the plugin does not expose cluster state or metadata
     * customs
     */
    protected Optional<String> getFeature() {
        return Optional.empty();
    }

    /**
     * Node level guice modules.
     */
    public Collection<Module> createGuiceModules() {
        return Collections.emptyList();
    }

    /**
     * Node level services that will be automatically started/stopped/closed. This classes must be constructed
     * by injection with guice.
     */
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        return Collections.emptyList();
    }

    /**
     * Returns components added by this plugin.
     * <p>
     * Any components returned that implement {@link LifecycleComponent} will have their lifecycle managed.
     * Note: To aid in the migration away from guice, all objects returned as components will be bound in guice
     * to themselves.
     *
     * @param threadPool A service to allow retrieving an executor to run an async action
     * @param xContentRegistry the registry for extensible xContent parsing
     * @param environment the environment for path and setting configurations
     * @param namedWriteableRegistry the registry for {@link NamedWriteable} object parsing
     */
    public Collection<Object> createComponents(
        ThreadPool threadPool,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NamedWriteableRegistry namedWriteableRegistry
    ) {
        return Collections.emptyList();
    }

    /**
     * Additional node settings loaded by the plugin. Note that settings that are explicit in the nodes settings can't be
     * overwritten with the additional settings. These settings added if they don't exist.
     */
    public Settings additionalSettings() {
        return Settings.Builder.EMPTY_SETTINGS;
    }

    /**
     * Returns parsers for {@link NamedWriteable} this plugin will use over the transport protocol.
     * @see NamedWriteableRegistry
     */
    public List<NamedWriteableRegistry.Entry> getNamedWriteables() {
        return Collections.emptyList();
    }

    /**
     * Returns parsers for named objects this plugin will parse from {@link XContentParser#namedObject(Class, String, Object)}.
     * @see NamedWriteableRegistry
     */
    public List<NamedXContentRegistry.Entry> getNamedXContent() {
        return Collections.emptyList();
    }

    /**
     * Returns a list of additional {@link Setting} definitions for this plugin.
     */
    public List<Setting<?>> getSettings() {
        return Collections.emptyList();
    }

    /**
     * Returns a list of additional settings filter for this plugin
     */
    public List<String> getSettingsFilter() {
        return Collections.emptyList();
    }

    /**
     * Get the setting upgraders provided by this plugin.
     *
     * @return the settings upgraders
     */
    public List<SettingUpgrader<?>> getSettingUpgraders() {
        return Collections.emptyList();
    }

    /**
     * Provides the list of this plugin's custom thread pools, empty if
     * none.
     *
     * @param settings the current settings
     * @return executors builders for this plugin's custom thread pools
     */
    public List<ExecutorBuilder<?>> getExecutorBuilders(Settings settings) {
        return Collections.emptyList();
    }

    /**
     * Returns a list of checks that are enforced when a node starts up once a node has the transport protocol bound to a non-loopback
     * interface. In this case we assume the node is running in production and all bootstrap checks must pass. This allows plugins
     * to provide a better out of the box experience by pre-configuring otherwise (in production) mandatory settings or to enforce certain
     * configurations like OS settings or 3rd party resources.
     */
    public List<BootstrapCheck> getBootstrapChecks() {
        return Collections.emptyList();
    }

    public Set<DiscoveryNodeRole> getRoles() {
        return Collections.emptySet();
    }

    /**
     * Close the resources opened by this plugin.
     *
     * @throws IOException if the plugin failed to close its resources
     */
    @Override
    public void close() throws IOException {

    }

    /**
     * Returns the {@link SecureSettingsFactory} instance that could be used to configure the
     * security related components (fe. transports)
     * @return the {@link SecureSettingsFactory} instance
     */
    public Optional<SecureSettingsFactory> getSecureSettingFactory(Settings settings) {
        return Optional.empty();
    }
}
