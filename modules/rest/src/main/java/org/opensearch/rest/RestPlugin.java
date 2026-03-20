/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rest;

import org.opensearch.http.HttpServerTransport;
import org.opensearch.plugins.NetworkPlugin;
import org.opensearch.plugins.Plugin;

import java.util.Optional;

/**
 * Plugin that provides the REST layer dispatcher for handling HTTP requests.
 *
 * @opensearch.internal
 */
public class RestPlugin extends Plugin implements NetworkPlugin {

    @Override
    public Optional<HttpServerTransport.Dispatcher> getHttpServerTransportDispatcher() {
        return Optional.empty();
    }
}
