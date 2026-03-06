/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.plugins.Plugin;

/**
 * Minimal plugin class so the rest module gets the opensearchplugin convention (e.g. compileOnly server).
 * The rest module is a library consumed by server, not a loadable plugin.
 *
 * @opensearch.internal
 */
public class RestModulePlugin extends Plugin {
}
