/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.action.rest;

/**
 * Server-level interface for the REST controller. The rest module provides the implementation.
 * Allows ActionModule and plugins to register handlers without the server depending on the rest module.
 *
 * @opensearch.internal
 */
public interface RestController {

    void registerHandler(Object handler);
}
