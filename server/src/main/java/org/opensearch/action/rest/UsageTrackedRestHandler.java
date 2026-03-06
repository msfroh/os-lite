/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.action.rest;

/**
 * Minimal interface for a REST handler that can be tracked by UsageService.
 * The rest module's BaseRestHandler implements this.
 *
 * @opensearch.internal
 */
public interface UsageTrackedRestHandler {

    String getName();

    long getUsageCount();
}
