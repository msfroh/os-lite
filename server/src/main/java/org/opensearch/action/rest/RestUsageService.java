/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.action.rest;

/**
 * Service that tracks REST handler usage. UsageService implements this.
 *
 * @opensearch.internal
 */
public interface RestUsageService {

    void addRestHandler(UsageTrackedRestHandler handler);
}
