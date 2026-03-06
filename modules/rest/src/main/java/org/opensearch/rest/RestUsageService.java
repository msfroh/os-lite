/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

/**
 * Service that tracks REST handler usage. The server's UsageService implements this interface.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestUsageService {

    void addRestHandler(BaseRestHandler handler);
}
