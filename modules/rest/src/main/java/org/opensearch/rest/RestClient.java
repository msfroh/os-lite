/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

/**
 * Client interface used by {@link RestHandler} to execute actions.
 * The server provides an implementation (e.g. {@code NodeClient}) that implements this interface.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestClient {
}
