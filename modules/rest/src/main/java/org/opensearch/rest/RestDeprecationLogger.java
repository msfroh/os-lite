/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

/**
 * Logger for deprecation warnings. The server provides an implementation (e.g. {@code DeprecationLogger}).
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestDeprecationLogger {

    void deprecate(String key, String message);
}
