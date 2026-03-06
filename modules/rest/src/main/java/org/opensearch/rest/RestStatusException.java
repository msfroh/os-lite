/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.core.rest.RestStatus;

/**
 * Exception that carries a REST status code. Used when building error responses.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestStatusException {

    RestStatus status();
}
