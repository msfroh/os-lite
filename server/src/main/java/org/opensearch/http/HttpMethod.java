/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http;

import org.opensearch.common.annotation.PublicApi;

/**
 * HTTP method (GET, POST, PUT, etc.). Canonical type for the server and rest layers; lives in server since these are
 * HTTP concepts, not REST-specific.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    HEAD,
    PATCH,
    TRACE,
    CONNECT
}
