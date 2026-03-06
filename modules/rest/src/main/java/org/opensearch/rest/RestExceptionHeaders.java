/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

import java.util.List;
import java.util.Set;

/**
 * Exception that can contribute headers to a REST response. Used by {@link RestResponse#copyHeaders(RestExceptionHeaders)}.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestExceptionHeaders {

    Set<String> getHeaderKeys();

    List<String> getHeader(String key);
}
