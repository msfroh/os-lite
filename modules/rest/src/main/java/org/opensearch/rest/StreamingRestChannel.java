/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.rest.RestStatus;

import java.util.List;
import java.util.Map;

import org.reactivestreams.Publisher;

/**
 * A streaming channel used to prepare response and send the response in chunks.
 *
 * @opensearch.experimental
 */
@ExperimentalApi
public interface StreamingRestChannel extends RestChannel, Publisher<RestChunk> {

    void sendChunk(RestChunk chunk);

    void prepareResponse(RestStatus status, Map<String, List<String>> headers);

    boolean isReadable();

    boolean isWritable();
}
