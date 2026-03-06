/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.ExperimentalApi;
import org.opensearch.core.common.bytes.BytesReference;

/**
 * A chunk of a streaming REST response. The HTTP transport wraps its chunk type (e.g. HttpChunk) in this interface.
 *
 * @opensearch.experimental
 */
@ExperimentalApi
public interface RestChunk {

    /**
     * Whether this is the last chunk of the stream.
     */
    boolean isLast();

    /**
     * Content of this chunk.
     */
    BytesReference content();
}
