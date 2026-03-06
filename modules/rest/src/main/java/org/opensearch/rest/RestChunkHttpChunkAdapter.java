/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.core.common.bytes.BytesReference;

/**
 * Wraps a {@link RestChunk} and exposes chunk semantics (isLast, content, close).
 * The HTTP transport layer (server) uses this and presents it as its chunk type.
 *
 * @opensearch.internal
 */
public class RestChunkHttpChunkAdapter {

    private final RestChunk restChunk;

    public RestChunkHttpChunkAdapter(RestChunk restChunk) {
        this.restChunk = restChunk;
    }

    public boolean isLast() {
        return restChunk.isLast();
    }

    public BytesReference content() {
        return restChunk.content();
    }

    /**
     * No-op; RestChunk has no release. Subclasses in the transport layer may override.
     */
    public void close() {
        // no-op
    }
}
