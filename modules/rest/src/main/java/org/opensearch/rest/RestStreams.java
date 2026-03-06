/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Minimal stream utilities for the rest module (no dependency on server common).
 */
final class RestStreams {

    private RestStreams() {}

    /**
     * Wraps an output stream so that it is flushed on close.
     */
    static OutputStream flushOnCloseStream(OutputStream stream) {
        Objects.requireNonNull(stream);
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                stream.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                stream.write(b, off, len);
            }

            @Override
            public void flush() throws IOException {
                stream.flush();
            }

            @Override
            public void close() throws IOException {
                try {
                    stream.flush();
                } finally {
                    stream.close();
                }
            }
        };
    }
}
