/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream output for building REST response bytes. The server may wrap its own stream type (e.g. BytesStreamOutput).
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public abstract class RestBytesStream extends OutputStream {

    public abstract void reset();

    /**
     * Simple implementation using ByteArrayOutputStream. Server channels may use a different implementation.
     */
    public static final class Default extends RestBytesStream {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        @Override
        public void reset() {
            out.reset();
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            out.close();
        }
    }
}
