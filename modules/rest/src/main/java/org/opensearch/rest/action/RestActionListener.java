/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;

import java.io.IOException;

/**
 * An action listener that requires {@link #processResponse(Object)} to be implemented
 * and will automatically handle failures.
 */
public abstract class RestActionListener<Response> implements ActionListener<Response> {

    private static final Logger logger = LogManager.getLogger(RestActionListener.class);

    protected final RestChannel channel;

    protected RestActionListener(RestChannel channel) {
        this.channel = channel;
    }

    @Override
    public final void onResponse(Response response) {
        try {
            processResponse(response);
        } catch (Exception e) {
            onFailure(e);
        }
    }

    protected abstract void processResponse(Response response) throws Exception;

    private BytesRestResponse from(Exception e) throws IOException {
        try {
            return new BytesRestResponse(channel, e);
        } catch (Exception inner) {
            try {
                return new BytesRestResponse(channel, inner);
            } finally {
                inner.addSuppressed(e);
                logger.error("failed to construct failure response", inner);
            }
        }
    }

    @Override
    public final void onFailure(Exception e) {
        try {
            channel.sendResponse(from(e));
        } catch (Exception inner) {
            inner.addSuppressed(e);
            logger.error("failed to send failure response", inner);
        }
    }
}
