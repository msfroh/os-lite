/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest.action;

import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;

/**
 * A REST enabled action listener that has a basic onFailure implementation, and requires
 * sub classes to only implement {@link #buildResponse(Object)}.
 */
public abstract class RestResponseListener<Response> extends RestActionListener<Response> {

    protected RestResponseListener(RestChannel channel) {
        super(channel);
    }

    @Override
    protected final void processResponse(Response response) throws Exception {
        channel.sendResponse(buildResponse(response));
    }

    public abstract RestResponse buildResponse(Response response) throws Exception;
}
