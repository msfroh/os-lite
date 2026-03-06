/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.Nullable;
import org.opensearch.common.annotation.PublicApi;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * A channel used to construct bytes / builder based outputs, and send responses.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface RestChannel {

    XContentBuilder newBuilder() throws IOException;

    XContentBuilder newErrorBuilder() throws IOException;

    XContentBuilder newBuilder(@Nullable MediaType mediaType, boolean useFiltering) throws IOException;

    XContentBuilder newBuilder(@Nullable MediaType mediaType, @Nullable MediaType responseContentType, boolean useFiltering)
        throws IOException;

    RestBytesStream bytesOutput();

    RestRequest request();

    boolean detailedErrorsEnabled();

    boolean detailedErrorStackTraceEnabled();

    void sendResponse(RestResponse response);
}
