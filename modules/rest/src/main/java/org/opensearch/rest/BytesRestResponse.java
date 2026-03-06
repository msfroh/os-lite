/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.logging.log4j.util.Supplier;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * REST response in bytes. Error responses use {@link RestStatusException} for status and
 * {@link RestExceptionHeaders} for headers when available.
 */
public class BytesRestResponse extends RestResponse {

    public static final String TEXT_CONTENT_TYPE = "text/plain; charset=UTF-8";
    public static final String REST_EXCEPTION_SKIP_STACK_TRACE = "rest.exception.skip_stack_trace";
    public static final boolean REST_EXCEPTION_SKIP_STACK_TRACE_DEFAULT = false;

    private static final String STATUS = "status";
    private static final Logger SUPPRESSED_ERROR_LOGGER = LogManager.getLogger("rest.suppressed");

    private final RestStatus status;
    private final BytesReference content;
    private final String contentType;

    public BytesRestResponse(RestStatus status, XContentBuilder builder) {
        this(status, builder.contentType().mediaType(), BytesReference.bytes(builder));
    }

    public BytesRestResponse(RestStatus status, String content) {
        this(status, TEXT_CONTENT_TYPE, new BytesArray(content));
    }

    public BytesRestResponse(RestStatus status, String contentType, String content) {
        this(status, contentType, new BytesArray(content));
    }

    public BytesRestResponse(RestStatus status, String contentType, byte[] content) {
        this(status, contentType, new BytesArray(content));
    }

    public BytesRestResponse(RestStatus status, String contentType, BytesReference content) {
        this.status = status;
        this.content = content;
        this.contentType = contentType;
    }

    public BytesRestResponse(RestChannel channel, Exception e) throws IOException {
        this(channel, statusFrom(e), e);
    }

    public BytesRestResponse(RestChannel channel, RestStatus status, Exception e) throws IOException {
        ToXContent.Params params = channel.request();
        if (params.paramAsBoolean(REST_EXCEPTION_SKIP_STACK_TRACE, !REST_EXCEPTION_SKIP_STACK_TRACE_DEFAULT) && e != null) {
            Supplier<?> messageSupplier = () -> new ParameterizedMessage(
                "path: {}, params: {}",
                channel.request().rawPath(),
                channel.request().params()
            );
            if (status.getStatus() < 500) {
                SUPPRESSED_ERROR_LOGGER.debug(messageSupplier, e);
            } else {
                SUPPRESSED_ERROR_LOGGER.warn(messageSupplier, e);
            }
        }
        this.status = status;
        try (XContentBuilder builder = channel.newErrorBuilder()) {
            buildErrorContent(builder, status, channel.detailedErrorsEnabled(), e);
            this.content = BytesReference.bytes(builder);
            this.contentType = builder.contentType().mediaType();
        }
        if (e instanceof RestExceptionHeaders) {
            copyHeaders((RestExceptionHeaders) e);
        }
    }

    private static RestStatus statusFrom(Exception e) {
        if (e instanceof RestStatusException) {
            return ((RestStatusException) e).status();
        }
        return RestStatus.INTERNAL_SERVER_ERROR;
    }

    private void buildErrorContent(XContentBuilder builder, RestStatus status, boolean detailedErrorsEnabled, Exception e)
        throws IOException {
        builder.startObject();
        builder.field("type", e != null ? e.getClass().getSimpleName() : "unknown");
        builder.field("reason", e != null ? e.getMessage() : "unknown");
        if (detailedErrorsEnabled && e != null && e.getCause() != null) {
            builder.startArray("root_cause");
            Throwable t = e.getCause();
            while (t != null) {
                builder.startObject();
                builder.field("type", t.getClass().getSimpleName());
                builder.field("reason", t.getMessage());
                builder.endObject();
                t = t.getCause();
            }
            builder.endArray();
        }
        if (detailedErrorsEnabled && e != null) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            builder.field("stack_trace", sw.toString());
        }
        builder.field(STATUS, status.getStatus());
        builder.endObject();
    }

    @Override
    public String contentType() {
        return this.contentType;
    }

    @Override
    public BytesReference content() {
        return this.content;
    }

    @Override
    public RestStatus status() {
        return this.status;
    }

    protected boolean skipStackTrace() {
        return false;
    }

    public static BytesRestResponse createSimpleErrorResponse(RestChannel channel, RestStatus status, String errorMessage) throws IOException {
        return new BytesRestResponse(
            status,
            channel.newErrorBuilder().startObject().field("error", errorMessage).field("status", status.getStatus()).endObject()
        );
    }
}
