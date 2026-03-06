/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.Nullable;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Set;
import java.util.function.Predicate;

import static java.util.stream.Collectors.toSet;

/**
 * Base REST channel
 */
public abstract class AbstractRestChannel implements RestChannel {

    private static final Predicate<String> INCLUDE_FILTER = f -> f.charAt(0) != '-';
    private static final Predicate<String> EXCLUDE_FILTER = INCLUDE_FILTER.negate();

    protected final RestRequest request;
    private final boolean detailedErrorsEnabled;
    private final String format;
    private final String filterPath;
    private final boolean pretty;
    private final boolean human;
    private final String acceptHeader;
    private final boolean detailedErrorStackTraceRequested;

    private RestBytesStream bytesOut;

    protected AbstractRestChannel(RestRequest request, boolean detailedErrorsEnabled) {
        this.request = request;
        this.detailedErrorsEnabled = detailedErrorsEnabled;
        this.format = request.param("format");
        this.acceptHeader = request.header("Accept");
        this.filterPath = request.param("filter_path", null);
        this.pretty = request.paramAsBoolean("pretty", false);
        this.human = request.paramAsBoolean("human", false);
        this.detailedErrorStackTraceRequested = request.paramAsBoolean("error_trace", false);
    }

    @Override
    public XContentBuilder newBuilder() throws IOException {
        return newBuilder(request.getMediaType(), true);
    }

    @Override
    public XContentBuilder newErrorBuilder() throws IOException {
        return newBuilder(request.getMediaType(), false);
    }

    @Override
    public XContentBuilder newBuilder(@Nullable MediaType requestContentType, boolean useFiltering) throws IOException {
        return newBuilder(requestContentType, null, useFiltering);
    }

    @Override
    public XContentBuilder newBuilder(@Nullable MediaType requestContentType, @Nullable MediaType responseContentType, boolean useFiltering)
        throws IOException {
        if (responseContentType == null) {
            responseContentType = MediaType.fromFormat(format);
            if (responseContentType == null) {
                responseContentType = MediaType.fromMediaType(acceptHeader);
            }
        }
        if (responseContentType == null) {
            if (requestContentType != null) {
                responseContentType = requestContentType;
            } else {
                responseContentType = MediaTypeRegistry.getDefaultMediaType();
            }
        }

        Set<String> includes = Collections.emptySet();
        Set<String> excludes = Collections.emptySet();
        if (useFiltering) {
            Set<String> filters = Strings.tokenizeByCommaToSet(filterPath);
            includes = filters.stream().filter(INCLUDE_FILTER).collect(toSet());
            excludes = filters.stream().filter(EXCLUDE_FILTER).map(f -> f.substring(1)).collect(toSet());
        }

        OutputStream unclosableOutputStream = RestStreams.flushOnCloseStream((OutputStream) bytesOutput());
        XContentBuilder builder = new XContentBuilder(responseContentType.xContent(), unclosableOutputStream, includes, excludes);
        if (pretty) {
            builder.prettyPrint().lfAtEnd();
        }
        builder.humanReadable(human);
        return builder;
    }

    @Override
    public final RestBytesStream bytesOutput() {
        if (bytesOut == null) {
            bytesOut = newBytesOutput();
        } else {
            bytesOut.reset();
        }
        return bytesOut;
    }

    protected final RestBytesStream bytesOutputOrNull() {
        return bytesOut;
    }

    protected RestBytesStream newBytesOutput() {
        return new RestBytesStream.Default();
    }

    @Override
    public RestRequest request() {
        return this.request;
    }

    @Override
    public boolean detailedErrorsEnabled() {
        return detailedErrorsEnabled;
    }

    public boolean detailedErrorStackTraceEnabled() {
        return detailedErrorStackTraceRequested;
    }
}
