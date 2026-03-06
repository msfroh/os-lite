/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.OpenSearchParseException;
import org.opensearch.common.Booleans;
import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.Nullable;
import org.opensearch.common.SetOnce;
import org.opensearch.common.annotation.PublicApi;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.opensearch.common.unit.TimeValue.parseTimeValue;
import static org.opensearch.core.common.unit.ByteSizeValue.parseBytesSizeValue;

/**
 * REST Request. Built only from {@link IncomingRequest}; the server adapts HTTP to IncomingRequest.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public class RestRequest implements ToXContent.Params {

    private static final Pattern TCHAR_PATTERN = Pattern.compile("[a-zA-z0-9!#$%&'*+\\-.\\^_`|~]+");
    private static final AtomicLong requestIdGenerator = new AtomicLong();

    private final NamedXContentRegistry xContentRegistry;
    private final Map<String, String> params;
    private final Map<String, List<String>> headers;
    private final String rawPath;
    private final Set<String> consumedParams = new HashSet<>();
    private final SetOnce<MediaType> mediaType = new SetOnce<>();
    private IncomingRequest source;

    private boolean contentConsumed = false;
    private final long requestId;

    public boolean isContentConsumed() {
        return contentConsumed;
    }

    RestRequest(
        NamedXContentRegistry xContentRegistry,
        Map<String, String> params,
        String path,
        Map<String, List<String>> headers,
        IncomingRequest source,
        long requestId
    ) {
        final MediaType parsedMediaType;
        try {
            parsedMediaType = parseContentType(headers.get("Content-Type"));
        } catch (final IllegalArgumentException e) {
            throw new ContentTypeHeaderException(e);
        }
        if (parsedMediaType != null) {
            this.mediaType.set(parsedMediaType);
        }
        this.xContentRegistry = xContentRegistry;
        this.source = source;
        this.params = params;
        this.rawPath = path;
        this.headers = Collections.unmodifiableMap(headers);
        this.requestId = requestId;
    }

    protected RestRequest(RestRequest restRequest) {
        this(
            restRequest.getXContentRegistry(),
            restRequest.params(),
            restRequest.rawPath(),
            restRequest.getHeaders(),
            restRequest.source,
            restRequest.getRequestId()
        );
    }

    void ensureSafeBuffers() {
        this.source = this.source.releaseAndCopy();
    }

    public static RestRequest request(NamedXContentRegistry xContentRegistry, IncomingRequest incomingRequest) {
        Map<String, String> params = params(incomingRequest.uri());
        String path = path(incomingRequest.uri());
        return new RestRequest(
            xContentRegistry,
            params,
            path,
            incomingRequest.getHeaders(),
            incomingRequest,
            requestIdGenerator.incrementAndGet()
        );
    }

    private static Map<String, String> params(final String uri) {
        final Map<String, String> params = new HashMap<>();
        int index = uri.indexOf('?');
        if (index >= 0) {
            try {
                RestUtils.decodeQueryString(uri, index + 1, params);
            } catch (final IllegalArgumentException e) {
                throw new BadParameterException(e);
            }
        }
        return params;
    }

    private static String path(final String uri) {
        final int index = uri.indexOf('?');
        if (index >= 0) {
            return uri.substring(0, index);
        } else {
            return uri;
        }
    }

    public static RestRequest requestWithoutParameters(NamedXContentRegistry xContentRegistry, IncomingRequest incomingRequest) {
        Map<String, String> params = Collections.emptyMap();
        return new RestRequest(
            xContentRegistry,
            params,
            incomingRequest.uri(),
            incomingRequest.getHeaders(),
            incomingRequest,
            requestIdGenerator.incrementAndGet()
        );
    }

    public org.opensearch.http.HttpMethod method() {
        return source.method();
    }

    public String uri() {
        return source.uri();
    }

    public String rawPath() {
        return rawPath;
    }

    public final String path() {
        return RestUtils.decodeComponent(rawPath());
    }

    public boolean hasContent() {
        return content(false).length() > 0;
    }

    public BytesReference content() {
        return content(true);
    }

    protected BytesReference content(final boolean contentConsumed) {
        this.contentConsumed = this.contentConsumed | contentConsumed;
        return source.content();
    }

    public final BytesReference requiredContent() {
        if (hasContent() == false) {
            throw new OpenSearchParseException("request body is required");
        } else if (mediaType.get() == null) {
            throw new IllegalStateException("unknown content type");
        }
        return content();
    }

    public final String header(String name) {
        List<String> values = headers.get(name);
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }

    public final List<String> getAllHeaderValues(String name) {
        List<String> values = headers.get(name);
        if (values != null) {
            return Collections.unmodifiableList(values);
        }
        return null;
    }

    public final Map<String, List<String>> getHeaders() {
        return headers;
    }

    public final long getRequestId() {
        return requestId;
    }

    @Nullable
    public final MediaType getMediaType() {
        return mediaType.get();
    }

    public List<String> getStrictCookies() {
        return source.strictCookies();
    }

    public final boolean hasParam(String key) {
        return params.containsKey(key);
    }

    @Override
    public final String param(String key) {
        consumedParams.add(key);
        return params.get(key);
    }

    @Override
    public final String param(String key, String defaultValue) {
        consumedParams.add(key);
        String value = params.get(key);
        return value != null ? value : defaultValue;
    }

    public Map<String, String> params() {
        return params;
    }

    public List<String> consumedParams() {
        return new ArrayList<>(consumedParams);
    }

    List<String> unconsumedParams() {
        return params.keySet().stream().filter(p -> !consumedParams.contains(p)).collect(Collectors.toList());
    }

    public float paramAsFloat(String key, float defaultValue) {
        String sValue = param(key);
        if (sValue == null) return defaultValue;
        try {
            return Float.parseFloat(sValue);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Failed to parse float parameter [" + key + "] with value [" + sValue + "]", e);
        }
    }

    public int paramAsInt(String key, int defaultValue) {
        String sValue = param(key);
        if (sValue == null) return defaultValue;
        try {
            return Integer.parseInt(sValue);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Failed to parse int parameter [" + key + "] with value [" + sValue + "]", e);
        }
    }

    public long paramAsLong(String key, long defaultValue) {
        String sValue = param(key);
        if (sValue == null) return defaultValue;
        try {
            return Long.parseLong(sValue);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Failed to parse long parameter [" + key + "] with value [" + sValue + "]", e);
        }
    }

    @Override
    public boolean paramAsBoolean(String key, boolean defaultValue) {
        String rawParam = param(key);
        if (rawParam != null && rawParam.length() == 0) return true;
        return Booleans.parseBoolean(rawParam, defaultValue);
    }

    @Override
    public Boolean paramAsBoolean(String key, Boolean defaultValue) {
        return Booleans.parseBoolean(param(key), defaultValue);
    }

    public TimeValue paramAsTime(String key, TimeValue defaultValue) {
        return parseTimeValue(param(key), defaultValue, key);
    }

    public ByteSizeValue paramAsSize(String key, ByteSizeValue defaultValue) {
        return parseBytesSizeValue(param(key), defaultValue, key);
    }

    public String[] paramAsStringArray(String key, String[] defaultValue) {
        String value = param(key);
        if (value == null) return defaultValue;
        return Strings.splitStringByCommaToArray(value);
    }

    public String[] paramAsStringArrayOrEmptyIfAll(String key) {
        String[] params = paramAsStringArray(key, Strings.EMPTY_ARRAY);
        if (Strings.isAllOrWildcard(params)) return Strings.EMPTY_ARRAY;
        return params;
    }

    public NamedXContentRegistry getXContentRegistry() {
        return xContentRegistry;
    }

    public final XContentParser contentParser() throws IOException {
        BytesReference content = requiredContent();
        return mediaType.get().xContent().createParser(xContentRegistry, DeprecationHandler.IGNORE_DEPRECATIONS, content.streamInput());
    }

    public final void applyContentParser(CheckedConsumer<XContentParser, IOException> applyParser) throws IOException {
        if (hasContent()) {
            try (XContentParser parser = contentParser()) {
                applyParser.accept(parser);
            }
        }
    }

    public final boolean hasContentOrSourceParam() {
        return hasContent() || hasParam("source");
    }

    public final XContentParser contentOrSourceParamParser() throws IOException {
        Tuple<MediaType, BytesReference> tuple = contentOrSourceParam();
        return tuple.v1().xContent().createParser(xContentRegistry, DeprecationHandler.IGNORE_DEPRECATIONS, tuple.v2().streamInput());
    }

    public final void withContentOrSourceParamParserOrNull(CheckedConsumer<XContentParser, IOException> withParser) throws IOException {
        if (hasContentOrSourceParam()) {
            Tuple<MediaType, BytesReference> tuple = contentOrSourceParam();
            BytesReference content = tuple.v2();
            MediaType mt = tuple.v1();
            try (
                InputStream stream = content.streamInput();
                XContentParser parser = mt.xContent().createParser(xContentRegistry, DeprecationHandler.IGNORE_DEPRECATIONS, stream)
            ) {
                withParser.accept(parser);
            }
        } else {
            withParser.accept(null);
        }
    }

    public final Tuple<MediaType, BytesReference> contentOrSourceParam() {
        if (!hasContentOrSourceParam()) {
            throw new OpenSearchParseException("request body or source parameter is required");
        }
        if (hasContent()) {
            return new Tuple<>(mediaType.get(), requiredContent());
        }
        String sourceParam = param("source");
        String typeParam = param("source_content_type");
        if (sourceParam == null || typeParam == null) {
            throw new IllegalStateException("source and source_content_type parameters are required");
        }
        BytesArray bytes = new BytesArray(sourceParam);
        MediaType mt = parseContentType(Collections.singletonList(typeParam));
        if (mt == null) {
            throw new IllegalStateException("Unknown value for source_content_type [" + typeParam + "]");
        }
        return new Tuple<>(mt, bytes);
    }

    public static MediaType parseContentType(List<String> header) {
        if (header == null || header.isEmpty()) return null;
        if (header.size() > 1) {
            throw new IllegalArgumentException("only one Content-Type header should be provided");
        }
        String rawContentType = header.get(0);
        final String[] elements = rawContentType.split("[ \t]*;");
        if (elements.length > 0) {
            final String[] splitMediaType = elements[0].split("/");
            if (splitMediaType.length == 2
                && TCHAR_PATTERN.matcher(splitMediaType[0]).matches()
                && TCHAR_PATTERN.matcher(splitMediaType[1].trim()).matches()) {
                return MediaType.fromMediaType(elements[0]);
            } else {
                throw new IllegalArgumentException("invalid Content-Type header [" + rawContentType + "]");
            }
        }
        throw new IllegalArgumentException("empty Content-Type header");
    }

    public static final class ContentTypeHeaderException extends RuntimeException {
        ContentTypeHeaderException(IllegalArgumentException cause) {
            super(cause);
        }
    }

    public static final class BadParameterException extends RuntimeException {
        BadParameterException(IllegalArgumentException cause) {
            super(cause);
        }
    }
}
