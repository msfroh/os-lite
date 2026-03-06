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
import org.opensearch.common.Nullable;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.breaker.CircuitBreaker;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.indices.breaker.CircuitBreakerService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import org.reactivestreams.Subscriber;
import reactor.core.publisher.Mono;

import static org.opensearch.core.rest.RestStatus.BAD_REQUEST;
import static org.opensearch.core.rest.RestStatus.INTERNAL_SERVER_ERROR;
import static org.opensearch.core.rest.RestStatus.METHOD_NOT_ALLOWED;
import static org.opensearch.core.rest.RestStatus.NOT_ACCEPTABLE;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.rest.BytesRestResponse.TEXT_CONTENT_TYPE;

/**
 * OpenSearch REST controller. Implements {@link RestDispatcher}; the server provides
 * {@link HandlerRegistry} (e.g. PathTrie-based) and {@link RestClient} (e.g. NodeClient).
 */
public class RestController implements RestDispatcher {

    private static final Logger logger = LogManager.getLogger(RestController.class);
    private final RestDeprecationLogger deprecationLogger;
    private static final String OPENSEARCH_PRODUCT_ORIGIN_HTTP_HEADER = "X-opensearch-product-origin";

    private static final BytesReference FAVICON_RESPONSE;

    static {
        try (InputStream stream = RestController.class.getResourceAsStream("/config/favicon.ico")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(stream, out);
            FAVICON_RESPONSE = new BytesArray(out.toByteArray());
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private final HandlerRegistry<RestMethodHandlers> handlers;
    private final UnaryOperator<RestHandler> handlerWrapper;
    private final RestClient client;
    private final CircuitBreakerService circuitBreakerService;
    private final Set<RestHeaderDefinition> headersToCopy;
    private final RestUsageService usageService;

    public RestController(
        HandlerRegistry<RestMethodHandlers> handlers,
        Set<RestHeaderDefinition> headersToCopy,
        UnaryOperator<RestHandler> handlerWrapper,
        RestClient client,
        CircuitBreakerService circuitBreakerService,
        RestUsageService usageService,
        RestDeprecationLogger deprecationLogger
    ) {
        this.handlers = handlers;
        this.headersToCopy = headersToCopy;
        this.usageService = usageService;
        this.handlerWrapper = handlerWrapper != null ? handlerWrapper : h -> h;
        this.client = client;
        this.circuitBreakerService = circuitBreakerService;
        this.deprecationLogger = deprecationLogger;
        registerHandlerNoWrap(
            RestRequest.Method.GET,
            "/favicon.ico",
            (request, channel, clnt) -> channel.sendResponse(new BytesRestResponse(RestStatus.OK, "image/x-icon", FAVICON_RESPONSE))
        );
    }

    protected HandlerRegistry<RestMethodHandlers> getHandlers() {
        return handlers;
    }

    public Iterator<MethodHandlers> getAllHandlers() {
        List<MethodHandlers> methodHandlers = new ArrayList<>();
        handlers.retrieveAll().forEachRemaining(methodHandlers::add);
        return methodHandlers.iterator();
    }

    protected void registerAsDeprecatedHandler(RestRequest.Method method, String path, RestHandler handler, String deprecationMessage) {
        assert (handler instanceof DeprecationRestHandler) == false;
        registerHandler(method, path, new DeprecationRestHandler(handler, deprecationMessage, deprecationLogger));
    }

    protected void registerWithDeprecatedHandler(
        RestRequest.Method method,
        String path,
        RestHandler handler,
        RestRequest.Method deprecatedMethod,
        String deprecatedPath
    ) {
        final String deprecationMessage = "["
            + deprecatedMethod.name()
            + " "
            + deprecatedPath
            + "] is deprecated! Use ["
            + method.name()
            + " "
            + path
            + "] instead.";
        registerHandler(method, path, handler);
        registerAsDeprecatedHandler(deprecatedMethod, deprecatedPath, handler, deprecationMessage);
    }

    protected void registerHandler(RestRequest.Method method, String path, RestHandler handler) {
        if (handler instanceof BaseRestHandler) {
            usageService.addRestHandler((BaseRestHandler) handler);
        }
        registerHandlerNoWrap(method, path, handlerWrapper.apply(handler));
    }

    private void registerHandlerNoWrap(RestRequest.Method method, String path, RestHandler maybeWrappedHandler) {
        handlers.insertOrUpdate(
            path,
            new RestMethodHandlers(path, maybeWrappedHandler, method),
            (mHandlers, newMHandler) -> mHandlers.addMethods(maybeWrappedHandler, method)
        );
    }

    public void registerHandler(final RestHandler restHandler) {
        restHandler.routes().forEach(route -> registerHandler(route.getMethod(), route.getPath(), restHandler));
        restHandler.deprecatedRoutes()
            .forEach(route -> registerAsDeprecatedHandler(route.getMethod(), route.getPath(), restHandler, route.getDeprecationMessage()));
        restHandler.replacedRoutes()
            .forEach(
                route -> registerWithDeprecatedHandler(
                    route.getMethod(),
                    route.getPath(),
                    restHandler,
                    route.getDeprecatedMethod(),
                    route.getDeprecatedPath()
                )
            );
    }

    @Override
    public Optional<RestHandler> dispatchHandler(String uri, String rawPath, RestRequest.Method method, Map<String, String> params) {
        final Iterator<RestMethodHandlers> allHandlers = getAllRestMethodHandlers(params, rawPath);
        while (allHandlers.hasNext()) {
            final RestMethodHandlers methodHandlers = allHandlers.next();
            if (methodHandlers == null) {
                continue;
            }
            final RestHandler handler = methodHandlers.getHandler(method);
            if (handler != null) {
                return Optional.of(handler);
            }
            final Set<RestRequest.Method> validMethodSet = getValidHandlerMethodSet(rawPath);
            if (!validMethodSet.contains(method)) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    @Override
    public void dispatchRequest(RestRequest request, RestChannel channel, RestRequestContext requestContext) {
        try {
            tryAllHandlers(request, channel, requestContext);
        } catch (Exception e) {
            try {
                channel.sendResponse(new BytesRestResponse(channel, e));
            } catch (Exception inner) {
                inner.addSuppressed(e);
                logger.error(() -> new ParameterizedMessage("failed to send failure response for uri [{}]", request.uri()), inner);
            }
        }
    }

    @Override
    public void dispatchBadRequest(RestChannel channel, RestRequestContext requestContext, Throwable cause) {
        try {
            final Exception e;
            if (cause == null) {
                e = new Exception("unknown cause");
            } else if (cause instanceof Exception) {
                e = (Exception) cause;
            } else {
                e = new Exception(cause);
            }
            channel.sendResponse(new BytesRestResponse(channel, BAD_REQUEST, e));
        } catch (IOException ex) {
            if (cause != null) {
                ex.addSuppressed(cause);
            }
            logger.warn("failed to send bad request response", ex);
            channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR, TEXT_CONTENT_TYPE, BytesArray.EMPTY));
        }
    }

    private void dispatchRequest(RestRequest request, RestChannel channel, RestHandler handler) throws Exception {
        final int contentLength = request.content().length();
        final MediaType mediaType = request.getMediaType();
        if (contentLength > 0) {
            if (mediaType == null) {
                sendContentTypeErrorMessage(request.getAllHeaderValues("Content-Type"), channel);
                return;
            }
            if (handler.supportsContentStream() && mediaType != MediaTypeRegistry.JSON && mediaType != XContentType.SMILE) {
                channel.sendResponse(
                    BytesRestResponse.createSimpleErrorResponse(
                        channel,
                        RestStatus.NOT_ACCEPTABLE,
                        "Content-Type [" + mediaType + "] does not support stream parsing. Use JSON or SMILE instead"
                    )
                );
                return;
            }
        }

        RestChannel responseChannel = channel;
        try {
            if (handler.canTripCircuitBreaker()) {
                inFlightRequestsBreaker(circuitBreakerService).addEstimateBytesAndMaybeBreak(contentLength, "<http_request>");
            } else {
                inFlightRequestsBreaker(circuitBreakerService).addWithoutBreaking(contentLength);
            }

            if (handler.supportsStreaming()) {
                if (channel instanceof StreamingRestChannel) {
                    responseChannel = new StreamHandlingRestChannel((StreamingRestChannel) channel, circuitBreakerService, contentLength);
                } else {
                    throw new IllegalStateException(
                        "The engine does not support HTTP streaming, unable to serve uri ["
                            + request.uri()
                            + "] and method ["
                            + request.method()
                            + "]"
                    );
                }
                if (mediaType == null) {
                    sendContentTypeErrorMessage(request.getAllHeaderValues("Content-Type"), responseChannel);
                    return;
                }
            } else {
                responseChannel = new ResourceHandlingRestChannel(channel, circuitBreakerService, contentLength);
            }

            if (!handler.allowsUnsafeBuffers()) {
                request.ensureSafeBuffers();
            }

            handler.handleRequest(request, responseChannel, client);
        } catch (Exception e) {
            responseChannel.sendResponse(new BytesRestResponse(responseChannel, e));
        }
    }

    private boolean handleNoHandlerFound(String rawPath, RestRequest.Method method, String uri, RestChannel channel) {
        final Set<RestRequest.Method> validMethodSet = getValidHandlerMethodSet(rawPath);
        if (!validMethodSet.contains(method)) {
            if (method == RestRequest.Method.OPTIONS) {
                handleOptionsRequest(channel, validMethodSet);
                return true;
            }
            if (!validMethodSet.isEmpty()) {
                handleUnsupportedHttpMethod(uri, method, channel, validMethodSet, null);
                return true;
            }
        }
        return false;
    }

    private void sendContentTypeErrorMessage(@Nullable List<String> contentTypeHeader, RestChannel channel) throws IOException {
        final String errorMessage;
        if (contentTypeHeader == null) {
            errorMessage = "Content-Type header is missing";
        } else {
            errorMessage = "Content-Type header [" + Strings.collectionToCommaDelimitedString(contentTypeHeader) + "] is not supported";
        }
        channel.sendResponse(BytesRestResponse.createSimpleErrorResponse(channel, NOT_ACCEPTABLE, errorMessage));
    }

    private void tryAllHandlers(final RestRequest request, final RestChannel channel, final RestRequestContext requestContext) throws Exception {
        for (final RestHeaderDefinition restHeader : headersToCopy) {
            final String name = restHeader.getName();
            final List<String> headerValues = request.getAllHeaderValues(name);
            if (headerValues != null && !headerValues.isEmpty()) {
                final List<String> distinctHeaderValues = headerValues.stream().distinct().collect(Collectors.toList());
                if (!restHeader.isMultiValueAllowed() && distinctHeaderValues.size() > 1) {
                    channel.sendResponse(
                        BytesRestResponse.createSimpleErrorResponse(
                            channel,
                            BAD_REQUEST,
                            "multiple values for single-valued header [" + name + "]."
                        )
                    );
                    return;
                } else {
                    requestContext.putHeader(name, String.join(",", distinctHeaderValues));
                }
            }
        }
        if (request.paramAsBoolean("error_trace", false) && !channel.detailedErrorsEnabled()) {
            channel.sendResponse(
                BytesRestResponse.createSimpleErrorResponse(channel, BAD_REQUEST, "error traces in responses are disabled.")
            );
            return;
        }

        final String rawPath = request.rawPath();
        final String uri = request.uri();
        final RestRequest.Method requestMethod;
        try {
            requestMethod = request.method();
            Iterator<RestMethodHandlers> allHandlers = getAllRestMethodHandlers(request.params(), rawPath);
            while (allHandlers.hasNext()) {
                final RestMethodHandlers methodHandlers = allHandlers.next();
                final RestHandler handler = methodHandlers != null ? methodHandlers.getHandler(requestMethod) : null;
                if (handler == null) {
                    if (handleNoHandlerFound(rawPath, requestMethod, uri, channel)) {
                        return;
                    }
                } else {
                    dispatchRequest(request, channel, handler);
                    return;
                }
            }
        } catch (IllegalArgumentException e) {
            handleUnsupportedHttpMethod(uri, null, channel, getValidHandlerMethodSet(rawPath), e);
            return;
        }
        handleBadRequest(uri, requestMethod, channel);
    }

    Iterator<RestMethodHandlers> getAllRestMethodHandlers(@Nullable Map<String, String> requestParamsRef, String rawPath) {
        final Supplier<Map<String, String>> paramsSupplier;
        if (requestParamsRef == null) {
            paramsSupplier = () -> null;
        } else {
            final Map<String, String> originalParams = new HashMap<>(requestParamsRef);
            paramsSupplier = () -> {
                requestParamsRef.clear();
                requestParamsRef.putAll(originalParams);
                return requestParamsRef;
            };
        }
        return handlers.retrieveAll(rawPath, paramsSupplier);
    }

    private void handleUnsupportedHttpMethod(
        String uri,
        @Nullable RestRequest.Method method,
        RestChannel channel,
        Set<RestRequest.Method> validMethodSet,
        @Nullable IllegalArgumentException exception
    ) {
        try {
            final StringBuilder msg = new StringBuilder();
            if (exception == null) {
                msg.append("Incorrect HTTP method for uri [").append(uri).append("] and method [").append(method).append("]");
            } else {
                msg.append("Unexpected HTTP method");
            }
            if (!validMethodSet.isEmpty()) {
                msg.append(", allowed: ").append(validMethodSet);
            }
            BytesRestResponse bytesRestResponse = BytesRestResponse.createSimpleErrorResponse(channel, METHOD_NOT_ALLOWED, msg.toString());
            if (!validMethodSet.isEmpty()) {
                bytesRestResponse.addHeader("Allow", Strings.collectionToDelimitedString(validMethodSet, ","));
            }
            channel.sendResponse(bytesRestResponse);
        } catch (IOException e) {
            logger.warn("failed to send bad request response", e);
            channel.sendResponse(new BytesRestResponse(INTERNAL_SERVER_ERROR, TEXT_CONTENT_TYPE, BytesArray.EMPTY));
        }
    }

    private void handleOptionsRequest(RestChannel channel, Set<RestRequest.Method> validMethodSet) {
        BytesRestResponse bytesRestResponse = new BytesRestResponse(OK, TEXT_CONTENT_TYPE, BytesArray.EMPTY);
        if (!validMethodSet.isEmpty()) {
            bytesRestResponse.addHeader("Allow", Strings.collectionToDelimitedString(validMethodSet, ","));
        }
        channel.sendResponse(bytesRestResponse);
    }

    private void handleBadRequest(String uri, RestRequest.Method method, RestChannel channel) throws IOException {
        try (XContentBuilder builder = channel.newErrorBuilder()) {
            builder.startObject();
            try {
                uri = new URI(uri).getPath();
                builder.field("error", "no handler found for uri [" + uri + "] and method [" + method + "]");
            } catch (Exception e) {
                builder.field("error", "invalid uri has been requested");
            }
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(BAD_REQUEST, builder));
        }
    }

    private Set<RestRequest.Method> getValidHandlerMethodSet(String rawPath) {
        Set<RestRequest.Method> validMethods = new HashSet<>();
        Iterator<RestMethodHandlers> allHandlers = getAllRestMethodHandlers(null, rawPath);
        while (allHandlers.hasNext()) {
            final MethodHandlers methodHandlers = allHandlers.next();
            if (methodHandlers != null) {
                validMethods.addAll(methodHandlers.getValidMethods());
            }
        }
        return validMethods;
    }

    private static CircuitBreaker inFlightRequestsBreaker(CircuitBreakerService circuitBreakerService) {
        return circuitBreakerService.getBreaker(CircuitBreaker.IN_FLIGHT_REQUESTS);
    }

    private static final class ResourceHandlingRestChannel implements RestChannel {
        private final RestChannel delegate;
        private final CircuitBreakerService circuitBreakerService;
        private final int contentLength;
        private final AtomicBoolean closed = new AtomicBoolean();

        ResourceHandlingRestChannel(RestChannel delegate, CircuitBreakerService circuitBreakerService, int contentLength) {
            this.delegate = delegate;
            this.circuitBreakerService = circuitBreakerService;
            this.contentLength = contentLength;
        }

        @Override
        public XContentBuilder newBuilder() throws IOException { return delegate.newBuilder(); }

        @Override
        public XContentBuilder newErrorBuilder() throws IOException { return delegate.newErrorBuilder(); }

        @Override
        public XContentBuilder newBuilder(@Nullable MediaType mediaType, boolean useFiltering) throws IOException {
            return delegate.newBuilder(mediaType, useFiltering);
        }

        @Override
        public XContentBuilder newBuilder(MediaType mediaType, MediaType responseContentType, boolean useFiltering) throws IOException {
            return delegate.newBuilder(mediaType, responseContentType, useFiltering);
        }

        @Override
        public RestBytesStream bytesOutput() { return delegate.bytesOutput(); }

        @Override
        public RestRequest request() { return delegate.request(); }

        @Override
        public boolean detailedErrorsEnabled() { return delegate.detailedErrorsEnabled(); }

        @Override
        public boolean detailedErrorStackTraceEnabled() { return delegate.detailedErrorStackTraceEnabled(); }

        @Override
        public void sendResponse(RestResponse response) {
            close();
            delegate.sendResponse(response);
        }

        private void close() {
            if (!closed.compareAndSet(false, true)) {
                throw new IllegalStateException("Channel is already closed");
            }
            inFlightRequestsBreaker(circuitBreakerService).addWithoutBreaking(-contentLength);
        }
    }

    private static final class StreamHandlingRestChannel implements StreamingRestChannel {
        private final StreamingRestChannel delegate;
        private final CircuitBreakerService circuitBreakerService;
        private final int contentLength;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean subscribed = new AtomicBoolean();

        StreamHandlingRestChannel(StreamingRestChannel delegate, CircuitBreakerService circuitBreakerService, int contentLength) {
            this.delegate = delegate;
            this.circuitBreakerService = circuitBreakerService;
            this.contentLength = contentLength;
        }

        @Override
        public XContentBuilder newBuilder() throws IOException { return delegate.newBuilder(); }

        @Override
        public XContentBuilder newErrorBuilder() throws IOException { return delegate.newErrorBuilder(); }

        @Override
        public XContentBuilder newBuilder(@Nullable MediaType mediaType, boolean useFiltering) throws IOException {
            return delegate.newBuilder(mediaType, useFiltering);
        }

        @Override
        public XContentBuilder newBuilder(MediaType mediaType, MediaType responseContentType, boolean useFiltering) throws IOException {
            return delegate.newBuilder(mediaType, responseContentType, useFiltering);
        }

        @Override
        public RestBytesStream bytesOutput() { return delegate.bytesOutput(); }

        @Override
        public RestRequest request() { return delegate.request(); }

        @Override
        public boolean detailedErrorsEnabled() { return delegate.detailedErrorsEnabled(); }

        @Override
        public boolean detailedErrorStackTraceEnabled() { return delegate.detailedErrorStackTraceEnabled(); }

        @Override
        public void sendResponse(RestResponse response) {
            close();
            if (!subscribed.get()) {
                prepareResponse(response.status(), Map.of("Content-Type", List.of(response.contentType())));
            }
            Mono.from(this).ignoreElement().then(Mono.just(response)).subscribe(delegate::sendResponse);
        }

        @Override
        public void sendChunk(RestChunk chunk) {
            delegate.sendChunk(chunk);
        }

        @Override
        public void prepareResponse(RestStatus status, Map<String, List<String>> headers) {
            delegate.prepareResponse(status, headers);
        }

        @Override
        public void subscribe(Subscriber<? super RestChunk> subscriber) {
            subscribed.set(true);
            delegate.subscribe(subscriber);
        }

        private void close() {
            if (!closed.compareAndSet(false, true)) {
                throw new IllegalStateException("Channel is already closed");
            }
            inFlightRequestsBreaker(circuitBreakerService).addWithoutBreaking(-contentLength);
        }

        @Override
        public boolean isReadable() { return delegate.isReadable(); }

        @Override
        public boolean isWritable() { return delegate.isWritable(); }
    }
}
