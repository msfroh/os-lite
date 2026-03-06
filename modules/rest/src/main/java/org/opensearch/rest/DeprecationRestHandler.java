/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.core.common.Strings;

import java.util.Objects;

/**
 * Proxy for any existing {@link RestHandler} so that usage can be logged via {@link RestDeprecationLogger}.
 */
public class DeprecationRestHandler implements RestHandler {

    private final RestHandler handler;
    private final String deprecationMessage;
    private final RestDeprecationLogger deprecationLogger;

    public DeprecationRestHandler(RestHandler handler, String deprecationMessage, RestDeprecationLogger deprecationLogger) {
        this.handler = Objects.requireNonNull(handler);
        this.deprecationMessage = requireValidHeader(deprecationMessage);
        this.deprecationLogger = Objects.requireNonNull(deprecationLogger);
    }

    @Override
    public void handleRequest(RestRequest request, RestChannel channel, RestClient client) throws Exception {
        deprecationLogger.deprecate("deprecated_route", deprecationMessage);
        handler.handleRequest(request, channel, client);
    }

    @Override
    public boolean supportsContentStream() {
        return handler.supportsContentStream();
    }

    public static boolean validHeaderValue(String value) {
        if (Strings.hasText(value) == false) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 32 || c > 126) {
                return false;
            }
        }
        return true;
    }

    public static String requireValidHeader(String value) {
        if (validHeaderValue(value) == false) {
            throw new IllegalArgumentException("header value must contain only US ASCII text");
        }
        return value;
    }
}
