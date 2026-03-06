/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.Booleans;
import org.opensearch.core.common.Strings;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * REST utility class (pure decoding and CORS helpers). Path decoder is provided by the server.
 */
public final class RestUtils {

    private static final boolean DECODE_PLUS_AS_SPACE = Booleans.parseBoolean(
        System.getProperty("opensearch.rest.url_plus_as_space", "false")
    );

    private RestUtils() {}

    public static void decodeQueryString(String s, int fromIndex, Map<String, String> params) {
        if (fromIndex < 0) return;
        if (fromIndex >= s.length()) return;

        int queryStringLength = s.contains("#") ? s.indexOf("#") : s.length();

        String name = null;
        int pos = fromIndex;
        int i;
        char c = 0;
        for (i = fromIndex; i < queryStringLength; i++) {
            c = s.charAt(i);
            if (c == '=' && name == null) {
                if (pos != i) {
                    name = decodeQueryStringParam(s.substring(pos, i));
                }
                pos = i + 1;
            } else if (c == '&' || c == ';') {
                if (name == null && pos != i) {
                    addParam(params, decodeQueryStringParam(s.substring(pos, i)), "");
                } else if (name != null) {
                    addParam(params, name, decodeQueryStringParam(s.substring(pos, i)));
                    name = null;
                }
                pos = i + 1;
            }
        }

        if (pos != i) {
            if (name == null) {
                addParam(params, decodeQueryStringParam(s.substring(pos, i)), "");
            } else {
                addParam(params, name, decodeQueryStringParam(s.substring(pos, i)));
            }
        } else if (name != null) {
            addParam(params, name, "");
        }
    }

    private static String decodeQueryStringParam(final String s) {
        return decodeComponent(s, StandardCharsets.UTF_8, true);
    }

    private static void addParam(Map<String, String> params, String name, String value) {
        params.put(name, value);
    }

    public static String decodeComponent(final String s) {
        return decodeComponent(s, StandardCharsets.UTF_8, DECODE_PLUS_AS_SPACE);
    }

    public static String decodeComponent(final String s, final Charset charset, boolean plusAsSpace) {
        if (s == null) return "";
        final int size = s.length();
        if (!decodingNeeded(s, size, plusAsSpace)) return s;
        final byte[] buf = new byte[size];
        int pos = decode(s, size, buf, plusAsSpace);
        return new String(buf, 0, pos, charset);
    }

    private static boolean decodingNeeded(String s, int size, boolean plusAsSpace) {
        for (int i = 0; i < size; i++) {
            final char c = s.charAt(i);
            if (c == '%') {
                i++;
                return true;
            } else if (plusAsSpace && c == '+') {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("fallthrough")
    private static int decode(String s, int size, byte[] buf, boolean plusAsSpace) {
        int pos = 0;
        for (int i = 0; i < size; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '+':
                    buf[pos++] = (byte) (plusAsSpace ? ' ' : '+');
                    break;
                case '%':
                    if (i == size - 1) {
                        throw new IllegalArgumentException("unterminated escape sequence at end of string: " + s);
                    }
                    c = s.charAt(++i);
                    if (c == '%') {
                        buf[pos++] = '%';
                        break;
                    } else if (i == size - 1) {
                        throw new IllegalArgumentException("partial escape sequence at end of string: " + s);
                    }
                    c = decodeHexNibble(c);
                    final char c2 = decodeHexNibble(s.charAt(++i));
                    if (c == Character.MAX_VALUE || c2 == Character.MAX_VALUE) {
                        throw new IllegalArgumentException(
                            "invalid escape sequence `%" + s.charAt(i - 1) + s.charAt(i) + "' at index " + (i - 2) + " of: " + s
                        );
                    }
                    c = (char) (c * 16 + c2);
                default:
                    buf[pos++] = (byte) c;
                    break;
            }
        }
        return pos;
    }

    private static char decodeHexNibble(final char c) {
        if ('0' <= c && c <= '9') return (char) (c - '0');
        if ('a' <= c && c <= 'f') return (char) (c - 'a' + 10);
        if ('A' <= c && c <= 'F') return (char) (c - 'A' + 10);
        return Character.MAX_VALUE;
    }

    public static Pattern checkCorsSettingForRegex(String corsSetting) {
        if (corsSetting == null) return null;
        int len = corsSetting.length();
        boolean isRegex = len > 2 && corsSetting.startsWith("/") && corsSetting.endsWith("/");
        if (isRegex) {
            return Pattern.compile(corsSetting.substring(1, corsSetting.length() - 1));
        }
        return null;
    }

    public static String[] corsSettingAsArray(String corsSetting) {
        if (Strings.isNullOrEmpty(corsSetting)) {
            return new String[0];
        }
        return Arrays.stream(corsSetting.split(",")).map(String::trim).toArray(String[]::new);
    }
}
