/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.rest;

import org.opensearch.common.annotation.PublicApi;

import java.util.Iterator;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Supplier;

/**
 * Registry for path-based handler lookup (e.g. PathTrie). The server provides an implementation.
 *
 * @opensearch.api
 */
@PublicApi(since = "1.0.0")
public interface HandlerRegistry<T> {

    /**
     * Decoder for path segments (e.g. URL decoding).
     */
    @FunctionalInterface
    interface Decoder {
        String decode(String value);
    }

    void insertOrUpdate(String path, T value, BiFunction<T, T, T> updater);

    Iterator<T> retrieveAll(String path, Supplier<Map<String, String>> paramSupplier);

    Iterator<T> retrieveAll();
}
