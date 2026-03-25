/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.rest.spi;

import org.opensearch.common.Nullable;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.http.HttpRequest;

import java.util.List;
import java.util.Map;

public interface RestRequest extends ToXContent.Params {
    String rawPath();

    String path();

    String header(String name);

    Map<String, List<String>> getHeaders();

    long getRequestId();

    @Nullable
    MediaType getMediaType();

    HttpRequest.Method method();

    HttpRequest getHttpRequest();

    boolean hasParam(String key);

    Map<String, String> params();

    List<String> consumedParams();

    List<String> unconsumedParams();

    TimeValue paramAsTime(String key, TimeValue defaultValue);

    ByteSizeValue paramAsSize(String key, ByteSizeValue defaultValue);

    String[] paramAsStringArray(String key, String[] defaultValue);

    String[] paramAsStringArrayOrEmptyIfAll(String key);
}
