/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.plugins;

import org.opensearch.common.annotation.PublicApi;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

/**
 * A holder class for the various resources that Plugin may reasonably need from server.
 */
@PublicApi(since = "1.0.0")
public record PluginResources(NamedXContentRegistry namedXContentRegistry, NamedWriteableRegistry namedWriteableRegistry,
    Environment environment, ThreadPool threadPool, NodeClient nodeClient) {
}
