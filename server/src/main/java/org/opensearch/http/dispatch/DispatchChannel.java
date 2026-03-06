/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.http.dispatch;

import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;

/**
 * Server-level abstraction of a channel to send a response. Used by the HTTP transport and dispatcher
 * without depending on the rest module. The rest module's {@code RestChannel} implements this interface.
 *
 * @opensearch.internal
 */
public interface DispatchChannel {

    void sendResponse(RestStatus status, BytesReference content);
}
