/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class PythonEvalRequest extends ActionRequest {
    private final String source;

    public PythonEvalRequest(String source) {
        this.source = source;
    }

    public PythonEvalRequest(StreamInput in) throws IOException {
        super(in);
        this.source = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(source);
    }

    public String source() {
        return source;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }
}
