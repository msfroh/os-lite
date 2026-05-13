/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

public class PythonEvalResponse extends ActionResponse implements ToXContentObject {
    private final String result;
    private final String stdout;
    private final String stderr;
    private final String error;

    public PythonEvalResponse(String result, String stdout, String stderr, String error) {
        this.result = result;
        this.stdout = stdout;
        this.stderr = stderr;
        this.error = error;
    }

    public PythonEvalResponse(StreamInput in) throws IOException {
        super(in);
        this.result = in.readOptionalString();
        this.stdout = in.readString();
        this.stderr = in.readString();
        this.error = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(result);
        out.writeString(stdout);
        out.writeString(stderr);
        out.writeOptionalString(error);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (result != null) {
            builder.field("result", result);
        }
        builder.field("stdout", stdout);
        if (!stderr.isEmpty()) {
            builder.field("stderr", stderr);
        }
        if (error != null) {
            builder.field("error", error);
        }
        builder.endObject();
        return builder;
    }
}
