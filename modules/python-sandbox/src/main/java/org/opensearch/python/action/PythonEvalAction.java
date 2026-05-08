/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.action;

import org.opensearch.action.ActionType;

public class PythonEvalAction extends ActionType<PythonEvalResponse> {
    public static final String NAME = "cluster:python/eval";
    public static final PythonEvalAction INSTANCE = new PythonEvalAction();

    private PythonEvalAction() {
        super(NAME, PythonEvalResponse::new);
    }
}
