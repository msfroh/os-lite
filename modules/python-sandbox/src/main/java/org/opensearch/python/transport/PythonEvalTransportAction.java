/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.transport;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.python.action.PythonEvalAction;
import org.opensearch.python.action.PythonEvalRequest;
import org.opensearch.python.action.PythonEvalResponse;
import org.opensearch.python.engine.PythonEngine;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class PythonEvalTransportAction extends HandledTransportAction<PythonEvalRequest, PythonEvalResponse> {

    @Inject
    public PythonEvalTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(PythonEvalAction.NAME, transportService, actionFilters, PythonEvalRequest::new);
    }

    @Override
    protected void doExecute(Task task, PythonEvalRequest request, ActionListener<PythonEvalResponse> listener) {
        try {
            PythonEngine.EvalResult r = PythonEngine.eval(request.source());
            listener.onResponse(new PythonEvalResponse(r.result(), r.stdout(), r.stderr(), r.error()));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }
}
