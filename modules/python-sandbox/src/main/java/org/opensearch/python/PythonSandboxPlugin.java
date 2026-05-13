/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python;

import org.opensearch.action.ActionRequest;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.python.action.PythonEvalAction;
import org.opensearch.python.engine.PythonEngine;
import org.opensearch.python.rest.RestPythonAction;
import org.opensearch.python.transport.PythonEvalTransportAction;
import org.opensearch.rest.spi.RestHandler;
import org.opensearch.rest.spi.RestHandlerPlugin;

import java.util.List;

public class PythonSandboxPlugin extends Plugin implements ActionPlugin, RestHandlerPlugin {

    public PythonSandboxPlugin() {
        // Eagerly initialize the GraalPy engine and warm a context so Truffle extracts
        // its native helpers and python-home stdlib to the per-user cache here, where
        // the stack is plugin-loading code (broad FS perms). At request time the stack
        // includes the rest module, which has no FS perms, and the agent's policy
        // requires every domain on the stack to grant the perm.
        PythonEngine.warmup();
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(new ActionHandler<>(PythonEvalAction.INSTANCE, PythonEvalTransportAction.class));
    }

    @Override
    public List<RestHandler> getRestHandlers() {
        return List.of(new RestPythonAction());
    }
}
