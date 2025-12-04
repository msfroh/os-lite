/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.helloworld.action;

import org.opensearch.action.ActionType;

public class HelloWorldAction extends ActionType<HelloWorldResponse> {
    public static final String NAME = "cluster:hello/world";
    public static final HelloWorldAction INSTANCE = new HelloWorldAction();

    private HelloWorldAction() {
        super(NAME, HelloWorldResponse::new);
    }
}
