/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.plugins;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.TransportAction;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.Strings;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * An additional extension point for {@link Plugin}s that extends OpenSearch's scripting functionality. Implement it like this:
 * <pre>{@code
 *   {@literal @}Override
 *   public List<ActionHandler<?, ?>> getActions() {
 *       return Arrays.asList(new ActionHandler<>(ReindexAction.INSTANCE, TransportReindexAction.class),
 *               new ActionHandler<>(UpdateByQueryAction.INSTANCE, TransportUpdateByQueryAction.class),
 *               new ActionHandler<>(DeleteByQueryAction.INSTANCE, TransportDeleteByQueryAction.class),
 *               new ActionHandler<>(RethrottleAction.INSTANCE, TransportRethrottleAction.class));
 *   }
 * }</pre>
 *
 * @opensearch.api
 */
public interface ActionPlugin {
    /**
     * Actions added by this plugin.
     */
    default List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return Collections.emptyList();
    }

    /**
     * Client actions added by this plugin. This defaults to all of the {@linkplain ActionType} in
     * {@linkplain ActionPlugin#getActions()}.
     */
    default List<ActionType<? extends ActionResponse>> getClientActions() {
        return getActions().stream().map(a -> a.action).collect(Collectors.toList());
    }

    /**
     * ActionType filters added by this plugin.
     */
    default List<ActionFilter> getActionFilters() {
        return Collections.emptyList();
    }

    /**
     * Returns headers which should be copied from internal requests into tasks.
     */
    default Collection<String> getTaskHeaders() {
        return Collections.emptyList();
    }

    /**
     *  Class responsible for handing Transport Actions
     *
     * @opensearch.internal
     */
    final class ActionHandler<Request extends ActionRequest, Response extends ActionResponse> {
        private final ActionType<Response> action;
        private final Class<? extends TransportAction<Request, Response>> transportAction;
        private final Class<?>[] supportTransportActions;

        /**
         * Create a record of an action, the {@linkplain TransportAction} that handles it, and any supporting TransportActions
         * that are needed by that {@linkplain TransportAction}.
         */
        public ActionHandler(
            ActionType<Response> action,
            Class<? extends TransportAction<Request, Response>> transportAction,
            Class<?>... supportTransportActions
        ) {
            this.action = action;
            this.transportAction = transportAction;
            this.supportTransportActions = supportTransportActions;
        }

        public ActionType<Response> getAction() {
            return action;
        }

        public Class<? extends TransportAction<Request, Response>> getTransportAction() {
            return transportAction;
        }

        public Class<?>[] getSupportTransportActions() {
            return supportTransportActions;
        }

        @Override
        public String toString() {
            StringBuilder b = new StringBuilder().append(action.name()).append(" is handled by ").append(transportAction.getName());
            if (supportTransportActions.length > 0) {
                b.append('[').append(Strings.arrayToCommaDelimitedString(supportTransportActions)).append(']');
            }
            return b.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null || obj.getClass() != ActionHandler.class) {
                return false;
            }
            ActionHandler<?, ?> other = (ActionHandler<?, ?>) obj;
            return Objects.equals(action, other.action)
                && Objects.equals(transportAction, other.transportAction)
                && Objects.deepEquals(supportTransportActions, other.supportTransportActions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(action, transportAction, supportTransportActions);
        }
    }
}
