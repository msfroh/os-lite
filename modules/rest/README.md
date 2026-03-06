# Rest module (placeholder)

Rest-related types currently live in `server` under `org.opensearch.rest`. To allow a future extraction into this module without circular dependencies, the following decoupling was done in server:

- **`IncomingRequest`** (in `server/.../rest/IncomingRequest.java`) – abstraction over an incoming HTTP request. The rest layer builds `RestRequest` from `IncomingRequest` instead of from `HttpRequest`/`HttpChannel`, so it does not depend on HTTP transport types.
- **`HttpIncomingRequestAdapter`** (in `server/.../http/HttpIncomingRequestAdapter.java`) – in the server, adapts `HttpRequest` and `HttpChannel` to `IncomingRequest`. Used by `AbstractHttpServerTransport` when creating `RestRequest`.
- **`RestRequest`** now uses `IncomingRequest` internally; `getHttpRequest()`/`getHttpChannel()` were removed in favor of `getStrictCookies()` and `request.uri()`/`request.method()` where needed.

To complete extraction: move all `org.opensearch.rest` classes from server into this module, have server depend on this module, and ensure any remaining server-only types (e.g. `PathTrie`, `NodeClient`) are either moved to a shared lib or accessed via interfaces defined in this module.
