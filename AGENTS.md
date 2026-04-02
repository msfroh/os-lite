# AGENTS.md — Context for Coding Agents

## Project Overview

`os-lite` is a lightweight, modular reimplementation of [OpenSearch](https://opensearch.org/) (version 3.4.0-SNAPSHOT). The goal is a clean, extensible search/analytics server where features are delivered as pluggable modules rather than baked into the core. It is licensed under Apache 2.0.

## Repository Layout

```
os-lite/
├── server/                  # Core server: bootstrap, cluster, HTTP, REST, node, plugins, transport
├── modules/
│   ├── hello-world/         # Demo plugin: shows how to add an action + REST handler
│   ├── transport-netty4/    # Netty 4 HTTP/transport implementation
│   ├── rest/                # REST infrastructure (being migrated to a module)
│   └── http-api/            # HTTP API definitions (placeholder)
├── libs/
│   └── generic-engine/      # Shared library code
├── distribution/            # Packaging (Linux x64 tar, macOS arm64 tar)
│   └── tools/               # java-version-checker, launchers
├── buildSrc/                # Custom Gradle plugins and build tasks
├── test/
│   └── logger-usage/        # Logger usage validator (OpenSearchLoggerUsageChecker)
└── gradle/                  # Gradle helper scripts (run, formatting, coverage, IDE, etc.)
```

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 21+ |
| Build | Gradle 8.5 (wrapper: `./gradlew`) |
| Dependency versions | `gradle/libs.versions.toml` (version catalog) |
| Search engine | Lucene 10.3.2 |
| Networking | Netty 4.2.7, Reactor Netty 1.3.0 |
| Serialization | Jackson 2.18.2, Protocol Buffers 3.25.8 |
| Logging | Log4j 2.21.0, SLF4j 2.0.17 |
| Testing | JUnit 4/5, Hamcrest, Mockito 5, RandomizedRunner |
| Bundled JDK | Adoptium JDK 25.0.1+8 |

## Build, Run, and Test Commands

```bash
# Build everything
./gradlew build

# Assemble distribution archives only
./gradlew assemble

# Run the server (single node)
./gradlew run

# Run with multiple nodes / zones
./gradlew run -PnumNodes=3
./gradlew run -PnumZones=2

# Run all tests
./gradlew test

# Run tests for a specific subproject
./gradlew :server:test
./gradlew :modules:hello-world:test

# Check code formatting (Spotless)
./gradlew spotlessCheck

# Apply code formatting
./gradlew spotlessApply
```

## Plugin / Module Architecture

The project uses an action-plugin system. A module contributes functionality by:

1. Extending `Plugin` (and optionally `ActionPlugin`, `RestPlugin`, etc.) in its main plugin class.
2. Declaring its plugin class in the `opensearch.plugin` Gradle extension.
3. Registering actions, REST handlers, and transport handlers via overridden methods.

The `modules/hello-world` module is the canonical reference example. Study these files to understand the pattern:

| File | Purpose |
|---|---|
| `HelloWorldPlugin.java` | Plugin entry point; registers actions and REST handlers |
| `HelloWorldAction.java` | Defines the action (name, request/response types) |
| `RestHelloWorldAction.java` | Maps an HTTP route to the action |
| `HelloWorldTransportAction.java` | Server-side handler that executes the action |
| `HelloWorldRequest.java` / `HelloWorldResponse.java` | Request and response value objects |

When adding a new module, follow the same structure and register the subproject in `settings.gradle`.

Note that plugins/modules depend on `server/`, not the other way around. We do not explicitly declare the dependency on `server/` in the plugin's `build.gradle` file. Instead,
the dependency is implicitly injected by the `opensearchplugin` Gradle plugin, which is implemented in `buildSrc/src/main/groovy/org/opensearch/gradle/plugin/PluginBuildPlugin.groovy`.
Specifically, its `configureDependencies` method adds `compileOnly project.project(':server')` the plugin's dependencies.

## Active Work (branch: `move_rest_to_a_module`)

The current branch is extracting REST API infrastructure out of `server/` and into `modules/rest/`, continuing the trend of keeping `server/` minimal and delegating to modules.

Any class in `/server` with "Rest" somewhere in its name will need to move into `modules/rest`.

This will require a number of changes. For example:
1. We will need to remove the creation of `RestController` from `ActionModule.java`. Instead, we will need to create `RestController` in the `modules/rest/` plugin, probably in the plugin's `createComponents` method.
2. We need to replace the `RestRequest`/`RestChannel` parameters in `HttpServerTransport.Dispatcher`'s method with `HttpRequest` and `HttpChannel`. Right now, we have some HTTP/REST bridge logic in `DefaultRestChannel` and in `AbstractHttpServerTransport`. Currently, the boundary says that `AbstractHttpServerTransport` is responsible for converting an `HttpRequest` into a `RestRequest` (and the `HttpChannel` is adapted to a `RestChannel`). The `RestRequest` and `RestChannel` are passed to `RestController` via the `HttpServerTransport.Dispatcher` interface. With this refactoring, we only want `server/` to know about HTTP. So, the responsibility of converting from HTTP to REST must move out of `AbstractHttpServerTransport` and into `RestController`. That is, the `modules/rest/` plugin will understand HTTP and REST, but `server/` will only understand HTTP.
3. We should add a method to `NetworkPlugin` called `HttpServerTransport.Dispatcher getHttpServerTransportDispatcher()`. If more than one loaded `NetworkPlugin` implements this method, we can throw an `IllegalStateException`. Then, in the `Node` constructor, we can pass the supplied `HttpServerTransport.Dispatcher` to the `NetworkModule` constructor. If no `NetworkPlugin` supplies an `HttpServerTransport.Dispatcher`, we should pass `HttpServerTransport.NO_OP_DISPATCHER` to the `NetworkModule` constructor.
4. We will need to remove `RestHelloWorldAction` from the `modules/hello-world/` plugin, at least until we're ready to make it an extension of the REST module, since `BaseRestHandler` will move out of `server/`.

## Code Quality

- The build enforces strict compiler warnings (`-Xlint:all`) and strict Javadoc linting (`-Xdoclint`).
- Code formatting is enforced via Spotless — run `./gradlew spotlessApply` before committing.
- Logger usage is validated by the `test/logger-usage` tool; use the project's logging conventions.
- Use `@opensearch.internal`, `@opensearch.api`, or `@opensearch.experimental` Javadoc tags to classify APIs.

## Key Gradle Properties (`gradle.properties`)

- Build caching and parallel builds are enabled.
- JVM max heap is set to 3 GB (`org.gradle.jvmargs=-Xmx3g`).
- Dependency version conflict detection is disabled (versions are managed centrally in `gradle/libs.versions.toml`).

## Notes for Agents

- Prefer editing existing files over creating new ones.
- When adding a new plugin feature, model it after `modules/hello-world`.
- All dependency versions must go through `gradle/libs.versions.toml`; do not hard-code versions in `build.gradle` files.
- Do not skip Spotless or compiler-warning fixes — the build will fail.
- The distribution archives bundle a JDK; do not assume a system JDK at runtime.
