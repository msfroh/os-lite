/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.python.engine;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.EnvironmentAccess;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.io.IOAccess;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Shared GraalPy execution engine. The {@link Engine} is process-wide; each evaluation
 * runs in its own short-lived {@link Context}.
 *
 * <p>GraalPy community edition only supports {@code SandboxPolicy.TRUSTED}, so we use
 * TRUSTED but explicitly deny every dangerous capability: no host (Java) access, no IO,
 * no threads, no native access, no subprocess, no environment access. This gives us an
 * in-process sandbox where Python code cannot escape into the JVM or the OS.
 *
 * <p>Stronger isolation (CONSTRAINED / ISOLATED / UNTRUSTED) requires GraalVM Enterprise
 * + the polyglot-isolate native library, which is not available on stock OpenJDK.
 */
public final class PythonEngine {

    private static final String LANGUAGE = "python";

    private static final Engine ENGINE = Engine.newBuilder(LANGUAGE)
        .out(OutputStream.nullOutputStream())
        .err(OutputStream.nullOutputStream())
        .build();

    /**
     * All Truffle work (Context construction, eval) goes through this executor so the
     * thread's call stack is just plugin-owned frames. The OpenSearch javaagent enforces
     * "every ProtectionDomain on the stack must imply the permission" semantics, and the
     * REST / server code higher up in the request stack has no FS-write permission, so
     * Truffle's resource-cache extraction would fail if run on the calling thread.
     */
    private static final ExecutorService EXEC = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "graalpy-engine");
        t.setDaemon(true);
        return t;
    });

    private PythonEngine() {}

    /**
     * Build and discard a Context to force Truffle to extract its internal resources
     * (native helpers, GraalPy stdlib) to the per-user cache. Must be called from a
     * stack frame with broad FS permissions (e.g. plugin construction).
     */
    public static void warmup() {
        runOnEngineThread(() -> {
            try (Context ctx = newContext(OutputStream.nullOutputStream(), OutputStream.nullOutputStream())) {
                ctx.eval(Source.newBuilder(LANGUAGE, "1", "<warmup>").build());
            }
            return null;
        });
    }

    private static <T> T runOnEngineThread(java.util.concurrent.Callable<T> task) {
        Future<T> f = EXEC.submit(task);
        try {
            return f.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) throw re;
            if (cause instanceof Error err) throw err;
            throw new RuntimeException(cause);
        }
    }

    private static Context newContext(OutputStream stdout, OutputStream stderr) {
        return Context.newBuilder(LANGUAGE)
            .engine(ENGINE)
            .out(stdout)
            .err(stderr)
            .allowHostAccess(HostAccess.NONE)
            .allowIO(IOAccess.NONE)
            .allowCreateThread(false)
            .allowNativeAccess(false)
            .allowCreateProcess(false)
            .allowEnvironmentAccess(EnvironmentAccess.NONE)
            .allowHostClassLookup(c -> false)
            .allowHostClassLoading(false)
            .build();
    }

    public static EvalResult eval(String source) {
        return runOnEngineThread(() -> {
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            try (Context ctx = newContext(stdout, stderr)) {
                Value result = ctx.eval(Source.newBuilder(LANGUAGE, source, "<request>").build());
                String resultStr = (result == null || result.isNull()) ? null : result.toString();
                return new EvalResult(resultStr, stdout.toString(), stderr.toString(), null);
            } catch (PolyglotException e) {
                return new EvalResult(null, stdout.toString(), stderr.toString(), e.getMessage());
            }
        });
    }

    public record EvalResult(String result, String stdout, String stderr, String error) {}
}
