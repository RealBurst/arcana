/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana.util;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs independent I/O tasks (one per archive entry) on a pool of threads.
 *
 * <p>Error handling mirrors a sequential loop: after the first failure no new
 * task is started, the running ones are allowed to finish (they are never
 * interrupted: an interrupt would close a shared {@link java.nio.channels.FileChannel}),
 * and the failure of the <b>first task in list order</b> is thrown.</p>
 *
 * <p>The worker threads are created by the calling thread, so they inherit its
 * {@link ExtractionGuard} scope (InheritableThreadLocal).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelRunner {

    /** A task that may throw an IOException. */
    public interface IOTask {
        void run() throws IOException;
    }

    private static final AtomicInteger POOL_ID = new AtomicInteger();

    private ParallelRunner() {}

    /**
     * Runs all tasks with at most {@code threads} threads (in the calling thread
     * when {@code threads <= 1}) and waits for them.
     */
    public static void runAll(final List<? extends IOTask> tasks, final int threads) throws IOException {
        if (threads <= 1 || tasks.size() <= 1) {
            for (final IOTask t : tasks) t.run();
            return;
        }
        final int id = POOL_ID.incrementAndGet();
        final AtomicInteger n = new AtomicInteger();
        final ExecutorService pool = Executors.newFixedThreadPool(Math.min(threads, tasks.size()), r -> {
            final Thread t = new Thread(r, "arcana-" + id + "-extract-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        final AtomicBoolean failed = new AtomicBoolean();
        final List<Future<?>> futures = new ArrayList<Future<?>>(tasks.size());
        try {
            for (final IOTask task : tasks) {
                futures.add(pool.submit(() -> {
                    if (failed.get()) return null; // stop starting new work after a failure
                    try {
                        task.run();
                    } catch (final IOException | RuntimeException | Error e) {
                        failed.set(true);
                        throw e;
                    }
                    return null;
                }));
            }
            Throwable first = null;
            boolean interrupted = false;
            for (final Future<?> f : futures) {
                while (true) {
                    try {
                        f.get();
                        break;
                    } catch (final InterruptedException e) {
                        interrupted = true; // keep waiting: tasks must not be abandoned while writing
                        failed.set(true);
                    } catch (final ExecutionException e) {
                        if (first == null) first = e.getCause();
                        break;
                    }
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
                if (first == null) throw new InterruptedIOException("Extraction interrupted");
            }
            if (first instanceof IOException) throw (IOException) first;
            if (first instanceof RuntimeException) throw (RuntimeException) first;
            if (first instanceof Error) throw (Error) first;
            if (first != null) throw new IOException(first);
        } finally {
            pool.shutdown();
        }
    }
}
