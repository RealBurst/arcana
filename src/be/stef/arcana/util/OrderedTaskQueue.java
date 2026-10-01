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
import java.util.ArrayDeque;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs independent tasks (compression of blocks) on worker threads and hands their
 * results back <b>in submission order</b> to a single consumer (the thread that
 * writes the output). At most {@code threads + 1} tasks are in flight, which bounds
 * the memory used by pending blocks.
 *
 * <p>The consumer runs on the caller's thread, inside {@link #submit} and
 * {@link #finish}, so the output stream is only ever touched by one thread.</p>
 *
 * @param <R> task result
 * @author Stef
 * @since 1.3
 */
public final class OrderedTaskQueue<R> implements AutoCloseable {

    /** Receives the results in order. */
    public interface Consumer<R> {
        void accept(R result) throws IOException;
    }

    private static final AtomicInteger POOL_ID = new AtomicInteger();

    private final ExecutorService pool;
    private final ArrayDeque<Future<R>> pending = new ArrayDeque<Future<R>>();
    private final int maxInFlight;
    private final Consumer<R> consumer;

    public OrderedTaskQueue(final int threads, final Consumer<R> consumer) {
        final int id = POOL_ID.incrementAndGet();
        final AtomicInteger n = new AtomicInteger();
        final ThreadPoolExecutor tpe = new ThreadPoolExecutor(threads, threads, 10L, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(), r -> {
            final Thread t = new Thread(r, "arcana-" + id + "-worker-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        // Idle workers end by themselves: no thread is leaked if the owner stream is never closed
        tpe.allowCoreThreadTimeOut(true);
        this.pool = tpe;
        this.maxInFlight = threads + 1;
        this.consumer = consumer;
    }

    /** Queues a task; blocks (consuming finished results) while too many are in flight. */
    public void submit(final Callable<R> task) throws IOException {
        while (pending.size() >= maxInFlight) consumeOldest();
        pending.add(pool.submit(task));
    }

    /** Waits for every task and consumes the remaining results. */
    public void finish() throws IOException {
        while (!pending.isEmpty()) consumeOldest();
    }

    private void consumeOldest() throws IOException {
        final Future<R> f = pending.poll();
        final R r;
        try {
            r = f.get();
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting for a worker");
        } catch (final ExecutionException e) {
            final Throwable c = e.getCause();
            if (c instanceof IOException) throw (IOException) c;
            if (c instanceof RuntimeException) throw (RuntimeException) c;
            if (c instanceof Error) throw (Error) c;
            throw new IOException(c);
        }
        consumer.accept(r);
    }

    @Override
    public void close() {
        for (final Future<R> f : pending) f.cancel(true);
        pending.clear();
        pool.shutdownNow();
    }
}
