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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.ArrayDeque;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stream made of independent blocks decoded in parallel (XZ blocks, LZMA2
 * sequences starting with a dictionary reset...). Block {@code i} is decoded by a
 * worker thread into a {@code byte[]}; the reader receives the blocks in order.
 * At most {@code threads + 1} blocks are decoded ahead (bounded memory).
 *
 * <p>Workers are never interrupted (an interrupt would close a shared
 * {@link java.nio.channels.FileChannel}). An error of a block is rethrown, with
 * its original type, when the reader reaches that block.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelBlockInputStream extends InputStream {

    /** Decodes one block; called from worker threads, possibly concurrently. */
    public interface BlockDecoder {
        byte[] decode(int index) throws IOException;
    }

    private static final AtomicInteger POOL_ID = new AtomicInteger();

    private final int blockCount;
    private final BlockDecoder decoder;
    private final Closeable onClose;
    private final ThreadPoolExecutor pool;
    private final ArrayDeque<Future<byte[]>> pending = new ArrayDeque<Future<byte[]>>();
    private final int maxInFlight;
    private int nextToSubmit;

    private byte[] current;
    private int pos;
    private boolean closed;
    private final byte[] one = new byte[1];

    /**
     * @param blockCount number of blocks
     * @param decoder    decodes a block
     * @param threads    worker threads (at least 1)
     * @param onClose    closed by {@link #close()} after the workers (may be null)
     */
    public ParallelBlockInputStream(final int blockCount, final BlockDecoder decoder, final int threads, final Closeable onClose) {
        this.blockCount = blockCount;
        this.decoder = decoder;
        this.onClose = onClose;
        final int t = Math.max(1, threads);
        final int id = POOL_ID.incrementAndGet();
        final AtomicInteger n = new AtomicInteger();
        this.pool = new ThreadPoolExecutor(t, t, 10L, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(), r -> {
            final Thread th = new Thread(r, "arcana-" + id + "-decode-" + n.incrementAndGet());
            th.setDaemon(true);
            return th;
        });
        this.pool.allowCoreThreadTimeOut(true);
        this.maxInFlight = t + 1;
        fill();
    }

    private void fill() {
        while (nextToSubmit < blockCount && pending.size() < maxInFlight) {
            final int index = nextToSubmit++;
            pending.add(pool.submit(() -> decoder.decode(index)));
        }
    }

    /** @return false at end of stream */
    private boolean nextBlock() throws IOException {
        while (true) {
            final Future<byte[]> f = pending.poll();
            if (f == null) return false;
            final byte[] b;
            try {
                b = f.get();
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("Interrupted while waiting for a decoded block");
            } catch (final ExecutionException e) {
                final Throwable c = e.getCause();
                if (c instanceof IOException) throw (IOException) c;
                if (c instanceof RuntimeException) throw (RuntimeException) c;
                if (c instanceof Error) throw (Error) c;
                throw new IOException(c);
            }
            fill();
            if (b.length > 0) {
                current = b;
                pos = 0;
                return true;
            }
        }
    }

    @Override
    public int read() throws IOException {
        final int n = read(one, 0, 1);
        return n < 0 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (closed) throw new IOException("Stream closed");
        if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
        if (len == 0) return 0;
        if ((current == null || pos == current.length) && !nextBlock()) return -1;
        final int n = Math.min(len, current.length - pos);
        System.arraycopy(current, pos, b, off, n);
        pos += n;
        return n;
    }

    @Override
    public int available() {
        return current == null ? 0 : current.length - pos;
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        for (final Future<byte[]> f : pending) f.cancel(false);
        pending.clear();
        pool.shutdown();
        boolean interrupted = false;
        try {
            while (!pool.awaitTermination(1, TimeUnit.SECONDS)) { /* running blocks finish (never interrupted) */ }
        } catch (final InterruptedException e) {
            interrupted = true;
        }
        if (interrupted) Thread.currentThread().interrupt();
        if (onClose != null) onClose.close();
    }
}
