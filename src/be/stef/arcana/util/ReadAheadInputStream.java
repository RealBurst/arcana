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
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Decompression pipeline (same idea as the RAR5 DecoderPipeline, on the read
 * side): a background thread reads the wrapped stream - typically a decompressor
 * - into 256 KiB chunks, while the caller parses the archive and writes the
 * files. Decompression and disk writes overlap instead of alternating.
 *
 * <p>At most {@value #QUEUE} chunks are waiting (bounded memory). Exceptions of
 * the background thread are rethrown to the reader unchanged (same type, e.g.
 * {@code ArcanaCorruptedException}), at the position where they occurred.</p>
 *
 * <p>Use {@link #wrap(InputStream)}, which returns the stream unchanged when
 * {@link ArcanaConcurrency#readAhead} is off or only one thread is configured.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ReadAheadInputStream extends InputStream {

    private static final int CHUNK = 256 * 1024;
    private static final int QUEUE = 4;
    private static final Chunk END = new Chunk(new byte[0], -1, null);
    private static final AtomicInteger THREAD_ID = new AtomicInteger();

    private static final class Chunk {
        final byte[] data;
        final int len;         // -1 = end of stream
        final Throwable error; // non-null = the source failed

        Chunk(final byte[] data, final int len, final Throwable error) {
            this.data = data;
            this.len = len;
            this.error = error;
        }
    }

    private final InputStream source;
    private final BlockingQueue<Chunk> queue = new ArrayBlockingQueue<Chunk>(QUEUE);
    private final ConcurrentLinkedQueue<byte[]> free = new ConcurrentLinkedQueue<byte[]>();
    private final Thread reader;
    private volatile boolean closed;   // pipeline stopped
    private boolean sourceClosed;

    private Chunk current;
    private int pos;
    private boolean eof;
    private final byte[] one = new byte[1];

    /** Wraps {@code in} in a read-ahead stream when enabled (see {@link ArcanaConcurrency}). */
    public static InputStream wrap(final InputStream in) {
        if (!ArcanaConcurrency.readAhead || ArcanaConcurrency.threads <= 1 || in instanceof ReadAheadInputStream || in instanceof ParallelBlockInputStream) return in; // already decoded ahead by its workers
        return new ReadAheadInputStream(in);
    }

    public ReadAheadInputStream(final InputStream source) {
        this.source = source;
        this.reader = new Thread(this::readLoop, "arcana-readahead-" + THREAD_ID.incrementAndGet());
        this.reader.setDaemon(true);
        this.reader.start();
    }

    // ---- background thread ----

    private void readLoop() {
        try {
            while (!closed) {
                byte[] buf = free.poll();
                if (buf == null) buf = new byte[CHUNK];
                int n = 0;
                while (n < CHUNK) {
                    final int r = source.read(buf, n, CHUNK - n);
                    if (r < 0) break;
                    n += r;
                }
                if (n > 0 && !put(new Chunk(buf, n, null))) return;
                if (n < CHUNK) {
                    put(END);
                    return;
                }
            }
        } catch (final Throwable t) {
            put(new Chunk(null, -1, t));
        }
    }

    /** @return false if the stream was closed meanwhile */
    private boolean put(final Chunk c) {
        try {
            while (!closed) {
                if (queue.offer(c, 100, TimeUnit.MILLISECONDS)) return true;
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    // ---- reader side ----

    /** @return false at end of stream */
    private boolean next() throws IOException {
        if (eof) return false;
        if (current != null && current.len > 0) free.add(current.data);
        current = null;
        final Chunk c;
        try {
            c = queue.take();
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting for decompressed data");
        }
        if (c.error != null) {
            eof = true;
            final Throwable t = c.error;
            if (t instanceof IOException) throw (IOException) t;
            if (t instanceof RuntimeException) throw (RuntimeException) t;
            if (t instanceof Error) throw (Error) t;
            throw new IOException(t);
        }
        if (c.len < 0) {
            eof = true;
            return false;
        }
        current = c;
        pos = 0;
        return true;
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
        if ((current == null || pos == current.len) && !next()) return -1;
        final int n = Math.min(len, current.len - pos);
        System.arraycopy(current.data, pos, b, off, n);
        pos += n;
        return n;
    }

    @Override
    public long skip(final long n) throws IOException {
        long left = n;
        while (left > 0) {
            if ((current == null || pos == current.len) && !next()) break;
            final int k = (int) Math.min(left, current.len - pos);
            pos += k;
            left -= k;
        }
        return n - left;
    }

    @Override
    public int available() {
        return current == null ? 0 : current.len - pos;
    }

    /**
     * Copies {@code in} to {@code out}, {@code in} being read ahead by a background
     * thread when enabled. {@code in} is not closed.
     *
     * @return number of bytes copied
     */
    public static long copy(final InputStream in, final OutputStream out) throws IOException {
        final InputStream src = wrap(in);
        if (src == in) return IOHelper.copy(in, out);
        final ReadAheadInputStream ra = (ReadAheadInputStream) src;
        try {
            return IOHelper.copy(ra, out);
        } finally {
            ra.stop();
        }
    }

    /** Stops the background thread (waiting for its current read), then closes the source. */
    @Override
    public void close() throws IOException {
        stop();
        if (!sourceClosed) {
            sourceClosed = true;
            source.close();
        }
    }

    /** Stops the background thread (waiting for its current read) without closing the source. */
    public void stop() {
        if (closed) return;
        closed = true;
        queue.clear();
        boolean interrupted = false;
        while (reader.isAlive()) {
            try {
                reader.join();
            } catch (final InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }
}
