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
package be.stef.arcana.formats.gzip;

import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.OrderedTaskQueue;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;

/**
 * Multithreaded gzip writer (same technique as pigz): the input is cut into
 * chunks of 256 KiB deflated by worker threads. Each chunk is primed with the
 * last 32 KiB of the previous one (preset dictionary), so the matches across
 * chunk boundaries are kept and the ratio stays practically the same as with a
 * single thread. Chunks end with a sync flush (byte aligned, empty stored block)
 * and are concatenated in order into <b>one standard gzip member</b>; the CRC32
 * is computed on the caller thread.
 *
 * <p>Use {@link #create(OutputStream)}: it returns a {@link GZIPOutputStream}
 * when only one thread is configured. Like {@link GZIPOutputStream},
 * {@link #finish()} does not close the underlying stream and {@link #close()} does.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelGzipOutputStream extends OutputStream {

    private static final int CHUNK = 256 * 1024;
    private static final int DICT = 32 * 1024;
    /** Deflater (~300 KB native) + input chunk + output buffer. */
    private static final long BYTES_PER_TASK = 3L * CHUNK + 512 * 1024;

    private final OutputStream out;
    private final int level;
    private final OrderedTaskQueue<Encoded> queue;
    private final ConcurrentLinkedQueue<Deflater> deflaters = new ConcurrentLinkedQueue<Deflater>();
    private final ConcurrentLinkedQueue<byte[]> freeBuffers = new ConcurrentLinkedQueue<byte[]>();
    private final CRC32 crc = new CRC32();
    private long totalIn;

    private byte[] buf;
    private int bufLen;
    private byte[] prevTail; // dictionary for the next chunk (last 32 KiB of the previous one)
    private boolean finished;
    private final byte[] one = new byte[1];

    private static final class Encoded {
        final byte[] data;
        final int len;

        Encoded(final byte[] data, final int len) {
            this.data = data;
            this.len = len;
        }
    }

    /** Returns a parallel writer, or a classic {@link GZIPOutputStream} when one thread is configured. */
    public static OutputStream create(final OutputStream out) throws IOException {
        final int workers = ArcanaConcurrency.workersFor(BYTES_PER_TASK);
        if (workers <= 1) return new GZIPOutputStream(out, 65536);
        return new ParallelGzipOutputStream(out, Deflater.DEFAULT_COMPRESSION, workers);
    }

    /**
     * Finishes a stream returned by {@link #create(OutputStream)} without closing
     * the underlying stream.
     */
    public static void finish(final OutputStream gz) throws IOException {
        if (gz instanceof ParallelGzipOutputStream) ((ParallelGzipOutputStream) gz).finish();
        else if (gz instanceof GZIPOutputStream) ((GZIPOutputStream) gz).finish();
        else gz.flush();
    }

    /**
     * @param out     destination
     * @param level   deflate level (0-9 or {@link Deflater#DEFAULT_COMPRESSION})
     * @param threads worker threads
     */
    public ParallelGzipOutputStream(final OutputStream out, final int level, final int threads) throws IOException {
        this.out = out;
        this.level = level;
        this.queue = new OrderedTaskQueue<Encoded>(threads, e -> out.write(e.data, 0, e.len));
        // Same header as java.util.zip.GZIPOutputStream: no name, mtime 0, OS 0
        out.write(new byte[] {0x1f, (byte) 0x8b, Deflater.DEFLATED, 0, 0, 0, 0, 0, 0, 0});
    }

    /**
     * Finishes the stream: last chunk, trailer (CRC32, size). A gzip wrapper that
     * must not close the underlying stream calls this instead of {@link #close()}.
     */
    public void finish() throws IOException {
        if (finished) return;
        finished = true;
        try {
            submit(true);
            queue.finish();
            final long c = crc.getValue();
            final long n = totalIn & 0xFFFFFFFFL;
            out.write(new byte[] {(byte) c, (byte) (c >> 8), (byte) (c >> 16), (byte) (c >> 24), (byte) n, (byte) (n >> 8), (byte) (n >> 16), (byte) (n >> 24)});
        } finally {
            queue.close();
            Deflater d;
            while ((d = deflaters.poll()) != null) d.end();
        }
    }

    @Override
    public void write(final int b) throws IOException {
        one[0] = (byte) b;
        write(one, 0, 1);
    }

    @Override
    public void write(final byte[] b, int off, int len) throws IOException {
        if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
        if (finished) throw new IOException("Stream finished");
        crc.update(b, off, len);
        totalIn += len;
        while (len > 0) {
            if (buf == null) {
                buf = freeBuffers.poll();
                if (buf == null) buf = new byte[CHUNK];
                bufLen = 0;
            }
            final int n = Math.min(len, CHUNK - bufLen);
            System.arraycopy(b, off, buf, bufLen, n);
            bufLen += n;
            off += n;
            len -= n;
            if (bufLen == CHUNK) submit(false);
        }
    }

    private void submit(final boolean last) throws IOException {
        final byte[] data = buf != null ? buf : new byte[0];
        final int len = buf != null ? bufLen : 0;
        final byte[] dict = prevTail;
        if (!last) prevTail = Arrays.copyOfRange(data, Math.max(0, len - DICT), len);
        buf = null;
        bufLen = 0;
        queue.submit(() -> {
            Deflater d = deflaters.poll();
            if (d == null) d = new Deflater(level, true);
            try {
                return deflate(d, data, len, dict, last);
            } finally {
                d.reset();
                deflaters.add(d);
                if (data.length == CHUNK) freeBuffers.add(data);
            }
        });
    }

    /** Deflates one chunk (runs on a worker thread). */
    private static Encoded deflate(final Deflater d, final byte[] data, final int len, final byte[] dict, final boolean last) {
        if (dict != null && dict.length > 0) d.setDictionary(dict);
        d.setInput(data, 0, len);
        final ExposedByteArrayOutputStream bo = new ExposedByteArrayOutputStream(len / 2 + 1024);
        final byte[] tmp = new byte[65536];
        if (last) {
            d.finish();
            while (!d.finished()) {
                final int n = d.deflate(tmp, 0, tmp.length, Deflater.NO_FLUSH);
                bo.write(tmp, 0, n);
            }
        } else {
            // SYNC_FLUSH: all input is consumed and the output ends byte aligned
            int n;
            do {
                n = d.deflate(tmp, 0, tmp.length, Deflater.SYNC_FLUSH);
                bo.write(tmp, 0, n);
            } while (n == tmp.length || !d.needsInput());
        }
        return new Encoded(bo.buffer(), bo.size());
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        try {
            finish();
        } finally {
            out.close();
        }
    }

    /** ByteArrayOutputStream giving access to its buffer (no copy). */
    private static final class ExposedByteArrayOutputStream extends ByteArrayOutputStream {
        ExposedByteArrayOutputStream(final int size) {
            super(size);
        }

        byte[] buffer() {
            return buf;
        }
    }
}
