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
package be.stef.arcana.formats.xz;

import be.stef.arcana.util.OrderedTaskQueue;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Multithreaded raw LZMA2 writer (7z coder 0x21), like 7-Zip's LZMA2 -mmt: the
 * input is cut into blocks compressed by worker threads as independent LZMA2
 * sequences (each starts with a dictionary reset), concatenated in order without
 * their end marker, and terminated by a single 0x00 end marker. The result is one
 * valid LZMA2 stream for any decoder.
 *
 * <p>Use {@link #create(OutputStream, LZMA2Options)}: it returns the classic
 * single-threaded encoder when only one worker is available (setting or heap).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelLZMA2OutputStream extends FinishableOutputStream {

    private final OutputStream out;
    private final LZMA2Options options;
    private final OrderedTaskQueue<Encoded> queue;
    private final ConcurrentLinkedQueue<byte[]> freeBuffers = new ConcurrentLinkedQueue<byte[]>();
    private final int blockSize;

    private byte[] buf;
    private int bufLen;
    private boolean finished;
    private final byte[] one = new byte[1];

    /**
     * Returns a parallel raw LZMA2 writer when several workers fit in the heap,
     * otherwise the classic {@link LZMA2OutputStream}. {@link #finish()} never
     * closes {@code out}.
     */
    public static FinishableOutputStream create(final OutputStream out, final LZMA2Options options) throws IOException {
        return create(out, options, -1L);
    }

    /**
     * Same as {@link #create(OutputStream, LZMA2Options)} with the expected input
     * size, used to balance the blocks between the threads (-1 = unknown).
     */
    public static FinishableOutputStream create(final OutputStream out, final LZMA2Options options, final long sizeHint) throws IOException {
        final int workers = ParallelXZOutputStream.workersFor(options);
        if (workers <= 1) return options.getOutputStream(new FinishableWrapperOutputStream(out), BasicArrayCache.getInstance());
        return new ParallelLZMA2OutputStream(out, options, workers, ParallelXZOutputStream.blockSizeFor(options, sizeHint, workers));
    }

    /**
     * @param threads   worker threads
     * @param blockSize uncompressed size of each independent block
     */
    public ParallelLZMA2OutputStream(final OutputStream out, final LZMA2Options options, final int threads, final int blockSize) {
        if (blockSize < 1) throw new IllegalArgumentException("blockSize must be > 0");
        this.out = out;
        this.options = options;
        this.blockSize = blockSize;
        this.queue = new OrderedTaskQueue<Encoded>(threads, r -> out.write(r.data, 0, r.len));
    }

    @Override
    public void write(final int b) throws IOException {
        one[0] = (byte) b;
        write(one, 0, 1);
    }

    @Override
    public void write(final byte[] b, int off, int len) throws IOException {
        if (off < 0 || len < 0 || off + len > b.length) throw new IndexOutOfBoundsException();
        if (finished) throw new XZIOException("Stream finished or closed");
        while (len > 0) {
            if (buf == null) {
                buf = freeBuffers.poll();
                if (buf == null) buf = new byte[blockSize];
                bufLen = 0;
            }
            final int n = Math.min(len, blockSize - bufLen);
            System.arraycopy(b, off, buf, bufLen, n);
            bufLen += n;
            off += n;
            len -= n;
            if (bufLen == blockSize) submitBlock();
        }
    }

    private void submitBlock() throws IOException {
        final byte[] data = buf;
        final int len = bufLen;
        buf = null;
        bufLen = 0;
        queue.submit(() -> {
            try {
                return encode(data, len);
            } finally {
                freeBuffers.add(data);
            }
        });
    }

    /** One encoded LZMA2 sequence (without end marker). */
    private static final class Encoded {
        final byte[] data;
        final int len;

        Encoded(final byte[] data, final int len) {
            this.data = data;
            this.len = len;
        }
    }

    private Encoded encode(final byte[] data, final int len) throws IOException {
        final ParallelXZOutputStream.ExposedByteArrayOutputStream bo = new ParallelXZOutputStream.ExposedByteArrayOutputStream(len / 2 + 4096);
        final FinishableOutputStream lz = options.getOutputStream(new FinishableWrapperOutputStream(bo), BasicArrayCache.getInstance());
        lz.write(data, 0, len);
        lz.finish();
        final int n = bo.size() - 1; // drop the 0x00 end marker: the next sequence starts with a dictionary reset
        if (n < 0 || bo.buffer()[n] != 0x00) throw new IOException("Unexpected LZMA2 stream end");
        return new Encoded(bo.buffer(), n);
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void finish() throws IOException {
        if (finished) return;
        finished = true;
        try {
            if (buf != null && bufLen > 0) submitBlock();
            queue.finish();
            out.write(0x00);
        } finally {
            queue.close();
        }
    }

    @Override
    public void close() throws IOException {
        try {
            finish();
        } finally {
            out.close();
        }
    }
}
