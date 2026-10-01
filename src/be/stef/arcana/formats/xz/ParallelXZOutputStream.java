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

import be.stef.arcana.formats.xz.check.Check;
import be.stef.arcana.formats.xz.common.EncoderUtil;
import be.stef.arcana.formats.xz.index.IndexEncoder;
import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.OrderedTaskQueue;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Multithreaded .xz writer, like {@code xz -T}: the input is cut into blocks of
 * up to {@code 3 x dictSize} (at least 1 MiB) which are compressed by worker threads as
 * independent XZ Blocks, then written in order into a single standard .xz stream
 * (one Index lists every block). Any xz decoder reads it; the ratio is only
 * slightly lower than a single-block stream (each block restarts with an empty
 * dictionary).
 *
 * <p>Use {@link #create(OutputStream, LZMA2Options)}: it returns the classic
 * single-threaded {@link XZOutputStream} when only one worker is available
 * (setting or heap), so that the output is then unchanged.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelXZOutputStream extends FinishableOutputStream {

    private static final int MIN_BLOCK = 1 << 20;

    private final OutputStream out;
    private final FilterOptions[] filterOptions;
    private final int checkType;
    private final IndexEncoder index = new IndexEncoder();
    private final OrderedTaskQueue<Chunk> queue;
    private final ConcurrentLinkedQueue<byte[]> freeBuffers = new ConcurrentLinkedQueue<byte[]>();
    private final int blockSize;

    private byte[] buf;
    private int bufLen;
    private boolean finished;
    private final byte[] one = new byte[1];

    /** Result of one worker: the encoded XZ Block. */
    private static final class Chunk {
        final byte[] data;
        final int len;
        final long unpadded;
        final long uncompressed;

        Chunk(final byte[] data, final int len, final long unpadded, final long uncompressed) {
            this.data = data;
            this.len = len;
            this.unpadded = unpadded;
            this.uncompressed = uncompressed;
        }
    }

    /**
     * Returns a parallel writer when several workers fit in the heap, otherwise a
     * classic {@link XZOutputStream}. CRC64 check, like xz.
     */
    public static FinishableOutputStream create(final OutputStream out, final LZMA2Options options) throws IOException {
        return create(out, options, -1L);
    }

    /**
     * Same as {@link #create(OutputStream, LZMA2Options)} with the expected input
     * size, used to cut blocks of equal size so that every thread gets the same
     * amount of work (-1 = unknown).
     */
    public static FinishableOutputStream create(final OutputStream out, final LZMA2Options options, final long sizeHint) throws IOException {
        final int workers = workersFor(options);
        if (workers <= 1) return new XZOutputStream(out, options);
        return new ParallelXZOutputStream(out, options, XZ.CHECK_CRC64, workers, blockSizeFor(options, sizeHint, workers));
    }

    /** Number of workers whose encoders fit in the heap (1 = use the single-threaded encoder). */
    static int workersFor(final LZMA2Options options) {
        final long perTask = options.getEncoderMemoryUsage() * 1024L + 3L * maxBlockSize(options);
        return ArcanaConcurrency.workersFor(perTask);
    }

    /** Largest block: 3 x dictionary size (xz -T default), at least 1 MiB. */
    static int maxBlockSize(final LZMA2Options options) {
        final long b = 3L * options.getDictSize();
        return (int) Math.max(MIN_BLOCK, Math.min(b, 1 << 30));
    }

    /**
     * Block size for {@code sizeHint} bytes of input: the number of blocks is a
     * multiple of {@code workers} (balanced load), each block between 1 x and
     * 3 x the dictionary size.
     */
    static int blockSizeFor(final LZMA2Options options, final long sizeHint, final int workers) {
        final int max = maxBlockSize(options);
        if (sizeHint <= 0) return max;
        final int min = (int) Math.max(MIN_BLOCK, Math.min(options.getDictSize(), max));
        long blocks = (sizeHint + max - 1) / max;
        blocks = ((blocks + workers - 1) / workers) * workers;
        final long size = (sizeHint + blocks - 1) / blocks;
        return (int) Math.max(min, Math.min(max, size));
    }

    /**
     * @param out       destination (not closed by {@link #finish()})
     * @param options   LZMA2 options
     * @param checkType XZ.CHECK_* integrity check of each block
     * @param threads   number of worker threads
     */
    public ParallelXZOutputStream(final OutputStream out, final LZMA2Options options, final int checkType, final int threads) throws IOException {
        this(out, options, checkType, threads, maxBlockSize(options));
    }

    /**
     * @param blockSize uncompressed size of each block (the last one may be smaller)
     */
    public ParallelXZOutputStream(final OutputStream out, final LZMA2Options options, final int checkType, final int threads, final int blockSize) throws IOException {
        if (blockSize < 1) throw new IllegalArgumentException("blockSize must be > 0");
        this.out = out;
        this.filterOptions = new FilterOptions[] {options};
        this.checkType = checkType;
        this.blockSize = blockSize;
        RawCoder.validate(new FilterEncoder[] {options.getFilterEncoder()});
        Check.getInstance(checkType); // validates the check type
        this.queue = new OrderedTaskQueue<Chunk>(threads, this::writeChunk);
        encodeStreamHeader();
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
                return encodeBlock(data, len);
            } finally {
                freeBuffers.add(data);
            }
        });
    }

    /** Compresses one independent XZ Block (runs on a worker thread). */
    private Chunk encodeBlock(final byte[] data, final int len) throws IOException {
        final ExposedByteArrayOutputStream bo = new ExposedByteArrayOutputStream(len / 2 + 4096);
        final FilterEncoder[] filters = new FilterEncoder[filterOptions.length];
        for (int i = 0; i < filters.length; i++) filters[i] = filterOptions[i].getFilterEncoder();
        final BlockOutputStream block = new BlockOutputStream(bo, filters, Check.getInstance(checkType), BasicArrayCache.getInstance());
        block.write(data, 0, len);
        block.finish();
        return new Chunk(bo.buffer(), bo.size(), block.getUnpaddedSize(), block.getUncompressedSize());
    }

    private void writeChunk(final Chunk c) throws IOException {
        out.write(c.data, 0, c.len);
        index.add(c.unpadded, c.uncompressed);
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
            index.encode(out);
            encodeStreamFooter();
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

    // ---- Stream header / footer (same layout as XZOutputStream) ----

    private void encodeStreamHeader() throws IOException {
        out.write(XZ.HEADER_MAGIC);
        final byte[] b = {0x00, (byte) checkType};
        out.write(b);
        EncoderUtil.writeCRC32(out, b);
    }

    private void encodeStreamFooter() throws IOException {
        final byte[] b = new byte[6];
        final long backwardSize = index.getIndexSize() / 4 - 1;
        for (int i = 0; i < 4; ++i) b[i] = (byte) (backwardSize >>> (i * 8));
        b[4] = 0x00;
        b[5] = (byte) checkType;
        EncoderUtil.writeCRC32(out, b);
        out.write(b);
        out.write(XZ.FOOTER_MAGIC);
    }

    /** ByteArrayOutputStream giving access to its buffer (no copy). */
    static final class ExposedByteArrayOutputStream extends java.io.ByteArrayOutputStream {
        ExposedByteArrayOutputStream(final int size) {
            super(size);
        }

        byte[] buffer() {
            return buf;
        }
    }
}
