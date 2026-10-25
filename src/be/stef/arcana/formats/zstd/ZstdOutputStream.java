/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.formats.zstd;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Writes one Zstandard frame (RFC 8878, section 3.1.1), written from the
 * specification:
 * <ul>
 *   <li>frame header with the window size, or with the content size when it
 *       is given (single segment when the content fits in the window);</li>
 *   <li>blocks of at most 128 KiB: compressed, raw when compression does not
 *       help, RLE when the block is one repeated byte;</li>
 *   <li>content checksum (low 32 bits of XXH64).</li>
 * </ul>
 * Levels: 1 ("fast", window 512 KiB) and 2 ("double fast", window 1 MiB);
 * other values are brought into that range. Output readable by any
 * Zstandard decoder (zstd 1.x, Arcana).
 *
 * <p>{@link #finish()} ends the frame without closing the underlying stream;
 * {@link #close()} finishes and closes it.</p>
 *
 * @author Stef
 * @since 1.2.0
 */
public class ZstdOutputStream extends OutputStream {

    /** Lowest level. */
    public static final int MIN_LEVEL = 1;
    /** Highest level implemented. */
    public static final int MAX_LEVEL = 2;
    /** Default level. */
    public static final int DEFAULT_LEVEL = 2;

    private static final int BLOCK = Constants.MAX_BLOCK_SIZE;

    private final OutputStream out;
    private final long contentSize;
    private final int windowLog;
    private final int windowSize;
    private final byte[] buf;
    private int fill;
    private int blockStart;
    private final ZstdMatchFinder finder;
    private final ZstdSequenceStore store = new ZstdSequenceStore();
    private final ZstdBlockEncoder encoder = new ZstdBlockEncoder();
    private final byte[] blockOut = new byte[3 + BLOCK + 16];
    private final XxHash64 checksum = new XxHash64();
    private long total;
    private boolean headerWritten;
    private boolean finished;
    private boolean closed;

    /** Level {@link #DEFAULT_LEVEL}, content size unknown. */
    public ZstdOutputStream(final OutputStream out) {
        this(out, DEFAULT_LEVEL, -1);
    }

    /** Content size unknown. */
    public ZstdOutputStream(final OutputStream out, final int level) {
        this(out, level, -1);
    }

    /**
     * @param out         destination
     * @param level       1 or 2 (lower values give 1, higher values 2)
     * @param contentSize number of bytes that will be written, stored in the frame header and checked by {@link #finish()}; -1 if unknown
     */
    public ZstdOutputStream(final OutputStream out, final int level, final long contentSize) {
        this.out = out;
        final int lv = Math.max(MIN_LEVEL, Math.min(MAX_LEVEL, level));
        this.contentSize = contentSize;
        int wlog = lv == 1 ? 19 : 20;
        if (contentSize >= 0) {
            while (wlog > Constants.MIN_WINDOW_LOG && (1L << (wlog - 1)) >= contentSize) wlog--;
        }
        this.windowLog = wlog;
        this.windowSize = 1 << wlog;
        this.buf = new byte[windowSize + BLOCK];
        this.finder = new ZstdMatchFinder(lv, windowSize);
    }

    @Override
    public void write(final int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(final byte[] b, int off, int len) throws IOException {
        if (finished) throw new IOException("Zstandard stream already finished");
        if (len <= 0) return;
        checksum.update(b, off, len);
        total += len;
        if (contentSize >= 0 && total > contentSize) throw new IOException("Zstandard: more data than the declared content size " + contentSize);
        while (len > 0) {
            if (fill - blockStart == BLOCK) {
                writeHeader();
                compressBlock(false);
            }
            if (fill == buf.length) slide();
            final int n = Math.min(len, Math.min(buf.length - fill, BLOCK - (fill - blockStart)));
            System.arraycopy(b, off, buf, fill, n);
            fill += n;
            off += n;
            len -= n;
        }
    }

    /** Keeps the last window before the next block, so that matches can still reach it. */
    private void slide() {
        final int shift = blockStart - windowSize;
        if (shift <= 0) return;
        System.arraycopy(buf, shift, buf, 0, fill - shift);
        fill -= shift;
        blockStart -= shift;
        finder.slide(shift);
    }

    /** Writes the end of the frame; the underlying stream stays open. */
    public void finish() throws IOException {
        if (finished) return;
        if (contentSize >= 0 && total != contentSize) throw new IOException("Zstandard: " + total + " bytes written, " + contentSize + " declared");
        writeHeader();
        compressBlock(true);
        final long h = checksum.hash();
        out.write(new byte[] {(byte) h, (byte) (h >>> 8), (byte) (h >>> 16), (byte) (h >>> 24)});
        finished = true;
        out.flush();
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        try {
            finish();
        } finally {
            closed = true;
            out.close();
        }
    }

    private void writeHeader() throws IOException {
        if (headerWritten) return;
        headerWritten = true;
        final byte[] h = new byte[14];
        int p = 0;
        h[p++] = (byte) Constants.MAGIC_NUMBER;
        h[p++] = (byte) (Constants.MAGIC_NUMBER >>> 8);
        h[p++] = (byte) (Constants.MAGIC_NUMBER >>> 16);
        h[p++] = (byte) (Constants.MAGIC_NUMBER >>> 24);
        final int checksumFlag = 1 << 2;
        if (contentSize < 0) {
            h[p++] = (byte) checksumFlag;
            h[p++] = (byte) ((windowLog - 10) << 3); // exponent, mantissa 0
        } else {
            final boolean single = contentSize <= windowSize;
            final int fcsFlag;
            final int fcsBytes;
            if (contentSize < 256 && single) {
                fcsFlag = 0;
                fcsBytes = 1;
            } else if (contentSize >= 256 && contentSize < 65536 + 256) {
                fcsFlag = 1;
                fcsBytes = 2;
            } else if (contentSize <= 0xFFFFFFFFL) {
                fcsFlag = 2;
                fcsBytes = 4;
            } else {
                fcsFlag = 3;
                fcsBytes = 8;
            }
            h[p++] = (byte) ((fcsFlag << 6) | (single ? 1 << 5 : 0) | checksumFlag);
            if (!single) h[p++] = (byte) ((windowLog - 10) << 3);
            final long v = fcsBytes == 2 ? contentSize - 256 : contentSize;
            for (int i = 0; i < fcsBytes; i++) h[p++] = (byte) (v >>> (8 * i));
        }
        out.write(h, 0, p);
    }

    private void compressBlock(final boolean last) throws IOException {
        final int start = blockStart;
        final int end = fill;
        final int size = end - start;
        final int lastBit = last ? 1 : 0;
        if (size == 0) {
            writeBlockHeader(lastBit, Constants.RAW_BLOCK, 0);
            return;
        }
        boolean same = true;
        final byte first = buf[start];
        for (int i = start + 1; i < end; i++) {
            if (buf[i] != first) {
                same = false;
                break;
            }
        }
        if (same && size > 1) {
            writeBlockHeader(lastBit, Constants.RLE_BLOCK, size);
            out.write(first);
            blockStart = end;
            return;
        }
        final int lowest = Math.max(0, start - windowSize);
        int compressed = -1;
        if (size > 64) {
            final int[] savedRep = finder.rep.clone();
            finder.find(buf, lowest, start, end, store);
            compressed = encoder.encode(store, blockOut, 0, size - 1);
            if (compressed < 0) {
                // stored raw: the decoder keeps its repeated offsets, so must the encoder
                System.arraycopy(savedRep, 0, finder.rep, 0, 3);
            }
        }
        if (compressed > 0) {
            writeBlockHeader(lastBit, Constants.COMPRESSED_BLOCK, compressed);
            out.write(blockOut, 0, compressed);
        } else {
            writeBlockHeader(lastBit, Constants.RAW_BLOCK, size);
            out.write(buf, start, size);
        }
        blockStart = end;
    }

    private void writeBlockHeader(final int last, final int type, final int size) throws IOException {
        final int v = last | (type << 1) | (size << 3);
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
    }
}
