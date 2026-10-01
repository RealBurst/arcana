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

import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.ParallelBlockInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;

/**
 * Multithreaded decoding of a raw LZMA2 stream stored in a file (7z coder 0x21).
 *
 * <p>An LZMA2 stream is a sequence of chunks. A chunk whose control byte is
 * 0xE0-0xFF resets the dictionary, the state and the properties: nothing before
 * it is needed to decode what follows. Multithreaded encoders (Arcana
 * {@link ParallelLZMA2OutputStream}, 7-Zip -mmt) start every block this way.
 * The chunk headers are scanned (only a few bytes are read per 64 KB chunk), the
 * stream is cut at these points and the segments are decoded in parallel, each
 * one by a new LZMA2 decoder.</p>
 *
 * <p>When the stream has a single segment (single-threaded encoders), is not
 * valid, or the memory is insufficient, {@link #tryOpen} returns null and the
 * caller uses the classic sequential decoder, which reports errors as usual.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelLZMA2InputStream {

    /** Segments larger than this are not decoded in memory. */
    private static final long MAX_SEGMENT = 256L << 20;

    private ParallelLZMA2InputStream() {}

    /** One independent part of the stream. */
    private static final class Segment {
        final long offset;   // file position of its first chunk
        long packed;         // compressed bytes (chunk headers included)
        long unpacked;       // decompressed bytes

        Segment(final long offset) {
            this.offset = offset;
        }
    }

    /**
     * Returns a parallel decoder of the LZMA2 stream at {@code [start, start + packSize)}
     * of {@code channel}, or null if the stream cannot or need not be split.
     * The channel is only read with positional reads (thread-safe); it is not closed.
     *
     * @param dictSize   dictionary size from the coder properties
     * @param unpackSize expected decompressed size
     */
    public static InputStream tryOpen(final FileChannel channel, final long start, final long packSize, final int dictSize, final long unpackSize) {
        if (ArcanaConcurrency.threads <= 1) return null;
        final List<Segment> segments;
        try {
            segments = scan(channel, start, packSize, unpackSize);
        } catch (final IOException | RuntimeException e) {
            return null;
        }
        if (segments == null || segments.size() < 2) return null;
        long largest = 0;
        for (final Segment s : segments) largest = Math.max(largest, s.unpacked);
        if (largest > MAX_SEGMENT) return null;
        final long perWorker = 2 * largest + Math.min(dictSize, largest) + (1L << 20);
        final int workers = Math.min(segments.size(), ArcanaConcurrency.workersFor(perWorker));
        if (workers < 2) return null;
        final ParallelBlockInputStream.BlockDecoder decoder = index -> decode(channel, segments.get(index), dictSize);
        return new ParallelBlockInputStream(segments.size(), decoder, workers, null);
    }

    /** Reads the chunk headers and cuts the stream before every chunk resetting the dictionary and the properties. */
    private static List<Segment> scan(final FileChannel ch, final long start, final long packSize, final long unpackSize) throws IOException {
        final long end = start + packSize;
        final byte[] h = new byte[6];
        final List<Segment> list = new ArrayList<Segment>();
        Segment cur = null;
        long pos = start;
        long total = 0;
        while (true) {
            if (pos >= end) return null; // no end marker
            readFully(ch, pos, h, 0, (int) Math.min(6, end - pos));
            final int ctrl = h[0] & 0xFF;
            if (ctrl == 0x00) {
                if (cur != null) cur.packed = pos - cur.offset;
                break;
            }
            final long chunkUnpacked;
            final long chunkSize;
            if (ctrl == 0x01 || ctrl == 0x02) {
                chunkUnpacked = (((h[1] & 0xFF) << 8) | (h[2] & 0xFF)) + 1;
                chunkSize = 3 + chunkUnpacked;
            } else if (ctrl >= 0x80) {
                chunkUnpacked = (((ctrl & 0x1F) << 16) | ((h[1] & 0xFF) << 8) | (h[2] & 0xFF)) + 1;
                final int packed = (((h[3] & 0xFF) << 8) | (h[4] & 0xFF)) + 1;
                chunkSize = (ctrl >= 0xC0 ? 6 : 5) + packed;
            } else {
                return null; // invalid control byte
            }
            if (cur == null) {
                if (ctrl != 0x01 && ctrl < 0xE0) return null; // the stream must start with a dictionary reset
                cur = new Segment(pos);
                list.add(cur);
            } else if (ctrl >= 0xE0) {
                cur.packed = pos - cur.offset;
                cur = new Segment(pos);
                list.add(cur);
            }
            cur.unpacked += chunkUnpacked;
            total += chunkUnpacked;
            pos += chunkSize;
        }
        return total == unpackSize ? list : null;
    }

    /** Decodes one segment (worker thread): its chunks followed by an end marker. */
    private static byte[] decode(final FileChannel ch, final Segment s, final int dictSize) throws IOException {
        final byte[] packed = new byte[(int) s.packed + 1]; // + 0x00 end marker
        readFully(ch, s.offset, packed, 0, (int) s.packed);
        // The segment starts with a dictionary reset: it never looks further back than its own data
        final int segDict = (int) Math.max(4096, Math.min(dictSize, s.unpacked));
        final LZMA2InputStream lz = new LZMA2InputStream(new ByteArrayInputStream(packed), segDict, null, BasicArrayCache.getInstance());
        try {
            final byte[] out = new byte[(int) s.unpacked];
            int n = 0;
            while (n < out.length) {
                final int k = lz.read(out, n, out.length - n);
                if (k < 0) throw new CorruptedInputException("LZMA2 segment is truncated");
                n += k;
            }
            if (lz.read() != -1) throw new CorruptedInputException("LZMA2 segment is longer than announced");
            return out;
        } finally {
            lz.close();
        }
    }

    /** Positional read (thread-safe, does not move the channel position). */
    private static void readFully(final FileChannel ch, long pos, final byte[] b, final int off, final int len) throws IOException {
        final ByteBuffer bb = ByteBuffer.wrap(b, off, len);
        while (bb.hasRemaining()) {
            final int n = ch.read(bb, pos);
            if (n < 0) throw new EOFException("Truncated LZMA2 stream");
            pos += n;
        }
    }
}
