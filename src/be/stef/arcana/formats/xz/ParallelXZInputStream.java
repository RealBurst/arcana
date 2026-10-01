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
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Multithreaded .xz decoding of a file, like {@code xz -T} in decompression mode.
 *
 * <p>A .xz file made of several blocks (xz -T, ParallelXZOutputStream, pixz...)
 * lists them in its Index: each block is decoded by a worker thread with its own
 * {@link SeekableXZInputStream} (integrity checks verified as usual), and the
 * blocks are returned in order. A single-block file (plain {@code xz}) cannot be
 * split and is decoded by the classic {@link XZInputStream}.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ParallelXZInputStream {

    /** Blocks larger than this are not decoded in memory: the sequential decoder is used. */
    private static final long MAX_BLOCK = 256L << 20;
    /** Decoder memory assumed per worker in addition to the block (LZMA2 dictionary). */
    private static final long DECODER_MEMORY = 64L << 20;

    private ParallelXZInputStream() {}

    /**
     * Opens the decompressed content of an .xz file: decoded in parallel when the
     * file has several blocks and several threads are available, sequentially otherwise.
     */
    public static InputStream open(final File file) throws IOException {
        final InputStream parallel = tryParallel(file);
        if (parallel != null) return parallel;
        return new XZInputStream(new BufferedInputStream(new FileInputStream(file), 65536));
    }

    private static InputStream tryParallel(final File file) {
        if (ArcanaConcurrency.threads <= 1) return null;
        final SeekableXZInputStream first;
        try {
            first = new SeekableXZInputStream(new FileSeekableInputStream(file));
        } catch (final IOException | RuntimeException e) {
            return null; // not seekable (damaged index, trailing data...): the sequential decoder reports it
        }
        final int count = first.getBlockCount();
        final long largest = first.getLargestBlockSize();
        final int workers = count < 2 || largest > MAX_BLOCK ? 1 : Math.min(count, ArcanaConcurrency.workersFor(DECODER_MEMORY + 3 * largest));
        if (workers < 2) {
            try { first.close(); } catch (final IOException ignored) { /* nothing */ }
            return null;
        }
        final ConcurrentLinkedQueue<SeekableXZInputStream> free = new ConcurrentLinkedQueue<SeekableXZInputStream>();
        final List<SeekableXZInputStream> all = new ArrayList<SeekableXZInputStream>();
        free.add(first);
        all.add(first);
        final ParallelBlockInputStream.BlockDecoder decoder = index -> {
            SeekableXZInputStream r = free.poll();
            if (r == null) {
                r = new SeekableXZInputStream(new FileSeekableInputStream(file));
                synchronized (all) { all.add(r); }
            }
            boolean ok = false;
            try {
                final byte[] out = new byte[(int) r.getBlockSize(index)];
                r.seekToBlock(index);
                int n = 0;
                while (n < out.length) {
                    final int k = r.read(out, n, out.length - n);
                    if (k < 0) throw new CorruptedInputException("XZ block " + index + " is truncated");
                    n += k;
                }
                ok = true;
                return out;
            } finally {
                if (ok) free.add(r); // a reader that failed keeps its error: not reused
            }
        };
        return new ParallelBlockInputStream(count, decoder, workers, () -> {
            synchronized (all) {
                for (final SeekableXZInputStream r : all) {
                    try { r.close(); } catch (final IOException ignored) { /* closing */ }
                }
            }
        });
    }

    /** Buffered SeekableInputStream over a RandomAccessFile (one per worker). */
    static final class FileSeekableInputStream extends SeekableInputStream {
        private final RandomAccessFile raf;
        private final byte[] buf = new byte[65536];
        private long bufStart; // file position of buf[0]
        private int bufLen;
        private int bufPos;

        FileSeekableInputStream(final File file) throws IOException {
            this.raf = new RandomAccessFile(file, "r");
        }

        private boolean fill() throws IOException {
            bufStart += bufLen;
            bufPos = 0;
            bufLen = 0;
            raf.seek(bufStart);
            final int n = raf.read(buf, 0, buf.length);
            if (n <= 0) return false;
            bufLen = n;
            return true;
        }

        @Override
        public int read() throws IOException {
            if (bufPos == bufLen && !fill()) return -1;
            return buf[bufPos++] & 0xFF;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            if (bufPos == bufLen && !fill()) return -1;
            final int n = Math.min(len, bufLen - bufPos);
            System.arraycopy(buf, bufPos, b, off, n);
            bufPos += n;
            return n;
        }

        @Override
        public long length() throws IOException {
            return raf.length();
        }

        @Override
        public long position() {
            return bufStart + bufPos;
        }

        @Override
        public void seek(final long pos) {
            if (pos >= bufStart && pos <= bufStart + bufLen) {
                bufPos = (int) (pos - bufStart);
            } else {
                bufStart = pos;
                bufLen = 0;
                bufPos = 0;
            }
        }

        @Override
        public void close() throws IOException {
            raf.close();
        }
    }
}
