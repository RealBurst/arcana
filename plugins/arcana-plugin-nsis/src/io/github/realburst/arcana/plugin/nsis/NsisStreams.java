/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.nsis;

import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.simple.X86;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/** Input streams used by NSIS installers: raw byte ranges of the file and the three NSIS decompressors. */
final class NsisStreams {

    /** Compression methods of NSIS ("SetCompressor"). */
    enum Method {
        /** "SetCompress off": blocks are stored. */
        STORED("stored"),
        /** "SetCompressor zlib": raw Deflate, without zlib header. */
        DEFLATE("zlib (Deflate)"),
        /** "SetCompressor bzip2": NSIS variant of BZip2 (no header, no CRC). */
        BZIP2("bzip2"),
        /** "SetCompressor lzma": 5 bytes of LZMA properties, then the raw LZMA stream. */
        LZMA("LZMA"),
        /** LZMA preceded by a filter flag byte (1 = x86 BCJ filter), written by some NSIS builds. */
        LZMA_FLAGGED("LZMA");

        final String label;

        Method(final String label) {
            this.label = label;
        }
    }

    private NsisStreams() {
    }

    /** Random access to the bytes of the installer (a file, or the ByteSource given to an analyzer). */
    interface Source {
        long length();

        /** Reads up to len bytes at pos; returns the number of bytes read, -1 at the end. */
        int read(long pos, byte[] b, int off, int len) throws IOException;
    }

    /** Reads exactly b.length bytes at pos. */
    static void readFully(final Source src, final long pos, final byte[] b) throws IOException {
        int n = 0;
        while (n < b.length) {
            final int k = src.read(pos + n, b, n, b.length - n);
            if (k < 0) throw new EOFException("NSIS data truncated at offset " + (pos + n));
            n += k;
        }
    }

    /** Sequential stream over [pos, pos + len) of the source. */
    static InputStream range(final Source src, final long pos, final long len) {
        return new InputStream() {
            private long p = pos;
            private final long end = pos + len;

            @Override
            public int read() throws IOException {
                final byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(final byte[] b, final int off, final int n) throws IOException {
                if (n == 0) return 0;
                if (p >= end) return -1;
                final int k = src.read(p, b, off, (int) Math.min(n, end - p));
                if (k > 0) p += k;
                return k;
            }

            @Override
            public long skip(final long n) {
                final long k = Math.max(0, Math.min(n, end - p));
                p += k;
                return k;
            }
        };
    }

    /** Detects the compression method from the first bytes of a compressed stream. */
    static Method detect(final byte[] b, final int off) {
        if (off + 5 <= b.length && (b[off] & 0xff) == 0x5D && b[off + 1] == 0) return Method.LZMA;
        if (off + 6 <= b.length && (b[off] & 0xff) <= 1 && (b[off + 1] & 0xff) == 0x5D && b[off + 2] == 0) return Method.LZMA_FLAGGED;
        if (off < b.length && (b[off] & 0xff) == 0x31) return Method.BZIP2;
        return Method.DEFLATE;
    }

    /** Decompressing stream for one NSIS compressed stream (a block, or the whole solid data). */
    static InputStream decoder(final InputStream source, final Method method) throws IOException {
        // the decoders read a few bytes at a time: avoid one seek + read per call on the file
        final InputStream raw = new BufferedInputStream(source, 65536);
        switch (method) {
            case STORED:
                return raw;
            case DEFLATE:
                // "nowrap" inflaters need one dummy byte after the data to report the end of the stream
                return new InflaterInputStream(new SequenceInputStream(raw, new ByteArrayInputStream(new byte[1])), new Inflater(true), 65536);
            case BZIP2:
                return BZip2InputStream.forNsis(raw);
            case LZMA:
                return lzma(raw);
            case LZMA_FLAGGED:
                final int flag = raw.read();
                if (flag < 0) throw new EOFException("NSIS LZMA stream truncated");
                final InputStream lzma = lzma(raw);
                return flag == 1 ? new X86FilterInputStream(lzma) : lzma;
            default:
                throw new IOException("Unsupported NSIS compression " + method);
        }
    }

    private static InputStream lzma(final InputStream raw) throws IOException {
        final int props = raw.read();
        int dict = 0;
        for (int i = 0; i < 4; i++) {
            final int c = raw.read();
            if (props < 0 || c < 0) throw new EOFException("NSIS LZMA properties truncated");
            dict |= c << (8 * i);
        }
        // no uncompressed size is stored: the stream ends with the LZMA end marker or with the input
        return new LZMAInputStream(raw, -1, (byte) props, dict);
    }

    /** Reads exactly n bytes; fails on a premature end of stream. */
    static void readFully(final InputStream in, final byte[] b, final int n) throws IOException {
        int done = 0;
        while (done < n) {
            final int k = in.read(b, done, n - done);
            if (k < 0) throw new EOFException("NSIS stream ended early (" + done + " of " + n + " bytes)");
            done += k;
        }
    }

    /** Skips exactly n bytes of a decompressing stream. */
    static void skipFully(final InputStream in, long n) throws IOException {
        final byte[] buf = new byte[65536];
        while (n > 0) {
            final int k = in.read(buf, 0, (int) Math.min(buf.length, n));
            if (k < 0) throw new EOFException("NSIS stream ended early");
            n -= k;
        }
    }

    /** Little-endian 32-bit integer read from a stream. */
    static long readInt(final InputStream in) throws IOException {
        final byte[] b = new byte[4];
        readFully(in, b, 4);
        return (b[0] & 0xffL) | (b[1] & 0xffL) << 8 | (b[2] & 0xffL) << 16 | (b[3] & 0xffL) << 24;
    }

    /** Reverses the x86 BCJ filter (relative CALL/JMP addresses turned into absolute ones). */
    private static final class X86FilterInputStream extends InputStream {
        private final InputStream in;
        private final X86 filter = new X86(false, 0);
        private final byte[] buf = new byte[65536];
        private int start; // first byte not yet returned
        private int filtered; // end of the filtered bytes
        private int end; // end of the buffered bytes
        private boolean eof;

        X86FilterInputStream(final InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            final byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            while (start == filtered) {
                if (eof && filtered == end) return -1;
                System.arraycopy(buf, start, buf, 0, end - start);
                end -= start;
                start = 0;
                filtered = 0;
                while (!eof && end < buf.length) {
                    final int k = in.read(buf, end, buf.length - end);
                    if (k < 0) eof = true;
                    else end += k;
                }
                filtered = filter.code(buf, 0, end);
                if (eof) filtered = end; // the last bytes cannot hold a complete instruction
            }
            final int n = Math.min(len, filtered - start);
            System.arraycopy(buf, start, b, off, n);
            start += n;
            return n;
        }
    }
}
