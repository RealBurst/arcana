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
package be.stef.arcana.formats.lzip;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.formats.xz.LZMAInputStream;
import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;

/**
 * Decompresses an lzip file (.lz), written from the "File format" section of
 * the lzip manual.
 *
 * <p>A file is a series of members. Each member holds:</p>
 * <ul>
 * <li>a 6-byte header: "LZIP", version 1, coded dictionary size (bits 0-4:
 *     base 2 logarithm of the base size, 12 to 29; bits 5-7: number of
 *     sixteenths of the base size to subtract);</li>
 * <li>a raw LZMA stream (lc=3, lp=0, pb=2) ended by the end-of-stream marker;</li>
 * <li>a 20-byte trailer: CRC32 of the uncompressed data (4 bytes), data size
 *     (8 bytes) and member size (8 bytes, header and trailer included), all
 *     little-endian.</li>
 * </ul>
 *
 * <p>The members are decoded one after the other and their data is
 * concatenated; the CRC32 and both sizes of every member are checked. Data
 * after the last member that does not start with "LZIP" is ignored, as lzip
 * does by default. The LZMA decoder is {@link LZMAInputStream} (XZ for Java,
 * raw mode with explicit properties).</p>
 *
 * @author Stef
 * @since 1.4
 */
public final class LzipInputStream extends InputStream {

    private static final byte[] MAGIC = {'L', 'Z', 'I', 'P'};
    private static final int HEADER_SIZE  = 6;
    private static final int TRAILER_SIZE = 20;
    private static final byte LZMA_PROPS  = (byte) 0x5D; // (pb * 5 + lp) * 9 + lc with lc=3, lp=0, pb=2

    private final Counting in;
    private final CRC32 crc = new CRC32();
    private final byte[] one = new byte[1];
    private LZMAInputStream lzma;
    private long memberStart;
    private long dataSize;
    private int members;
    private boolean finished;

    /**
     * @param in lzip file content, read from its first byte
     * @throws IOException if the first member header is not valid
     */
    public LzipInputStream(final InputStream in) throws IOException {
        this.in = new Counting(new BufferedInputStream(in, 65536));
        if (!nextMember()) throw new ArcanaCorruptedException("Not an lzip file (missing \"LZIP\" header)");
    }

    /** Number of members decoded or being decoded. */
    public int getMemberCount() {
        return members;
    }

    @Override
    public int read() throws IOException {
        return read(one, 0, 1) < 0 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        while (!finished) {
            if (lzma == null) {
                if (!nextMember()) {
                    finished = true;
                    break;
                }
            }
            final int n;
            try {
                n = lzma.read(b, off, len);
            } catch (final EOFException e) {
                throw new ArcanaCorruptedException("lzip: unexpected end of file in member " + members, e);
            } catch (final ArcanaCorruptedException e) {
                throw e;
            } catch (final IOException e) {
                throw new ArcanaCorruptedException("lzip: corrupted LZMA data in member " + members + (e.getMessage() != null ? " (" + e.getMessage() + ")" : ""), e);
            }
            if (n > 0) {
                crc.update(b, off, n);
                dataSize += n;
                return n;
            }
            endMember();
        }
        return -1;
    }

    /** Reads the next member header; false at the end of the file (or before trailing data). */
    private boolean nextMember() throws IOException {
        final byte[] h = new byte[HEADER_SIZE];
        final long start = in.count;
        final int n = readUpTo(h);
        if (n == 0 && members > 0) return false;
        int match = 0;
        while (match < MAGIC.length && match < n && h[match] == MAGIC[match]) match++;
        if (match < MAGIC.length) {
            if (members == 0) return false;
            if (match == n) throw new ArcanaCorruptedException("lzip: truncated header after member " + members);
            return false; // trailing data, ignored
        }
        if (n < HEADER_SIZE) throw new ArcanaCorruptedException("lzip: truncated header of member " + (members + 1));
        if (h[4] != 1) throw new ArcanaCorruptedException("lzip: version " + (h[4] & 0xFF) + " not supported in member " + (members + 1) + " (only version 1)");
        final int dictSize = dictionarySize(h[5] & 0xFF);
        if (dictSize < 0) throw new ArcanaCorruptedException("lzip: invalid dictionary size in member " + (members + 1));
        members++;
        memberStart = start;
        dataSize = 0;
        crc.reset();
        try {
            lzma = new LZMAInputStream(in, -1, LZMA_PROPS, dictSize);
        } catch (final EOFException e) {
            throw new ArcanaCorruptedException("lzip: unexpected end of file in member " + members, e);
        } catch (final IOException e) {
            throw new ArcanaCorruptedException("lzip: corrupted LZMA data in member " + members, e);
        }
        return true;
    }

    /** Checks the trailer of the member whose LZMA stream just ended. */
    private void endMember() throws IOException {
        lzma = null;
        final byte[] t = new byte[TRAILER_SIZE];
        if (readUpTo(t) < TRAILER_SIZE) throw new ArcanaCorruptedException("lzip: truncated trailer of member " + members);
        final long storedCrc  = le(t, 0, 4);
        final long storedData = le(t, 4, 8);
        final long storedSize = le(t, 12, 8);
        if (storedCrc != crc.getValue()) throw new ArcanaCorruptedException("lzip: CRC32 mismatch in member " + members + String.format(" (stored %08X, computed %08X)", storedCrc, crc.getValue()));
        if (storedData != dataSize) throw new ArcanaCorruptedException("lzip: data size mismatch in member " + members + " (stored " + storedData + ", decoded " + dataSize + ")");
        if (storedSize != in.count - memberStart) throw new ArcanaCorruptedException("lzip: member size mismatch in member " + members + " (stored " + storedSize + ", read " + (in.count - memberStart) + ")");
    }

    /**
     * Dictionary size coded in the header byte: 2^(bits 0-4) minus (bits 5-7)
     * sixteenths of it, from 4 KiB to 512 MiB; -1 when out of range.
     */
    static int dictionarySize(final int coded) {
        final int log = coded & 0x1F;
        if (log < 12 || log > 29) return -1;
        final int base = 1 << log;
        final int size = base - (base / 16) * (coded >>> 5);
        return log == 12 && (coded >>> 5) != 0 ? -1 : size;
    }

    private int readUpTo(final byte[] b) throws IOException {
        int n = 0;
        while (n < b.length) {
            final int r = in.read(b, n, b.length - n);
            if (r < 0) break;
            n += r;
        }
        return n;
    }

    private static long le(final byte[] b, final int off, final int len) {
        long v = 0;
        for (int i = len - 1; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
    }

    @Override
    public void close() throws IOException {
        lzma = null;
        in.in.close();
    }

    /** Counts the bytes read (member size check); close is done by the outer stream only. */
    private static final class Counting extends InputStream {
        private final InputStream in;
        private long count;

        Counting(final InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            final int c = in.read();
            if (c >= 0) count++;
            return c;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = in.read(b, off, len);
            if (n > 0) count += n;
            return n;
        }

        @Override
        public void close() {
            // the LZMA decoder of a member must not close the file
        }
    }
}
