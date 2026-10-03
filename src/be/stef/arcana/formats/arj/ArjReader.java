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
package be.stef.arcana.formats.arj;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.lha.LhaDecoder;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.zip.CRC32;

/**
 * Sequential reader for ARJ archives, written from the ARJ technical notes
 * (header layout) and the description of the ARJ compression methods.
 *
 * <p>Every header starts with 0x60 0xEA, a 16-bit basic header size (0 marks
 * the end of the archive), the basic header and its CRC-32, then extended
 * headers (skipped). The first header is the archive header. Methods: 0
 * stored, 1 to 3 static Huffman with a 26 KiB window (the -lh7- coding of
 * LHA), 4 "fastest" (lengths and distances coded with unary prefixes).
 * Encrypted ("garbled") entries and entries continued on another volume
 * cannot be extracted.</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class ArjReader implements AutoCloseable {

    /** File types of the basic header. */
    private static final int TYPE_BINARY = 0;
    private static final int TYPE_TEXT = 1;
    private static final int TYPE_MAIN = 2;
    private static final int TYPE_DIRECTORY = 3;

    /** Hosts storing a Unix time instead of an MS-DOS date and time. */
    private static final int HOST_UNIX = 2;
    private static final int HOST_NEXT = 8;

    private static final int FLAG_GARBLED = 0x01;
    private static final int FLAG_VOLUME = 0x04;
    private static final int FLAG_EXTFILE = 0x08;

    private static final int MAX_HEADER = 2600;
    private static final Charset OEM = oemCharset();

    private final InputStream in;
    private ArjEntry current;
    private long remaining; // compressed bytes of the current entry not consumed yet
    private boolean finished;

    /**
     * Opens the archive and reads its main header.
     *
     * @param in archive data, from its first byte
     */
    public ArjReader(final InputStream in) throws IOException {
        this.in = in;
        final byte[] main = readHeader();
        if (main == null || main.length < 30 || (main[6] & 0xff) != TYPE_MAIN) throw new ArcanaCorruptedException("Not an ARJ archive");
    }

    /**
     * Moves to the next file or directory; the data of the previous entry not read is skipped.
     *
     * @return the entry, or null at the end of the archive
     */
    public ArjEntry nextEntry() throws IOException {
        while (true) {
            skipFully(remaining);
            remaining = 0;
            current = null;
            if (finished) return null;
            final byte[] h = readHeader();
            if (h == null) {
                finished = true;
                return null;
            }
            if (h.length < 30) throw new ArcanaCorruptedException("ARJ header too short");
            final int first = h[0] & 0xff;
            if (first < 30 || first > h.length) throw new ArcanaCorruptedException("Invalid ARJ header");
            final int host = h[3] & 0xff;
            final int flags = h[4] & 0xff;
            final int method = h[5] & 0xff;
            final int type = h[6] & 0xff;
            final long time = le32(h, 8) & 0xffffffffL;
            final long packed = le32(h, 12) & 0xffffffffL;
            final long size = le32(h, 16) & 0xffffffffL;
            final int crc = le32(h, 20);
            int end = first;
            while (end < h.length && h[end] != 0) end++;
            remaining = packed;
            if (type != TYPE_BINARY && type != TYPE_TEXT && type != TYPE_DIRECTORY) continue; // volume label, chapter
            final String name = path(decodeName(h, first, end - first));
            if (name.isEmpty()) continue;
            current = new ArjEntry(name, type == TYPE_DIRECTORY, method, flags, size, packed, crc, host == HOST_UNIX || host == HOST_NEXT ? time * 1000L : dosTime(time));
            return current;
        }
    }

    /**
     * Returns the decompressed data of the current entry, checked against its CRC-32 at the end.
     */
    public InputStream openData() throws IOException {
        final ArjEntry e = current;
        if (e == null || e.directory) throw new IllegalStateException("No file entry");
        if ((e.flags & FLAG_GARBLED) != 0) throw new ArcanaUnsupportedFormatException("Encrypted ARJ entry: " + e.name);
        if ((e.flags & (FLAG_VOLUME | FLAG_EXTFILE)) != 0) throw new ArcanaUnsupportedFormatException("ARJ entry split across volumes: " + e.name);
        final InputStream raw = new Bounded();
        final InputStream data;
        switch (e.method) {
            case 0:
                if (e.packedSize != e.size) throw new ArcanaCorruptedException("ARJ stored entry with wrong size: " + e.name);
                data = raw;
                break;
            case 1:
            case 2:
            case 3:
                data = LhaDecoder.arj(raw);
                break;
            case 4:
                data = new FastestDecoder(raw);
                break;
            default:
                throw new ArcanaUnsupportedFormatException("ARJ method " + e.method + " is not supported: " + e.name);
        }
        return new Checked(data, e);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Headers
    // =========================================================================

    /** Reads one header; null for the end-of-archive marker. */
    private byte[] readHeader() throws IOException {
        final int id1 = in.read();
        final int id2 = in.read();
        if (id1 < 0) return null; // no end marker: tolerated
        if (id1 != 0x60 || id2 != 0xEA) throw new ArcanaCorruptedException("ARJ header id not found");
        final int size = readU16();
        if (size == 0) return null;
        if (size > MAX_HEADER) throw new ArcanaCorruptedException("ARJ header too large");
        final byte[] h = new byte[size];
        readFully(h);
        final byte[] c = new byte[4];
        readFully(c);
        final CRC32 crc = new CRC32();
        crc.update(h, 0, size);
        if ((int) crc.getValue() != le32(c, 0)) throw new ArcanaCorruptedException("ARJ header CRC error");
        int ext;
        while ((ext = readU16()) != 0) skipFully(ext + 4L); // extended headers and their CRC
        return h;
    }

    private static String decodeName(final byte[] b, final int off, final int len) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b, off, len)).toString();
        } catch (final CharacterCodingException ex) {
            return new String(b, off, len, OEM);
        }
    }

    /** '\' and '/' are both separators; drive, "." and ".." parts are dropped. */
    private static String path(final String name) {
        final StringBuilder sb = new StringBuilder();
        for (final String part : name.replace('\\', '/').split("/")) {
            if (part.isEmpty() || part.equals(".") || part.equals("..") || part.endsWith(":")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(part);
        }
        return sb.toString();
    }

    private static Charset oemCharset() {
        try {
            return Charset.forName("IBM437");
        } catch (final RuntimeException e) {
            return StandardCharsets.ISO_8859_1;
        }
    }

    /** MS-DOS date and time (local time) to Java milliseconds, 0 if absent. */
    private static long dosTime(final long t) {
        if (t == 0) return 0;
        final Calendar c = Calendar.getInstance();
        c.clear();
        c.set((int) ((t >> 25) & 0x7f) + 1980, (int) ((t >> 21) & 0x0f) - 1, (int) ((t >> 16) & 0x1f), (int) ((t >> 11) & 0x1f), (int) ((t >> 5) & 0x3f), (int) ((t & 0x1f) * 2));
        return c.getTimeInMillis();
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private int readU16() throws IOException {
        final int a = in.read();
        final int b = in.read();
        if (b < 0) throw new EOFException("ARJ archive truncated");
        return a | b << 8;
    }

    private void readFully(final byte[] b) throws IOException {
        int n = 0;
        while (n < b.length) {
            final int r = in.read(b, n, b.length - n);
            if (r < 0) throw new EOFException("ARJ archive truncated");
            n += r;
        }
    }

    private void skipFully(long n) throws IOException {
        while (n > 0) {
            final long s = in.skip(n);
            if (s > 0) {
                n -= s;
            } else {
                if (in.read() < 0) throw new EOFException("ARJ archive truncated");
                n--;
            }
        }
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    /** The compressed bytes of the current entry. */
    private final class Bounded extends InputStream {
        @Override
        public int read() throws IOException {
            if (remaining <= 0) return -1;
            final int b = in.read();
            if (b < 0) throw new EOFException("ARJ archive truncated");
            remaining--;
            return b;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            if (remaining <= 0) return -1;
            final int n = in.read(b, off, (int) Math.min(len, remaining));
            if (n < 0) throw new EOFException("ARJ archive truncated");
            remaining -= n;
            return n;
        }
    }

    /** Stops at the original size and checks the CRC-32. */
    private static final class Checked extends InputStream {
        private final InputStream data;
        private final ArjEntry entry;
        private final CRC32 crc = new CRC32();
        private long left;

        Checked(final InputStream data, final ArjEntry entry) throws IOException {
            this.data = data;
            this.entry = entry;
            this.left = entry.size;
            if (left == 0) check();
        }

        @Override
        public int read() throws IOException {
            final byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            if (left <= 0) return -1;
            final int n = data.read(b, off, (int) Math.min(len, left));
            if (n < 0) throw new ArcanaCorruptedException("ARJ data truncated: " + entry.name);
            crc.update(b, off, n);
            left -= n;
            if (left == 0) check();
            return n;
        }

        private void check() throws IOException {
            if ((int) crc.getValue() != entry.crc) throw new ArcanaCorruptedException("ARJ CRC error: " + entry.name);
        }
    }

    // =========================================================================
    // Method 4 ("fastest")
    // =========================================================================

    /**
     * Method 4: a 0 bit followed by 8 bits is a literal; otherwise the match
     * length and distance are each a unary prefix (up to 7 and 4 one-bits)
     * giving the number of extra bits.
     */
    private static final class FastestDecoder extends InputStream {
        private static final int WINDOW = 26624;
        private final InputStream in;
        private final byte[] window = new byte[WINDOW];
        private int pos;
        private int copyFrom;
        private int copyLeft;
        private int bitBuf;
        private int bitCount;

        FastestDecoder(final InputStream in) {
            this.in = in;
        }

        private int bit() throws IOException {
            if (bitCount == 0) {
                final int b = in.read();
                bitBuf = b < 0 ? 0 : b; // past the end: zeros, as ARJ does
                bitCount = 8;
            }
            bitCount--;
            return bitBuf >> bitCount & 1;
        }

        private int bits(final int n) throws IOException {
            int v = 0;
            for (int i = 0; i < n; i++) v = v << 1 | bit();
            return v;
        }

        /** Unary prefix from start to stop bits, then that many bits. */
        private int prefixed(final int start, final int stop) throws IOException {
            int plus = 0;
            int pwr = 1 << start;
            int width = start;
            while (width < stop && bit() == 1) {
                plus += pwr;
                pwr <<= 1;
                width++;
            }
            return (width == 0 ? 0 : bits(width)) + plus;
        }

        @Override
        public int read() throws IOException {
            if (copyLeft == 0) {
                final int len = prefixed(0, 7);
                if (len == 0) {
                    final int c = bits(8);
                    put(c);
                    return c;
                }
                copyLeft = len + 2;
                final int dist = prefixed(9, 13);
                copyFrom = pos - dist - 1;
                if (copyFrom < 0) copyFrom += WINDOW;
                if (copyFrom < 0) throw new ArcanaCorruptedException("Invalid ARJ distance");
            }
            final int c = window[copyFrom] & 0xff;
            if (++copyFrom == WINDOW) copyFrom = 0;
            copyLeft--;
            put(c);
            return c;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            for (int i = 0; i < len; i++) b[off + i] = (byte) read();
            return len;
        }

        private void put(final int c) {
            window[pos] = (byte) c;
            if (++pos == WINDOW) pos = 0;
        }
    }
}
