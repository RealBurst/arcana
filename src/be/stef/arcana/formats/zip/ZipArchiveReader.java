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
package be.stef.arcana.formats.zip;

import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.zip.CRC32;
import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * Pure-Java reader for the ZIP central directory (PKWARE APPNOTE 6.3.x).
 *
 * <p>Replaces {@link java.util.zip.ZipFile}, which rejects encrypted entries on
 * recent JDKs, only decodes Stored/Deflated data and needs reflection to reach
 * the local header offset. This reader only parses the structure; decoding the
 * entry data (compression methods, encryption) is done by the caller on the
 * stream returned by {@link #openRaw(Entry, int)}.</p>
 *
 * <p>Supported: ZIP64 (sizes, offsets and entry count), UTF-8 names (flag bit 11),
 * Info-ZIP Unicode path extra field (0x7075), extended timestamp (0x5455),
 * WinZip AES extra field (0x9901), archives with prepended data (self-extracting
 * stubs). Names without the UTF-8 flag are decoded as UTF-8 when valid, otherwise
 * as IBM437 (the code page defined by the specification).</p>
 *
 * <p>The streams returned by {@link #openRaw(Entry, int)} use positional reads
 * ({@link FileChannel#read(ByteBuffer, long)}): several entries can be read at
 * the same time, from different threads (parallel extraction).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ZipArchiveReader implements Closeable {

    private static final int SIG_LOCAL   = 0x04034b50;
    private static final int SIG_CENTRAL = 0x02014b50;
    private static final int SIG_EOCD    = 0x06054b50;
    private static final int SIG_EOCD64  = 0x06064b50;
    private static final int SIG_LOC64   = 0x07064b50;

    private static final int EOCD_SIZE        = 22;
    private static final int MAX_COMMENT      = 65535;
    private static final long ZIP64_MAGIC     = 0xFFFFFFFFL;

    private static final int EXTRA_ZIP64      = 0x0001;
    private static final int EXTRA_TIMESTAMP  = 0x5455;
    private static final int EXTRA_UNICODE    = 0x7075;
    private static final int EXTRA_AES        = 0x9901;

    private static final Charset CP437 = loadCp437();

    private final RandomAccessFile raf;
    private final List<Entry> entries;
    private long shift; // bytes prepended before the ZIP data (self-extracting stub)

    /** One central directory record. */
    public static final class Entry {
        String name;
        int    flags;
        int    method;
        int    dosTime;
        int    dosDate;
        long   crc;
        long   compressedSize;
        long   size;
        long   localHeaderOffset;
        long   mtimeUtc = -1;      // seconds, from extended timestamp (0x5455), -1 if absent
        int    aesVendorVersion;   // 1 (AE-1) or 2 (AE-2), 0 if not AES
        int    aesStrength;        // 1 = 128, 2 = 192, 3 = 256
        int    aesMethod;          // real compression method under AES

        public String  getName()               { return name; }
        public int     getFlags()              { return flags; }
        public int     getMethod()             { return method; }
        public long    getCrc()                { return crc; }
        public long    getCompressedSize()     { return compressedSize; }
        public long    getSize()               { return size; }
        public int     getDosTime()            { return dosTime; }
        public boolean isDirectory()           { return name.endsWith("/"); }
        public boolean isEncrypted()           { return (flags & 1) != 0; }
        public boolean isStrongEncryption()    { return (flags & 0x40) != 0; }
        public boolean hasDataDescriptor()     { return (flags & 0x08) != 0; }
        public boolean isAes()                 { return aesVendorVersion != 0; }
        public int     getAesVendorVersion()   { return aesVendorVersion; }
        public int     getAesStrength()        { return aesStrength; }
        public int     getAesMethod()          { return aesMethod; }

        /** Last modification time in seconds since the epoch, or -1 if unknown. */
        public long getLastModifiedSeconds() {
            if (mtimeUtc >= 0) return mtimeUtc;
            if (dosDate == 0) return -1L;
            final Calendar c = new GregorianCalendar();
            c.clear();
            c.set(((dosDate >> 9) & 0x7F) + 1980, ((dosDate >> 5) & 0x0F) - 1, dosDate & 0x1F, (dosTime >> 11) & 0x1F, (dosTime >> 5) & 0x3F, (dosTime & 0x1F) * 2);
            return c.getTimeInMillis() / 1000L;
        }

        @Override
        public String toString() { return name; }
    }

    public ZipArchiveReader(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        try {
            entries = Collections.unmodifiableList(readCentralDirectory(file.getName()));
        } catch (IOException | RuntimeException e) {
            raf.close();
            throw e;
        }
    }

    /** Entries in central directory order. */
    public List<Entry> getEntries() {
        return entries;
    }

    /**
     * Opens the raw (still compressed and possibly encrypted) data of an entry.
     *
     * @param trailer number of bytes to exclude at the end of the data (10 for the
     *                WinZip AES authentication code, 0 otherwise)
     */
    public InputStream openRaw(final Entry e, final int trailer) throws IOException {
        final long lh = e.localHeaderOffset + shift;
        final byte[] hdr = new byte[30];
        readFully(raf.getChannel(), lh, hdr, 0, hdr.length);
        if (le32(hdr, 0) != SIG_LOCAL) throw new ArcanaCorruptedException("Invalid local header for ZIP entry '" + e.name + "'");
        final long dataStart = lh + 30 + le16(hdr, 26) + le16(hdr, 28);
        final long len = e.compressedSize - trailer;
        if (len < 0 || dataStart + e.compressedSize > raf.length()) throw new ArcanaCorruptedException("Truncated data for ZIP entry '" + e.name + "'");
        return new SliceInputStream(raf.getChannel(), dataStart, len);
    }

    /** Positional read (thread-safe, does not move the file pointer). */
    private static void readFully(final FileChannel ch, long pos, final byte[] b, final int off, final int len) throws IOException {
        final ByteBuffer bb = ByteBuffer.wrap(b, off, len);
        while (bb.hasRemaining()) {
            final int n = ch.read(bb, pos);
            if (n < 0) throw new EOFException("Unexpected end of ZIP file");
            pos += n;
        }
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // ---- Central directory ----------------------------------------------

    private List<Entry> readCentralDirectory(final String archiveName) throws IOException {
        final long fileLen = raf.length();
        final int tailLen = (int) Math.min(fileLen, EOCD_SIZE + MAX_COMMENT);
        final byte[] tail = new byte[tailLen];
        raf.seek(fileLen - tailLen);
        raf.readFully(tail);

        int p = -1;
        for (int i = tailLen - EOCD_SIZE; i >= 0; i--) {
            if (le32(tail, i) == SIG_EOCD && i + EOCD_SIZE + le16(tail, i + 20) <= tailLen) { p = i; break; }
        }
        if (p < 0) throw new ArcanaCorruptedException("Not a ZIP archive (end of central directory not found): " + archiveName);
        final long eocdPos = fileLen - tailLen + p;

        long count    = le16(tail, p + 10);
        long cdSize   = le32(tail, p + 12) & ZIP64_MAGIC;
        long cdOffset = le32(tail, p + 16) & ZIP64_MAGIC;
        long cdEnd    = eocdPos;

        // ZIP64 end of central directory locator (just before the classic EOCD)
        if (eocdPos >= 20) {
            final byte[] loc = new byte[20];
            raf.seek(eocdPos - 20);
            raf.readFully(loc);
            if (le32(loc, 0) == SIG_LOC64) {
                final long eocd64Pos = le64(loc, 8);
                final byte[] e64 = new byte[56];
                long pos64 = eocd64Pos;
                if (pos64 >= 0 && pos64 + 56 <= fileLen) {
                    raf.seek(pos64);
                    raf.readFully(e64);
                }
                if (le32(e64, 0) != SIG_EOCD64) {
                    // prepended data: the ZIP64 record sits just before the locator
                    pos64 = eocdPos - 20 - 56;
                    raf.seek(pos64);
                    raf.readFully(e64);
                    if (le32(e64, 0) != SIG_EOCD64) throw new ArcanaCorruptedException("Invalid ZIP64 end of central directory: " + archiveName);
                }
                count    = le64(e64, 32);
                cdSize   = le64(e64, 40);
                cdOffset = le64(e64, 48);
                cdEnd    = pos64;
            }
        }

        // Self-extracting archives: offsets are relative to the start of the ZIP data
        shift = cdEnd - cdSize - cdOffset;
        if (shift < 0) shift = 0;
        if (cdSize > Integer.MAX_VALUE) throw new ArcanaCorruptedException("ZIP central directory too large: " + archiveName);

        final byte[] cd = new byte[(int) cdSize];
        raf.seek(cdOffset + shift);
        raf.readFully(cd);

        final List<Entry> list = new ArrayList<Entry>((int) Math.min(count, 65536));
        int q = 0;
        while (q + 46 <= cd.length && le32(cd, q) == SIG_CENTRAL) {
            final Entry e = new Entry();
            e.flags             = le16(cd, q + 8);
            e.method            = le16(cd, q + 10);
            e.dosTime           = le16(cd, q + 12);
            e.dosDate           = le16(cd, q + 14);
            e.crc               = le32(cd, q + 16) & ZIP64_MAGIC;
            e.compressedSize    = le32(cd, q + 20) & ZIP64_MAGIC;
            e.size              = le32(cd, q + 24) & ZIP64_MAGIC;
            final int nameLen   = le16(cd, q + 28);
            final int extraLen  = le16(cd, q + 30);
            final int commLen   = le16(cd, q + 32);
            e.localHeaderOffset = le32(cd, q + 42) & ZIP64_MAGIC;
            final int nameOff   = q + 46;
            if (nameOff + nameLen + extraLen + commLen > cd.length) throw new ArcanaCorruptedException("Truncated ZIP central directory: " + archiveName);
            e.name = decodeName(cd, nameOff, nameLen, (e.flags & 0x800) != 0);
            parseExtra(e, cd, nameOff + nameLen, extraLen, cd, nameOff, nameLen);
            list.add(e);
            q = nameOff + nameLen + extraLen + commLen;
        }
        if (list.isEmpty() && count > 0) throw new ArcanaCorruptedException("Invalid ZIP central directory: " + archiveName);
        return list;
    }

    private static void parseExtra(final Entry e, final byte[] b, final int off, final int len, final byte[] nameBuf, final int nameOff, final int nameLen) {
        int p = off;
        final int end = off + len;
        while (p + 4 <= end) {
            final int id = le16(b, p);
            final int sz = le16(b, p + 2);
            final int d = p + 4;
            if (d + sz > end) break;
            if (id == EXTRA_ZIP64) {
                int r = d;
                if (e.size == ZIP64_MAGIC && r + 8 <= d + sz)              { e.size = le64(b, r); r += 8; }
                if (e.compressedSize == ZIP64_MAGIC && r + 8 <= d + sz)    { e.compressedSize = le64(b, r); r += 8; }
                if (e.localHeaderOffset == ZIP64_MAGIC && r + 8 <= d + sz) { e.localHeaderOffset = le64(b, r); }
            } else if (id == EXTRA_TIMESTAMP && sz >= 5 && (b[d] & 1) != 0) {
                e.mtimeUtc = le32(b, d + 1) & ZIP64_MAGIC;
            } else if (id == EXTRA_UNICODE && sz >= 5 && b[d] == 1) {
                final CRC32 crc = new CRC32();
                crc.update(nameBuf, nameOff, nameLen);
                if ((le32(b, d + 1) & ZIP64_MAGIC) == crc.getValue()) e.name = new String(b, d + 5, sz - 5, StandardCharsets.UTF_8);
            } else if (id == EXTRA_AES && sz >= 7) {
                e.aesVendorVersion = le16(b, d);
                e.aesStrength      = b[d + 4] & 0xFF;
                e.aesMethod        = le16(b, d + 5);
            }
            p = d + sz;
        }
    }

    private static String decodeName(final byte[] b, final int off, final int len, final boolean utf8Flag) {
        if (utf8Flag) return new String(b, off, len, StandardCharsets.UTF_8);
        boolean ascii = true;
        for (int i = off; i < off + len; i++) if (b[i] < 0) { ascii = false; break; }
        if (ascii) return new String(b, off, len, StandardCharsets.US_ASCII);
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b, off, len)).toString();
        } catch (final CharacterCodingException notUtf8) {
            return new String(b, off, len, CP437);
        }
    }

    private static Charset loadCp437() {
        try {
            return Charset.forName("IBM437");
        } catch (final RuntimeException e) {
            return StandardCharsets.ISO_8859_1;
        }
    }

    // ---- Little-endian helpers -------------------------------------------

    private static int le16(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    private static long le64(final byte[] b, final int p) {
        return (le32(b, p) & ZIP64_MAGIC) | ((long) le32(b, p + 4) << 32);
    }

    // ---- Buffered slice of the RandomAccessFile --------------------------

    private static final class SliceInputStream extends InputStream {
        private final FileChannel ch;
        private final byte[] buf = new byte[65536];
        private long pos;
        private long remaining;
        private int bufPos;
        private int bufLen;

        SliceInputStream(final FileChannel ch, final long start, final long length) {
            this.ch = ch;
            this.pos = start;
            this.remaining = length;
        }

        private boolean fill() throws IOException {
            if (remaining <= 0) return false;
            final int n = (int) Math.min(buf.length, remaining);
            readFully(ch, pos, buf, 0, n);
            pos += n;
            remaining -= n;
            bufPos = 0;
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
        public int available() {
            return (int) Math.min(Integer.MAX_VALUE, (bufLen - bufPos) + remaining);
        }

        @Override
        public void close() {
            // the RandomAccessFile is owned by the reader
        }
    }
}
