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
/* CPIO format specification: https://www.mkssoftware.com/docs/man4/cpio.4.asp
 * Supports SVR4 newc (070701/070702) and old ASCII odc (070707) formats. */
package be.stef.arcana.formats.cpio;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reads entries from a CPIO archive stream.
 *
 * <p>Supports the three most common CPIO variants:</p>
 * <ul>
 *   <li><b>newc</b> (SVR4 ASCII, magic {@code 070701}) - the standard modern
 *       format used by Linux initramfs images and RPM packages. Fields are
 *       8-char hex, aligned to 4-byte boundaries.</li>
 *   <li><b>newc+crc</b> (SVR4 ASCII+CRC, magic {@code 070702}) - identical
 *       to newc with an optional per-file CRC32; the checksum field is read
 *       and available via {@link CpioEntry#getChecksum()} but not verified.</li>
 *   <li><b>odc</b> (old POSIX ASCII, magic {@code 070707}) - the legacy
 *       portable ASCII format; fields are octal, no alignment padding.</li>
 * </ul>
 *
 * <p>Binary CPIO formats (little-endian and big-endian) are detected and
 * rejected with a clear error message rather than producing garbage output.</p>
 *
 * <p>Usage pattern:</p>
 * <pre>
 *   try (CpioInputStream cis = new CpioInputStream(in)) {
 *       CpioEntry entry;
 *       while ((entry = cis.getNextEntry()) != null) {
 *           // read entry content from cis (respects entry.getSize() bytes)
 *           cis.closeEntry();
 *       }
 *   }
 * </pre>
 *
 * @author Stef
 * @since 1.1
 */
public final class CpioInputStream extends InputStream {

    // ---- CPIO magic bytes ----
    static final String MAGIC_NEWC     = "070701";
    static final String MAGIC_NEWC_CRC = "070702";
    static final String MAGIC_ODC      = "070707";

    /** Name of the synthetic end-of-archive entry. */
    public static final String TRAILER = "TRAILER!!!";

    /** NEWC header length (magic + 13 * 8 hex chars). */
    private static final int NEWC_HEADER_LEN = 110;
    /** ODC header length (magic + fields in octal ASCII). */
    private static final int ODC_HEADER_LEN = 76;

    private final InputStream in;
    private CpioEntry currentEntry;
    private long entryBytesRead;
    private long totalBytesRead; // for padding calculations in NEWC

    public CpioInputStream(final InputStream in) {
        this.in = in;
    }

    // =========================================================================
    // Entry lifecycle
    // =========================================================================

    /**
     * Reads the next CPIO entry header and positions the stream at the
     * beginning of the entry's data. Returns {@code null} at end of archive.
     *
     * @return the next entry, or {@code null} if the archive trailer has been reached
     * @throws IOException on read error or malformed header
     */
    public CpioEntry getNextEntry() throws IOException {
        // Align to 4-byte boundary if the previous entry was NEWC format
        // (closeEntry() handles data padding, but we also need to handle the
        // case where the caller did not call closeEntry() at all)
        if (currentEntry != null && currentEntry.isNewc()) {
            final long remaining = currentEntry.getSize() - entryBytesRead;
            skipFully(remaining);
            // data padding already handled inside skipFully tracking
            alignNewcData(currentEntry.getSize());
        }

        final byte[] magic = new byte[6];
        final int n = readFully(magic, 0, 6, false);
        if (n < 6) return null;
        final String magicStr = new String(magic, "US-ASCII");

        if (magicStr.equals(MAGIC_NEWC) || magicStr.equals(MAGIC_NEWC_CRC)) {
            currentEntry = readNewcHeader(magicStr);
        } else if (magicStr.equals(MAGIC_ODC)) {
            currentEntry = readOdcHeader();
        } else if ((magic[0] == (byte) 0xC7 && magic[1] == 0x71) || (magic[0] == 0x71 && magic[1] == (byte) 0xC7)) {
            throw new IOException("Binary CPIO format is not supported (only newc/odc ASCII formats are)");
        } else {
            throw new IOException("Not a CPIO archive (unknown magic: " + magicStr + ")");
        }

        entryBytesRead = 0;
        if (TRAILER.equals(currentEntry.getName())) {
            return null;
        }
        return currentEntry;
    }

    /**
     * Skips any unread data and alignment padding for the current entry,
     * leaving the stream positioned at the next entry header.
     *
     * @throws IOException on read error
     */
    public void closeEntry() throws IOException {
        if (currentEntry == null) return;
        final long remaining = currentEntry.getSize() - entryBytesRead;
        skipFully(remaining);
        if (currentEntry.isNewc()) {
            alignNewcData(currentEntry.getSize());
        }
        currentEntry = null;
    }

    // =========================================================================
    // InputStream - delegates to underlying stream, tracks bytes read
    // =========================================================================

    @Override
    public int read() throws IOException {
        if (currentEntry == null || entryBytesRead >= currentEntry.getSize()) return -1;
        final int b = in.read();
        if (b >= 0) { entryBytesRead++; totalBytesRead++; }
        return b;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (currentEntry == null || entryBytesRead >= currentEntry.getSize()) return -1;
        final int toRead = (int) Math.min(len, currentEntry.getSize() - entryBytesRead);
        final int n = in.read(buf, off, toRead);
        if (n > 0) { entryBytesRead += n; totalBytesRead += n; }
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // NEWC header parsing
    // =========================================================================

    private CpioEntry readNewcHeader(final String magic) throws IOException {
        // 110 bytes total: 6 magic + 104 hex chars (13 fields * 8 chars each)
        final byte[] rest = new byte[NEWC_HEADER_LEN - 6];
        readFully(rest, 0, rest.length, true);
        totalBytesRead += NEWC_HEADER_LEN;

        final int nameSize  = hexInt(rest, 88, 8);   // offset 94 in full header = 88 in rest
        final long fileSize = hexLong(rest, 48, 8);  // offset 54
        final int mode      = (int) hexLong(rest, 8, 8);  // offset 14
        final long mtime    = hexLong(rest, 40, 8);  // offset 46
        final long checksum = hexLong(rest, 96, 8);  // offset 102

        final byte[] nameBytes = new byte[nameSize];
        readFully(nameBytes, 0, nameSize, true);
        totalBytesRead += nameSize;
        // Pad name to 4-byte boundary from start of header
        final int namePad = (4 - ((NEWC_HEADER_LEN + nameSize) % 4)) % 4;
        skipFully(namePad);

        final String name = trimName(nameBytes);
        return new CpioEntry(name, mode, fileSize, mtime, checksum, true);
    }

    // =========================================================================
    // ODC header parsing
    // =========================================================================

    private CpioEntry readOdcHeader() throws IOException {
        // 76 bytes total: 6 magic + 70 octal chars, no padding in odc format
        final byte[] rest = new byte[ODC_HEADER_LEN - 6];
        readFully(rest, 0, rest.length, true);
        totalBytesRead += ODC_HEADER_LEN;

        // ODC rest layout (without the 6-byte magic already consumed):
        // [0..5]=dev [6..11]=ino [12..17]=mode [18..23]=uid [24..29]=gid
        // [30..35]=nlink [36..41]=rdev [42..52]=mtime(11) [53..58]=namesize(6) [59..69]=filesize(11)
        final int mode      = (int) octLong(rest, 12, 6);
        final long mtime    = octLong(rest, 42, 11);
        final long fileSize = octLong(rest, 59, 11);
        final int nameSize  = (int) octLong(rest, 53, 6);

        final byte[] nameBytes = new byte[nameSize];
        readFully(nameBytes, 0, nameSize, true);
        totalBytesRead += nameSize;
        // No padding in ODC format

        final String name = trimName(nameBytes);
        return new CpioEntry(name, mode, fileSize, mtime, 0L, false);
    }

    // =========================================================================
    // Alignment helper for NEWC data sections
    // =========================================================================

    /** Aligns the stream to a 4-byte boundary after {@code dataSize} bytes of file data. */
    private void alignNewcData(final long dataSize) throws IOException {
        final int pad = (int) ((4 - (dataSize % 4)) % 4);
        skipFully(pad);
    }

    // =========================================================================
    // Parsing helpers
    // =========================================================================

    private static long hexLong(final byte[] buf, final int off, final int len) {
        long v = 0;
        for (int i = 0; i < len; i++) {
            final int c = buf[off + i] & 0xFF;
            v = v * 16 + (c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0');
        }
        return v;
    }

    private static int hexInt(final byte[] buf, final int off, final int len) {
        return (int) hexLong(buf, off, len);
    }

    private static long octLong(final byte[] buf, final int off, final int len) {
        long v = 0;
        for (int i = 0; i < len; i++) v = v * 8 + ((buf[off + i] & 0xFF) - '0');
        return v;
    }

    private static String trimName(final byte[] nameBytes) {
        int len = nameBytes.length;
        while (len > 0 && nameBytes[len - 1] == 0) len--;
        // Strip leading "./" 
        String name;
        try {
            name = new String(nameBytes, 0, len, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            name = new String(nameBytes, 0, len);
        }
        if (name.startsWith("./")) name = name.substring(2);
        return name;
    }

    // =========================================================================
    // I/O helpers
    // =========================================================================

    private int readFully(final byte[] buf, final int off, final int len, final boolean required) throws IOException {
        int remaining = len;
        int pos = off;
        while (remaining > 0) {
            final int n = in.read(buf, pos, remaining);
            if (n < 0) {
                if (required) throw new IOException("Unexpected end of CPIO stream");
                return len - remaining;
            }
            pos += n;
            remaining -= n;
        }
        return len;
    }

    private void skipFully(final long n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            final long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() < 0) throw new IOException("Unexpected end of CPIO stream while skipping");
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
        totalBytesRead += n;
    }
}