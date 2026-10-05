/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.jexepack;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * Reader of the executables made by JexePack (Duckware): a small Windows
 * launcher followed by records holding the Java program.
 *
 * <p>Format worked out from the launchers of JexePack 5.5, 7.3 and 8.3. A record
 * starts on a 16-byte boundary with a 15-byte signature (byte i = 0x4A + 3i/2:
 * "JKMNPQ..."), a type letter, an 8-byte check value (inverse mod 2^64 of a
 * hash of the stored data) and a 32-bit length.</p>
 *
 * <ul>
 *   <li>Version 1 (JexePack 5): data at 0x1C, coded as (b XOR (i AND 0xFF)) - 0x64
 *       (the "V" settings are plain text). B: bootstrap class; Z: file count,
 *       total size, then a gzip stream of files (4-byte tag, name length, name,
 *       flag byte, 32-bit size, data); V: settings.</li>
 *   <li>Version 2 (JexePack 7): a 32-bit hash of the header at 0x1C, data at
 *       0x20, version 1 coding (V: plain settings text). The other records
 *       hold one file: ANSI name (8-bit length, characters, 0), uncompressed
 *       and stored sizes, then the data, gzip-compressed for Z records.</li>
 *   <li>Version 3 (JexePack 8): same header as version 2, data coded by a
 *       linear congruential generator (seed 0x1FA583BB, each decoded byte
 *       added to the state), settings included. Files have a UTF-16 name
 *       (32-bit length, characters, 16-bit 0).</li>
 * </ul>
 */
final class JexePackArchive {

    /** A file of the executable. */
    static final class Item {
        final String name;
        final byte[] data;

        Item(final String name, final byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    static final int HEADER = 0x1C;
    static final int HEADER_V2 = 0x20;
    private static final long MAX_TOTAL = 1L << 31;

    final List<Item> items = new ArrayList<Item>();
    String settings = "";
    String packager = "";
    String mainClass = "";
    int records;
    int version;

    /** Random access to the executable. */
    interface Source {
        long length() throws IOException;

        /** Reads exactly len bytes at pos. */
        void readFully(long pos, byte[] b, int off, int len) throws IOException;
    }

    /** True if a record signature starts at off. */
    static boolean isSignature(final byte[] b, final int off) {
        if (off < 0 || off + HEADER > b.length) return false;
        for (int i = 0; i < 15; i++) {
            if ((b[off + i] & 0xff) != 0x4A + (3 * i) / 2) return false;
        }
        return true;
    }

    /** Position of the first record (16-byte aligned), or -1. */
    static long findFirst(final Source src) throws IOException {
        final long len = src.length();
        final byte[] buf = new byte[1 << 20];
        for (long base = 0; base < len; base += buf.length - 64) {
            final int n = (int) Math.min(buf.length, len - base);
            src.readFully(base, buf, 0, n);
            for (int i = (int) ((16 - base % 16) % 16); i + HEADER <= n; i += 16) {
                if (buf[i] == 0x4A && isSignature(buf, i)) return base + i;
            }
            if (base + n >= len) break;
        }
        return -1;
    }

    /** Reads every record. */
    static JexePackArchive read(final Source src) throws IOException {
        final JexePackArchive a = new JexePackArchive();
        long pos = findFirst(src);
        if (pos < 0) throw new ArcanaUnsupportedFormatException("Not a JexePack executable");
        final long len = src.length();
        final Set<String> used = new HashSet<String>();
        final byte[] h = new byte[HEADER_V2];
        while (pos >= 0 && pos + HEADER <= len) {
            final int n = (int) Math.min(HEADER_V2, len - pos);
            src.readFully(pos, h, 0, n);
            if (!isSignature(h, 0)) {
                pos = nextSignature(src, pos + 16);
                continue;
            }
            final boolean v2 = n == HEADER_V2 && headerHash(h) == le32(h, 0x1C);
            final int start = v2 ? HEADER_V2 : HEADER;
            final char type = (char) (h[15] & 0xff);
            final long check = le64(h, 16);
            final long size = le32(h, 24) & 0xffffffffL;
            if (size > MAX_TOTAL || pos + start + size > len) throw new ArcanaCorruptedException("JexePack record " + type + " truncated");
            final byte[] data = new byte[(int) size];
            src.readFully(pos + start, data, 0, data.length);
            if (hash(data) * check != 1) throw new ArcanaCorruptedException("JexePack record " + type + " damaged (check value mismatch)");
            a.records++;
            if (v2) {
                a.addV2(type, data, used);
            } else {
                if (a.version == 0) a.version = 1;
                if (type != 'V') decode(data);
                a.add(type, data, used);
            }
            pos = (pos + start + size + 15) & ~15L;
        }
        if (a.records == 0) throw new ArcanaUnsupportedFormatException("Not a JexePack executable");
        return a;
    }

    /** Version 2: hash of the first 0x1C header bytes, bits 16 to 47. */
    private static int headerHash(final byte[] h) {
        final byte[] b = new byte[HEADER];
        System.arraycopy(h, 0, b, 0, HEADER);
        return (int) (hash(b) >>> 16);
    }

    private static long nextSignature(final Source src, long pos) throws IOException {
        final long len = src.length();
        final byte[] b = new byte[HEADER];
        for (pos = (pos + 15) & ~15L; pos + HEADER <= len; pos += 16) {
            src.readFully(pos, b, 0, 1);
            if (b[0] != 0x4A) continue;
            src.readFully(pos, b, 0, HEADER);
            if (isSignature(b, 0)) return pos;
        }
        return -1;
    }

    /**
     * Record with a version 2 header: settings text, or one file (name, sizes,
     * data). JexePack 7 keeps the version 1 coding, plain settings and an ANSI
     * name (8-bit length, characters, 0); JexePack 8 codes everything with the
     * generator and stores a UTF-16 name.
     */
    private void addV2(final char type, final byte[] data, final Set<String> used) throws IOException {
        if (type == 'V') {
            if (!isText(data)) {
                decodeV2(data);
                version = 3;
            } else if (version == 0) {
                version = 2;
            }
            int end = data.length;
            while (end > 0 && data[end - 1] == 0) end--;
            settings(new String(data, 0, end, StandardCharsets.ISO_8859_1).trim());
            items.add(new Item(unique("jexepack-settings.txt", used), (settings + "\n").getBytes(StandardCharsets.ISO_8859_1)));
            return;
        }
        final byte[] wide = data.clone();
        decodeV2(wide);
        if (wideBody(wide) > 0) {
            version = 3;
            addFile(type, wide, wideBody(wide), new String(wide, 4, le32(wide, 0) * 2, StandardCharsets.UTF_16LE), used);
            return;
        }
        decode(data);
        if (data.length < 10) throw new ArcanaCorruptedException("JexePack record " + type + " too short");
        final int len = data[0] & 0xff;
        if (len == 0 || 1 + len + 9 > data.length || data[1 + len] != 0) throw new ArcanaCorruptedException("Invalid JexePack file name in record " + type);
        if (version == 0) version = 2;
        addFile(type, data, 1 + len + 1, new String(data, 1, len, StandardCharsets.ISO_8859_1), used);
    }

    /** JexePack 8 file record (decoded): offset of the sizes after the UTF-16 name, or -1. */
    private static int wideBody(final byte[] d) {
        if (d.length < 14) return -1;
        final long chars = le32(d, 0) & 0xffffffffL;
        if (chars == 0 || chars > 4096 || 4 + chars * 2 + 10 > d.length) return -1;
        final int q = 4 + (int) chars * 2;
        if (d[q] != 0 || d[q + 1] != 0) return -1;
        for (int i = 4; i < q; i += 2) {
            if (d[i] == 0 && d[i + 1] == 0) return -1;
        }
        return (le32(d, q + 6) & 0xffffffffL) == d.length - (q + 10) ? q + 2 : -1;
    }

    /** True if the settings record is stored as plain text (JexePack 7). */
    private static boolean isText(final byte[] d) {
        for (final byte c : d) {
            if (c != 0 && c != '\t' && c != '\n' && c != '\r' && (c < 0x20 || c > 0x7e)) return false;
        }
        return true;
    }

    /** File record body: uncompressed size, stored size, then the data (gzip for Z records). */
    private void addFile(final char type, final byte[] data, final int q, final String name, final Set<String> used) throws IOException {
        if (q + 8 > data.length) throw new ArcanaCorruptedException("JexePack file " + name + " truncated");
        final long size = le32(data, q) & 0xffffffffL;
        final long stored = le32(data, q + 4) & 0xffffffffL;
        final int body = q + 8;
        if (stored != data.length - body) throw new ArcanaCorruptedException("JexePack file " + name + " has a wrong stored size");
        byte[] content;
        if (type == 'Z' || type == 'z') {
            if (size > MAX_TOTAL) throw new ArcanaCorruptedException("JexePack file " + name + " too large");
            content = new byte[(int) size];
            try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(data, body, data.length - body), 65536)) {
                int n = 0;
                while (n < content.length) {
                    final int r = in.read(content, n, content.length - n);
                    if (r < 0) throw new ArcanaCorruptedException("JexePack file " + name + " truncated");
                    n += r;
                }
            }
        } else {
            if (size != stored) throw new ArcanaCorruptedException("JexePack file " + name + " has a wrong size");
            content = new byte[(int) size];
            System.arraycopy(data, body, content, 0, content.length);
        }
        items.add(new Item(unique(clean(name), used), content));
    }

    private void settings(final String text) {
        settings = text;
        for (final String line : text.split("[\r\n]+")) {
            if (line.startsWith("packager=")) packager = line.substring(9).trim();
            else if (line.startsWith("main=")) mainClass = line.substring(5).trim();
        }
    }

    private void add(final char type, final byte[] data, final Set<String> used) throws IOException {
        switch (type) {
            case 'V':
                settings(new String(data, StandardCharsets.ISO_8859_1));
                items.add(new Item(unique("jexepack-settings.txt", used), data));
                return;
            case 'B':
                items.add(new Item(unique("Boot.class", used), data));
                return;
            case 'Z':
                readFiles(data, used);
                return;
            default:
                final boolean zip = data.length > 4 && data[0] == 'P' && data[1] == 'K';
                items.add(new Item(unique("record-" + type + (zip ? ".jar" : ".bin"), used), data));
        }
    }

    /** "Z" record: count, total size, gzip of (tag, name, flag, size, data) entries. */
    private void readFiles(final byte[] z, final Set<String> used) throws IOException {
        if (z.length < 10) throw new ArcanaCorruptedException("JexePack file record too short");
        final long total = le32(z, 4) & 0xffffffffL;
        if (total > MAX_TOTAL) throw new ArcanaCorruptedException("JexePack file record too large");
        final byte[] u = new byte[(int) total];
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(z, 8, z.length - 8), 65536)) {
            int n = 0;
            while (n < u.length) {
                final int r = in.read(u, n, u.length - n);
                if (r < 0) throw new ArcanaCorruptedException("JexePack file record truncated");
                n += r;
            }
        }
        int p = 0;
        while (p < u.length) {
            if (p + 5 > u.length) throw new ArcanaCorruptedException("JexePack file entry truncated");
            final int nameLen = u[p + 4] & 0xff;
            final int q = p + 5 + nameLen;
            if (q + 5 > u.length) throw new ArcanaCorruptedException("JexePack file entry truncated");
            final String name = new String(u, p + 5, nameLen, StandardCharsets.ISO_8859_1);
            final long size = le32(u, q + 1) & 0xffffffffL;
            if (q + 5 + size > u.length) throw new ArcanaCorruptedException("JexePack file " + name + " truncated");
            final ByteArrayOutputStream data = new ByteArrayOutputStream((int) size);
            data.write(u, q + 5, (int) size);
            items.add(new Item(unique(clean(name), used), data.toByteArray()));
            p = q + 5 + (int) size;
        }
    }

    // =========================================================================

    /** Version 2 data coding: generator x = x * 0x41C64E6D + 0x3039, byte XOR low byte of x, then x += decoded byte (signed). */
    static void decodeV2(final byte[] b) {
        int x = 0x1FA583BB;
        for (int i = 0; i < b.length; i++) {
            x = x * 0x41C64E6D + 0x3039;
            b[i] ^= (byte) x;
            x += b[i];
        }
    }

    /** Version 1 data coding: (b XOR i) - 0x64. */
    static void decode(final byte[] b) {
        for (int i = 0; i < b.length; i++) b[i] = (byte) ((b[i] ^ i) - 0x64);
    }

    /** Hash checked by the launcher: its product with the stored value is 1 (mod 2^64). */
    static long hash(final byte[] data) {
        long acc = 0;
        for (int k = 0; k < data.length; k++) {
            final long v = 0x65434531L << ((k * 7) & 0x1f);
            acc ^= v * ((data[k] & 0xff) + (long) k);
        }
        return acc | 1;
    }

    private static String clean(final String s) {
        final StringBuilder sb = new StringBuilder();
        for (final String part : s.replace('\\', '/').split("/")) {
            if (part.isEmpty() || part.equals(".") || part.equals("..") || part.endsWith(":")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(part);
        }
        return sb.length() == 0 ? "_" : sb.toString();
    }

    private static String unique(final String path, final Set<String> used) {
        if (used.add(path.toLowerCase())) return path;
        final int dot = path.lastIndexOf('.');
        final int slash = path.lastIndexOf('/');
        final String stem = dot > slash + 1 ? path.substring(0, dot) : path;
        final String ext = dot > slash + 1 ? path.substring(dot) : "";
        for (int n = 2;; n++) {
            final String p = stem + " (" + n + ")" + ext;
            if (used.add(p.toLowerCase())) return p;
        }
    }

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    static long le64(final byte[] b, final int p) {
        return (le32(b, p) & 0xffffffffL) | (long) le32(b, p + 4) << 32;
    }
}
