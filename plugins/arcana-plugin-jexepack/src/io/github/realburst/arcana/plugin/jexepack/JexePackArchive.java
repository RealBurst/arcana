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
 * <p>Format worked out from the launcher of JexePack 5.5. A record starts on
 * a 16-byte boundary with a 15-byte signature (byte i = 0x4A + 3i/2: "JKMNPQ..."),
 * a type letter, an 8-byte check value and a 32-bit length, then the data.
 * The check value is the inverse (mod 2^64) of a hash of the data. Data bytes
 * are coded as (b XOR (i AND 0xFF)) - 0x64, except for the "V" record.</p>
 *
 * <ul>
 *   <li>V: settings (text: packager, main class, Java options, jar names);</li>
 *   <li>B: the bootstrap class (Boot.class);</li>
 *   <li>Z: file count, total size, then a gzip stream of files, each one
 *       a 4-byte tag, name length, name, a flag byte, a 32-bit size and the data
 *       (the jar files of the program and its DLLs);</li>
 *   <li>J, F: jar and files of other JexePack versions, written as decoded.</li>
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
    private static final long MAX_TOTAL = 1L << 31;

    final List<Item> items = new ArrayList<Item>();
    String settings = "";
    String packager = "";
    String mainClass = "";
    int records;

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
        final byte[] h = new byte[HEADER];
        while (pos >= 0 && pos + HEADER <= len) {
            src.readFully(pos, h, 0, HEADER);
            if (!isSignature(h, 0)) {
                pos = nextSignature(src, pos + 16);
                continue;
            }
            final char type = (char) (h[15] & 0xff);
            final long check = le64(h, 16);
            final long size = le32(h, 24) & 0xffffffffL;
            if (size > MAX_TOTAL || pos + HEADER + size > len) throw new ArcanaCorruptedException("JexePack record " + type + " truncated");
            final byte[] data = new byte[(int) size];
            src.readFully(pos + HEADER, data, 0, data.length);
            if (hash(data) * check != 1) throw new ArcanaCorruptedException("JexePack record " + type + " damaged (check value mismatch)");
            a.records++;
            if (type != 'V') decode(data);
            a.add(type, data, used);
            pos = (pos + HEADER + size + 15) & ~15L;
        }
        if (a.records == 0) throw new ArcanaUnsupportedFormatException("Not a JexePack executable");
        return a;
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

    private void add(final char type, final byte[] data, final Set<String> used) throws IOException {
        switch (type) {
            case 'V':
                settings = new String(data, StandardCharsets.ISO_8859_1);
                for (final String line : settings.split("[\r\n]+")) {
                    if (line.startsWith("packager=")) packager = line.substring(9).trim();
                    else if (line.startsWith("main=")) mainClass = line.substring(5).trim();
                }
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

    /** Data coding of the records: (b XOR i) - 0x64. */
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
