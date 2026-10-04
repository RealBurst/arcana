/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 *
 * Format knowledge from ISx (Copyright (c) 2017 lifenjoiner, MIT license).
 */
package io.github.realburst.arcana.plugin.installshield;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.InflaterInputStream;

/**
 * Reader of the files embedded in an InstallShield setup.exe (InstallShield
 * 9 / DevStudio to 2021 and later): the launcher is followed by its files
 * (setup.ini, the .msi, data1.cab, setup.inx, prerequisites...).
 *
 * <ul>
 *   <li>"InstallShield" 0 header (46 bytes, file count at 14), then for each file a
 *       312-byte record (ANSI name, flags at 260, size at 268, "deflated" at 280)
 *       followed by the data;</li>
 *   <li>"ISSetupStream" 0 header (type at 16), then 24-byte records (name length,
 *       flags, size at 10, "deflated" at 22; type 4: 24 more bytes) followed by the
 *       UTF-16 name and the data;</li>
 *   <li>older "plain" layouts: name, destination name, version and decimal size
 *       as zero-separated strings (single-byte, or UTF-16 after a file count).</li>
 * </ul>
 *
 * <p>Data may be XOR-encoded with a key made from the file name: each byte is
 * swapped (nibbles), xored with the key byte and inverted; the key restarts
 * every 1024 bytes (flag 4) or runs over the whole file (flag 2, old header).
 * "Deflated" files (Unicode launchers) are then zlib streams.</p>
 */
final class IsSetup implements Closeable {

    private static final byte[] SIG_OLD = "InstallShield\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SIG_STREAM = "ISSetupStream\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_MASK = {0x13, 0x35, (byte) 0x86, 0x07};
    private static final Charset ANSI = Charset.isSupported("windows-1252") ? Charset.forName("windows-1252") : StandardCharsets.ISO_8859_1;

    /** An embedded file. */
    static final class Item {
        final String path;
        final long offset;
        final long size;
        final byte[] key;      // null: not encoded
        final boolean perBlock;
        final boolean deflated;

        Item(final String path, final long offset, final long size, final byte[] key, final boolean perBlock, final boolean deflated) {
            this.path = path;
            this.offset = offset;
            this.size = size;
            this.key = key;
            this.perBlock = perBlock;
            this.deflated = deflated;
        }
    }

    private final RandomAccessFile raf;
    final List<Item> items = new ArrayList<Item>();
    String layout = "";

    private IsSetup(final RandomAccessFile raf) {
        this.raf = raf;
    }

    static IsSetup open(final File file) throws IOException {
        final RandomAccessFile raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            final IsSetup s = new IsSetup(raf);
            s.read();
            ok = true;
            return s;
        } finally {
            if (!ok) raf.close();
        }
    }

    // =========================================================================
    // Layouts
    // =========================================================================

    /** End of the executable image: the embedded files follow. */
    static long overlay(final RandomAccessFile raf) throws IOException {
        final byte[] mz = read(raf, 0, 64);
        if (mz[0] != 'M' || mz[1] != 'Z') return -1;
        final long pe = IsCabinet.le32(mz, 0x3c) & 0xffffffffL;
        if (pe <= 0 || pe + 24 > raf.length()) return -1;
        final byte[] fh = read(raf, pe, 24);
        if (fh[0] != 'P' || fh[1] != 'E' || fh[2] != 0 || fh[3] != 0) return -1;
        final int sections = (fh[6] & 0xff) | (fh[7] & 0xff) << 8;
        final int optSize = (fh[20] & 0xff) | (fh[21] & 0xff) << 8;
        final long table = pe + 24 + optSize;
        if (sections <= 0 || sections > 96 || table + 40L * sections > raf.length()) return -1;
        final byte[] st = read(raf, table, 40 * sections);
        long end = 0;
        for (int i = 0; i < sections; i++) {
            final long size = IsCabinet.le32(st, 40 * i + 16) & 0xffffffffL;
            final long ptr = IsCabinet.le32(st, 40 * i + 20) & 0xffffffffL;
            if (size > 0) end = Math.max(end, ptr + size);
        }
        return end;
    }

    private void read() throws IOException {
        long pos = overlay(raf);
        if (pos <= 0 || pos >= raf.length()) throw new ArcanaUnsupportedFormatException("No InstallShield data after the setup program");
        pos = skipDebugInfo(pos);
        final byte[] h = read(raf, pos, (int) Math.min(46, raf.length() - pos));
        if (h.length == 46 && (startsWith(h, SIG_OLD) || startsWith(h, SIG_STREAM))) {
            readEncoded(pos, h);
        } else if (!readPlainWide(pos) && !readPlain(pos)) {
            throw new ArcanaUnsupportedFormatException("Unknown InstallShield setup layout (no embedded file list found)");
        }
        if (items.isEmpty()) throw new ArcanaUnsupportedFormatException("No file found in this InstallShield setup");
    }

    /** InstallShield 2009/2010 may start the data with a "NB10" debug record: skipped. */
    private long skipDebugInfo(final long pos) throws IOException {
        final byte[] b = read(raf, pos, (int) Math.min(1024, raf.length() - pos));
        if (b.length < 4 || b[0] != 'N' || b[1] != 'B' || b[2] != '1' || b[3] != '0') return pos;
        int i = 4;
        i = skip(b, i, 0); // zero or 0xFF bytes
        i = skip(b, i, 1); // binary run without zero
        i = skip(b, i, 0);
        i = skip(b, i, 2); // printable run (path of the PDB)
        i = skip(b, i, 0);
        return pos + i;
    }

    /** kind 0: bytes 00 / FF; 1: bytes 01-FE; 2: bytes 20-FE. */
    private static int skip(final byte[] b, int i, final int kind) {
        while (i < b.length) {
            final int c = b[i] & 0xff;
            final boolean in = kind == 0 ? (c == 0 || c == 0xff) : kind == 1 ? (c != 0 && c != 0xff) : (c >= 0x20 && c != 0xff);
            if (!in) break;
            i++;
        }
        return i;
    }

    private void readEncoded(long pos, final byte[] h) throws IOException {
        final boolean stream = startsWith(h, SIG_STREAM);
        layout = stream ? "ISSetupStream" : "InstallShield";
        final int count = (h[14] & 0xff) | (h[15] & 0xff) << 8;
        final int type = IsCabinet.le32(h, 16);
        if (type < 0 || type > 4) throw new ArcanaUnsupportedFormatException("Unsupported InstallShield setup stream type " + type);
        pos += 46;
        final Set<String> used = new HashSet<String>();
        for (int i = 0; i < count; i++) {
            final String name;
            final byte[] seed;
            final int flags;
            final long size;
            final boolean deflated;
            if (!stream) {
                final byte[] a = read(raf, pos, 312);
                int n = 0;
                while (n < 260 && a[n] != 0) n++;
                seed = new byte[n];
                System.arraycopy(a, 0, seed, 0, n);
                name = new String(seed, ANSI);
                flags = IsCabinet.le32(a, 260);
                size = IsCabinet.le32(a, 268) & 0xffffffffL;
                deflated = ((a[280] & 0xff) | (a[281] & 0xff) << 8) != 0;
                pos += 312;
            } else {
                final byte[] a = read(raf, pos, 24);
                final long nameLen = IsCabinet.le32(a, 0) & 0xffffffffL;
                if (nameLen == 0 || nameLen > 2048) throw new ArcanaCorruptedException("Invalid InstallShield file name length");
                flags = IsCabinet.le32(a, 4);
                size = IsCabinet.le32(a, 10) & 0xffffffffL;
                deflated = ((a[22] & 0xff) | (a[23] & 0xff) << 8) != 0;
                pos += 24 + (type == 4 ? 24 : 0);
                String nm = new String(read(raf, pos, (int) nameLen), StandardCharsets.UTF_16LE);
                final int nul = nm.indexOf('\0');
                if (nul >= 0) nm = nm.substring(0, nul);
                if (nm.startsWith("\uFEFF")) nm = nm.substring(1);
                name = nm;
                seed = nm.getBytes(StandardCharsets.UTF_8);
                pos += nameLen;
            }
            if (pos + size > raf.length()) throw new ArcanaCorruptedException("InstallShield setup truncated");
            byte[] key = null;
            boolean perBlock = false;
            if ((flags & 4) != 0) {
                key = key(seed);
                perBlock = true;
            } else if ((flags & 2) != 0 && !stream) {
                key = key(seed);
            }
            if (key != null && key.length == 0) key = null;
            items.add(new Item(unique(clean(name), used), pos, size, key, perBlock, deflated));
            pos += size;
        }
    }

    /** "plain" layout with UTF-16 strings: file count, then name, destination, version, size, data. */
    private boolean readPlainWide(final long start) throws IOException {
        final byte[] c = read(raf, start, (int) Math.min(4, raf.length() - start));
        if (c.length < 4) return false;
        final long count = IsCabinet.le32(c, 0) & 0xffffffffL;
        if (count == 0 || count > 10000) return false;
        long pos = start + 4;
        final List<Item> found = new ArrayList<Item>();
        final Set<String> used = new HashSet<String>();
        while (found.size() < count) {
            final long[] p = {pos};
            final String name = wideField(p);
            final String dest = wideField(p);
            final String version = wideField(p);
            final String sizeText = wideField(p);
            if (name == null || dest == null || version == null || sizeText == null) break;
            final long size = parseSize(sizeText);
            if (size < 0 || p[0] + size > raf.length()) break;
            found.add(new Item(unique(clean(dest), used), p[0], size, null, false, false));
            pos = p[0] + size;
        }
        if (found.isEmpty()) return false;
        layout = "plain (Unicode)";
        items.addAll(found);
        return true;
    }

    /** "plain" layout with single-byte strings. */
    private boolean readPlain(long pos) throws IOException {
        final Set<String> used = new HashSet<String>();
        while (pos < raf.length()) {
            final long[] p = {pos};
            final String name = field(p);
            final String dest = field(p);
            final String version = field(p);
            final String sizeText = field(p);
            if (name == null || dest == null || version == null || sizeText == null) break;
            final long size = parseSize(sizeText);
            if (size < 0 || p[0] + size > raf.length()) break;
            items.add(new Item(unique(clean(dest), used), p[0], size, null, false, false));
            pos = p[0] + size;
        }
        if (!items.isEmpty()) layout = "plain";
        return !items.isEmpty();
    }

    private static long parseSize(final String s) {
        final String t = s.trim();
        if (t.isEmpty() || t.length() > 12) return -1;
        for (int i = 0; i < t.length(); i++) {
            if (!Character.isDigit(t.charAt(i))) return -1;
        }
        return Long.parseLong(t);
    }

    /** A printable single-byte string followed by zero bytes; null if none. */
    private String field(final long[] p) throws IOException {
        final byte[] b = read(raf, p[0], (int) Math.min(600, raf.length() - p[0]));
        int i = 0;
        while (i < b.length && (b[i] & 0xff) >= 0x20 && (b[i] & 0xff) != 0xff) i++;
        if (i == 0 || i > 259 || i >= b.length) return null;
        final String s = new String(b, 0, i, ANSI);
        while (i < b.length && (b[i] == 0 || b[i] == (byte) 0xff)) i++;
        p[0] += i;
        return s;
    }

    /** A UTF-16 string followed by zero characters; null if none. */
    private String wideField(final long[] p) throws IOException {
        final byte[] b = read(raf, p[0], (int) Math.min(1200, raf.length() - p[0]));
        int i = 0;
        while (i + 1 < b.length) {
            final int ch = (b[i] & 0xff) | (b[i + 1] & 0xff) << 8;
            if (ch < 0x20 || ch >= 0xFFFE) break;
            i += 2;
        }
        if (i == 0 || i > 518 || i + 1 >= b.length) return null;
        final String s = new String(b, 0, i, StandardCharsets.UTF_16LE);
        while (i + 1 < b.length && ((b[i] == 0 && b[i + 1] == 0) || (b[i] == (byte) 0xff && b[i + 1] == (byte) 0xff) || (b[i] == (byte) 0xfe && b[i + 1] == (byte) 0xff))) i += 2;
        p[0] += i;
        return s;
    }

    // =========================================================================
    // Data
    // =========================================================================

    /** The content of an embedded file. */
    InputStream open(final Item it) {
        InputStream in = new InputStream() {
            private long pos;

            @Override
            public int read() throws IOException {
                final byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                if (len == 0) return 0;
                if (pos >= it.size) return -1;
                final int n = (int) Math.min(len, it.size - pos);
                raf.seek(it.offset + pos);
                raf.readFully(b, off, n);
                if (it.key != null) {
                    final byte[] k = it.key;
                    for (int i = 0; i < n; i++) {
                        final long j = pos + i;
                        final int ki = it.perBlock ? (int) ((j % 1024) % k.length) : (int) (j % k.length);
                        final int x = b[off + i] & 0xff;
                        b[off + i] = (byte) ~(k[ki] ^ ((x << 4 | x >>> 4) & 0xff));
                    }
                }
                pos += n;
                return n;
            }
        };
        if (it.deflated) in = new InflaterInputStream(in);
        return in;
    }

    private static byte[] key(final byte[] seed) {
        final byte[] k = new byte[seed.length];
        for (int i = 0; i < k.length; i++) k[i] = (byte) (seed[i] ^ KEY_MASK[i % 4]);
        return k;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // =========================================================================

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

    private static boolean startsWith(final byte[] b, final byte[] p) {
        if (b.length < p.length) return false;
        for (int i = 0; i < p.length; i++) {
            if (b[i] != p[i]) return false;
        }
        return true;
    }

    private static byte[] read(final RandomAccessFile raf, final long pos, final int len) throws IOException {
        final byte[] b = new byte[Math.max(0, len)];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }
}
