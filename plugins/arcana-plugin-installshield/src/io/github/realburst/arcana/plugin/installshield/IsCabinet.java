/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 *
 * Format knowledge from unshield (Copyright (c) 2003 David Eriksson, MIT license).
 */
package io.github.realburst.arcana.plugin.installshield;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Reader of InstallShield cabinet sets: data1.hdr (header) with data1.cab,
 * data2.cab... (volumes), or data1.cab alone holding the header (old versions).
 *
 * <p>Header ("ISc(" signature): a descriptor with the offsets of the file table
 * (directory names, then file descriptors), of the file groups and of the
 * components. Files are listed by file group: "group/directory/name". A file
 * is stored, or compressed in raw Deflate chunks (16-bit size + data), in
 * older versions one stream cut by sync markers; it may be obfuscated (byte
 * rotation and subtraction), split across volumes, or a link to a previous
 * identical file. Version 6 and later give the MD5 of every file.</p>
 */
final class IsCabinet implements Closeable {

    static final int SIGNATURE = 0x28635349; // "ISc("
    private static final int MAX_GROUPS = 71;
    private static final int FLAG_SPLIT = 1;
    private static final int FLAG_OBFUSCATED = 2;
    private static final int FLAG_COMPRESSED = 4;
    private static final int FLAG_INVALID = 8;
    private static final int LINK_PREV = 1;
    private static final Charset ANSI = Charset.isSupported("windows-1252") ? Charset.forName("windows-1252") : StandardCharsets.ISO_8859_1;

    /** A file of the cabinet set. */
    static final class Item {
        final String path;
        final int index;
        final long size;

        Item(final String path, final int index, final long size) {
            this.path = path;
            this.index = index;
            this.size = size;
        }
    }

    /** File descriptor. */
    private static final class Fd {
        int nameOffset;
        int directory;
        int flags;
        long size;
        long packed;
        long dataOffset;
        byte[] md5;
        int volume;
        int linkPrevious;
        int linkFlags;
    }

    private final File dir;
    private final String prefix;
    private final byte[] h;
    private final int major;
    private final int cdo;          // cab descriptor offset
    private final int fileTable;    // offset of the file table (from cdo)
    private final int fileTable2;
    private final int dirCount;
    private final int fileCount;
    private final int[] table;
    final String versionLabel;
    final List<Item> items = new ArrayList<Item>();
    private final Fd[] fds;

    // ---- current volume while reading ------------------------------------------
    private RandomAccessFile vol;
    private int volNumber;
    private long volLeft;
    private long volPos;

    private IsCabinet(final File dir, final String prefix, final byte[] header, final int forcedMajor) throws IOException {
        this.dir = dir;
        this.prefix = prefix;
        this.h = header;
        if (h.length < 20 || le32(0) != SIGNATURE) throw new ArcanaCorruptedException("Not an InstallShield cabinet");
        final int version = le32(4);
        int m;
        if (version >>> 24 == 1) m = (version >>> 12) & 0xf;
        else if (version >>> 24 == 2 || version >>> 24 == 4) m = (version & 0xffff) / 100;
        else m = 0;
        major = forcedMajor >= 0 ? forcedMajor : m;
        versionLabel = major == 0 ? "5 or older" : String.valueOf(major);
        cdo = le32(12);
        if (le32(16) == 0 || cdo <= 0 || cdo + 0x30 + 0xe + 8 * MAX_GROUPS > h.length) throw new ArcanaCorruptedException("InstallShield cabinet without descriptor");
        fileTable = le32(cdo + 0x0c);
        dirCount = le32(cdo + 0x1c);
        fileCount = le32(cdo + 0x28);
        fileTable2 = le32(cdo + 0x2c);
        if (dirCount < 0 || fileCount < 0 || (long) dirCount + fileCount > 1 << 22) throw new ArcanaCorruptedException("Invalid InstallShield file table");
        table = new int[dirCount + fileCount];
        for (int i = 0; i < table.length; i++) table[i] = le32(cdo + fileTable + 4 * i);
        fds = new Fd[fileCount];
        // file groups, in table order: "group/directory/name"
        final Set<Integer> seen = new HashSet<Integer>();
        final Set<String> used = new HashSet<String>();
        final int groupsAt = cdo + 0x30 + 0xe;
        for (int g = 0; g < MAX_GROUPS; g++) {
            int next = le32(groupsAt + 4 * g);
            int guard = 0;
            while (next != 0 && guard++ < 10000) {
                final int p = cdo + next;
                final int desc = le32(p + 4);
                next = le32(p + 8);
                final int q = cdo + desc;
                final String group = string(le32(q));
                final int fq = q + 4 + (major <= 5 ? 0x48 : 0x12);
                final int first = le32(fq);
                final int last = le32(fq + 4);
                if (first < 0 || last < first) continue;
                for (int i = first; i <= last && i < fileCount; i++) {
                    if (!valid(i) || !seen.add(i)) continue;
                    final Fd fd = fd(i);
                    final String d = dirCount > 0 && fd.directory < dirCount ? string(table[fd.directory] + fileTable) : "";
                    final String name = stringAt(cdo + fileTable + fd.nameOffset);
                    final String path = clean(group) + "/" + (d.isEmpty() ? "" : clean(d) + "/") + clean(name);
                    items.add(new Item(unique(path.replace("//", "/"), used), i, fd.size));
                }
            }
        }
        if (seen.isEmpty()) {
            // no usable file group: all the files, by directory
            for (int i = 0; i < fileCount; i++) {
                if (!valid(i)) continue;
                final Fd fd = fd(i);
                final String d = fd.directory < dirCount ? string(table[fd.directory] + fileTable) : "";
                items.add(new Item(unique((d.isEmpty() ? "" : clean(d) + "/") + clean(stringAt(cdo + fileTable + fd.nameOffset)), used), i, fd.size));
            }
        }
    }

    /**
     * Opens the set containing a header (dataN.hdr) or volume (dataN.cab) file.
     */
    static IsCabinet open(final File any) throws IOException {
        final File dir = any.getAbsoluteFile().getParentFile();
        final String name = any.getName();
        int cut = 0;
        while (cut < name.length() && name.charAt(cut) != '.' && !Character.isDigit(name.charAt(cut))) cut++;
        final String prefix = name.substring(0, cut);
        File hdr = find(dir, prefix + "1.hdr");
        if (hdr == null) hdr = find(dir, prefix + "1.cab");
        if (hdr == null) hdr = any; // a cabinet named differently: use it as is
        final byte[] header = readAll(hdr);
        return new IsCabinet(dir, prefix, header, -1);
    }

    /** Case-insensitive search of a file in a directory. */
    static File find(final File dir, final String name) {
        final File f = new File(dir, name);
        if (f.isFile()) return f;
        final String[] names = dir.list();
        if (names != null) {
            for (final String n : names) {
                if (n.equalsIgnoreCase(name)) return new File(dir, n);
            }
        }
        return null;
    }

    private static byte[] readAll(final File f) throws IOException {
        if (f.length() > 1 << 28) throw new ArcanaUnsupportedFormatException("InstallShield header too large");
        final byte[] b = new byte[(int) f.length()];
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            r.readFully(b);
        }
        return b;
    }

    // =========================================================================
    // Descriptors
    // =========================================================================

    private boolean valid(final int i) throws IOException {
        final Fd fd = fd(i);
        return (fd.flags & FLAG_INVALID) == 0 && fd.nameOffset != 0 && fd.dataOffset != 0;
    }

    private Fd fd(final int i) throws IOException {
        if (fds[i] != null) return fds[i];
        final Fd fd = new Fd();
        if (major == 0 || major == 5) {
            final int p = cdo + fileTable + table[dirCount + i];
            check(p, 0x3a);
            fd.volume = -1; // the volume holding the header, or the next ones
            fd.nameOffset = le32(p);
            fd.directory = le16(p + 4);
            fd.flags = le16(p + 8);
            fd.size = u32(p + 10);
            fd.packed = u32(p + 14);
            fd.dataOffset = u32(p + 0x26);
            if (major == 5) fd.md5 = copy(p + 0x2a, 16);
        } else {
            final int p = cdo + fileTable + fileTable2 + i * 0x57;
            check(p, 0x57);
            fd.flags = le16(p);
            fd.size = le64(p + 2);
            fd.packed = le64(p + 10);
            fd.dataOffset = le64(p + 18);
            fd.md5 = copy(p + 26, 16);
            fd.nameOffset = le32(p + 58);
            fd.directory = le16(p + 62);
            fd.linkPrevious = le32(p + 76);
            fd.linkFlags = h[p + 84] & 0xff;
            fd.volume = le16(p + 85);
        }
        if (fd.size < 0 || fd.packed < 0) throw new ArcanaCorruptedException("Invalid InstallShield file descriptor " + i);
        fds[i] = fd;
        return fd;
    }

    // =========================================================================
    // Data
    // =========================================================================

    /**
     * Writes the content of a file.
     *
     * @param old true for the old layout of compressed data (one stream cut by
     *            sync markers), to try when the normal layout fails
     */
    void copy(final Item item, final OutputStream out, final boolean old) throws IOException {
        int index = item.index;
        Fd fd = fd(index);
        for (int guard = 0; (fd.linkFlags & LINK_PREV) != 0 && guard < 64; guard++) {
            index = fd.linkPrevious;
            if (index < 0 || index >= fileCount) throw new ArcanaCorruptedException("Invalid InstallShield file link");
            fd = fd(index);
        }
        extract(index, fd, out, old);
    }

    /** True when the file is compressed (the old layout may then be tried). */
    boolean compressed(final Item item) throws IOException {
        return (fd(item.index).flags & FLAG_COMPRESSED) != 0;
    }

    private void extract(final int index, final Fd fd, final OutputStream out, final boolean old) throws IOException {
        openFor(index, fd, fd.volume < 0 ? 1 : fd.volume);
        if (volPos >= vol.length() && fd.dataOffset >= vol.length()) {
            // data offset at the end of the cabinet: the file is stored next to it, in its directory
            if (!old) throw new ArcanaCorruptedException("InstallShield file stored outside the cabinet");
            openExternal(fd);
        }
        final MessageDigest md5 = major >= 6 ? md5() : null;
        final Reader in = new Reader(index, fd);
        long written = 0;
        final byte[] buf = new byte[65536];
        if ((fd.flags & FLAG_COMPRESSED) == 0) {
            long left = fd.size;
            while (left > 0) {
                final int n = (int) Math.min(buf.length, left);
                in.read(buf, n);
                if (md5 != null) md5.update(buf, 0, n);
                out.write(buf, 0, n);
                left -= n;
                written += n;
            }
        } else if (!old) {
            long left = fd.packed;
            final byte[] chunk = new byte[65537];
            final byte[] two = new byte[2];
            final Inflater inf = new Inflater(true);
            try {
                while (left > 0) {
                    in.read(two, 2);
                    final int len = (two[0] & 0xff) | (two[1] & 0xff) << 8;
                    if (len == 0) throw new ArcanaCorruptedException("Invalid InstallShield chunk");
                    in.read(chunk, len);
                    chunk[len] = 0; // Inflater needs one extra byte in raw mode
                    inf.reset();
                    inf.setInput(chunk, 0, len + 1);
                    int n;
                    while ((n = inflate(inf, buf)) > 0) {
                        if (md5 != null) md5.update(buf, 0, n);
                        out.write(buf, 0, n);
                        written += n;
                        if (inf.finished()) break;
                    }
                    if (!inf.finished()) throw new ArcanaCorruptedException("InstallShield chunk not terminated");
                    left -= 2 + len;
                }
            } finally {
                inf.end();
            }
        } else {
            written = extractOld(in, fd, out, md5, buf);
        }
        if (written != fd.size) throw new ArcanaCorruptedException("InstallShield file size mismatch (" + written + " of " + fd.size + " bytes)");
        if (md5 != null && fd.md5 != null && !MessageDigest.isEqual(md5.digest(), fd.md5)) throw new ArcanaCorruptedException("InstallShield MD5 mismatch");
    }

    /** Old layout: the compressed data of each volume part, cut at the 00 00 FF FF sync markers. */
    private long extractOld(final Reader in, final Fd fd, final OutputStream out, final MessageDigest md5, final byte[] buf) throws IOException {
        long written = 0;
        while (written < fd.size) {
            if (volLeft == 0 && !in.nextVolume()) throw new ArcanaCorruptedException("InstallShield data truncated");
            final int size = (int) Math.min(volLeft, Integer.MAX_VALUE - 16);
            final byte[] data = new byte[size + 4];
            in.read(data, size);
            int start = 0;
            while (start < size && written < fd.size) {
                int end = indexOfMarker(data, start, size);
                // a marker inside the data: the next block cannot start with a 1 bit
                while (end >= 0 && end + 4 < size && (data[end + 4] & 1) != 0) end = indexOfMarker(data, end + 4, size);
                // last part without its sync marker: the part of the marker already there is kept
                int have = 0;
                if (end < 0) {
                    end = size;
                    for (int k = 3; k > 0; k--) {
                        if (end - start >= k && endsWithMarkerStart(data, end, k)) {
                            have = k;
                            break;
                        }
                    }
                }
                final Inflater inf = new Inflater(true);
                try {
                    final int len = end - start;
                    final byte[] part = new byte[len + 4 - have + 1];
                    System.arraycopy(data, start, part, 0, len);
                    System.arraycopy(MARKER, have, part, len, 4 - have);
                    inf.setInput(part);
                    int n;
                    while ((n = inflate(inf, buf)) > 0) {
                        if (md5 != null) md5.update(buf, 0, n);
                        out.write(buf, 0, n);
                        written += n;
                    }
                } finally {
                    inf.end();
                }
                start = end + 4;
            }
        }
        return written;
    }

    private static final byte[] MARKER = {0, 0, (byte) 0xff, (byte) 0xff};

    /** True when the k bytes before end are the first k bytes of the sync marker. */
    private static boolean endsWithMarkerStart(final byte[] b, final int end, final int k) {
        for (int i = 0; i < k; i++) {
            if (b[end - k + i] != MARKER[i]) return false;
        }
        return true;
    }

    private static int indexOfMarker(final byte[] b, final int from, final int end) {
        for (int i = from; i + 4 <= end; i++) {
            if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == (byte) 0xff && b[i + 3] == (byte) 0xff) return i;
        }
        return -1;
    }

    private static int inflate(final Inflater inf, final byte[] buf) throws IOException {
        try {
            return inf.inflate(buf);
        } catch (final DataFormatException e) {
            throw new ArcanaCorruptedException("InstallShield data corrupted: " + e.getMessage());
        }
    }

    /** Reads the stored bytes of a file over its volumes, removing the obfuscation. */
    private final class Reader {
        private final int index;
        private final Fd fd;
        private int seed;

        Reader(final int index, final Fd fd) {
            this.index = index;
            this.fd = fd;
        }

        void read(final byte[] b, final int len) throws IOException {
            int done = 0;
            while (done < len) {
                if (volLeft == 0 && !nextVolume()) throw new EOFException("InstallShield data truncated");
                final int n = (int) Math.min(len - done, volLeft);
                vol.seek(volPos);
                vol.readFully(b, done, n);
                volPos += n;
                volLeft -= n;
                done += n;
            }
            if ((fd.flags & FLAG_OBFUSCATED) != 0) {
                for (int i = 0; i < len; i++) {
                    final int x = (b[i] & 0xff) ^ 0xd5;
                    b[i] = (byte) (((x >>> 2) | (x << 6)) - (seed++ % 0x47));
                }
            }
        }

        boolean nextVolume() throws IOException {
            return openVolume(index, fd, volNumber + 1);
        }
    }

    /** Opens the volume holding the start of a file (old versions: the first volume whose last file is not before it). */
    private void openFor(final int index, final Fd fd, int volume) throws IOException {
        for (int guard = 0; guard < 1000; guard++) {
            if (!openVolume(index, fd, volume)) throw new ArcanaCorruptedException("Missing InstallShield volume " + prefix + volume + ".cab");
            if (major <= 5 && index > lastIndex) {
                volume++;
                continue;
            }
            return;
        }
        throw new ArcanaCorruptedException("InstallShield volume not found");
    }

    private long lastIndex;

    /** Opens a volume and positions on the part of the file it holds; false if the volume does not exist. */
    private boolean openVolume(final int index, final Fd fd, final int volume) throws IOException {
        closeVolume();
        final File f = find(dir, prefix + volume + ".cab");
        if (f == null) return false;
        vol = new RandomAccessFile(f, "r");
        volNumber = volume;
        final byte[] c = new byte[20 + 64];
        final int n = (int) Math.min(c.length, vol.length());
        vol.readFully(c, 0, n);
        if (n < 20 || le32(c, 0) != SIGNATURE) throw new ArcanaCorruptedException("Invalid InstallShield volume " + f.getName());
        long dataOffset;
        long firstIndex;
        long firstOffset;
        long firstSize;
        long firstPacked;
        long lastOffset;
        long lastSize;
        long lastPacked;
        if (major == 0 || major == 5) {
            dataOffset = u32(c, 20);
            firstIndex = u32(c, 28);
            lastIndex = u32(c, 32);
            firstOffset = u32(c, 36);
            firstSize = u32(c, 40);
            firstPacked = u32(c, 44);
            lastOffset = u32(c, 48);
            lastSize = u32(c, 52);
            lastPacked = u32(c, 56);
            if (lastOffset == 0) lastOffset = Integer.MAX_VALUE;
        } else {
            dataOffset = le64(c, 20);
            firstIndex = u32(c, 28);
            lastIndex = u32(c, 32);
            firstOffset = le64(c, 36);
            firstSize = le64(c, 44);
            firstPacked = le64(c, 52);
            lastOffset = le64(c, 60);
            lastSize = le64(c, 68);
            lastPacked = le64(c, 76);
        }
        boolean split = (fd.flags & FLAG_SPLIT) != 0;
        if (major == 5 && !split) {
            if (index < fileCount - 1 && index == lastIndex && lastPacked != fd.packed) split = true;
            else if (index > 0 && index == firstIndex && firstPacked != fd.packed) split = true;
            if (split) fd.flags |= FLAG_SPLIT;
        }
        final boolean comp = (fd.flags & FLAG_COMPRESSED) != 0;
        if (split) {
            if (index == lastIndex && lastOffset != 0x7FFFFFFF) {
                volPos = lastOffset;
                volLeft = comp ? lastPacked : lastSize;
            } else if (index == firstIndex) {
                volPos = firstOffset;
                volLeft = comp ? firstPacked : firstSize;
            } else {
                volPos = 0;
                volLeft = 0;
            }
        } else {
            volPos = fd.dataOffset;
            volLeft = comp ? fd.packed : fd.size;
        }
        return true;
    }

    /** Old versions: "directory/name" next to the cabinet holds the compressed data of the file. */
    private void openExternal(final Fd fd) throws IOException {
        final String d = fd.directory < dirCount ? string(table[fd.directory] + fileTable) : "";
        final String name = stringAt(cdo + fileTable + fd.nameOffset);
        File f = dir;
        for (final String part : (d + "\\" + name).replace('\\', '/').split("/")) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) continue;
            final File next = find(f, part);
            if (next == null && !new File(f, part).isDirectory()) throw new ArcanaCorruptedException("InstallShield file stored outside the cabinet not found: " + d + "\\" + name);
            f = next != null ? next : new File(f, part);
        }
        closeVolume();
        vol = new RandomAccessFile(f, "r");
        volPos = 0;
        volLeft = (fd.flags & FLAG_COMPRESSED) != 0 ? Math.min(vol.length(), fd.packed) : fd.size;
        volNumber = Integer.MAX_VALUE - 1; // no next volume
    }

    private void closeVolume() throws IOException {
        if (vol != null) vol.close();
        vol = null;
    }

    @Override
    public void close() throws IOException {
        closeVolume();
    }

    // =========================================================================
    // Low level
    // =========================================================================

    /** String at an offset from the cab descriptor. */
    private String string(final int offset) throws IOException {
        return offset == 0 ? "" : stringAt(cdo + offset);
    }

    /** Zero-terminated string: UTF-16LE from version 17, single bytes before. */
    private String stringAt(final int p) throws IOException {
        if (p < 0 || p >= h.length) throw new ArcanaCorruptedException("InstallShield string outside the header");
        int e = p;
        if (major >= 17) {
            while (e + 1 < h.length && (h[e] != 0 || h[e + 1] != 0)) e += 2;
            return new String(h, p, e - p, StandardCharsets.UTF_16LE);
        }
        while (e < h.length && h[e] != 0) e++;
        return new String(h, p, e - p, ANSI);
    }

    /** Backslashes become '/', empty and "." / ".." parts are removed. */
    private static String clean(final String s) {
        final StringBuilder sb = new StringBuilder();
        for (final String part : s.replace('\\', '/').split("/")) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(part);
        }
        return sb.length() == 0 ? "_" : sb.toString();
    }

    private static String unique(final String path, final Set<String> used) {
        if (used.add(path.toLowerCase())) return path;
        final int slash = path.lastIndexOf('/');
        final int dot = path.lastIndexOf('.');
        final String stem = dot > slash + 1 ? path.substring(0, dot) : path;
        final String ext = dot > slash + 1 ? path.substring(dot) : "";
        for (int n = 2;; n++) {
            final String p = stem + " (" + n + ")" + ext;
            if (used.add(p.toLowerCase())) return p;
        }
    }

    private static MessageDigest md5() throws IOException {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException e) {
            throw new IOException("MD5 not available", e);
        }
    }

    private void check(final int p, final int len) throws IOException {
        if (p < 0 || p + len > h.length) throw new ArcanaCorruptedException("InstallShield descriptor outside the header");
    }

    private byte[] copy(final int p, final int len) {
        final byte[] r = new byte[len];
        System.arraycopy(h, p, r, 0, len);
        return r;
    }

    private int le16(final int p) throws IOException {
        check(p, 2);
        return (h[p] & 0xff) | (h[p + 1] & 0xff) << 8;
    }

    private int le32(final int p) throws IOException {
        check(p, 4);
        return le32(h, p);
    }

    private long u32(final int p) throws IOException {
        return le32(p) & 0xffffffffL;
    }

    private long le64(final int p) throws IOException {
        return u32(p) | (long) le32(p + 4) << 32;
    }

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    private static long u32(final byte[] b, final int p) {
        return le32(b, p) & 0xffffffffL;
    }

    private static long le64(final byte[] b, final int p) {
        return u32(b, p) | (long) le32(b, p + 4) << 32;
    }
}
