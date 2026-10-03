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
package be.stef.arcana.formats.ole;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Reader for Compound File Binary files (OLE2 structured storage: MSI
 * packages, legacy Word / Excel / PowerPoint documents, Outlook messages),
 * written from the Microsoft specification [MS-CFB].
 *
 * <p>The file is a small FAT file system: 512 or 4096-byte sectors chained by
 * the FAT (whose sectors are listed by the DIFAT), a directory of 128-byte
 * entries (storages and streams, each storage holding a red-black tree of its
 * children), and a "mini stream" of 64-byte sectors, chained by the MiniFAT,
 * for the streams smaller than 4096 bytes.</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class CompoundFile implements AutoCloseable {

    /** A storage or a stream. */
    public static final class Node {
        /** Raw name (may contain control characters such as \u0005). */
        public final String name;
        /** True for a storage (directory). */
        public final boolean storage;
        public final long size;
        /** Modification time, Unix seconds, or -1. */
        public final long mtime;
        /** Children of a storage, in directory order. */
        public final List<Node> children = new ArrayList<Node>();
        final int start;

        Node(final String name, final boolean storage, final long size, final long mtime, final int start) {
            this.name = name;
            this.storage = storage;
            this.size = size;
            this.mtime = mtime;
            this.start = start;
        }
    }

    private static final byte[] SIGNATURE = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
    private static final int ENDOFCHAIN = 0xFFFFFFFE;
    private static final int FREESECT = 0xFFFFFFFF;
    private static final int MAX_STREAM = Integer.MAX_VALUE - 64;

    private final RandomAccessFile raf;
    private final long fileLength;
    private final int sectorSize;
    private final int miniSectorSize;
    private final long miniCutoff;
    private final int[] fat;
    private final int[] miniFat;
    private final Node root;
    private final String rootClsid;
    private byte[] miniStream;

    public CompoundFile(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            fileLength = raf.length();
            if (fileLength < 512) throw new ArcanaCorruptedException("OLE file too short");
            final byte[] h = new byte[512];
            raf.readFully(h);
            for (int i = 0; i < 8; i++) if (h[i] != SIGNATURE[i]) throw new ArcanaCorruptedException("Not an OLE compound file");
            final int shift = le16(h, 30);
            final int miniShift = le16(h, 32);
            if (shift != 9 && shift != 12) throw new ArcanaCorruptedException("Invalid OLE sector size");
            if (miniShift != 6) throw new ArcanaCorruptedException("Invalid OLE mini sector size");
            sectorSize = 1 << shift;
            miniSectorSize = 1 << miniShift;
            miniCutoff = le32(h, 56) & 0xffffffffL;
            final long numFat = le32(h, 44) & 0xffffffffL;
            final long sectors = (fileLength + sectorSize - 1) / sectorSize;
            if (numFat > sectors) throw new ArcanaCorruptedException("Invalid OLE FAT size");

            // DIFAT: 109 entries in the header, then a chain of DIFAT sectors
            final List<Integer> fatSectors = new ArrayList<Integer>();
            for (int i = 0; i < 109 && fatSectors.size() < numFat; i++) fatSectors.add(le32(h, 76 + 4 * i));
            int difat = le32(h, 68);
            final Set<Integer> seen = new HashSet<Integer>();
            while (fatSectors.size() < numFat && difat != ENDOFCHAIN && difat != FREESECT) {
                if (!seen.add(difat)) throw new ArcanaCorruptedException("OLE DIFAT loop");
                final byte[] d = sector(difat);
                final int per = sectorSize / 4 - 1;
                for (int i = 0; i < per && fatSectors.size() < numFat; i++) fatSectors.add(le32(d, 4 * i));
                difat = le32(d, sectorSize - 4);
            }
            if (fatSectors.size() < numFat) throw new ArcanaCorruptedException("OLE FAT incomplete");
            fat = new int[(int) (numFat * (sectorSize / 4))];
            for (int i = 0; i < fatSectors.size(); i++) {
                final byte[] d = sector(fatSectors.get(i));
                for (int k = 0; k < sectorSize / 4; k++) fat[i * (sectorSize / 4) + k] = le32(d, 4 * k);
            }
            final byte[] dir = chain(le32(h, 48), -1);
            final int miniFatStart = le32(h, 60);
            if (miniFatStart != ENDOFCHAIN && miniFatStart != FREESECT) {
                final byte[] mf = chain(miniFatStart, -1);
                miniFat = new int[mf.length / 4];
                for (int i = 0; i < miniFat.length; i++) miniFat[i] = le32(mf, 4 * i);
            } else {
                miniFat = new int[0];
            }
            if (dir.length < 128) throw new ArcanaCorruptedException("OLE directory empty");
            root = entry(dir, 0);
            rootClsid = clsid(dir, 80);
            if (!root.storage) throw new ArcanaCorruptedException("OLE root entry missing");
            readChildren(dir, 0, root, new HashSet<Integer>(), 0);
            ok = true;
        } finally {
            if (!ok) raf.close();
        }
    }

    /** The root storage. */
    public Node getRoot() {
        return root;
    }

    /** CLSID of the root storage, "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}". */
    public String getRootClsid() {
        return rootClsid;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // =========================================================================
    // Directory
    // =========================================================================

    private Node entry(final byte[] dir, final int index) throws IOException {
        final int p = index * 128;
        int nameLen = le16(dir, p + 64);
        if (nameLen > 64 || (nameLen & 1) != 0) throw new ArcanaCorruptedException("Invalid OLE directory entry name");
        nameLen = Math.max(0, nameLen - 2); // without the terminating null
        final String name = new String(dir, p, nameLen, StandardCharsets.UTF_16LE);
        final int type = dir[p + 66] & 0xff;
        final long ft = le64(dir, p + 108);
        final long mtime = ft <= 0 ? -1 : ft / 10000000L - 11644473600L;
        final long size = le64(dir, p + 120);
        return new Node(name, type == 1 || type == 5, sectorSize == 512 ? size & 0xffffffffL : size, mtime, le32(dir, p + 116));
    }

    /** Adds the children of a storage: in-order walk of the red-black tree rooted at its "child" entry. */
    private void readChildren(final byte[] dir, final int index, final Node node, final Set<Integer> visited, final int depth) throws IOException {
        if (depth > 256) throw new ArcanaCorruptedException("OLE storage nesting too deep");
        final int child = le32(dir, index * 128 + 76);
        walkTree(dir, child, node, visited, depth);
    }

    private void walkTree(final byte[] dir, final int index, final Node parent, final Set<Integer> visited, final int depth) throws IOException {
        if (index == FREESECT || index < 0) return;
        if ((long) index * 128 + 128 > dir.length || !visited.add(index)) throw new ArcanaCorruptedException("Invalid OLE directory tree");
        final int p = index * 128;
        walkTree(dir, le32(dir, p + 68), parent, visited, depth);
        final int type = dir[p + 66] & 0xff;
        if (type == 1 || type == 2) {
            final Node n = entry(dir, index);
            parent.children.add(n);
            if (type == 1) readChildren(dir, index, n, visited, depth + 1);
        }
        walkTree(dir, le32(dir, p + 72), parent, visited, depth);
    }

    // =========================================================================
    // Streams
    // =========================================================================

    /** Reads a whole stream. */
    public byte[] read(final Node n) throws IOException {
        if (n.storage) throw new IOException("Not a stream: " + n.name);
        if (n.size > MAX_STREAM) throw new ArcanaCorruptedException("OLE stream too large: " + n.name);
        final ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(n.size, 1 << 20));
        copy(n, out);
        return out.toByteArray();
    }

    /** Writes a stream. */
    public void copy(final Node n, final OutputStream out) throws IOException {
        if (n.storage) throw new IOException("Not a stream: " + n.name);
        if (n.size == 0) return;
        if (n.size < miniCutoff) {
            if (miniStream == null) miniStream = chain(root.start, root.size);
            long left = n.size;
            int s = n.start;
            int guard = 0;
            while (left > 0) {
                if (s < 0 || s >= miniFat.length || (long) s * miniSectorSize + miniSectorSize > miniStream.length || ++guard > miniFat.length + 1) throw new ArcanaCorruptedException("Invalid OLE mini stream chain: " + n.name);
                final int k = (int) Math.min(miniSectorSize, left);
                out.write(miniStream, s * miniSectorSize, k);
                left -= k;
                s = miniFat[s];
            }
            return;
        }
        long left = n.size;
        int s = n.start;
        int guard = 0;
        while (left > 0) {
            if (s < 0 || s >= fat.length || ++guard > fat.length + 1) throw new ArcanaCorruptedException("Invalid OLE sector chain: " + n.name);
            final int k = (int) Math.min(sectorSize, left);
            final long pos = (long) (s + 1) * sectorSize;
            if (pos + k > fileLength) throw new ArcanaCorruptedException("OLE stream outside the file: " + n.name);
            final byte[] b = new byte[k];
            raf.seek(pos);
            raf.readFully(b);
            out.write(b);
            left -= k;
            s = fat[s];
        }
    }

    /** Reads a FAT chain (whole chain when size < 0). */
    private byte[] chain(int s, final long size) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        long left = size < 0 ? Long.MAX_VALUE : size;
        int guard = 0;
        while (s != ENDOFCHAIN && left > 0) {
            if (s < 0 || s >= fat.length || ++guard > fat.length + 1) throw new ArcanaCorruptedException("Invalid OLE sector chain");
            final byte[] d = sector(s);
            final int k = (int) Math.min(sectorSize, left);
            out.write(d, 0, k);
            if (size >= 0) left -= k;
            s = fat[s];
            if (out.size() > MAX_STREAM - sectorSize) throw new ArcanaCorruptedException("OLE stream too large");
        }
        return out.toByteArray();
    }

    private byte[] sector(final int s) throws IOException {
        final long pos = ((s & 0xffffffffL) + 1) * sectorSize;
        if (pos + sectorSize > fileLength) {
            // the last sector may be truncated
            if (pos >= fileLength) throw new ArcanaCorruptedException("OLE sector outside the file");
            final byte[] b = new byte[sectorSize];
            raf.seek(pos);
            raf.readFully(b, 0, (int) (fileLength - pos));
            return b;
        }
        final byte[] b = new byte[sectorSize];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private static String clsid(final byte[] b, final int p) {
        return String.format("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", le32(b, p), le16(b, p + 4), le16(b, p + 6),
                b[p + 8] & 0xff, b[p + 9] & 0xff, b[p + 10] & 0xff, b[p + 11] & 0xff, b[p + 12] & 0xff, b[p + 13] & 0xff, b[p + 14] & 0xff, b[p + 15] & 0xff);
    }

    static int le16(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8;
    }

    static int le32(final byte[] b, final int p) {
        return le16(b, p) | le16(b, p + 2) << 16;
    }

    static long le64(final byte[] b, final int p) {
        return (le32(b, p) & 0xffffffffL) | (long) le32(b, p + 4) << 32;
    }
}
