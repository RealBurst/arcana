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
package be.stef.arcana.formats.wim;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reader for Windows Imaging Format files (.wim, .esd), written from the
 * Microsoft "Windows Imaging File Format (WIM)" specification.
 *
 * <p>Layout: a 208-byte header pointing to the lookup table (one 50-byte
 * entry per resource: location, flags, part number, reference count, SHA-1),
 * the XML data and the resources. Each image has a metadata resource holding
 * its security data and its directory tree (DIRENTRY records); file contents
 * are resources found by the SHA-1 of their unnamed stream.</p>
 *
 * <p>Compressed resources are split in chunks (32 KiB by default) compressed
 * separately with XPRESS (Huffman) or LZX, preceded by a table of chunk
 * offsets. Version 3584 files may group several streams in "solid"
 * resources. LZMS (used by most .esd files) is not supported.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public final class WimReader implements AutoCloseable {

    /** One file or directory of an image. */
    public static final class Entry {
        /** Path, '/' separated; prefixed by the image number when the file has several images. */
        public final String path;
        public final boolean directory;
        /** Size of the unnamed data stream (0 for directories and reparse points). */
        public final long size;
        /** Last write time, Unix seconds, or -1. */
        public final long mtime;
        /** True for a reparse point (symbolic link, junction): extracted without data. */
        public final boolean reparsePoint;
        final Resource data;

        Entry(final String path, final boolean directory, final long size, final long mtime, final boolean reparsePoint, final Resource data) {
            this.path = path;
            this.directory = directory;
            this.size = size;
            this.mtime = mtime;
            this.reparsePoint = reparsePoint;
            this.data = data;
        }
    }

    /** Callback of {@link #walk}. */
    public interface Visitor {
        void visit(Entry entry) throws IOException;
    }

    private static final int HEADER_SIZE = 208;
    private static final int FLAG_COMPRESSION = 0x2;
    private static final int FLAG_SPANNED = 0x8;
    private static final int COMPRESS_XPRESS = 0x20000;
    private static final int COMPRESS_LZX = 0x40000;
    private static final int COMPRESS_LZMS = 0x80000;
    private static final int COMPRESS_XPRESS2 = 0x200000;

    private static final int RES_METADATA = 0x2;
    private static final int RES_COMPRESSED = 0x4;
    private static final int RES_SOLID = 0x10;
    private static final long SOLID_MAGIC = 0x100000000L;

    private static final int ATTR_DIRECTORY = 0x10;
    private static final int ATTR_REPARSE = 0x400;

    private static final int CT_NONE = 0;
    private static final int CT_XPRESS = 1;
    private static final int CT_LZX = 2;
    private static final int CT_LZMS = 3;

    private static final long MAX_METADATA = 512L * 1024 * 1024;
    private static final int MAX_DEPTH = 1024;

    private final RandomAccessFile raf;
    private final long fileLength;
    private final int compression;
    private final int chunkSize;
    private final int imageCount;
    private final List<Resource> metadata = new ArrayList<Resource>();
    private final Map<String, Resource> byHash = new HashMap<String, Resource>();
    private XpressHuffmanDecoder xpress;
    private final Map<Integer, WimLzxDecoder> lzx = new HashMap<Integer, WimLzxDecoder>();

    /** A resource: a stream stored alone, or a part of a solid resource. */
    static final class Resource {
        long offset;
        long storedSize;
        long size;
        int flags;
        /** For a stream inside solid resources: the group and the offset in its uncompressed data. */
        SolidGroup group;
        long groupOffset;
    }

    /** Consecutive solid resources whose uncompressed data are concatenated. */
    static final class SolidGroup {
        final List<Resource> parts = new ArrayList<Resource>();
        long[] partSize; // uncompressed size of each part, read from its header
    }

    public WimReader(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            fileLength = raf.length();
            if (fileLength < HEADER_SIZE) throw new ArcanaCorruptedException("WIM file too short");
            final byte[] h = read(0, HEADER_SIZE);
            if (!new String(h, 0, 5, StandardCharsets.US_ASCII).equals("MSWIM")) throw new ArcanaCorruptedException("Not a WIM file");
            final int flags = le32(h, 16);
            final int chunk = le32(h, 20);
            final int part = le16(h, 40);
            final int parts = le16(h, 42);
            imageCount = le32(h, 44);
            if ((flags & FLAG_SPANNED) != 0 || parts > 1 || part != 1) throw new ArcanaUnsupportedFormatException("Split WIM files (.swm) are not supported: part " + part + " of " + parts);
            if ((flags & FLAG_COMPRESSION) == 0) compression = CT_NONE;
            else if ((flags & (COMPRESS_XPRESS | COMPRESS_XPRESS2)) != 0) compression = CT_XPRESS;
            else if ((flags & COMPRESS_LZX) != 0) compression = CT_LZX;
            else if ((flags & COMPRESS_LZMS) != 0) compression = CT_LZMS;
            else compression = CT_NONE;
            chunkSize = chunk == 0 ? 32768 : chunk;
            if (chunkSize < 4096 || chunkSize > (1 << 26) || Integer.bitCount(chunkSize) != 1) throw new ArcanaCorruptedException("Invalid WIM chunk size " + chunkSize);
            if (imageCount < 0 || imageCount > 10000) throw new ArcanaCorruptedException("Invalid WIM image count");
            readLookupTable(reshdr(h, 48));
            if (metadata.size() < imageCount) throw new ArcanaCorruptedException("WIM metadata resources missing");
            ok = true;
        } finally {
            if (!ok) raf.close();
        }
    }

    public int getImageCount() {
        return imageCount;
    }

    /** "none", "XPRESS", "LZX" or "LZMS". */
    public String getCompressionName() {
        switch (compression) {
            case CT_XPRESS: return "XPRESS";
            case CT_LZX: return "LZX";
            case CT_LZMS: return "LZMS";
            default: return "none";
        }
    }

    /** True when some resources are solid (version 3584, typical of .esd files). */
    public boolean hasSolidResources() {
        for (final Resource r : byHash.values()) if (r.group != null) return true;
        return false;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // =========================================================================
    // Lookup table
    // =========================================================================

    private Resource reshdr(final byte[] b, final int p) {
        final Resource r = new Resource();
        r.storedSize = (le32(b, p) & 0xffffffffL) | (long) (le32(b, p + 3) >>> 8) << 32;
        r.flags = b[p + 7] & 0xff;
        r.offset = le64(b, p + 8);
        r.size = le64(b, p + 16);
        return r;
    }

    private void readLookupTable(final Resource table) throws IOException {
        if (table.size <= 0 || table.size % 50 != 0 || table.size > 256L * 1024 * 1024) throw new ArcanaCorruptedException("Invalid WIM lookup table");
        final byte[] t = readResource(table, 0, (int) table.size);
        SolidGroup group = null;
        boolean blobsSeen = false;
        for (int p = 0; p < t.length; p += 50) {
            final Resource r = reshdr(t, p);
            final String hash = hex(t, p + 30, 20);
            if ((r.flags & RES_SOLID) != 0) {
                if (r.size == SOLID_MAGIC) {
                    if (group == null || blobsSeen) {
                        group = new SolidGroup();
                        blobsSeen = false;
                    }
                    group.parts.add(r);
                    continue;
                }
                if (group == null) throw new ArcanaCorruptedException("WIM stream outside any solid resource");
                blobsSeen = true;
                r.group = group;
                r.groupOffset = r.offset;
                r.size = r.storedSize;
            }
            if ((r.flags & RES_METADATA) != 0) metadata.add(r);
            else byHash.put(hash, r);
        }
    }

    // =========================================================================
    // Directory tree
    // =========================================================================

    /** Visits every file and directory of every image, parents first. */
    public void walk(final Visitor visitor) throws IOException {
        for (int i = 0; i < imageCount; i++) {
            final Resource m = metadata.get(i);
            if (m.size > MAX_METADATA || m.size < 8) throw new ArcanaCorruptedException("Invalid WIM metadata resource");
            final byte[] md = readResource(m, 0, (int) m.size);
            final String prefix = imageCount > 1 ? String.valueOf(i + 1) : "";
            if (!prefix.isEmpty()) visitor.visit(new Entry(prefix, true, 0, -1, false, null));
            long security = le32(md, 0) & 0xffffffffL;
            if (security < 8) security = 8;
            final long root = (security + 7) & ~7L;
            if (root + 102 > md.length) throw new ArcanaCorruptedException("Invalid WIM security data");
            final long children = le64(md, (int) root + 16);
            walkDir(md, children, prefix, visitor, new HashSet<Long>(), 0);
        }
    }

    private void walkDir(final byte[] md, final long first, final String prefix, final Visitor visitor, final Set<Long> active, final int depth) throws IOException {
        if (first == 0) return;
        if (depth > MAX_DEPTH || !active.add(first)) throw new ArcanaCorruptedException("WIM directory loop");
        long p = first;
        while (true) {
            if (p < 0 || p + 8 > md.length) throw new ArcanaCorruptedException("WIM directory entry outside the metadata");
            final long length = le64(md, (int) p);
            if (length == 0) break;
            if (length < 102 || p + length > md.length) throw new ArcanaCorruptedException("Invalid WIM directory entry");
            final int d = (int) p;
            final int attributes = le32(md, d + 8);
            final long subdir = le64(md, d + 16);
            final long writeTime = le64(md, d + 56);
            final int streams = le16(md, d + 96);
            final int nameBytes = le16(md, d + 100);
            if (102 + nameBytes > length) throw new ArcanaCorruptedException("Invalid WIM file name");
            final String name = new String(md, d + 102, nameBytes, StandardCharsets.UTF_16LE);
            String hash = hex(md, d + 64, 20);
            long next = p + ((length + 7) & ~7L);
            for (int s = 0; s < streams; s++) {
                if (next + 38 > md.length) throw new ArcanaCorruptedException("Invalid WIM stream entry");
                final long slen = le64(md, (int) next);
                final int snameBytes = le16(md, (int) next + 36);
                if (slen < 38 || next + slen > md.length) throw new ArcanaCorruptedException("Invalid WIM stream entry");
                if (snameBytes == 0) hash = hex(md, (int) next + 16, 20); // unnamed data stream
                next += (slen + 7) & ~7L;
            }
            if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) throw new ArcanaCorruptedException("Invalid WIM file name: " + name);
            final String path = prefix.isEmpty() ? name : prefix + "/" + name;
            final boolean dir = (attributes & ATTR_DIRECTORY) != 0;
            final boolean reparse = (attributes & ATTR_REPARSE) != 0;
            final long mtime = writeTime <= 0 ? -1 : writeTime / 10000000L - 11644473600L;
            Resource data = null;
            if (!dir && !reparse && !isZero(hash)) {
                data = byHash.get(hash);
                if (data == null) throw new ArcanaCorruptedException("WIM data missing for " + path);
            }
            visitor.visit(new Entry(path, dir, data != null ? data.size : 0, mtime, reparse, data));
            if (dir && !reparse) walkDir(md, subdir, path, visitor, active, depth + 1);
            p = next;
        }
        active.remove(first);
    }

    // =========================================================================
    // Data
    // =========================================================================

    /** Writes the content of a file entry (nothing for directories and reparse points). */
    public void copyFile(final Entry e, final OutputStream out) throws IOException {
        if (e.data == null) return;
        copy(e.data, 0, e.data.size, out);
    }

    private byte[] readResource(final Resource r, final long from, final int len) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(len, 1 << 20));
        copy(r, from, len, out);
        return out.toByteArray();
    }

    /** Copies uncompressed bytes [from, from + len) of a resource. */
    private void copy(final Resource r, final long from, final long len, final OutputStream out) throws IOException {
        if (len == 0) return;
        if (r.group != null) {
            copySolid(r.group, r.groupOffset + from, len, out);
            return;
        }
        if ((r.flags & RES_COMPRESSED) == 0 || r.storedSize == r.size && compression == CT_NONE) {
            if (from + len > r.storedSize) throw new ArcanaCorruptedException("WIM resource shorter than expected");
            copyRaw(r.offset + from, len, out);
            return;
        }
        copyChunked(r.offset, r.storedSize, r.size, chunkSize, compression, 0, from, len, out);
    }

    /**
     * Chunked resource: a table of offsets (4 bytes, or 8 for resources of 4 GiB
     * and more) of chunks 1..n-1 relative to the end of the table, then the
     * chunks. A chunk whose stored size equals its uncompressed size is stored.
     * For solid resources (sizeTable == true) the table holds the sizes of all
     * chunks instead.
     */
    private void copyChunked(final long start, final long stored, final long size, final int chunk, final int type, final int solidHeader, final long from, final long len, final OutputStream out) throws IOException {
        if (type == CT_LZMS) throw new ArcanaUnsupportedFormatException("WIM LZMS compression (.esd files) is not supported");
        if (type != CT_XPRESS && type != CT_LZX) throw new ArcanaUnsupportedFormatException("Unknown WIM compression " + type);
        if (chunk > (1 << 21)) throw new ArcanaCorruptedException("WIM chunk size too large: " + chunk);
        final long chunks = (size + chunk - 1) / chunk;
        if (chunks > Integer.MAX_VALUE / 8) throw new ArcanaCorruptedException("Invalid WIM chunk count");
        final boolean solid = solidHeader > 0;
        final int entry = !solid && size > 0xFFFFFFFFL ? 8 : 4;
        final int tableEntries = (int) (solid ? chunks : chunks - 1);
        final long tableStart = start + solidHeader;
        final byte[] table = read(tableStart, tableEntries * entry);
        final long dataStart = tableStart + (long) tableEntries * entry;
        final long dataEnd = start + stored;
        final long[] offsets = new long[(int) chunks + 1];
        if (solid) {
            for (int i = 0; i < chunks; i++) offsets[i + 1] = offsets[i] + (le32(table, i * 4) & 0xffffffffL);
        } else {
            for (int i = 1; i < chunks; i++) offsets[i] = entry == 8 ? le64(table, (i - 1) * 8) : le32(table, (i - 1) * 4) & 0xffffffffL;
            offsets[(int) chunks] = dataEnd - dataStart;
        }
        final byte[] buf = new byte[chunk];
        long pos = from;
        long left = len;
        while (left > 0) {
            final int index = (int) (pos / chunk);
            final int inChunk = (int) (pos % chunk);
            final int usize = (int) Math.min(chunk, size - (long) index * chunk);
            final long cpos = dataStart + offsets[index];
            final long clen = offsets[index + 1] - offsets[index];
            if (clen <= 0 || clen > usize || cpos + clen > dataEnd) throw new ArcanaCorruptedException("Invalid WIM chunk " + index);
            final byte[] raw = read(cpos, (int) clen);
            byte[] data;
            if (clen == usize) {
                data = raw;
            } else {
                decompress(type, raw, buf, usize, chunk);
                data = buf;
            }
            final int n = (int) Math.min(left, usize - inChunk);
            out.write(data, inChunk, n);
            pos += n;
            left -= n;
        }
    }

    private void copySolid(final SolidGroup g, final long from, final long len, final OutputStream out) throws IOException {
        if (g.partSize == null) {
            g.partSize = new long[g.parts.size()];
            for (int i = 0; i < g.parts.size(); i++) g.partSize[i] = le64(read(g.parts.get(i).offset, 8), 0);
        }
        long base = 0;
        long pos = from;
        long left = len;
        for (int i = 0; i < g.parts.size() && left > 0; i++) {
            final long psize = g.partSize[i];
            if (pos < base + psize) {
                final Resource part = g.parts.get(i);
                final byte[] h = read(part.offset, 16);
                final int chunk = le32(h, 8);
                final int type = le32(h, 12);
                if (chunk < 4096 || chunk > (1 << 26) || Integer.bitCount(chunk) != 1) throw new ArcanaCorruptedException("Invalid WIM solid chunk size");
                final long n = Math.min(left, base + psize - pos);
                copyChunked(part.offset, part.storedSize, psize, chunk, type, 16, pos - base, n, out);
                pos += n;
                left -= n;
            }
            base += psize;
        }
        if (left > 0) throw new ArcanaCorruptedException("WIM stream outside its solid resource");
    }

    private void decompress(final int type, final byte[] raw, final byte[] dst, final int usize, final int chunk) throws IOException {
        switch (type) {
            case CT_XPRESS:
                if (xpress == null) xpress = new XpressHuffmanDecoder();
                xpress.decompress(raw, 0, raw.length, dst, usize);
                return;
            case CT_LZX:
                WimLzxDecoder d = lzx.get(chunk);
                if (d == null) {
                    d = new WimLzxDecoder(chunk);
                    lzx.put(chunk, d);
                }
                d.decompress(raw, 0, raw.length, dst, usize);
                return;
            case CT_LZMS:
                throw new ArcanaUnsupportedFormatException("WIM LZMS compression (.esd files) is not supported");
            default:
                throw new ArcanaUnsupportedFormatException("Unknown WIM compression " + type);
        }
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private void copyRaw(final long pos, final long len, final OutputStream out) throws IOException {
        if (pos < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("WIM data outside the file");
        final byte[] buf = new byte[65536];
        raf.seek(pos);
        long left = len;
        while (left > 0) {
            final int n = (int) Math.min(buf.length, left);
            raf.readFully(buf, 0, n);
            out.write(buf, 0, n);
            left -= n;
        }
    }

    private byte[] read(final long pos, final int len) throws IOException {
        if (pos < 0 || len < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("WIM data outside the file");
        final byte[] b = new byte[len];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }

    private static boolean isZero(final String hash) {
        for (int i = 0; i < hash.length(); i++) if (hash.charAt(i) != '0') return false;
        return true;
    }

    private static String hex(final byte[] b, final int p, final int n) {
        final StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(Character.forDigit((b[p + i] >> 4) & 15, 16));
            sb.append(Character.forDigit(b[p + i] & 15, 16));
        }
        return sb.toString();
    }

    private static int le16(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8;
    }

    private static int le32(final byte[] b, final int p) {
        return le16(b, p) | le16(b, p + 2) << 16;
    }

    private static long le64(final byte[] b, final int p) {
        return (le32(b, p) & 0xffffffffL) | (long) le32(b, p + 4) << 32;
    }
}
