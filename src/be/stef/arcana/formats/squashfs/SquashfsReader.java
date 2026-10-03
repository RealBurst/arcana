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
package be.stef.arcana.formats.squashfs;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.lz4.LZ4BlockInputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import be.stef.arcana.formats.zstd.ZstdInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Reader for SquashFS 4.0 file systems (Linux live systems, Snap and AppImage
 * payloads, router firmware), written from the community description of the
 * on-disk format.
 *
 * <p>Layout: a 96-byte superblock, the data blocks and fragments, then the
 * inode, directory, fragment, export and id tables. Tables are made of
 * "metadata blocks" (2-byte header, at most 8 KiB once decompressed); an inode
 * is addressed by a reference (block position &lt;&lt; 16 | offset in the block).
 * A file is a list of data blocks, each compressed separately, plus optionally
 * its tail packed in a "fragment" block shared with other small files.</p>
 *
 * <p>Compressors: gzip (zlib), LZMA, LZO, XZ, LZ4 and Zstandard. Symbolic
 * links, devices, FIFOs and sockets are reported but carry no data.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public final class SquashfsReader implements AutoCloseable {

    /** Entry kinds reported to the visitor. */
    public static final int DIRECTORY = 1;
    public static final int FILE = 2;
    public static final int SYMLINK = 3;
    public static final int OTHER = 4;

    /** One entry of the file system. */
    public static final class Entry {
        /** Path inside the image, '/' separated, without leading '/'. */
        public final String path;
        /** DIRECTORY, FILE, SYMLINK or OTHER. */
        public final int kind;
        /** File size (FILE), target length (SYMLINK), 0 otherwise. */
        public final long size;
        /** Modification time, Unix seconds. */
        public final long mtime;
        /** Target of a symbolic link, null otherwise. */
        public final String linkTarget;
        final Inode inode;

        Entry(final String path, final int kind, final long size, final long mtime, final String linkTarget, final Inode inode) {
            this.path = path;
            this.kind = kind;
            this.size = size;
            this.mtime = mtime;
            this.linkTarget = linkTarget;
            this.inode = inode;
        }
    }

    /** Callback of {@link #walk}. */
    public interface Visitor {
        void visit(Entry entry) throws IOException;
    }

    private static final int MAGIC = 0x73717368; // "hsqs"
    private static final int METADATA_SIZE = 8192;
    private static final int NO_FRAGMENT = 0xFFFFFFFF;
    private static final int MAX_DEPTH = 256;

    private static final int GZIP = 1;
    private static final int LZMA = 2;
    private static final int LZO = 3;
    private static final int XZ = 4;
    private static final int LZ4 = 5;
    private static final int ZSTD = 6;

    private final RandomAccessFile raf;
    private final long fileLength;
    private final int blockSize;
    private final int compressor;
    private final long fragmentCount;
    private final long rootInode;
    private final long inodeTable;
    private final long directoryTable;
    private final long fragmentTable;
    private final Inflater inflater = new Inflater();

    /** Decompressed metadata blocks: position -> {data, next position}. */
    private final Map<Long, Object[]> metaCache = new LinkedHashMap<Long, Object[]>(64, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(final Map.Entry<Long, Object[]> e) {
            return size() > 256;
        }
    };
    private long cachedFragmentPos = -1;
    private byte[] cachedFragment;
    private int cachedFragmentLength;

    public SquashfsReader(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            fileLength = raf.length();
            final byte[] sb = new byte[96];
            if (fileLength < 96) throw new ArcanaCorruptedException("SquashFS image too short");
            raf.readFully(sb);
            if (le32(sb, 0) != MAGIC) {
                if (be32(sb, 0) == MAGIC) throw new ArcanaUnsupportedFormatException("Big-endian SquashFS (version 3 or older) is not supported");
                throw new ArcanaCorruptedException("Not a SquashFS image");
            }
            final int major = le16(sb, 28);
            final int minor = le16(sb, 30);
            if (major != 4) throw new ArcanaUnsupportedFormatException("SquashFS version " + major + "." + minor + " is not supported (4.0 only)");
            blockSize = le32(sb, 12);
            final int blockLog = le16(sb, 22);
            if (blockSize < 4096 || blockSize > (1 << 20) || blockSize != 1 << blockLog) throw new ArcanaCorruptedException("Invalid SquashFS block size " + blockSize);
            compressor = le16(sb, 20);
            if (compressor < GZIP || compressor > ZSTD) throw new ArcanaUnsupportedFormatException("Unknown SquashFS compressor " + compressor);
            fragmentCount = le32(sb, 16) & 0xffffffffL;
            rootInode = le64(sb, 32);
            inodeTable = le64(sb, 64);
            directoryTable = le64(sb, 72);
            fragmentTable = le64(sb, 80);
            if (inodeTable <= 0 || inodeTable >= fileLength || directoryTable <= inodeTable || directoryTable >= fileLength) throw new ArcanaCorruptedException("Invalid SquashFS table positions");
            ok = true;
        } finally {
            if (!ok) raf.close();
        }
    }

    /** Block size of the image. */
    public int getBlockSize() {
        return blockSize;
    }

    /** Name of the compressor ("gzip", "xz"...). */
    public String getCompressorName() {
        switch (compressor) {
            case GZIP: return "gzip";
            case LZMA: return "lzma";
            case LZO: return "lzo";
            case XZ: return "xz";
            case LZ4: return "lz4";
            default: return "zstd";
        }
    }

    @Override
    public void close() throws IOException {
        inflater.end();
        raf.close();
    }

    // =========================================================================
    // Directory tree
    // =========================================================================

    /** Visits every entry, parents before their children. */
    public void walk(final Visitor visitor) throws IOException {
        final Inode root = readInode(rootInode);
        if (root.kind != DIRECTORY) throw new ArcanaCorruptedException("SquashFS root is not a directory");
        walkDir(root, "", visitor, new HashSet<Long>(), 0);
    }

    private void walkDir(final Inode dir, final String prefix, final Visitor visitor, final Set<Long> active, final int depth) throws IOException {
        if (depth > MAX_DEPTH || !active.add(dir.ref)) throw new ArcanaCorruptedException("SquashFS directory loop");
        final Cursor c = new Cursor(directoryTable + dir.dirBlock, dir.dirOffset);
        long left = dir.size - 3; // the size counts "." and ".."
        while (left >= 12) {
            final int count = c.u32() + 1;
            final long start = c.u32() & 0xffffffffL;
            c.u32(); // base inode number
            left -= 12;
            if (count > 256 || count <= 0) throw new ArcanaCorruptedException("Invalid SquashFS directory header");
            for (int i = 0; i < count; i++) {
                final int offset = c.u16();
                c.u16(); // inode number delta
                c.u16(); // type (the inode has the full information)
                final int nameSize = c.u16() + 1;
                final byte[] raw = c.bytes(nameSize);
                left -= 8 + nameSize;
                final String name = new String(raw, StandardCharsets.UTF_8);
                if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0) throw new ArcanaCorruptedException("Invalid SquashFS file name: " + name);
                final Inode inode = readInode(start << 16 | offset);
                final String path = prefix.isEmpty() ? name : prefix + "/" + name;
                visitor.visit(new Entry(path, inode.kind, inode.kind == FILE ? inode.size : inode.kind == SYMLINK ? inode.target.length() : 0, inode.mtime, inode.target, inode));
                if (inode.kind == DIRECTORY) walkDir(inode, path, visitor, active, depth + 1);
            }
        }
        active.remove(dir.ref);
    }

    // =========================================================================
    // Inodes
    // =========================================================================

    static final class Inode {
        long ref;
        int kind;
        long mtime;
        long size;
        long dirBlock;
        int dirOffset;
        long blocksStart;
        int fragment = NO_FRAGMENT;
        int fragmentOffset;
        int[] blockSizes;
        String target;
    }

    private Inode readInode(final long ref) throws IOException {
        final Cursor c = new Cursor(inodeTable + (ref >>> 16), (int) (ref & 0xffff));
        final Inode n = new Inode();
        n.ref = ref;
        final int type = c.u16();
        c.u16(); // permissions
        c.u16(); // uid index
        c.u16(); // gid index
        n.mtime = c.u32() & 0xffffffffL;
        c.u32(); // inode number
        switch (type) {
            case 1: // basic directory
                n.kind = DIRECTORY;
                n.dirBlock = c.u32() & 0xffffffffL;
                c.u32(); // link count
                n.size = c.u16();
                n.dirOffset = c.u16();
                break;
            case 8: // extended directory
                n.kind = DIRECTORY;
                c.u32(); // link count
                n.size = c.u32() & 0xffffffffL;
                n.dirBlock = c.u32() & 0xffffffffL;
                c.u32(); // parent inode
                c.u16(); // index count
                n.dirOffset = c.u16();
                break;
            case 2: // basic file
                n.kind = FILE;
                n.blocksStart = c.u32() & 0xffffffffL;
                n.fragment = c.u32();
                n.fragmentOffset = c.u32();
                n.size = c.u32() & 0xffffffffL;
                readBlockList(c, n);
                break;
            case 9: // extended file
                n.kind = FILE;
                n.blocksStart = c.u64();
                n.size = c.u64();
                c.u64(); // sparse bytes
                c.u32(); // link count
                n.fragment = c.u32();
                n.fragmentOffset = c.u32();
                c.u32(); // xattr index
                readBlockList(c, n);
                break;
            case 3: // basic symlink
            case 10: // extended symlink
                n.kind = SYMLINK;
                c.u32(); // link count
                final int len = c.u32();
                if (len < 0 || len > 65536) throw new ArcanaCorruptedException("Invalid SquashFS symlink");
                n.target = new String(c.bytes(len), StandardCharsets.UTF_8);
                break;
            case 4: case 5: case 6: case 7: case 11: case 12: case 13: case 14:
                n.kind = OTHER; // devices, FIFOs, sockets
                break;
            default:
                throw new ArcanaCorruptedException("Unknown SquashFS inode type " + type);
        }
        return n;
    }

    private void readBlockList(final Cursor c, final Inode n) throws IOException {
        if (n.size < 0 || n.blocksStart < 0 || n.blocksStart > fileLength) throw new ArcanaCorruptedException("Invalid SquashFS file inode");
        final long full = n.size / blockSize;
        final long count = n.fragment != NO_FRAGMENT || n.size % blockSize == 0 ? full : full + 1;
        if (count > Integer.MAX_VALUE / 8 || count * 4 > fileLength) throw new ArcanaCorruptedException("Invalid SquashFS block count");
        n.blockSizes = new int[(int) count];
        for (int i = 0; i < count; i++) n.blockSizes[i] = c.u32();
    }

    // =========================================================================
    // File data
    // =========================================================================

    /** Writes the content of a FILE entry. */
    public void copyFile(final Entry entry, final OutputStream out) throws IOException {
        final Inode n = entry.inode;
        if (n.kind != FILE) return;
        final byte[] block = new byte[blockSize];
        long pos = n.blocksStart;
        long left = n.size;
        for (final int b : n.blockSizes) {
            final int want = (int) Math.min(blockSize, left);
            final int size = b & 0xFFFFFF;
            if (size == 0) {
                // sparse block
                java.util.Arrays.fill(block, 0, want, (byte) 0);
                out.write(block, 0, want);
            } else {
                final byte[] raw = read(pos, size);
                if ((b & 0x1000000) != 0) {
                    if (size < want) throw new ArcanaCorruptedException("SquashFS data block too short");
                    out.write(raw, 0, want);
                } else {
                    final int got = decompress(raw, size, block);
                    if (got < want) throw new ArcanaCorruptedException("SquashFS data block too short");
                    out.write(block, 0, want);
                }
                pos += size;
            }
            left -= want;
        }
        if (left > 0) {
            if (n.fragment == NO_FRAGMENT) throw new ArcanaCorruptedException("SquashFS file shorter than its size");
            final byte[] frag = fragment(n.fragment);
            if (n.fragmentOffset < 0 || n.fragmentOffset + left > cachedFragmentLength) throw new ArcanaCorruptedException("SquashFS fragment too short");
            out.write(frag, n.fragmentOffset, (int) left);
        }
    }

    private byte[] fragment(final int index) throws IOException {
        if ((index & 0xffffffffL) >= fragmentCount) throw new ArcanaCorruptedException("Invalid SquashFS fragment index");
        final long tableBlock = read64(fragmentTable + 8L * (index / 512));
        final Cursor c = new Cursor(tableBlock, (index % 512) * 16);
        final long start = c.u64();
        final int b = c.u32();
        if (start == cachedFragmentPos) return cachedFragment;
        final int size = b & 0xFFFFFF;
        final byte[] raw = read(start, size);
        if (cachedFragment == null) cachedFragment = new byte[blockSize];
        if ((b & 0x1000000) != 0) {
            System.arraycopy(raw, 0, cachedFragment, 0, Math.min(size, blockSize));
            cachedFragmentLength = Math.min(size, blockSize);
        } else {
            cachedFragmentLength = decompress(raw, size, cachedFragment);
        }
        cachedFragmentPos = start;
        return cachedFragment;
    }

    // =========================================================================
    // Metadata blocks
    // =========================================================================

    /** Sequential reader over metadata blocks, starting at (block position, offset). */
    private final class Cursor {
        private byte[] data;
        private long next;
        private int pos;

        Cursor(final long blockPos, final int offset) throws IOException {
            load(blockPos);
            if (offset < 0 || offset > data.length) throw new ArcanaCorruptedException("Invalid SquashFS metadata offset");
            pos = offset;
        }

        private void load(final long blockPos) throws IOException {
            final Object[] m = metadata(blockPos);
            data = (byte[]) m[0];
            next = (Long) m[1];
            pos = 0;
        }

        int u8() throws IOException {
            while (pos >= data.length) load(next);
            return data[pos++] & 0xff;
        }

        int u16() throws IOException {
            return u8() | u8() << 8;
        }

        int u32() throws IOException {
            return u16() | u16() << 16;
        }

        long u64() throws IOException {
            return (u32() & 0xffffffffL) | (long) u32() << 32;
        }

        byte[] bytes(final int n) throws IOException {
            final byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte) u8();
            return b;
        }
    }

    private Object[] metadata(final long pos) throws IOException {
        Object[] m = metaCache.get(pos);
        if (m != null) return m;
        if (pos < 0 || pos + 2 > fileLength) throw new ArcanaCorruptedException("SquashFS metadata outside the image");
        final byte[] h = read(pos, 2);
        final int header = le16(h, 0);
        final int size = header & 0x7FFF;
        if (size == 0 || size > METADATA_SIZE) throw new ArcanaCorruptedException("Invalid SquashFS metadata block");
        final byte[] raw = read(pos + 2, size);
        byte[] data;
        if ((header & 0x8000) != 0) {
            data = raw;
        } else {
            final byte[] out = new byte[METADATA_SIZE];
            final int n = decompress(raw, size, out);
            data = java.util.Arrays.copyOf(out, n);
        }
        m = new Object[] {data, pos + 2 + size};
        metaCache.put(pos, m);
        return m;
    }

    // =========================================================================
    // Decompression
    // =========================================================================

    /** Decompresses src[0, len) into dst; returns the number of bytes produced. */
    private int decompress(final byte[] src, final int len, final byte[] dst) throws IOException {
        switch (compressor) {
            case GZIP:
                inflater.reset();
                inflater.setInput(src, 0, len);
                try {
                    int n = 0;
                    while (n < dst.length && !inflater.finished()) {
                        final int k = inflater.inflate(dst, n, dst.length - n);
                        if (k == 0 && (inflater.needsInput() || inflater.needsDictionary())) break;
                        n += k;
                    }
                    return n;
                } catch (final DataFormatException e) {
                    throw new ArcanaCorruptedException("SquashFS gzip block corrupted", e);
                }
            case LZO:
                return Lzo1xDecompressor.decompress(src, 0, len, dst);
            case LZ4:
                try (InputStream in = new LZ4BlockInputStream(src, 0, len, -1)) {
                    return readAll(in, dst);
                }
            case LZMA:
                try (InputStream in = new LZMAInputStream(new ByteArrayInputStream(src, 0, len))) {
                    return readAll(in, dst);
                }
            case XZ:
                try (InputStream in = new XZInputStream(new ByteArrayInputStream(src, 0, len))) {
                    return readAll(in, dst);
                }
            default:
                try (InputStream in = new ZstdInputStream(new ByteArrayInputStream(src, 0, len))) {
                    return readAll(in, dst);
                }
        }
    }

    private static int readAll(final InputStream in, final byte[] dst) throws IOException {
        int n = 0;
        while (n < dst.length) {
            final int k = in.read(dst, n, dst.length - n);
            if (k < 0) return n;
            n += k;
        }
        if (in.read() >= 0) throw new ArcanaCorruptedException("SquashFS block larger than the block size");
        return n;
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private byte[] read(final long pos, final int len) throws IOException {
        if (pos < 0 || len < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("SquashFS data outside the image");
        final byte[] b = new byte[len];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }

    private long read64(final long pos) throws IOException {
        return le64(read(pos, 8), 0);
    }

    private static int le16(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8;
    }

    private static int le32(final byte[] b, final int p) {
        return le16(b, p) | le16(b, p + 2) << 16;
    }

    private static int be32(final byte[] b, final int p) {
        return (b[p] & 0xff) << 24 | (b[p + 1] & 0xff) << 16 | (b[p + 2] & 0xff) << 8 | (b[p + 3] & 0xff);
    }

    private static long le64(final byte[] b, final int p) {
        return (le32(b, p) & 0xffffffffL) | (long) le32(b, p + 4) << 32;
    }
}
