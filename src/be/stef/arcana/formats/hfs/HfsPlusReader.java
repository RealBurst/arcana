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
package be.stef.arcana.formats.hfs;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.lzfse.LzfseDecoder;
import be.stef.arcana.formats.lzfse.LzvnDecoder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Read-only reader of HFS+ and HFSX volumes (Mac OS Extended), written from
 * Apple Technical Note TN1150 "HFS Plus Volume Format" and, for the
 * transparent compression, from the public descriptions of the decmpfs
 * extended attribute.
 *
 * <p>Layout: a 512-byte volume header at offset 1024 (signature "H+" or "HX",
 * block size, fork data of the special files), the extents overflow file and
 * the catalog file, both B-trees (fixed-size nodes, records addressed by
 * offsets stored at the end of each node, leaf nodes chained). The catalog
 * leaves hold folder, file and thread records keyed by (parent folder ID,
 * UTF-16 name). A fork is described by 8 extents (start block, block count);
 * the following ones are in the extents overflow file. An HFS+ volume
 * embedded in an HFS ("BD") wrapper is supported.</p>
 *
 * <p>Handled: data forks, file names (HFS+ stores them decomposed: they are
 * returned in NFC; a '/' in a name becomes ':' as in the BSD layer),
 * modification dates, hard links (files "hlnk" pointing to "iNode&lt;n&gt;"
 * in the private metadata folder), symbolic links ("slnk", reported as
 * SYMLINK), and files compressed with decmpfs (attribute "com.apple.decmpfs"
 * in the attributes file: types 1 raw, 3 / 4 zlib, 7 / 8 LZVN, 11 / 12
 * LZFSE, inline or in the resource fork). Resource forks of normal files,
 * directory hard links, the private folders and the journal files are
 * skipped. The journal is not replayed.</p>
 *
 * @author Stef
 * @since 1.5
 */
public final class HfsPlusReader {

    /** Random-access source of the volume (a partition of a disk image, a file...). */
    public interface Source {
        long length();

        void readFully(long pos, byte[] b, int off, int len) throws IOException;
    }

    /** Entry kinds reported to the visitor. */
    public static final int DIRECTORY = 1;
    public static final int FILE = 2;
    public static final int SYMLINK = 3;

    /** One entry of the file system. */
    public static final class Entry {
        /** Path inside the volume, '/' separated, NFC, without leading '/'. */
        public final String path;
        /** DIRECTORY, FILE or SYMLINK. */
        public final int kind;
        /** Size of the data (FILE), 0 otherwise. */
        public final long size;
        /** Content modification time, Unix seconds (0 if unknown). */
        public final long mtime;
        /** True if the file is stored compressed (decmpfs). */
        public final boolean compressed;
        final Rec rec;

        Entry(final String path, final int kind, final long size, final long mtime, final boolean compressed, final Rec rec) {
            this.path = path;
            this.kind = kind;
            this.size = size;
            this.mtime = mtime;
            this.compressed = compressed;
            this.rec = rec;
        }
    }

    /** Callback of {@link #walk}. */
    public interface Visitor {
        void visit(Entry entry) throws IOException;
    }

    private static final int SIG_HFSPLUS = 0x482B; // "H+"
    private static final int SIG_HFSX = 0x4858; // "HX"
    private static final int SIG_HFS = 0x4244; // "BD"
    private static final long MAC_EPOCH_OFFSET = 2082844800L; // 1904-01-01 to 1970-01-01, seconds
    private static final int ROOT_PARENT_ID = 1;
    private static final int ROOT_FOLDER_ID = 2;
    private static final int EXTENTS_FILE_ID = 3;
    private static final int CATALOG_FILE_ID = 4;
    private static final int ATTRIBUTES_FILE_ID = 8;
    private static final int REC_FOLDER = 1;
    private static final int REC_FILE = 2;
    private static final int UF_COMPRESSED = 0x20;
    private static final int TYPE_HLNK = 0x686C6E6B; // "hlnk"
    private static final int CREATOR_HFSPLUS = 0x6866732B; // "hfs+"
    private static final int TYPE_FDRP = 0x66647270; // "fdrp"
    private static final int CREATOR_MACS = 0x4D414353; // "MACS"
    private static final int TYPE_SLNK = 0x736C6E6B; // "slnk"
    private static final int CREATOR_RHAP = 0x72686170; // "rhap"
    private static final String PRIVATE_FILES = "\u0000\u0000\u0000\u0000HFS+ Private Data";
    private static final String PRIVATE_DIRS = ".HFS+ Private Directory Data\r";
    private static final int DECMPFS_MAGIC = 0x636D7066; // "cmpf", little-endian
    private static final int DECMPFS_CHUNK = 65536;
    private static final int MAX_DEPTH = 512;
    private static final int MAX_ATTRIBUTE = 16 << 20;

    private final Source src;
    private final long volumeOffset;
    private final int signature;
    private final int version;
    private final int attributes;
    private final long fileCount;
    private final long folderCount;
    private final int blockSize;
    private final long totalBlocks;
    private final Fork extentsFork;
    private final Fork catalogFork;
    private final Fork attributesFork;
    private Map<Long, List<long[]>> overflow;
    private BTree catalog;
    private Map<Integer, byte[]> decmpfs;
    private int resourceForks;
    private int directoryLinks;

    /** Fork data: logical size, block count, and its first 8 extents. */
    static final class Fork {
        final int fileId;
        final int forkType;
        final long logicalSize;
        final long blocks;
        final long[] start = new long[8];
        final long[] count = new long[8];
        long[][] extents;

        Fork(final byte[] b, final int off, final int fileId, final int forkType) {
            this.fileId = fileId;
            this.forkType = forkType;
            logicalSize = be64(b, off);
            blocks = be32(b, off + 12) & 0xffffffffL;
            for (int i = 0; i < 8; i++) {
                start[i] = be32(b, off + 16 + 8 * i) & 0xffffffffL;
                count[i] = be32(b, off + 20 + 8 * i) & 0xffffffffL;
            }
        }
    }

    /** Catalog folder or file record. */
    static final class Rec {
        int parent;
        String rawName;
        String name;
        int type;
        int id;
        long mtime;
        int ownerFlags;
        int special;
        int fdType;
        int fdCreator;
        Fork data;
        Fork rsrc;
    }

    /** Opens the volume; reads and checks the volume header. */
    public HfsPlusReader(final Source source) throws IOException {
        this.src = source;
        if (source.length() < 1536) throw new ArcanaCorruptedException("HFS+ volume too short");
        byte[] h = read(1024, 512);
        long base = 0;
        if (be16(h, 0) == SIG_HFS) {
            // HFS wrapper (Master Directory Block) with an embedded HFS+ volume
            if (be16(h, 0x7C) != SIG_HFSPLUS) throw new ArcanaUnsupportedFormatException("HFS (Mac OS Standard) volume without embedded HFS+ volume: not supported");
            final long alBlkSiz = be32(h, 0x14) & 0xffffffffL;
            final long alBlSt = be16(h, 0x1C);
            base = alBlSt * 512 + be16(h, 0x7E) * alBlkSiz;
            if (base <= 0 || base + 1536 > source.length()) throw new ArcanaCorruptedException("Invalid embedded HFS+ volume position");
            h = read(base + 1024, 512);
        }
        volumeOffset = base;
        signature = be16(h, 0);
        if (signature != SIG_HFSPLUS && signature != SIG_HFSX) throw new ArcanaCorruptedException("Not an HFS+ volume (no H+ / HX signature)");
        version = be16(h, 2);
        attributes = be32(h, 4);
        fileCount = be32(h, 32) & 0xffffffffL;
        folderCount = be32(h, 36) & 0xffffffffL;
        blockSize = be32(h, 40);
        totalBlocks = be32(h, 44) & 0xffffffffL;
        if (blockSize < 512 || Integer.bitCount(blockSize) != 1 || blockSize > (1 << 26)) throw new ArcanaCorruptedException("Invalid HFS+ block size " + blockSize);
        extentsFork = new Fork(h, 192, EXTENTS_FILE_ID, 0);
        catalogFork = new Fork(h, 272, CATALOG_FILE_ID, 0);
        attributesFork = new Fork(h, 352, ATTRIBUTES_FILE_ID, 0);
    }

    /** "H+" or "HX". */
    public String getSignature() {
        return signature == SIG_HFSX ? "HX" : "H+";
    }

    public int getVersion() {
        return version;
    }

    public long getFileCount() {
        return fileCount;
    }

    public long getFolderCount() {
        return folderCount;
    }

    /** True if the volume has a journal (kHFSVolumeJournaledBit). */
    public boolean isJournaled() {
        return (attributes & (1 << 13)) != 0;
    }

    /** Resource forks of normal files skipped by the last {@link #walk}. */
    public int getResourceForkCount() {
        return resourceForks;
    }

    /** Directory hard links skipped by the last {@link #walk}. */
    public int getDirectoryLinkCount() {
        return directoryLinks;
    }

    /** Name of the volume (name of the root folder). */
    public String getVolumeName() throws IOException {
        final BTree t = catalog();
        final String[] name = new String[1];
        t.forEachLeafRecord((node, off) -> {
            if (be32(node, off + 2) == ROOT_PARENT_ID) {
                final Rec r = catalogRecord(node, off);
                if (r != null && r.id == ROOT_FOLDER_ID) {
                    name[0] = r.name;
                    return false;
                }
            }
            return true;
        });
        return name[0] != null ? name[0] : "";
    }

    // =========================================================================
    // Directory tree
    // =========================================================================

    /** Visits every entry, parents before their children. */
    public void walk(final Visitor visitor) throws IOException {
        final Map<Integer, List<Rec>> children = new HashMap<Integer, List<Rec>>();
        final BTree t = catalog();
        final boolean[] compressedSeen = new boolean[1];
        t.forEachLeafRecord((node, off) -> {
            final Rec r = catalogRecord(node, off);
            if (r != null) {
                List<Rec> l = children.get(r.parent);
                if (l == null) children.put(r.parent, l = new ArrayList<Rec>());
                l.add(r);
                compressedSeen[0] |= (r.ownerFlags & UF_COMPRESSED) != 0;
            }
            return true;
        });
        // hard link targets: files "iNode<n>" of the private metadata folder
        final Map<Integer, Rec> inodes = new HashMap<Integer, Rec>();
        for (final Rec r : list(children, ROOT_FOLDER_ID)) {
            if (r.type == REC_FOLDER && PRIVATE_FILES.equals(r.rawName)) {
                for (final Rec i : list(children, r.id)) {
                    if (i.type == REC_FILE && i.rawName.startsWith("iNode")) {
                        try {
                            inodes.put(Integer.parseInt(i.rawName.substring(5)), i);
                        } catch (final NumberFormatException ignored) {
                            // not a link target
                        }
                    }
                }
            }
        }
        if (compressedSeen[0]) loadDecmpfs();
        resourceForks = 0;
        directoryLinks = 0;
        walkFolder(ROOT_FOLDER_ID, "", children, inodes, visitor, new HashSet<Integer>(), 0);
    }

    private static List<Rec> list(final Map<Integer, List<Rec>> children, final int id) {
        final List<Rec> l = children.get(id);
        return l != null ? l : new ArrayList<Rec>();
    }

    private void walkFolder(final int id, final String prefix, final Map<Integer, List<Rec>> children, final Map<Integer, Rec> inodes, final Visitor visitor, final Set<Integer> active, final int depth) throws IOException {
        if (depth > MAX_DEPTH || !active.add(id)) throw new ArcanaCorruptedException("HFS+ folder loop");
        for (final Rec r : list(children, id)) {
            if (id == ROOT_FOLDER_ID) {
                if (r.type == REC_FOLDER && (PRIVATE_FILES.equals(r.rawName) || PRIVATE_DIRS.equals(r.rawName))) continue;
                if (r.type == REC_FILE && (".journal".equals(r.rawName) || ".journal_info_block".equals(r.rawName))) continue;
            }
            final String path = prefix.isEmpty() ? r.name : prefix + "/" + r.name;
            if (r.type == REC_FOLDER) {
                visitor.visit(new Entry(path, DIRECTORY, 0, r.mtime, false, r));
                walkFolder(r.id, path, children, inodes, visitor, active, depth + 1);
                continue;
            }
            if (r.fdType == TYPE_FDRP && r.fdCreator == CREATOR_MACS) {
                directoryLinks++;
                continue;
            }
            if (r.fdType == TYPE_SLNK && r.fdCreator == CREATOR_RHAP) {
                visitor.visit(new Entry(path, SYMLINK, 0, r.mtime, false, r));
                continue;
            }
            Rec target = r;
            if (r.fdType == TYPE_HLNK && r.fdCreator == CREATOR_HFSPLUS) {
                target = inodes.get(r.special);
                if (target == null) throw new ArcanaCorruptedException("HFS+ hard link without target: " + path);
            }
            final boolean compressed = (target.ownerFlags & UF_COMPRESSED) != 0;
            if (!compressed && target == r && r.rsrc.logicalSize > 0) resourceForks++;
            final long size = compressed ? decmpfsSize(target, path) : target.data.logicalSize;
            visitor.visit(new Entry(path, FILE, size, r.mtime, compressed, target));
        }
        active.remove(id);
    }

    /** Folder or file record at a catalog leaf record, null for thread records. */
    private Rec catalogRecord(final byte[] node, final int off) throws IOException {
        final int keyLength = be16(node, off);
        final int nameLength = be16(node, off + 6);
        if (keyLength < 6 || nameLength > 255 || 8 + 2 * nameLength > keyLength + 2) throw new ArcanaCorruptedException("Invalid HFS+ catalog key");
        final int d = off + 2 + keyLength;
        final int type = be16(node, d);
        if (type != REC_FOLDER && type != REC_FILE) return null;
        final Rec r = new Rec();
        r.parent = be32(node, off + 2);
        r.rawName = new String(node, off + 8, 2 * nameLength, StandardCharsets.UTF_16BE);
        r.name = Normalizer.normalize(r.rawName, Normalizer.Form.NFC).replace('/', ':');
        r.type = type;
        if (r.name.isEmpty() || r.name.equals(".") || r.name.equals("..")) r.name = "_" + r.name;
        if (type == REC_FOLDER) {
            if (d + 88 > node.length) throw new ArcanaCorruptedException("Invalid HFS+ folder record");
            r.id = be32(node, d + 8);
            r.mtime = unixTime(be32(node, d + 16) & 0xffffffffL);
        } else {
            if (d + 248 > node.length) throw new ArcanaCorruptedException("Invalid HFS+ file record");
            r.id = be32(node, d + 8);
            r.mtime = unixTime(be32(node, d + 16) & 0xffffffffL);
            r.ownerFlags = node[d + 41] & 0xff;
            r.special = be32(node, d + 44);
            r.fdType = be32(node, d + 48);
            r.fdCreator = be32(node, d + 52);
            r.data = new Fork(node, d + 88, r.id, 0);
            r.rsrc = new Fork(node, d + 168, r.id, 0xFF);
        }
        return r;
    }

    // =========================================================================
    // File data
    // =========================================================================

    /** Writes the content of a FILE entry (nothing for folders and symbolic links). */
    public void copyFile(final Entry entry, final OutputStream out) throws IOException {
        if (entry.kind != FILE) return;
        if (entry.compressed) {
            copyCompressed(entry.rec, entry.path, out);
            return;
        }
        final Fork f = entry.rec.data;
        final byte[] buf = new byte[65536];
        long pos = 0;
        while (pos < f.logicalSize) {
            final int n = (int) Math.min(buf.length, f.logicalSize - pos);
            readFork(f, pos, buf, 0, n);
            out.write(buf, 0, n);
            pos += n;
        }
    }

    /** Reads bytes of a fork at a position of its logical content. */
    private void readFork(final Fork f, long pos, final byte[] b, int off, int len) throws IOException {
        if (pos < 0 || pos + len > f.logicalSize) throw new ArcanaCorruptedException("Read beyond the end of an HFS+ fork");
        final long[][] ext = extents(f);
        while (len > 0) {
            long block = pos / blockSize;
            int i = 0;
            while (i < ext.length && block >= ext[i][1]) {
                block -= ext[i][1];
                i++;
            }
            if (i == ext.length) throw new ArcanaCorruptedException("HFS+ fork shorter than its size (file ID " + f.fileId + ")");
            final long inExtent = block * blockSize + pos % blockSize;
            final int n = (int) Math.min(len, ext[i][1] * blockSize - inExtent);
            final long at = volumeOffset + ext[i][0] * blockSize + inExtent;
            if (at + n > src.length()) throw new ArcanaCorruptedException("HFS+ extent beyond the end of the volume (file ID " + f.fileId + ")");
            src.readFully(at, b, off, n);
            pos += n;
            off += n;
            len -= n;
        }
    }

    /** All the extents of a fork ({start block, block count}), the overflow ones included. */
    private long[][] extents(final Fork f) throws IOException {
        if (f.extents != null) return f.extents;
        final List<long[]> l = new ArrayList<long[]>();
        long have = 0;
        for (int i = 0; i < 8 && f.count[i] > 0; i++) {
            l.add(new long[] {f.start[i], f.count[i]});
            have += f.count[i];
        }
        if (have < f.blocks && f.fileId != EXTENTS_FILE_ID) {
            final List<long[]> more = overflow().get((long) f.fileId << 8 | f.forkType);
            if (more != null) {
                for (final long[] r : more) {
                    if (r[0] != have) continue; // record for another part of the fork
                    for (int i = 0; i < 8 && r[2 + 2 * i] > 0; i++) {
                        l.add(new long[] {r[1 + 2 * i], r[2 + 2 * i]});
                        have += r[2 + 2 * i];
                    }
                    if (have >= f.blocks) break;
                }
            }
        }
        if (have * blockSize < f.logicalSize) throw new ArcanaCorruptedException("HFS+ fork shorter than its size (file ID " + f.fileId + ", missing extents)");
        for (final long[] e : l) if (e[0] + e[1] > totalBlocks) throw new ArcanaCorruptedException("HFS+ extent beyond the end of the volume (file ID " + f.fileId + ")");
        f.extents = l.toArray(new long[0][]);
        return f.extents;
    }

    /** Extents overflow records: (file ID << 8 | fork type) -> {start block in the fork, 8 x (start, count)}, sorted. */
    private Map<Long, List<long[]>> overflow() throws IOException {
        if (overflow != null) return overflow;
        overflow = new HashMap<Long, List<long[]>>();
        if (extentsFork.logicalSize == 0) return overflow;
        final BTree t = new BTree(extentsFork);
        t.forEachLeafRecord((node, off) -> {
            final int keyLength = be16(node, off);
            if (keyLength < 10) throw new ArcanaCorruptedException("Invalid HFS+ extents key");
            final int forkType = node[off + 2] & 0xff;
            final long fileId = be32(node, off + 4) & 0xffffffffL;
            final long start = be32(node, off + 8) & 0xffffffffL;
            final int d = off + 2 + keyLength;
            if (d + 64 > node.length) throw new ArcanaCorruptedException("Invalid HFS+ extents record");
            final long[] r = new long[17];
            r[0] = start;
            for (int i = 0; i < 8; i++) {
                r[1 + 2 * i] = be32(node, d + 8 * i) & 0xffffffffL;
                r[2 + 2 * i] = be32(node, d + 4 + 8 * i) & 0xffffffffL;
            }
            List<long[]> l = overflow.get(fileId << 8 | forkType);
            if (l == null) overflow.put(fileId << 8 | forkType, l = new ArrayList<long[]>());
            l.add(r);
            return true;
        });
        for (final List<long[]> l : overflow.values()) l.sort((a, b) -> Long.compare(a[0], b[0]));
        return overflow;
    }

    private BTree catalog() throws IOException {
        if (catalog == null) {
            if (catalogFork.logicalSize == 0) throw new ArcanaCorruptedException("HFS+ volume without catalog file");
            catalog = new BTree(catalogFork);
        }
        return catalog;
    }

    // =========================================================================
    // B-trees
    // =========================================================================

    /** Callback for every leaf record: node data and record offset; false stops the iteration. */
    private interface RecordVisitor {
        boolean visit(byte[] node, int off) throws IOException;
    }

    /** B-tree file (catalog, extents overflow, attributes). */
    private final class BTree {
        private final Fork fork;
        private final int nodeSize;
        private final long firstLeaf;
        private final long totalNodes;

        BTree(final Fork fork) throws IOException {
            this.fork = fork;
            final byte[] h = new byte[106];
            if (fork.logicalSize < 512) throw new ArcanaCorruptedException("HFS+ B-tree file too short (file ID " + fork.fileId + ")");
            readFork(fork, 0, h, 0, h.length);
            if (h[8] != 1) throw new ArcanaCorruptedException("Invalid HFS+ B-tree header node (file ID " + fork.fileId + ")");
            firstLeaf = be32(h, 14 + 10) & 0xffffffffL;
            nodeSize = be16(h, 14 + 18);
            totalNodes = be32(h, 14 + 22) & 0xffffffffL;
            if (nodeSize < 512 || nodeSize > 32768 || Integer.bitCount(nodeSize) != 1) throw new ArcanaCorruptedException("Invalid HFS+ B-tree node size " + nodeSize);
            if (totalNodes > fork.logicalSize / nodeSize) throw new ArcanaCorruptedException("Invalid HFS+ B-tree node count");
        }

        byte[] node(final long n) throws IOException {
            if (n <= 0 || n >= totalNodes) throw new ArcanaCorruptedException("Invalid HFS+ B-tree node number " + n);
            final byte[] b = new byte[nodeSize];
            readFork(fork, n * nodeSize, b, 0, nodeSize);
            return b;
        }

        void forEachLeafRecord(final RecordVisitor v) throws IOException {
            long n = firstLeaf;
            long visited = 0;
            while (n != 0) {
                if (++visited > totalNodes) throw new ArcanaCorruptedException("HFS+ B-tree leaf loop");
                final byte[] node = node(n);
                if (node[8] != -1) throw new ArcanaCorruptedException("HFS+ B-tree node " + n + " is not a leaf");
                final int records = be16(node, 10);
                if (records > nodeSize / 2) throw new ArcanaCorruptedException("Invalid HFS+ B-tree node " + n);
                for (int i = 0; i < records; i++) {
                    final int off = be16(node, nodeSize - 2 * (i + 1));
                    if (off < 14 || off + 8 > nodeSize - 2 * records) throw new ArcanaCorruptedException("Invalid HFS+ B-tree record offset in node " + n);
                    try {
                        if (!v.visit(node, off)) return;
                    } catch (final ArrayIndexOutOfBoundsException e) {
                        throw new ArcanaCorruptedException("Invalid HFS+ B-tree record in node " + n, e);
                    }
                }
                n = be32(node, 0) & 0xffffffffL;
            }
        }
    }

    // =========================================================================
    // decmpfs (transparent compression)
    // =========================================================================

    /** Loads the "com.apple.decmpfs" attributes of all files. */
    private void loadDecmpfs() throws IOException {
        decmpfs = new HashMap<Integer, byte[]>();
        if (attributesFork.logicalSize == 0) return;
        final BTree t = new BTree(attributesFork);
        final byte[] want = "com.apple.decmpfs".getBytes(StandardCharsets.UTF_16BE);
        t.forEachLeafRecord((node, off) -> {
            final int keyLength = be16(node, off);
            final int nameLength = be16(node, off + 12);
            if (keyLength < 12 || 14 + 2 * nameLength > keyLength + 2) throw new ArcanaCorruptedException("Invalid HFS+ attribute key");
            if (2 * nameLength != want.length) return true;
            for (int i = 0; i < want.length; i++) if (node[off + 14 + i] != want[i]) return true;
            final int fileId = be32(node, off + 4);
            final int d = off + 2 + keyLength;
            final int type = be32(node, d);
            byte[] value;
            if (type == 0x10) {
                final int size = be32(node, d + 12);
                if (size < 0 || d + 16 + size > node.length) throw new ArcanaCorruptedException("Invalid HFS+ inline attribute");
                value = java.util.Arrays.copyOfRange(node, d + 16, d + 16 + size);
            } else if (type == 0x20) {
                final Fork f = new Fork(node, d + 8, fileId, 0);
                if (f.logicalSize > MAX_ATTRIBUTE) throw new ArcanaCorruptedException("HFS+ attribute too large");
                if (f.blocks > 8) throw new ArcanaUnsupportedFormatException("HFS+ attribute with extents records: not supported");
                value = new byte[(int) f.logicalSize];
                readFork(f, 0, value, 0, value.length);
            } else {
                return true;
            }
            decmpfs.put(fileId, value);
            return true;
        });
    }

    private byte[] decmpfsHeader(final Rec r, final String path) throws IOException {
        final byte[] a = decmpfs != null ? decmpfs.get(r.id) : null;
        if (a == null) throw new ArcanaCorruptedException("HFS+ compressed file without decmpfs attribute: " + path);
        if (a.length < 16 || le32(a, 0) != DECMPFS_MAGIC) throw new ArcanaCorruptedException("Invalid decmpfs attribute: " + path);
        return a;
    }

    private long decmpfsSize(final Rec r, final String path) throws IOException {
        final long size = le64(decmpfsHeader(r, path), 8);
        if (size < 0) throw new ArcanaCorruptedException("Invalid decmpfs size: " + path);
        return size;
    }

    private void copyCompressed(final Rec r, final String path, final OutputStream out) throws IOException {
        final byte[] a = decmpfsHeader(r, path);
        final int type = le32(a, 4);
        final long size = le64(a, 8);
        switch (type) {
            case 1: // uncompressed, in the attribute
                if (a.length - 16 < size) throw new ArcanaCorruptedException("decmpfs data too short: " + path);
                out.write(a, 16, (int) size);
                return;
            case 3:
            case 7:
            case 11: { // one block in the attribute
                if (size > DECMPFS_CHUNK * 16L) throw new ArcanaCorruptedException("Invalid decmpfs size: " + path);
                final byte[] o = new byte[(int) size];
                final int n = decodeBlock(type, a, 16, a.length - 16, o, path);
                if (n != size) throw new ArcanaCorruptedException("decmpfs data decoded to " + n + " bytes instead of " + size + ": " + path);
                out.write(o, 0, n);
                return;
            }
            case 4:
            case 8:
            case 12:
                copyCompressedFork(type, r, size, path, out);
                return;
            default:
                throw new ArcanaUnsupportedFormatException("HFS+ compression type " + type + " is not supported: " + path);
        }
    }

    /** decmpfs blocks of 64 KiB stored in the resource fork. */
    private void copyCompressedFork(final int type, final Rec r, final long size, final String path, final OutputStream out) throws IOException {
        final Fork f = r.rsrc;
        final long blocks = (size + DECMPFS_CHUNK - 1) / DECMPFS_CHUNK;
        if (blocks > f.logicalSize) throw new ArcanaCorruptedException("Invalid decmpfs resource fork: " + path);
        final long[] offset = new long[(int) blocks];
        final long[] length = new long[(int) blocks];
        if (type == 4) {
            // resource fork header (big-endian), then at its data offset: data size (BE), block count and table (LE)
            final byte[] h = new byte[16];
            readFork(f, 0, h, 0, 16);
            final long dataOffset = be32(h, 0) & 0xffffffffL;
            final byte[] t = new byte[8];
            if (dataOffset + 8 > f.logicalSize) throw new ArcanaCorruptedException("Invalid decmpfs resource fork: " + path);
            readFork(f, dataOffset, t, 0, 8);
            final long n = le32(t, 4) & 0xffffffffL;
            if (n != blocks) throw new ArcanaCorruptedException("decmpfs block count mismatch: " + path);
            final byte[] table = new byte[(int) (8 * blocks)];
            if (dataOffset + 8 + table.length > f.logicalSize) throw new ArcanaCorruptedException("Invalid decmpfs resource fork: " + path);
            readFork(f, dataOffset + 8, table, 0, table.length);
            for (int i = 0; i < blocks; i++) {
                offset[i] = dataOffset + 4 + (le32(table, 8 * i) & 0xffffffffL);
                length[i] = le32(table, 8 * i + 4) & 0xffffffffL;
            }
        } else {
            // table of blocks + 1 little-endian offsets at the start of the fork
            final byte[] table = new byte[(int) (4 * (blocks + 1))];
            if (table.length > f.logicalSize) throw new ArcanaCorruptedException("Invalid decmpfs resource fork: " + path);
            readFork(f, 0, table, 0, table.length);
            for (int i = 0; i < blocks; i++) {
                offset[i] = le32(table, 4 * i) & 0xffffffffL;
                length[i] = (le32(table, 4 * i + 4) & 0xffffffffL) - offset[i];
            }
        }
        final byte[] o = new byte[DECMPFS_CHUNK];
        for (int i = 0; i < blocks; i++) {
            if (length[i] < 0 || length[i] > 2 * DECMPFS_CHUNK || offset[i] + length[i] > f.logicalSize) throw new ArcanaCorruptedException("Invalid decmpfs block table: " + path);
            final byte[] c = new byte[(int) length[i]];
            readFork(f, offset[i], c, 0, c.length);
            final int want = (int) Math.min(DECMPFS_CHUNK, size - (long) i * DECMPFS_CHUNK);
            final int n = decodeBlock(type, c, 0, c.length, o, path);
            if (n != want) throw new ArcanaCorruptedException("decmpfs block " + i + " decoded to " + n + " bytes instead of " + want + ": " + path);
            out.write(o, 0, n);
        }
    }

    /** Decodes one decmpfs block into o (whose length is the maximum size); returns the size. */
    private static int decodeBlock(final int type, final byte[] c, final int off, final int len, final byte[] o, final String path) throws IOException {
        if (len <= 0) return 0;
        if (type == 3 || type == 4) {
            if ((c[off] & 0x0F) == 0x0F) return stored(c, off + 1, len - 1, o, path);
            final Inflater inf = new Inflater();
            try {
                inf.setInput(c, off, len);
                int n = 0;
                while (n < o.length && !inf.finished()) {
                    final int k = inf.inflate(o, n, o.length - n);
                    if (k == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                    n += k;
                }
                return n;
            } catch (final DataFormatException e) {
                throw new ArcanaCorruptedException("decmpfs zlib data: " + e.getMessage() + ": " + path, e);
            } finally {
                inf.end();
            }
        }
        if (type == 7 || type == 8) {
            if (c[off] == 0x06) return stored(c, off + 1, len - 1, o, path);
            return LzvnDecoder.decode(c, off, off + len, o, 0, 0, o.length);
        }
        if (len >= 3 && c[off] == 'b' && c[off + 1] == 'v' && c[off + 2] == 'x') return LzfseDecoder.decode(c, off, len, o, 0, o.length);
        if ((c[off] & 0xff) == 0xFF) return stored(c, off + 1, len - 1, o, path);
        throw new ArcanaCorruptedException("Invalid decmpfs LZFSE data: " + path);
    }

    private static int stored(final byte[] c, final int off, final int len, final byte[] o, final String path) throws ArcanaCorruptedException {
        if (len > o.length) throw new ArcanaCorruptedException("decmpfs block too large: " + path);
        System.arraycopy(c, off, o, 0, len);
        return len;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private byte[] read(final long pos, final int len) throws IOException {
        if (pos + len > src.length()) throw new ArcanaCorruptedException("HFS+ volume truncated");
        final byte[] b = new byte[len];
        src.readFully(pos, b, 0, len);
        return b;
    }

    private static long unixTime(final long mac) {
        return mac == 0 ? 0 : mac - MAC_EPOCH_OFFSET;
    }

    static int be16(final byte[] b, final int off) {
        return (b[off] & 0xff) << 8 | (b[off + 1] & 0xff);
    }

    static int be32(final byte[] b, final int off) {
        return (b[off] & 0xff) << 24 | (b[off + 1] & 0xff) << 16 | (b[off + 2] & 0xff) << 8 | (b[off + 3] & 0xff);
    }

    static long be64(final byte[] b, final int off) {
        return (long) be32(b, off) << 32 | (be32(b, off + 4) & 0xffffffffL);
    }

    private static int le32(final byte[] b, final int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8 | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    private static long le64(final byte[] b, final int off) {
        return (le32(b, off) & 0xffffffffL) | (long) le32(b, off + 4) << 32;
    }
}
