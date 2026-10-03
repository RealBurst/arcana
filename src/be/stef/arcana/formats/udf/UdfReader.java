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
package be.stef.arcana.formats.udf;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

/**
 * Reader for UDF file systems (Universal Disk Format: DVD, Blu-ray, Windows
 * install media, packet-written discs), written from ECMA-167 3rd edition
 * and the OSTA UDF specification (revisions 1.02 to 2.60).
 *
 * <p>Steps: the Anchor Volume Descriptor Pointer (sector 256) gives the
 * Volume Descriptor Sequence; its Partition Descriptors and Logical Volume
 * Descriptor give the partitions, the logical block size, the partition maps
 * and the File Set Descriptor, which gives the root directory. Directories
 * are made of File Identifier Descriptors, each pointing to the File Entry
 * (or Extended File Entry) of a file; its allocation descriptors give the
 * extents of the data, or the data itself when it is embedded.</p>
 *
 * <p>Partition maps: type 1 (physical), sparable (read as physical: the
 * sparing tables only matter for defective sectors of a real disc), virtual
 * (VAT, write-once discs) and metadata (UDF 2.50 and later).</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public final class UdfReader implements AutoCloseable {

    /** One file or directory. */
    public static final class Entry {
        /** Path, '/' separated. */
        public final String path;
        public final boolean directory;
        /** True for a symbolic link (extracted without data). */
        public final boolean symlink;
        public final long size;
        /** Modification time, Unix seconds, or -1. */
        public final long mtime;
        final Node node;

        Entry(final String path, final Node node) {
            this.path = path;
            this.node = node;
            this.directory = node.fileType == FT_DIRECTORY;
            this.symlink = node.fileType == FT_SYMLINK;
            this.size = directory ? 0 : node.length;
            this.mtime = node.mtime;
        }
    }

    /** Callback of {@link #walk}. */
    public interface Visitor {
        void visit(Entry entry) throws IOException;
    }

    // descriptor tags (ECMA-167 3/7.2.1 and 4/7.2.1)
    private static final int TAG_PD = 5;
    private static final int TAG_AVDP = 2;
    private static final int TAG_VDP = 3;
    private static final int TAG_LVD = 6;
    private static final int TAG_TD = 8;
    private static final int TAG_FSD = 256;
    private static final int TAG_FID = 257;
    private static final int TAG_AED = 258;
    private static final int TAG_FE = 261;
    private static final int TAG_EFE = 266;

    // file types (ECMA-167 4/14.6.6, UDF 2.3.5.2)
    private static final int FT_DIRECTORY = 4;
    private static final int FT_FILE = 5;
    private static final int FT_SYMLINK = 12;
    private static final int FT_VAT20 = 248;
    private static final int FT_METADATA = 250;

    private static final int MAX_DEPTH = 256;
    private static final long MAX_DIRECTORY = 64L * 1024 * 1024;

    private final RandomAccessFile raf;
    private final long fileLength;
    private int sectorSize;
    private int blockSize;
    private final List<long[]> partitions = new ArrayList<long[]>(); // {number, start sector, length}
    private final List<PartitionMap> maps = new ArrayList<PartitionMap>();
    private long[] fsd; // {ref, lbn}
    private String revision = "";

    /** A partition map of the logical volume. */
    private final class PartitionMap {
        int kind; // 1 physical, 2 virtual, 3 metadata
        int partitionNumber;
        long start; // first sector of the physical partition
        long length; // in sectors
        int[] vat; // virtual: logical block -> block of the physical partition
        List<Extent> metadata; // metadata: extents of the metadata file in the physical partition

        /** Byte position of a logical block of this partition. */
        long position(final long lbn) throws IOException {
            switch (kind) {
                case 2: {
                    if (lbn < 0 || lbn >= vat.length || vat[(int) lbn] == -1) throw new ArcanaCorruptedException("UDF block outside the virtual allocation table");
                    return physical(vat[(int) lbn] & 0xffffffffL);
                }
                case 3: {
                    long offset = lbn * blockSize;
                    for (final Extent e : metadata) {
                        if (offset < e.length) {
                            final PartitionMap base = maps.get(e.ref);
                            return base.position(e.lbn) + offset;
                        }
                        offset -= (e.length + blockSize - 1) / blockSize * blockSize;
                    }
                    throw new ArcanaCorruptedException("UDF block outside the metadata partition");
                }
                default:
                    return physical(lbn);
            }
        }

        private long physical(final long lbn) throws IOException {
            if (lbn < 0 || length > 0 && lbn * blockSize >= length * sectorSize) throw new ArcanaCorruptedException("UDF block outside its partition");
            return start * sectorSize + lbn * blockSize;
        }

        /** True when consecutive logical blocks are consecutive on disc. */
        boolean contiguous() {
            return kind == 1;
        }
    }

    /** An extent: partition reference, first logical block, length in bytes, type (0 recorded, 1-2 not recorded). */
    static final class Extent {
        int ref;
        long lbn;
        long length;
        int type;
    }

    /** A File Entry. */
    static final class Node {
        int fileType;
        long length;
        long mtime;
        byte[] embedded;
        List<Extent> extents;
        int ref;
        long lbn;
    }

    public UdfReader(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            fileLength = raf.length();
            readVolume();
            ok = true;
        } finally {
            if (!ok) raf.close();
        }
    }

    /** UDF revision of the domain identifier ("1.02", "2.50"...), or "". */
    public String getRevision() {
        return revision;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // =========================================================================
    // Volume structure
    // =========================================================================

    private void readVolume() throws IOException {
        byte[] anchor = null;
        for (final int ss : new int[] {2048, 512, 4096, 1024}) {
            final long[] candidates = {256L, fileLength / ss - 1, fileLength / ss - 257};
            for (final long sector : candidates) {
                if (sector < 0 || (sector + 1) * ss > fileLength) continue;
                final byte[] b = read(sector * ss, 512);
                if (tagId(b, 0) == TAG_AVDP && le32(b, 12) == sector) {
                    sectorSize = ss;
                    anchor = b;
                    break;
                }
            }
            if (anchor != null) break;
        }
        if (anchor == null) throw new ArcanaCorruptedException("UDF anchor volume descriptor not found");
        if (!readVds(le32(anchor, 16) & 0xffffffffL, le32(anchor, 20) & 0xffffffffL) && !readVds(le32(anchor, 24) & 0xffffffffL, le32(anchor, 28) & 0xffffffffL)) throw new ArcanaCorruptedException("UDF volume descriptor sequence not readable");
        for (final PartitionMap m : maps) {
            final long[] pd = partition(m.partitionNumber);
            m.start = pd[1];
            m.length = pd[2];
        }
        for (int i = 0; i < maps.size(); i++) {
            final PartitionMap m = maps.get(i);
            if (m.kind == 2) readVat(m);
        }
        for (final PartitionMap m : maps) {
            if (m.kind == 3) readMetadataFile(m);
        }
    }

    private long[] partition(final int number) throws IOException {
        for (final long[] p : partitions) if (p[0] == number) return p;
        throw new ArcanaCorruptedException("UDF partition " + number + " not described");
    }

    /** Reads a Volume Descriptor Sequence; false if it holds no logical volume. */
    private boolean readVds(final long length, long sector) throws IOException {
        if (length == 0) return false;
        long end = sector + length / sectorSize;
        int guard = 0;
        boolean lvd = false;
        while (sector < end && guard++ < 1024) {
            final byte[] d = read(sector * sectorSize, Math.min(sectorSize, 2048));
            final int tag = tagId(d, 0);
            if (tag == TAG_TD || tag < 0) break;
            if (tag == TAG_VDP) {
                // continue in another extent
                final long len = le32(d, 20) & 0xffffffffL;
                sector = le32(d, 24) & 0xffffffffL;
                end = sector + len / sectorSize;
                continue;
            }
            if (tag == TAG_PD) {
                final int number = le16(d, 22);
                for (int i = partitions.size() - 1; i >= 0; i--) if (partitions.get(i)[0] == number) partitions.remove(i);
                partitions.add(new long[] {number, le32(d, 188) & 0xffffffffL, le32(d, 192) & 0xffffffffL});
            } else if (tag == TAG_LVD) {
                parseLvd(read(sector * sectorSize, Math.max(sectorSize, 2048)));
                lvd = true;
            }
            sector++;
        }
        return lvd && !partitions.isEmpty();
    }

    private void parseLvd(final byte[] d) throws IOException {
        blockSize = le32(d, 212);
        if (blockSize < 512 || blockSize > 65536 || Integer.bitCount(blockSize) != 1) throw new ArcanaCorruptedException("Invalid UDF logical block size " + blockSize);
        // domain identifier "*OSTA UDF Compliant", suffix: UDF revision (BCD)
        final int rev = le16(d, 216 + 24);
        if (rev != 0) revision = Integer.toHexString(rev >> 8) + "." + String.format("%02x", rev & 0xff);
        fsd = new long[] {le16(d, 248 + 8), le32(d, 248 + 4) & 0xffffffffL};
        final int count = le32(d, 268);
        int p = 440;
        maps.clear();
        for (int i = 0; i < count; i++) {
            if (p + 2 > d.length) throw new ArcanaCorruptedException("Invalid UDF partition maps");
            final int type = d[p] & 0xff;
            final int len = d[p + 1] & 0xff;
            if (len < 6 || p + len > d.length) throw new ArcanaCorruptedException("Invalid UDF partition map");
            final PartitionMap m = new PartitionMap();
            if (type == 1) {
                m.kind = 1;
                m.partitionNumber = le16(d, p + 4);
            } else if (type == 2 && len >= 64) {
                final String id = new String(d, p + 5, 23, StandardCharsets.US_ASCII).trim();
                m.partitionNumber = le16(d, p + 38);
                if (id.startsWith("*UDF Virtual Partition")) {
                    m.kind = 2;
                } else if (id.startsWith("*UDF Metadata Partition")) {
                    m.kind = 3;
                    m.metadata = new ArrayList<Extent>();
                    // metadata file and mirror locations, in the physical partition
                    m.vat = new int[] {le32(d, p + 40), le32(d, p + 44)};
                } else if (id.startsWith("*UDF Sparable Partition")) {
                    m.kind = 1;
                } else {
                    throw new ArcanaUnsupportedFormatException("Unsupported UDF partition map: " + id.trim());
                }
            } else {
                throw new ArcanaUnsupportedFormatException("Unsupported UDF partition map type " + type);
            }
            maps.add(m);
            p += len;
        }
        if (maps.isEmpty()) throw new ArcanaCorruptedException("UDF volume without partition map");
    }

    /** Index of the physical (type 1) map of a partition number. */
    private int physicalRef(final int number) throws IOException {
        for (int i = 0; i < maps.size(); i++) if (maps.get(i).kind == 1 && maps.get(i).partitionNumber == number) return i;
        // a lone virtual or metadata map: address the partition directly
        final PartitionMap m = new PartitionMap();
        m.kind = 1;
        m.partitionNumber = number;
        final long[] pd = partition(number);
        m.start = pd[1];
        m.length = pd[2];
        maps.add(m);
        return maps.size() - 1;
    }

    /** Metadata partition (UDF 2.50): the metadata file maps its blocks to the physical partition. */
    private void readMetadataFile(final PartitionMap m) throws IOException {
        final int base = physicalRef(m.partitionNumber);
        IOException error = null;
        for (final int loc : m.vat) {
            try {
                final Node n = readNode(base, loc & 0xffffffffL);
                if (n.fileType != FT_METADATA && n.fileType != FT_METADATA + 1) throw new ArcanaCorruptedException("UDF metadata file not found");
                if (n.extents == null) throw new ArcanaCorruptedException("Embedded UDF metadata file");
                m.metadata = n.extents;
                m.vat = null;
                return;
            } catch (final IOException e) {
                error = e;
            }
        }
        throw error;
    }

    /** Virtual partition: the Virtual Allocation Table is the last file written on the disc. */
    private void readVat(final PartitionMap m) throws IOException {
        final int base = physicalRef(m.partitionNumber);
        final PartitionMap phys = maps.get(base);
        final long last = lastWrittenSector();
        for (long s = last; s >= Math.max(phys.start, last - 64); s--) {
            final byte[] d = read(s * sectorSize, Math.min(sectorSize, (int) Math.min(fileLength - s * sectorSize, 4096)));
            final int tag = tagId(d, 0);
            final int type = d.length > 27 ? d[27] & 0xff : -1;
            if (tag != TAG_FE && tag != TAG_EFE || type != FT_VAT20 && type != 0) continue;
            byte[] data;
            Node n;
            try {
                n = parseNode(d, base, s - phys.start);
                data = readAll(n);
            } catch (final IOException e) {
                continue;
            }
            int first;
            int count;
            if (n.fileType == FT_VAT20) {
                first = le16(data, 0);
                count = (data.length - first) / 4;
            } else if (data.length >= 36 && new String(data, data.length - 35, 22, StandardCharsets.US_ASCII).equals("*UDF Virtual Alloc Tbl")) {
                first = 0;
                count = (data.length - 36) / 4;
            } else {
                continue;
            }
            final int[] vat = new int[count];
            for (int i = 0; i < count; i++) vat[i] = le32(data, first + 4 * i);
            m.vat = vat;
            return;
        }
        throw new ArcanaCorruptedException("UDF virtual allocation table not found");
    }

    /** Last sector that is not all zeros (an image may be padded after the last session). */
    private long lastWrittenSector() throws IOException {
        final long sectors = fileLength / sectorSize;
        final int span = Math.max(1, (1 << 20) / sectorSize);
        final long limit = Math.max(0, sectors - (256L << 20) / sectorSize);
        for (long end = sectors; end > limit; end -= span) {
            final long from = Math.max(limit, end - span);
            final byte[] b = read(from * sectorSize, (int) ((end - from) * sectorSize));
            for (int i = b.length - 1; i >= 0; i--) {
                if (b[i] != 0) return from + i / sectorSize;
            }
        }
        return sectors - 1;
    }

    // =========================================================================
    // Directory tree
    // =========================================================================

    /** Visits every file and directory, parents before their children. */
    public void walk(final Visitor visitor) throws IOException {
        if (fsd == null) throw new ArcanaCorruptedException("UDF file set descriptor missing");
        final byte[] f = readBlock((int) fsd[0], fsd[1]);
        if (tagId(f, 0) != TAG_FSD) throw new ArcanaCorruptedException("UDF file set descriptor not found");
        final Node root = readNode(le16(f, 400 + 8), le32(f, 400 + 4) & 0xffffffffL);
        if (root.fileType != FT_DIRECTORY) throw new ArcanaCorruptedException("UDF root is not a directory");
        walkDir(root, "", visitor, new HashSet<String>(), 0);
    }

    private void walkDir(final Node dir, final String prefix, final Visitor visitor, final Set<String> active, final int depth) throws IOException {
        final String key = dir.ref + ":" + dir.lbn;
        if (depth > MAX_DEPTH || !active.add(key)) throw new ArcanaCorruptedException("UDF directory loop");
        if (dir.length > MAX_DIRECTORY) throw new ArcanaCorruptedException("UDF directory too large");
        final byte[] d = readAll(dir);
        int p = 0;
        while (p + 38 <= d.length) {
            if (tagId(d, p) != TAG_FID) {
                // FIDs never cross a block boundary with padding: skip to the next block if the rest is empty
                final int next = (p / blockSize + 1) * blockSize;
                if (allZero(d, p, Math.min(next, d.length))) {
                    p = next;
                    continue;
                }
                throw new ArcanaCorruptedException("Invalid UDF file identifier descriptor");
            }
            final int characteristics = d[p + 18] & 0xff;
            final int nameLen = d[p + 19] & 0xff;
            final long icbLbn = le32(d, p + 24) & 0xffffffffL;
            final int icbRef = le16(d, p + 28);
            final int iuLen = le16(d, p + 36);
            final int size = (38 + iuLen + nameLen + 3) & ~3;
            if (p + 38 + iuLen + nameLen > d.length) throw new ArcanaCorruptedException("UDF file identifier truncated");
            if ((characteristics & 0x0C) == 0 && nameLen > 0) {
                // neither deleted (4) nor parent (8)
                String name = dstring(d, p + 38 + iuLen, nameLen);
                if (depth == 0 && (characteristics & 1) != 0 && name.equals("Non-Allocatable Space")) {
                    // UDF 1.50 system file listing unusable blocks
                    p += size;
                    continue;
                }
                name = name.replace('/', '_').replace('\u0000', '_');
                if (name.isEmpty() || name.equals(".") || name.equals("..")) throw new ArcanaCorruptedException("Invalid UDF file name");
                final Node n = readNode(icbRef, icbLbn);
                final String path = prefix.isEmpty() ? name : prefix + "/" + name;
                if (n.fileType == FT_DIRECTORY || n.fileType == FT_FILE || n.fileType == FT_SYMLINK || n.fileType == 0) {
                    if (n.fileType == 0) n.fileType = FT_FILE;
                    visitor.visit(new Entry(path, n));
                    if (n.fileType == FT_DIRECTORY) walkDir(n, path, visitor, active, depth + 1);
                }
            }
            p += size;
        }
        active.remove(key);
    }

    // =========================================================================
    // File entries and data
    // =========================================================================

    private Node readNode(final int ref, final long lbn) throws IOException {
        final byte[] d = readBlock(ref, lbn);
        final int tag = tagId(d, 0);
        if (tag != TAG_FE && tag != TAG_EFE) throw new ArcanaCorruptedException("UDF file entry not found at block " + lbn);
        return parseNode(d, ref, lbn);
    }

    private Node parseNode(final byte[] d, final int ref, final long lbn) throws IOException {
        final boolean extended = tagId(d, 0) == TAG_EFE;
        final Node n = new Node();
        n.ref = ref;
        n.lbn = lbn;
        n.fileType = d[16 + 11] & 0xff;
        final int flags = le16(d, 16 + 18);
        n.length = le64(d, 56);
        n.mtime = timestamp(d, extended ? 92 : 84);
        final int eaLen = le32(d, extended ? 208 : 168);
        final int adLen = le32(d, extended ? 212 : 172);
        final int adStart = (extended ? 216 : 176) + eaLen;
        if (eaLen < 0 || adLen < 0 || adStart + (long) adLen > d.length) throw new ArcanaCorruptedException("Invalid UDF file entry");
        if (n.length < 0) throw new ArcanaCorruptedException("Invalid UDF file size");
        final int adType = flags & 7;
        if (adType == 3) {
            n.embedded = Arrays.copyOfRange(d, adStart, adStart + adLen);
            return n;
        }
        n.extents = new ArrayList<Extent>();
        readAllocation(d, adStart, adLen, adType, ref, n.extents, 0);
        return n;
    }

    private void readAllocation(final byte[] d, final int start, final int len, final int adType, final int ref, final List<Extent> out, final int depth) throws IOException {
        if (depth > 64 || out.size() > 1000000) throw new ArcanaCorruptedException("Too many UDF allocation descriptors");
        final int size = adType == 0 ? 8 : adType == 1 ? 16 : adType == 2 ? 20 : -1;
        if (size < 0) throw new ArcanaCorruptedException("Invalid UDF allocation descriptor type");
        for (int p = start; p + size <= start + len; p += size) {
            final long raw = le32(d, p) & 0xffffffffL;
            final long length = raw & 0x3FFFFFFFL;
            final int type = (int) (raw >>> 30);
            if (length == 0) break;
            final Extent e = new Extent();
            e.length = length;
            e.type = type;
            if (adType == 0) {
                e.lbn = le32(d, p + 4) & 0xffffffffL;
                e.ref = ref;
            } else if (adType == 1) {
                e.lbn = le32(d, p + 4) & 0xffffffffL;
                e.ref = le16(d, p + 8);
            } else {
                e.lbn = le32(d, p + 12) & 0xffffffffL;
                e.ref = le16(d, p + 16);
            }
            if (e.ref < 0 || e.ref >= maps.size()) throw new ArcanaCorruptedException("Invalid UDF partition reference");
            if (type == 3) {
                // next extent of allocation descriptors (Allocation Extent Descriptor)
                final byte[] aed = readBytes(e.ref, e.lbn, (int) Math.min(length, 1 << 20));
                if (tagId(aed, 0) != TAG_AED) throw new ArcanaCorruptedException("UDF allocation extent descriptor not found");
                final int l = le32(aed, 20);
                if (l < 0 || 24 + l > aed.length) throw new ArcanaCorruptedException("Invalid UDF allocation extent descriptor");
                readAllocation(aed, 24, l, adType, e.ref, out, depth + 1);
                return;
            }
            out.add(e);
        }
    }

    /** Writes the data of a file (nothing for directories and symbolic links). */
    public void copyFile(final Entry e, final OutputStream out) throws IOException {
        if (e.directory || e.symlink) return;
        copy(e.node, out);
    }

    private byte[] readAll(final Node n) throws IOException {
        if (n.length > Integer.MAX_VALUE - 16) throw new ArcanaCorruptedException("UDF entry too large");
        final ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(n.length, 1 << 20));
        copy(n, out);
        return out.toByteArray();
    }

    private void copy(final Node n, final OutputStream out) throws IOException {
        if (n.embedded != null) {
            if (n.length > n.embedded.length) throw new ArcanaCorruptedException("UDF embedded data truncated");
            out.write(n.embedded, 0, (int) n.length);
            return;
        }
        long left = n.length;
        final byte[] buf = new byte[65536];
        for (final Extent e : n.extents) {
            if (left <= 0) break;
            final long take = Math.min(left, e.length);
            if (e.type != 0) {
                // allocated or not, but not recorded: zeros
                Arrays.fill(buf, (byte) 0);
                long z = take;
                while (z > 0) {
                    final int k = (int) Math.min(buf.length, z);
                    out.write(buf, 0, k);
                    z -= k;
                }
            } else {
                final PartitionMap m = maps.get(e.ref);
                if (m.contiguous()) {
                    copyRaw(m.position(e.lbn), take, out, buf);
                } else {
                    long done = 0;
                    long lbn = e.lbn;
                    while (done < take) {
                        final int k = (int) Math.min(blockSize, take - done);
                        copyRaw(m.position(lbn++), k, out, buf);
                        done += k;
                    }
                }
            }
            left -= take;
        }
        if (left > 0) throw new ArcanaCorruptedException("UDF file shorter than its size");
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private byte[] readBlock(final int ref, final long lbn) throws IOException {
        return readBytes(ref, lbn, blockSize);
    }

    private byte[] readBytes(final int ref, final long lbn, final int len) throws IOException {
        if (ref < 0 || ref >= maps.size()) throw new ArcanaCorruptedException("Invalid UDF partition reference");
        final PartitionMap m = maps.get(ref);
        if (m.contiguous()) return read(m.position(lbn), len);
        final byte[] b = new byte[len];
        for (int done = 0; done < len; done += blockSize) {
            final byte[] blk = read(m.position(lbn + done / blockSize), blockSize);
            System.arraycopy(blk, 0, b, done, Math.min(blockSize, len - done));
        }
        return b;
    }

    private void copyRaw(final long pos, final long len, final OutputStream out, final byte[] buf) throws IOException {
        if (pos < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("UDF data outside the image");
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
        if (pos < 0 || len < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("UDF data outside the image");
        final byte[] b = new byte[len];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }

    /** Tag identifier of a descriptor, or -1 when the tag checksum is wrong. */
    private static int tagId(final byte[] b, final int p) {
        if (p + 16 > b.length) return -1;
        int sum = 0;
        for (int i = 0; i < 16; i++) if (i != 4) sum += b[p + i] & 0xff;
        if ((sum & 0xff) != (b[p + 4] & 0xff)) return -1;
        return le16(b, p);
    }

    private static boolean allZero(final byte[] b, final int from, final int to) {
        for (int i = from; i < to; i++) if (b[i] != 0) return false;
        return true;
    }

    /** OSTA compressed unicode: first byte 8 (one byte per character) or 16 (UTF-16BE). */
    private static String dstring(final byte[] b, final int p, final int len) throws IOException {
        final int id = b[p] & 0xff;
        if (id == 8 || id == 254) return new String(b, p + 1, len - 1, StandardCharsets.ISO_8859_1);
        if (id == 16 || id == 255) return new String(b, p + 1, (len - 1) & ~1, StandardCharsets.UTF_16BE);
        throw new ArcanaCorruptedException("Invalid UDF file name encoding " + id);
    }

    /** ECMA-167 timestamp (12 bytes) to Unix seconds, or -1. */
    private static long timestamp(final byte[] b, final int p) {
        final int typeTz = le16(b, p);
        final int year = (short) le16(b, p + 2);
        final int month = b[p + 4];
        final int day = b[p + 5];
        if (year <= 0 || month < 1 || month > 12 || day < 1 || day > 31) return -1;
        int tz = typeTz & 0xFFF;
        if ((tz & 0x800) != 0) tz -= 0x1000;
        if (tz == -2047 || (typeTz >> 12) != 1) tz = 0;
        final Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        c.clear();
        c.set(year, month - 1, day, b[p + 6], b[p + 7], b[p + 8]);
        return c.getTimeInMillis() / 1000L - tz * 60L;
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
