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
package be.stef.arcana.formats.dmg;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.formats.hfs.HfsPlusReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * What Arcana extracts from each partition of a disk image: the files of the
 * HFS+ volumes (at the root of the output when there is only one, else in a
 * folder named after each volume), a raw image file
 * ("&lt;partition name&gt;.apfs.img", ".img") for the other file systems, and
 * nothing for the entries that only describe the partition scheme (partition
 * map, GPT, MBR, free space) or hold only zeros. A partition without known
 * file system that starts with its own partition map (a "whole disk" entry:
 * driver descriptor and Apple partition map, or GPT) is replaced by the
 * partitions of that map.
 *
 * @author Stef
 * @since 1.5
 */
public final class DmgContent {

    /** Partition scheme entry (map, GPT, MBR, free space): not extracted. */
    public static final int SCHEME = 0;
    /** Partition holding only zeros: not extracted. */
    public static final int EMPTY = 1;
    /** HFS+ / HFSX volume: its files are extracted. */
    public static final int HFS = 2;
    /** Other partition: extracted as a raw image file. */
    public static final int RAW = 3;

    /** Treatment of one partition, or of one partition of a partition map found inside a partition. */
    public static final class Item {
        public final UdifImage.Partition partition;
        /** Position in the partition map found inside the partition ("whole disk" entries), or -1. */
        public final int subIndex;
        /** Name, e.g. "disk image (Apple_HFS : 0)" or "whole disk (Apple_HFS : 0) / disk image (Apple_HFS : 1)". */
        public final String name;
        /** Start of the item in the decoded partition, and its size, in bytes. */
        public final long offset;
        public final long length;
        /** SCHEME, EMPTY, HFS or RAW. */
        public final int kind;
        /** File system found in the partition ("HFS+", "HFSX", "APFS", "FAT"...), or null. */
        public final String fileSystem;
        /** HFS: folder of its files in the output ("" = root). RAW: name of the image file. */
        public String target;

        Item(final UdifImage.Partition partition, final int kind, final String fileSystem) {
            this(partition, -1, partition.name, 0, partition.size(), kind, fileSystem);
        }

        Item(final UdifImage.Partition partition, final int subIndex, final String name, final long offset, final long length, final int kind, final String fileSystem) {
            this.partition = partition;
            this.subIndex = subIndex;
            this.name = name;
            this.offset = offset;
            this.length = length;
            this.kind = kind;
            this.fileSystem = fileSystem;
        }

        /** Name without the "(type : n)" suffix, e.g. "disk image"; may be empty. */
        public String shortName() {
            final int p = name.lastIndexOf(" (");
            final String n = p >= 0 && name.endsWith(")") ? name.substring(0, p) : name;
            final int slash = n.lastIndexOf(" / ");
            return (slash >= 0 ? n.substring(slash + 3) : n).trim();
        }
    }

    private DmgContent() {
    }

    /** Treatment of every partition of the image, in table order. */
    public static List<Item> plan(final UdifImage img) throws IOException {
        final List<Item> items = new ArrayList<Item>();
        int hfs = 0;
        for (final UdifImage.Partition p : img.getPartitions()) {
            if (p.isPartitionScheme()) {
                items.add(new Item(p, SCHEME, null));
            } else if (p.isEmpty() || p.sectorCount == 0) {
                items.add(new Item(p, EMPTY, null));
            } else {
                final UdifImage.PartitionReader r = img.openPartition(p);
                final String fs = fileSystem(r);
                final List<UdifImage.MapEntry> map = fs == null ? innerMap(r) : null;
                if (map != null) {
                    // "whole disk" entry: the partition holds its own partition map (driver descriptor and Apple partition map, or GPT)
                    for (final UdifImage.MapEntry e : map) {
                        final String name = p.name + " / " + e.name;
                        if (UdifImage.Partition.isSchemeType(UdifImage.Partition.typeOf(e.name)) || e.sectorCount == 0) {
                            items.add(new Item(p, e.index, name, e.firstSector * UdifImage.SECTOR, e.sectorCount * UdifImage.SECTOR, SCHEME, null));
                            continue;
                        }
                        final Slice s = new Slice(r, e.firstSector * UdifImage.SECTOR, e.sectorCount * UdifImage.SECTOR);
                        final String sfs = fileSystem(s);
                        final boolean isHfs = isHfs(sfs);
                        items.add(new Item(p, e.index, name, s.offset, s.length, isHfs ? HFS : RAW, sfs));
                        if (isHfs) hfs++;
                    }
                } else {
                    final boolean isHfs = isHfs(fs);
                    items.add(new Item(p, isHfs ? HFS : RAW, fs));
                    if (isHfs) hfs++;
                }
            }
        }
        final Set<String> used = new HashSet<String>();
        for (final Item it : items) {
            if (it.kind == HFS) {
                String name = "";
                if (hfs > 1) {
                    name = new HfsPlusReader(view(img.openPartition(it.partition), it)).getVolumeName().replace('/', ':');
                    if (name.isEmpty()) name = "volume " + it.partition.id + (it.subIndex >= 0 ? "." + it.subIndex : "");
                }
                it.target = unique(name, used);
            } else if (it.kind == RAW) {
                String base = it.shortName().replace('/', ':');
                if (base.isEmpty()) base = "partition " + it.partition.id + (it.subIndex >= 0 ? "." + it.subIndex : "");
                it.target = unique(base + ("APFS".equals(it.fileSystem) ? ".apfs.img" : ".img"), used);
            }
        }
        return items;
    }

    private static String unique(final String name, final Set<String> used) {
        if (name.isEmpty() || used.add(name.toLowerCase())) return name;
        final int dot = name.indexOf('.');
        for (int i = 2;; i++) {
            final String n = dot > 0 ? name.substring(0, dot) + " " + i + name.substring(dot) : name + " " + i;
            if (used.add(n.toLowerCase())) return n;
        }
    }

    private static boolean isHfs(final String fs) {
        return fs != null && fs.startsWith("HFS+") || "HFSX".equals(fs);
    }

    /** Partition map at the start of a partition without known file system, or null (an invalid one is ignored). */
    private static List<UdifImage.MapEntry> innerMap(final UdifImage.PartitionReader r) throws IOException {
        try {
            final List<UdifImage.MapEntry> map = UdifImage.readPartitionMap(r);
            return map == null || map.isEmpty() ? null : map;
        } catch (final ArcanaCorruptedException e) {
            return null;
        }
    }

    /** Content of an item: the whole partition, or the part of it given by the partition map found inside. */
    public static HfsPlusReader.Source view(final UdifImage.PartitionReader r, final Item it) {
        return it.offset == 0 && it.length == r.length() ? r : new Slice(r, it.offset, it.length);
    }

    /** Writes the content of an item to out. */
    public static void copy(final HfsPlusReader.Source src, final OutputStream out) throws IOException {
        final byte[] buf = new byte[1 << 16];
        long pos = 0;
        while (pos < src.length()) {
            final int n = (int) Math.min(buf.length, src.length() - pos);
            src.readFully(pos, buf, 0, n);
            out.write(buf, 0, n);
            pos += n;
        }
    }

    /** A range of a decoded partition. */
    private static final class Slice implements HfsPlusReader.Source {
        private final HfsPlusReader.Source base;
        final long offset;
        final long length;

        Slice(final HfsPlusReader.Source base, final long offset, final long length) {
            this.base = base;
            this.offset = offset;
            this.length = length;
        }

        @Override
        public long length() {
            return length;
        }

        @Override
        public void readFully(final long pos, final byte[] b, final int off, final int len) throws IOException {
            if (pos < 0 || len < 0 || pos > length - len) throw new ArcanaCorruptedException("Read beyond the end of a partition of the partition map");
            base.readFully(offset + pos, b, off, len);
        }
    }

    /** File system of a partition, from its first 4 KiB, or null if unknown. */
    public static String fileSystem(final HfsPlusReader.Source r) throws IOException {
        final int n = (int) Math.min(4096, r.length());
        if (n < 1536) return null;
        final byte[] b = new byte[n];
        r.readFully(0, b, 0, n);
        final int sig = UdifImage.be16(b, 1024);
        if (sig == 0x482B) return "HFS+";
        if (sig == 0x4858) return "HFSX";
        if (sig == 0x4244) return UdifImage.be16(b, 1024 + 0x7C) == 0x482B ? "HFS+ (in an HFS wrapper)" : "HFS";
        if (b[32] == 'N' && b[33] == 'X' && b[34] == 'S' && b[35] == 'B') return "APFS";
        final String oem = new String(b, 3, 8, java.nio.charset.StandardCharsets.ISO_8859_1);
        if (oem.equals("NTFS    ")) return "NTFS";
        if (oem.equals("EXFAT   ")) return "exFAT";
        if ((b[510] & 0xff) == 0x55 && (b[511] & 0xff) == 0xAA && (new String(b, 54, 3, java.nio.charset.StandardCharsets.ISO_8859_1).equals("FAT") || new String(b, 82, 3, java.nio.charset.StandardCharsets.ISO_8859_1).equals("FAT"))) return "FAT";
        return null;
    }
}
