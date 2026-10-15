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

import be.stef.arcana.formats.hfs.HfsPlusReader;
import java.io.IOException;
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
 * map, GPT, MBR, free space) or hold only zeros.
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

    /** Treatment of one partition. */
    public static final class Item {
        public final UdifImage.Partition partition;
        /** SCHEME, EMPTY, HFS or RAW. */
        public final int kind;
        /** File system found in the partition ("HFS+", "HFSX", "APFS", "FAT"...), or null. */
        public final String fileSystem;
        /** HFS: folder of its files in the output ("" = root). RAW: name of the image file. */
        public String target;

        Item(final UdifImage.Partition partition, final int kind, final String fileSystem) {
            this.partition = partition;
            this.kind = kind;
            this.fileSystem = fileSystem;
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
                final String fs = fileSystem(img.openPartition(p));
                final boolean isHfs = fs != null && fs.startsWith("HFS+") || "HFSX".equals(fs);
                items.add(new Item(p, isHfs ? HFS : RAW, fs));
                if (isHfs) hfs++;
            }
        }
        final Set<String> used = new HashSet<String>();
        for (final Item it : items) {
            if (it.kind == HFS) {
                String name = "";
                if (hfs > 1) {
                    name = new HfsPlusReader(img.openPartition(it.partition)).getVolumeName().replace('/', ':');
                    if (name.isEmpty()) name = "volume " + it.partition.id;
                }
                it.target = unique(name, used);
            } else if (it.kind == RAW) {
                String base = it.partition.shortName().replace('/', ':');
                if (base.isEmpty()) base = "partition " + it.partition.id;
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

    /** File system of a partition, from its first 4 KiB, or null if unknown. */
    public static String fileSystem(final UdifImage.PartitionReader r) throws IOException {
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
