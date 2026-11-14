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
package be.stef.arcana.formats.adf;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;

/**
 * Amiga floppy image without AmigaDOS file system: most games, whose boot
 * block loads their code with its own reads (a "track loader"). There are no
 * file names, so the disk is cut into pieces named after their offset in the
 * image:
 *
 * <ul>
 *   <li>{@code bootblock.bin}: the 1024 bytes of the boot block.</li>
 *   <li>The areas read by the boot block code. When the boot block checksum is
 *       valid (the Kickstart would run it), its code is searched for
 *       trackdisk.device reads: {@code MOVE.L #value,d16(A1)} with d16 =
 *       0x28 (io_Data), 0x24 (io_Length), 0x2C (io_Offset), then
 *       {@code JSR -456(A6)} (DoIO) or {@code JSR -462(A6)} (SendIO). The
 *       code is only read, never run.</li>
 *   <li>The other used areas: runs of non-empty blocks, a gap of less than
 *       one cylinder (22 blocks) does not split them.</li>
 *   <li>For each piece holding a packed program known by
 *       {@link AmigaDecruncher}, its unpacked content too
 *       ({@code OFFSET.unpacked.bin}).</li>
 *   <li>The files of the game directory ({@code file-NNN.bin}), when the
 *       programs read by the boot block (unpacked or not) hold one: a table
 *       of (length, offset) or (offset, length) longs whose files follow each
 *       other on the disk (see {@link Directory}). NNN is the entry number,
 *       the one the game uses to load the file.</li>
 * </ul>
 *
 * The game data is otherwise given as raw areas: where each piece starts is
 * written in the game code, in a form of its own (track and sector numbers,
 * blocks, 16-bit values...) that is not always found.
 *
 * @author Stef
 * @since 1.2.0
 */
public final class AdfRawDisk {

    /** One piece of the disk. */
    public static final class Entry {
        public final String name;
        /** Offset in the image, or -1 for unpacked data. */
        public final long offset;
        public final long size;
        public final String description;
        final byte[] data;
        /** Memory address where the piece is loaded, -1 if unknown. */
        final long address;

        Entry(final String name, final long offset, final long size, final String description, final byte[] data, final long address) {
            this.name = name;
            this.offset = offset;
            this.size = size;
            this.description = description;
            this.data = data;
            this.address = address;
        }
    }

    private static final int BOOT_SIZE = 1024;
    private static final int BLOCKS_PER_CYLINDER = 22;
    private static final int IO_LENGTH = 0x24;
    private static final int IO_DATA = 0x28;
    private static final int IO_OFFSET = 0x2C;

    private final byte[] disk;
    private final List<Entry> entries = new ArrayList<Entry>();
    private final List<String> skipped = new ArrayList<String>();

    /**
     * True when {@code disk} has the size of a floppy image but no AmigaDOS
     * file system: no "DOS" boot block, or no root block in the middle of the disk.
     */
    public static boolean isRaw(final byte[] disk) {
        if (disk.length != AdfVolume.DD_BLOCKS * AdfVolume.BLOCK && disk.length != AdfVolume.HD_BLOCKS * AdfVolume.BLOCK) return false;
        if (disk[0] != 'D' || disk[1] != 'O' || disk[2] != 'S') return true;
        return !AdfVolume.hasRootBlock(disk);
    }

    public AdfRawDisk(final byte[] disk) throws IOException {
        if (disk.length != AdfVolume.DD_BLOCKS * AdfVolume.BLOCK && disk.length != AdfVolume.HD_BLOCKS * AdfVolume.BLOCK) throw new ArcanaCorruptedException("Not an Amiga floppy image: " + disk.length + " bytes (expected 901120 or 1802240)");
        this.disk = disk;
        final int blocks = disk.length / AdfVolume.BLOCK;
        final boolean[] covered = new boolean[blocks];
        final Entry boot = new Entry("bootblock.bin", 0, BOOT_SIZE, bootChecksumOk() ? "boot block" : "boot block (bad checksum: not bootable)", null, -1);
        covered[0] = true;
        covered[1] = true;
        // areas read by the boot block, and the programs packed in them
        final List<Entry> pieces = new ArrayList<Entry>();
        final Map<Entry, Entry> unpacked = new HashMap<Entry, Entry>();
        if (bootChecksumOk()) {
            for (final long[] r : bootReads()) {
                final long off = r[0];
                final long len = Math.min(r[1], disk.length - off);
                if (len <= 0) continue;
                boolean known = false;
                for (final Entry e : pieces) known |= e.offset == off && e.size == len;
                if (known) continue;
                final Entry e = new Entry(hex(off) + ".bin", off, len, "read by the boot block to $" + hexAddress(r[2]), null, r[2]);
                pieces.add(e);
                cover(covered, off, len);
                unpack(e, unpacked);
            }
        }
        // directory of the game: in the programs read by the boot block, unpacked or not
        Directory best = null;
        for (final Entry e : pieces) {
            final Entry u = unpacked.get(e);
            final Directory d = Directory.find(data(e), e.address, e.name, disk.length);
            final Directory du = u == null ? null : Directory.find(u.data, u.address, u.name, disk.length);
            if (d != null && (best == null || d.files.size() > best.files.size())) best = d;
            if (du != null && (best == null || du.files.size() > best.files.size())) best = du;
        }
        if (best != null) {
            for (final long[] f : best.files) {
                final String name = String.format(Locale.ROOT, "file-%03d.bin", f[0]);
                pieces.add(new Entry(name, f[1], f[2], "file " + f[0] + " of the game directory ($" + hexAddress(best.address) + " in " + best.source + ")", null, -1));
                cover(covered, f[1], f[2]);
            }
        }
        // other used areas
        int b = 0;
        while (b < blocks) {
            if (covered[b] || empty(b)) {
                b++;
                continue;
            }
            final int first = b;
            int last = b;
            int gap = 0;
            for (b++; b < blocks && !covered[b]; b++) {
                if (empty(b)) {
                    if (++gap >= BLOCKS_PER_CYLINDER) break;
                } else {
                    last = b;
                    gap = 0;
                }
            }
            final long off = (long) first * AdfVolume.BLOCK;
            pieces.add(new Entry(hex(off) + ".bin", off, (long) (last - first + 1) * AdfVolume.BLOCK, "used blocks " + first + "-" + last + " (cylinders " + first / BLOCKS_PER_CYLINDER + "-" + last / BLOCKS_PER_CYLINDER + "), " + (best == null ? "not read by the boot block" : "not in the game directory"), null, -1));
            b = last + 1;
        }
        java.util.Collections.sort(pieces, new java.util.Comparator<Entry>() {
            @Override
            public int compare(final Entry x, final Entry y) {
                return Long.compare(x.offset, y.offset);
            }
        });
        entries.add(boot);
        for (final Entry e : pieces) {
            entries.add(e);
            if (!unpacked.containsKey(e)) unpack(e, unpacked);
            final Entry u = unpacked.get(e);
            if (u != null) entries.add(u);
        }
    }

    /** Marks the blocks of {@code [off, off + len)} as used by a piece. */
    private static void cover(final boolean[] covered, final long off, final long len) {
        for (long b = off / AdfVolume.BLOCK; b <= (off + len - 1) / AdfVolume.BLOCK && b < covered.length; b++) covered[(int) b] = true;
    }

    /** Unpacks the program packed in {@code e}, if any (null in the map otherwise). */
    private void unpack(final Entry e, final Map<Entry, Entry> unpacked) {
        Entry u = null;
        try {
            final AmigaDecruncher.Result r = AmigaDecruncher.find(disk, (int) e.offset, (int) e.size);
            if (r != null) u = new Entry(e.name.replace(".bin", ".unpacked.bin"), -1, r.data.length, "unpacked (" + r.method + "), loaded at $" + hexAddress(r.loadAddress) + ", entry $" + hexAddress(r.entry), r.data, r.loadAddress);
        } catch (final IOException ex) {
            skipped.add(e.name.replace(".bin", ".unpacked.bin") + ": " + ex.getMessage());
        }
        unpacked.put(e, u);
    }

    /**
     * Directory of a game: a table of entries of two longs, (length, offset)
     * or (offset, length) in the disk image, whose data follow each other on
     * the disk (the next offset is the end of the previous file, rounded up to
     * 4 bytes at most). Empty entries (two zeros) are allowed between files,
     * at most 64 in a row; the files are numbered by their entry index, from
     * the first file of the table. At least 4 files.
     */
    static final class Directory {
        private static final int MIN_FILES = 4;
        private static final int MAX_EMPTY = 64;

        /** {number, offset, length} of each file. */
        final List<long[]> files;
        /** Memory address of the table, or its position in the source if the address is unknown. */
        final long address;
        final String source;

        private Directory(final List<long[]> files, final long address, final String source) {
            this.files = files;
            this.address = address;
            this.source = source;
        }

        static Directory find(final byte[] b, final long base, final String source, final long diskLength) {
            List<long[]> best = null;
            int bestAt = 0;
            for (int p = 0; p + 8 * MIN_FILES <= b.length; p += 2) {
                for (int order = 0; order < 2; order++) {
                    final List<long[]> files = walk(b, p, order == 0, diskLength);
                    if (files.size() >= MIN_FILES && (best == null || files.size() > best.size())) {
                        best = files;
                        bestAt = p;
                    }
                }
            }
            if (best == null) return null;
            return new Directory(best, (base < 0 ? 0 : base) + bestAt, source);
        }

        private static List<long[]> walk(final byte[] b, final int p, final boolean lengthFirst, final long diskLength) {
            final List<long[]> files = new ArrayList<long[]>();
            long expected = -1;
            int empty = 0;
            for (int q = p, index = 0; q + 8 <= b.length; q += 8, index++) {
                final long x = u32(b, q);
                final long y = u32(b, q + 4);
                if (x == 0 && y == 0 && !files.isEmpty()) {
                    if (++empty > MAX_EMPTY) break;
                    continue;
                }
                final long length = lengthFirst ? x : y;
                final long offset = lengthFirst ? y : x;
                if (length <= 0 || offset < BOOT_SIZE || offset + length > diskLength) break;
                if (expected >= 0 && (offset < expected || offset > expected + 3)) break;
                files.add(new long[] {index, offset, length});
                expected = offset + length;
                empty = 0;
            }
            return files;
        }
    }

    public List<Entry> entries() {
        return entries;
    }

    /** Pieces that could not be produced (packed data not valid), with the reason. */
    public List<String> skipped() {
        return skipped;
    }

    /** Content of an entry. */
    public byte[] data(final Entry e) {
        if (e.data != null) return e.data;
        final byte[] r = new byte[(int) e.size];
        System.arraycopy(disk, (int) e.offset, r, 0, r.length);
        return r;
    }

    /** Reads of the boot block code: {offset, length, address}, in code order. */
    List<long[]> bootReads() {
        final List<long[]> reads = new ArrayList<long[]>();
        long data = -1;
        long length = -1;
        long offset = -1;
        for (int p = 12; p + 2 <= BOOT_SIZE; p += 2) {
            final int op = u16(p);
            if (op == 0x237C && p + 8 <= BOOT_SIZE) {
                final long v = u32(p + 2);
                final int field = u16(p + 6);
                if (field == IO_DATA) data = v;
                else if (field == IO_LENGTH) length = v;
                else if (field == IO_OFFSET) offset = v;
            } else if (op == 0x4EAE && p + 4 <= BOOT_SIZE && (u16(p + 2) == 0xFE38 || u16(p + 2) == 0xFE32)) {
                if (data >= 0 && length > 0 && offset >= 0 && offset < disk.length) reads.add(new long[] {offset, length, data});
                data = -1;
                length = -1;
                offset = -1;
            }
        }
        return reads;
    }

    /** Boot block checksum: sum of the 256 longs with carry wrap-around, all ones when valid. */
    private boolean bootChecksumOk() {
        long sum = 0;
        for (int p = 0; p < BOOT_SIZE; p += 4) {
            sum += u32(p);
            if (sum > 0xFFFFFFFFL) sum = (sum & 0xFFFFFFFFL) + 1;
        }
        return sum == 0xFFFFFFFFL;
    }

    private boolean empty(final int block) {
        final int p = block * AdfVolume.BLOCK;
        for (int i = 0; i < AdfVolume.BLOCK; i++) {
            if (disk[p + i] != 0) return false;
        }
        return true;
    }

    private static String hex(final long v) {
        return String.format(Locale.ROOT, "%06X", v);
    }

    private static String hexAddress(final long v) {
        return Long.toHexString(v).toUpperCase(Locale.ROOT);
    }

    private static long u32(final byte[] b, final int p) {
        return ((b[p] & 0xFFL) << 24) | ((b[p + 1] & 0xFFL) << 16) | ((b[p + 2] & 0xFFL) << 8) | (b[p + 3] & 0xFFL);
    }

    private int u16(final int p) {
        return ((disk[p] & 0xFF) << 8) | (disk[p + 1] & 0xFF);
    }

    private long u32(final int p) {
        return ((disk[p] & 0xFFL) << 24) | ((disk[p + 1] & 0xFFL) << 16) | ((disk[p + 2] & 0xFFL) << 8) | (disk[p + 3] & 0xFFL);
    }
}
