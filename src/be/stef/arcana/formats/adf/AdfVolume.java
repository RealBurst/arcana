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
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Amiga floppy disk image (.adf) with an AmigaDOS file system: OFS or FFS,
 * read from memory (880 KiB for a double density disk, 1760 KiB for high
 * density).
 *
 * <ul>
 *   <li>Blocks of 512 bytes; the boot block (2 blocks) starts with "DOS" and a
 *       flag byte: bit 0 FFS (else OFS), bit 1 international mode, bit 2
 *       directory cache.</li>
 *   <li>Root block in the middle of the disk (block 880 / 1760). The root and
 *       directory blocks hold a hash table of 72 block numbers (offset 24);
 *       entries of a slot are chained by "hash_chain" (offset 496).</li>
 *   <li>Header blocks (type 2): secondary type at 508 (1 root, 2 directory,
 *       -3 file, 3 soft link, -4 / 4 hard links), name at 432 (length byte,
 *       30 characters at most, ISO-8859-1), comment at 328, date at 420
 *       (days since 1978-01-01, minutes, ticks of 1/50 s), file size at 324.</li>
 *   <li>A file header lists its data blocks from offset 308 downward (72 per
 *       block), "high_seq" at 8 gives how many; more in extension blocks
 *       (type 16) chained at offset 504. OFS data blocks (type 8) have a
 *       24-byte header (data size at 12) and 488 bytes of data; FFS data
 *       blocks are 512 bytes of data.</li>
 *   <li>Every header block has a checksum at 20: the sum of its 128 longs is 0.</li>
 * </ul>
 */
public final class AdfVolume {

    public static final int BLOCK = 512;
    /** Blocks of a double density (880 KiB) and of a high density (1760 KiB) disk. */
    public static final int DD_BLOCKS = 1760;
    public static final int HD_BLOCKS = 3520;

    private static final int T_HEADER = 2;
    private static final int T_DATA = 8;
    private static final int T_LIST = 16;
    private static final int ST_ROOT = 1;
    private static final int ST_DIR = 2;
    private static final int ST_FILE = -3;
    private static final int HT_SIZE = 72;
    /** 1978-01-01 in Unix seconds. */
    private static final long AMIGA_EPOCH = 252460800L;

    /** A file or directory of the volume. */
    public static final class Entry {
        public final String path;
        public final boolean directory;
        public final long size;
        /** Unix seconds, 0 if unknown. */
        public final long time;
        public final String comment;
        final int header;

        Entry(final String path, final boolean directory, final long size, final long time, final String comment, final int header) {
            this.path = path;
            this.directory = directory;
            this.size = size;
            this.time = time;
            this.comment = comment;
            this.header = header;
        }
    }

    private final byte[] disk;
    private final int blocks;
    private final boolean ffs;
    private final String volumeName;
    private final List<Entry> entries = new ArrayList<Entry>();
    private final List<String> skipped = new ArrayList<String>();

    /** True when {@code size} is the size of a floppy image and {@code head} starts with "DOS". */
    public static boolean looksLikeAdf(final long size, final byte[] head) {
        return (size == (long) DD_BLOCKS * BLOCK || size == (long) HD_BLOCKS * BLOCK) && head.length >= 4 && head[0] == 'D' && head[1] == 'O' && head[2] == 'S' && (head[3] & 0xFF) <= 7;
    }

    public AdfVolume(final byte[] disk) throws IOException {
        this.disk = disk;
        if (disk.length != DD_BLOCKS * BLOCK && disk.length != HD_BLOCKS * BLOCK) throw new ArcanaCorruptedException("Not an Amiga floppy image: " + disk.length + " bytes (expected 901120 or 1802240)");
        blocks = disk.length / BLOCK;
        if (disk[0] != 'D' || disk[1] != 'O' || disk[2] != 'S') throw new ArcanaUnsupportedFormatException("Not an AmigaDOS disk (no \"DOS\" boot block): a game with its own track loader, nothing to extract as files");
        final int flags = disk[3] & 0xFF;
        if (flags > 5) throw new ArcanaUnsupportedFormatException("AmigaDOS file system DOS" + flags + " (long file names) is not supported");
        ffs = (flags & 1) != 0;
        final int root = blocks / 2;
        checkHeader(root, ST_ROOT, "root");
        volumeName = name(root, 432);
        final Set<Integer> seen = new HashSet<Integer>();
        seen.add(root);
        walk(root, "", seen, 0);
    }

    public List<Entry> entries() {
        return entries;
    }

    /** Entries that could not be read (links, damaged blocks), with the reason. */
    public List<String> skipped() {
        return skipped;
    }

    public String getVolumeName() {
        return volumeName;
    }

    /** "OFS" or "FFS". */
    public String getFileSystem() {
        return ffs ? "FFS" : "OFS";
    }

    private void walk(final int dir, final String path, final Set<Integer> seen, final int depth) throws IOException {
        if (depth > 64) throw new ArcanaCorruptedException("ADF: directories nested too deeply");
        for (int i = 0; i < HT_SIZE; i++) {
            int b = s32(dir, 24 + 4 * i);
            while (b != 0) {
                if (b < 2 || b >= blocks || !seen.add(b)) throw new ArcanaCorruptedException("ADF: invalid or repeated block " + b + " in " + (path.isEmpty() ? "the root" : path));
                final int type = s32(b, 0);
                final int sec = s32(b, 508);
                final String name = name(b, 432);
                final String full = path + name;
                if (type != T_HEADER || !checksumOk(b)) {
                    skipped.add(full + ": damaged header block " + b);
                } else if (sec == ST_DIR) {
                    entries.add(new Entry(full, true, 0, time(b), comment(b), b));
                    walk(b, full + "/", seen, depth + 1);
                } else if (sec == ST_FILE) {
                    entries.add(new Entry(full, false, s32(b, 324) & 0xFFFFFFFFL, time(b), comment(b), b));
                } else {
                    skipped.add(full + ": link (secondary type " + sec + "), not extracted");
                }
                b = s32(b, 496);
            }
        }
    }

    /** Writes the content of a file entry. */
    public void copy(final Entry e, final OutputStream out) throws IOException {
        if (e.directory) return;
        long left = e.size;
        int hdr = e.header;
        final Set<Integer> seen = new HashSet<Integer>();
        while (left > 0) {
            final int count = s32(hdr, 8); // high_seq: data blocks listed in this block
            if (count < 0 || count > HT_SIZE) throw new ArcanaCorruptedException("ADF: invalid block count in " + e.path);
            for (int i = 0; i < count && left > 0; i++) {
                final int db = s32(hdr, 308 - 4 * i);
                if (db < 2 || db >= blocks || !seen.add(db)) throw new ArcanaCorruptedException("ADF: invalid data block " + db + " in " + e.path);
                final int off;
                int n;
                if (ffs) {
                    off = db * BLOCK;
                    n = BLOCK;
                } else {
                    if (s32(db, 0) != T_DATA) throw new ArcanaCorruptedException("ADF: block " + db + " of " + e.path + " is not a data block");
                    off = db * BLOCK + 24;
                    n = s32(db, 12);
                    if (n < 0 || n > BLOCK - 24) throw new ArcanaCorruptedException("ADF: invalid data size in block " + db + " of " + e.path);
                }
                n = (int) Math.min(n, left);
                out.write(disk, off, n);
                left -= n;
            }
            if (left <= 0) break;
            hdr = s32(hdr, 504); // extension block
            if (hdr < 2 || hdr >= blocks || s32(hdr, 0) != T_LIST || !seen.add(hdr)) throw new ArcanaCorruptedException("ADF: file " + e.path + " is truncated (" + left + " bytes missing)");
        }
    }

    private void checkHeader(final int b, final int sec, final String what) throws IOException {
        if (s32(b, 0) != T_HEADER || s32(b, 508) != sec) throw new ArcanaCorruptedException("ADF: no " + what + " block at " + b);
        if (!checksumOk(b)) throw new ArcanaCorruptedException("ADF: bad checksum of the " + what + " block");
    }

    /** The sum of the 128 longs of a header block is 0 (checksum at offset 20). */
    private boolean checksumOk(final int b) {
        int sum = 0;
        for (int i = 0; i < BLOCK; i += 4) sum += s32(b, i);
        return sum == 0;
    }

    private long time(final int b) {
        final long days = s32(b, 420) & 0xFFFFFFFFL;
        final long mins = s32(b, 424) & 0xFFFFFFFFL;
        final long ticks = s32(b, 428) & 0xFFFFFFFFL;
        if (days == 0 && mins == 0 && ticks == 0) return 0;
        return AMIGA_EPOCH + days * 86400L + mins * 60L + ticks / 50L;
    }

    private String comment(final int b) {
        final String c = name(b, 328);
        return c.isEmpty() ? null : c;
    }

    private String name(final int b, final int at) {
        final int off = b * BLOCK + at;
        final int n = Math.min(disk[off] & 0xFF, at == 328 ? 79 : 30);
        return new String(disk, off + 1, n, StandardCharsets.ISO_8859_1);
    }

    private int s32(final int b, final int at) {
        final int p = b * BLOCK + at;
        return ((disk[p] & 0xFF) << 24) | ((disk[p + 1] & 0xFF) << 16) | ((disk[p + 2] & 0xFF) << 8) | (disk[p + 3] & 0xFF);
    }
}
