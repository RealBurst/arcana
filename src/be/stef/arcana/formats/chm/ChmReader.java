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
package be.stef.arcana.formats.chm;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.lzx.LzxDecoder;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Reader for Microsoft Compiled HTML Help files (.chm), written from the
 * community description of the ITSF format.
 *
 * <p>Layout: an "ITSF" header pointing to the directory ("ITSP" header then
 * "PMGL" listing chunks: name, section, offset and length of every entry,
 * integers coded on 7-bit groups) and to the content. Section 0 is stored;
 * section 1 ("MSCompressed") is one LZX stream, cut in 32 KiB frames whose
 * compressed positions are given by the reset table, the LZX state being
 * reset every "reset interval" frames.</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class ChmReader implements AutoCloseable {

    /** A file or directory of the help file. */
    public static final class Entry {
        /** Name without the leading '/', '/' separated. */
        public final String path;
        public final boolean directory;
        final int section;
        final long offset;
        public final long length;

        Entry(final String path, final boolean directory, final int section, final long offset, final long length) {
            this.path = path;
            this.directory = directory;
            this.section = section;
            this.offset = offset;
            this.length = length;
        }
    }

    private static final String CONTENT = "::DataSpace/Storage/MSCompressed/Content";
    private static final String CONTROL = "::DataSpace/Storage/MSCompressed/ControlData";
    private static final String RESET_TABLE = "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";
    private static final long MAX_CONTENT = 1L << 31;

    private final RandomAccessFile raf;
    private final long fileLength;
    private final long contentOffset;
    private final List<Entry> entries = new ArrayList<Entry>();
    private Entry content;
    private Entry control;
    private Entry resetTable;
    private byte[] section1;

    public ChmReader(final File file) throws IOException {
        raf = new RandomAccessFile(file, "r");
        boolean ok = false;
        try {
            fileLength = raf.length();
            final byte[] h = read(0, 0x58);
            if (h[0] != 'I' || h[1] != 'T' || h[2] != 'S' || h[3] != 'F') throw new ArcanaCorruptedException("Not a CHM file");
            final int version = le32(h, 4);
            final long dirOffset = le64(h, 72);
            final long dirLength = le64(h, 80);
            if (version >= 3 && le32(h, 8) >= 0x60) contentOffset = le64(read(88, 8), 0);
            else contentOffset = dirOffset + dirLength;
            readDirectory(dirOffset, dirLength);
            ok = true;
        } finally {
            if (!ok) raf.close();
        }
    }

    /** User-visible entries (the internal "::DataSpace" storage is left out). */
    public List<Entry> getEntries() {
        return entries;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }

    // =========================================================================
    // Directory
    // =========================================================================

    private void readDirectory(final long dirOffset, final long dirLength) throws IOException {
        final byte[] itsp = read(dirOffset, 0x54);
        if (itsp[0] != 'I' || itsp[1] != 'T' || itsp[2] != 'S' || itsp[3] != 'P') throw new ArcanaCorruptedException("CHM directory header not found");
        final int headerLen = le32(itsp, 8);
        final int chunkSize = le32(itsp, 16);
        final int total = le32(itsp, 44);
        if (chunkSize < 32 || chunkSize > (1 << 20) || total < 0 || (long) total * chunkSize > dirLength) throw new ArcanaCorruptedException("Invalid CHM directory");
        // every listing chunk ("PMGL"), in file order: the "first chunk" field and the
        // chunk links are not always right (index chunks are "PMGI")
        for (int chunk = 0; chunk < total; chunk++) {
            final byte[] c = read(dirOffset + headerLen + (long) chunk * chunkSize, chunkSize);
            if (c[0] != 'P' || c[1] != 'M' || c[2] != 'G' || c[3] != 'L') continue;
            final int free = le32(c, 4);
            final int end = chunkSize - free;
            if (free < 0 || end < 20) throw new ArcanaCorruptedException("Invalid CHM listing chunk");
            final int[] p = {20};
            while (p[0] < end) {
                final int nameLen = (int) encint(c, p);
                if (nameLen <= 0 || p[0] + nameLen > end) throw new ArcanaCorruptedException("Invalid CHM entry name");
                final String name = new String(c, p[0], nameLen, StandardCharsets.UTF_8);
                p[0] += nameLen;
                final int section = (int) encint(c, p);
                final long offset = encint(c, p);
                final long length = encint(c, p);
                if (name.equals(CONTENT)) content = new Entry(name, false, section, offset, length);
                else if (name.equals(CONTROL)) control = new Entry(name, false, section, offset, length);
                else if (name.equals(RESET_TABLE)) resetTable = new Entry(name, false, section, offset, length);
                if (name.startsWith("::") || name.equals("/")) continue;
                final boolean dir = name.endsWith("/");
                String path = name.startsWith("/") ? name.substring(1) : name;
                if (dir) path = path.substring(0, path.length() - 1);
                if (path.isEmpty()) continue;
                entries.add(new Entry(path, dir, section, offset, length));
            }
        }
    }

    /** CHM integers: big-endian 7-bit groups, high bit = more bytes. */
    private static long encint(final byte[] b, final int[] p) throws IOException {
        long v = 0;
        for (int i = 0; i < 9; i++) {
            if (p[0] >= b.length) throw new ArcanaCorruptedException("CHM directory truncated");
            final int x = b[p[0]++] & 0xff;
            v = v << 7 | (x & 0x7f);
            if (x < 0x80) return v;
        }
        throw new ArcanaCorruptedException("Invalid CHM integer");
    }

    // =========================================================================
    // Data
    // =========================================================================

    /** Writes the data of an entry. */
    public void copy(final Entry e, final OutputStream out) throws IOException {
        if (e.directory || e.length == 0) return;
        if (e.section == 0) {
            copyRaw(contentOffset + e.offset, e.length, out);
            return;
        }
        if (e.section != 1) throw new ArcanaUnsupportedFormatException("CHM section " + e.section + " is not supported");
        if (section1 == null) section1 = decompressSection1();
        if (e.offset < 0 || e.offset + e.length > section1.length) throw new ArcanaCorruptedException("CHM entry outside its section: " + e.path);
        out.write(section1, (int) e.offset, (int) e.length);
    }

    /** Decompresses the whole MSCompressed section, frame by frame. */
    private byte[] decompressSection1() throws IOException {
        if (content == null || control == null || resetTable == null) throw new ArcanaCorruptedException("CHM compressed section incomplete");
        final byte[] cd = read(contentOffset + control.offset, (int) Math.min(control.length, 64));
        if (cd.length < 24 || cd[4] != 'L' || cd[5] != 'Z' || cd[6] != 'X' || cd[7] != 'C') throw new ArcanaCorruptedException("Invalid CHM LZX control data");
        final int cdVersion = le32(cd, 8);
        long resetInterval = le32(cd, 12) & 0xffffffffL;
        long windowSize = le32(cd, 16) & 0xffffffffL;
        if (cdVersion == 2) {
            resetInterval *= LzxDecoder.FRAME_SIZE;
            windowSize *= LzxDecoder.FRAME_SIZE;
        }
        int windowBits = 15;
        while ((1L << windowBits) < windowSize && windowBits < 21) windowBits++;
        if ((1L << windowBits) != windowSize) throw new ArcanaCorruptedException("Invalid CHM LZX window size " + windowSize);
        if (resetInterval == 0 || resetInterval % LzxDecoder.FRAME_SIZE != 0) throw new ArcanaCorruptedException("Invalid CHM LZX reset interval");
        final long framesPerReset = resetInterval / LzxDecoder.FRAME_SIZE;

        final byte[] rt = read(contentOffset + resetTable.offset, (int) Math.min(resetTable.length, 1 << 26));
        final int count = le32(rt, 4);
        final int entrySize = le32(rt, 8);
        final int headerSize = le32(rt, 12);
        final long uncompressed = le64(rt, 16);
        final long compressed = le64(rt, 24);
        final long blockLen = le64(rt, 32);
        if (entrySize != 8 || blockLen != LzxDecoder.FRAME_SIZE || count < 0 || headerSize + (long) count * 8 > rt.length) throw new ArcanaCorruptedException("Unsupported CHM reset table");
        if (uncompressed < 0 || uncompressed > MAX_CONTENT || compressed > content.length) throw new ArcanaCorruptedException("Invalid CHM section size");
        final long frames = (uncompressed + LzxDecoder.FRAME_SIZE - 1) / LzxDecoder.FRAME_SIZE;
        if (count < frames) throw new ArcanaCorruptedException("CHM reset table incomplete");

        final byte[] packed = read(contentOffset + content.offset, (int) compressed);
        final byte[] out = new byte[(int) uncompressed];
        final byte[] frame = new byte[LzxDecoder.FRAME_SIZE];
        final LzxDecoder lzx = new LzxDecoder(windowBits);
        for (int i = 0; i < frames; i++) {
            final long from = le64(rt, headerSize + 8 * i);
            final long to = i + 1 < count ? le64(rt, headerSize + 8 * (i + 1)) : compressed;
            if (from < 0 || to < from || to > compressed) throw new ArcanaCorruptedException("Invalid CHM reset table entry " + i);
            if (i % framesPerReset == 0) {
                if (i == 0) lzx.reset();
                else lzx.resetState();
            }
            final int n = (int) Math.min(LzxDecoder.FRAME_SIZE, uncompressed - (long) i * LzxDecoder.FRAME_SIZE);
            lzx.decompress(packed, (int) from, (int) (to - from), frame, n);
            System.arraycopy(frame, 0, out, i * LzxDecoder.FRAME_SIZE, n);
        }
        return out;
    }

    // =========================================================================
    // Low level
    // =========================================================================

    private void copyRaw(final long pos, final long len, final OutputStream out) throws IOException {
        if (pos < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("CHM data outside the file");
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
        if (pos < 0 || len < 0 || pos + len > fileLength) throw new ArcanaCorruptedException("CHM data outside the file");
        final byte[] b = new byte[len];
        raf.seek(pos);
        raf.readFully(b);
        return b;
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    private static long le64(final byte[] b, final int p) {
        return (le32(b, p) & 0xffffffffL) | (long) le32(b, p + 4) << 32;
    }
}
