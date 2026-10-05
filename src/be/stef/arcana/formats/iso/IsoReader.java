/*
 * Copyright 2025 Stephane Bury
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
package be.stef.arcana.formats.iso;

import java.io.EOFException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;

/**
 * Pure-Java reader for ISO 9660 disc images (.iso), with support for the
 * Joliet (long Unicode names) and Rock Ridge (Unix names/attributes)
 * extensions. No external dependency, no JNI.
 *
 * <p>The reader opens the image via a {@link RandomAccessFile} because an
 * ISO is a random-access file system: directory records point to arbitrary
 * sector positions. It exposes a flat traversal via {@link #walk(IsoVisitor)}.</p>
 *
 * <p>Name resolution precedence (best available wins per entry):</p>
 * <ol>
 *   <li>Rock Ridge NM entry (true Unix name), if present</li>
 *   <li>Joliet name (UTF-16BE), if a Joliet supplementary volume is present</li>
 *   <li>ISO 9660 name (8.3 ASCII)</li>
 * </ol>
 *
 * @author Stef
 * @since 1.1
 */
public final class IsoReader implements AutoCloseable {

    /** Visitor callback invoked for every file entry found during {@link #walk}. */
    public interface IsoVisitor {
        /**
         * @param path      relative path inside the image (forward slashes)
         * @param isDir     true if this entry is a directory
         * @param extentLba starting sector of the file data (files only)
         * @param dataLength length of the file data in bytes (files only)
         * @param epochSeconds recording time (Unix seconds) or -1
         */
        void visit(String path, boolean isDir, long extentLba, long dataLength, long epochSeconds) throws IOException;
    }

    private final RandomAccessFile raf;

    /**
     * Files that are not one plain extent, keyed by their first extent LBA:
     * multi-extent files (ISO 9660 level 3, files over 4 GB) and zisofs-compressed
     * files (Rock Ridge "ZF" entry, transparent compression of mkisofs -z / xorriso).
     */
    private final Map<Long, FileLayout> layouts = new HashMap<Long, FileLayout>();

    private static final class FileLayout {
        final List<long[]> extents = new ArrayList<long[]>(); // {lba, length}
        long zisofsSize = -1;                                 // uncompressed size, -1 = not zisofs
    }

    /** Largest directory extent read in memory (a real directory is a few sectors). */
    private static final long MAX_DIRECTORY_SIZE = 64L * 1024 * 1024;

    /** Deepest directory level walked (ISO 9660 allows 8, Rock Ridge relocation or deep trees more). */
    private static final int MAX_DEPTH = 256;

    private static final byte[] ZISOFS_MAGIC = { (byte) 0x37, (byte) 0xE4, (byte) 0x53, (byte) 0x96, (byte) 0xC9, (byte) 0xDB, (byte) 0xD6, (byte) 0x07 };

    // Primary volume (ISO 9660)
    private long rootExtentLba;
    private long rootDataLength;

    // Joliet supplementary volume (if present)
    private boolean hasJoliet;
    private long jolietRootExtentLba;
    private long jolietRootDataLength;

    /**
     * Opens an ISO image and reads its volume descriptors.
     *
     * @param file ISO image file
     * @throws IOException if the file is not a valid ISO 9660 image
     */
    public IsoReader(java.io.File file) throws IOException {
        this.raf = new RandomAccessFile(file, "r");
        readVolumeDescriptors();
    }

    // =========================================================================
    // Volume descriptor parsing
    // =========================================================================

    private void readVolumeDescriptors() throws IOException {
        int sector = IsoConstants.FIRST_VOLUME_DESCRIPTOR_SECTOR;
        boolean foundPrimary = false;

        while (true) {
            byte[] vd;
            try {
                vd = readSector(sector);
            } catch (EOFException e) {
                throw new ArcanaCorruptedException("ISO: image truncated inside the volume descriptors (sector " + sector + ")", e);
            }
            int type = vd[0] & 0xff;

            // Verify standard identifier "CD001" at offset 1
            if (!matches(vd, 1, IsoConstants.STANDARD_ID)) {
                if (!foundPrimary) {
                    throw new IOException("Not a valid ISO 9660 image (missing CD001 identifier at sector " + sector + ")");
                }
                break;
            }

            if (type == IsoConstants.VD_PRIMARY) {
                // Root directory record is at offset 156, 34 bytes
                IsoDirectoryRecord root = IsoDirectoryRecord.parse(vd, 156);
                if (root != null) {
                    rootExtentLba = root.extentLba;
                    rootDataLength = root.dataLength;
                    foundPrimary = true;
                }
            } else if (type == IsoConstants.VD_SUPPLEMENTARY) {
                // Check the escape sequence at offset 88 for Joliet
                if (isJolietEscape(vd)) {
                    IsoDirectoryRecord root = IsoDirectoryRecord.parse(vd, 156);
                    if (root != null) {
                        hasJoliet = true;
                        jolietRootExtentLba = root.extentLba;
                        jolietRootDataLength = root.dataLength;
                    }
                }
            } else if (type == IsoConstants.VD_SET_TERMINATOR) {
                break;
            }

            sector++;
            if (sector > IsoConstants.FIRST_VOLUME_DESCRIPTOR_SECTOR + 64) {
                break; // safety guard against malformed images
            }
        }

        if (!foundPrimary) {
            throw new IOException("No primary volume descriptor found in ISO image");
        }
    }

    private boolean isJolietEscape(byte[] vd) {
        // Escape sequences field is at offset 88, length 32
        return matches(vd, 88, IsoConstants.JOLIET_ESCAPE_LEVEL1)
            || matches(vd, 88, IsoConstants.JOLIET_ESCAPE_LEVEL2)
            || matches(vd, 88, IsoConstants.JOLIET_ESCAPE_LEVEL3);
    }

    // =========================================================================
    // Directory traversal
    // =========================================================================

    /**
     * Walks the entire directory tree, invoking {@code visitor} for each entry.
     *
     * <p>If a Joliet volume is present it is used as the primary tree (better
     * names). Rock Ridge NM entries, when present in the ISO 9660 tree, take
     * precedence even over Joliet. Since Rock Ridge lives in the primary
     * (non-Joliet) tree, this method walks the primary tree when Rock Ridge is
     * detected, otherwise the Joliet tree when available, otherwise the
     * primary tree.</p>
     *
     * @param visitor callback invoked per entry
     * @throws IOException on read error
     */
    public void walk(IsoVisitor visitor) throws IOException {
        // Decide which tree to traverse. We prefer the primary tree if Rock Ridge
        // is present (detected lazily during traversal), otherwise Joliet.
        boolean useJoliet = hasJoliet && !primaryHasRockRidge();
        Set<Long> visited = new HashSet<Long>();
        if (useJoliet) {
            walkDirectory(jolietRootExtentLba, jolietRootDataLength, "", visitor, true, visited, 0);
        } else {
            walkDirectory(rootExtentLba, rootDataLength, "", visitor, false, visited, 0);
        }
    }

    /**
     * Quick probe: reads the root directory of the primary tree and checks
     * whether any child carries an "SP" (SUSP) or "RR"/"NM" system-use entry.
     */
    private boolean primaryHasRockRidge() throws IOException {
        byte[] dir = readExtent(rootExtentLba, rootDataLength);
        int pos = 0;
        while (pos < dir.length) {
            IsoDirectoryRecord rec = IsoDirectoryRecord.parse(dir, pos);
            if (rec == null) {
                // advance to next sector boundary
                int next = ((pos / IsoConstants.SECTOR_SIZE) + 1) * IsoConstants.SECTOR_SIZE;
                if (next <= pos) break;
                pos = next;
                continue;
            }
            if (rec.systemUseLength > 0) {
                int su = rec.systemUseOffset;
                // look for "SP", "RR", or "NM" signatures
                for (int i = su; i + 4 <= su + rec.systemUseLength && i + 4 <= dir.length; ) {
                    int el = dir[i + 2] & 0xff;
                    if (el < 4) break;
                    int c0 = dir[i] & 0xff, c1 = dir[i + 1] & 0xff;
                    if ((c0 == 'S' && c1 == 'P') || (c0 == 'R' && c1 == 'R') || (c0 == 'N' && c1 == 'M')) {
                        return true;
                    }
                    i += el;
                }
            }
            pos += rec.recordLength;
        }
        return false;
    }

    private void walkDirectory(long extentLba, long dataLength, String parentPath,
                               IsoVisitor visitor, boolean joliet, Set<Long> visited, int depth) throws IOException {
        if (!visited.add(extentLba)) {
            return; // directory already walked: loop (or shared extent) in a crafted image, skip it
        }
        if (depth > MAX_DEPTH) {
            throw new ArcanaCorruptedException("ISO: directory tree deeper than " + MAX_DEPTH + " levels at " + parentPath);
        }
        byte[] dir = readExtent(extentLba, dataLength);
        int pos = 0;
        List<long[]> subdirs = new ArrayList<long[]>();       // {lba, length}
        List<String> subdirPaths = new ArrayList<String>();
        FileLayout pending = null;                            // multi-extent file being assembled

        while (pos < dir.length) {
            IsoDirectoryRecord rec = IsoDirectoryRecord.parse(dir, pos);
            if (rec == null) {
                // padding to end of sector: jump to next sector
                int next = ((pos / IsoConstants.SECTOR_SIZE) + 1) * IsoConstants.SECTOR_SIZE;
                if (next <= pos) break;
                pos = next;
                continue;
            }

            // Skip "." and ".." entries (identifier 0x00 and 0x01)
            boolean isDot = rec.rawIdentifier.length == 1
                    && (rec.rawIdentifier[0] == 0x00 || rec.rawIdentifier[0] == 0x01);
            if (!isDot) {
                String name = resolveName(rec, joliet);
                String path = parentPath.isEmpty() ? name : parentPath + "/" + name;
                // Rock Ridge relocation: CL = placeholder file standing for a directory moved to rr_moved
                long clLba = (joliet || rec.isDirectory()) ? -1 : relocatedLba(rec);

                if (rec.isDirectory() && !joliet && (hasRrEntry(rec, 'R', 'E') || isRelocationDir(rec, parentPath, name))) {
                    // relocated directory (RE) or the rr_moved folder itself: reached through its CL placeholder
                } else if (rec.isDirectory() || clLba >= 0) {
                    long lba = clLba >= 0 ? clLba : rec.extentLba;
                    long len = clLba >= 0 ? selfLength(clLba) : rec.dataLength;
                    visitor.visit(path, true, lba, 0L, rec.recordingEpochSeconds);
                    subdirs.add(new long[]{lba, len});
                    subdirPaths.add(path);
                } else if (rec.isMultiExtent()) {
                    // not the last extent: the following record(s) of the same file continue it
                    if (pending == null) pending = new FileLayout();
                    pending.extents.add(new long[]{rec.extentLba, rec.dataLength});
                } else {
                    FileLayout layout = pending;
                    pending = null;
                    if (layout != null) layout.extents.add(new long[]{rec.extentLba, rec.dataLength});
                    long firstLba = layout != null ? layout.extents.get(0)[0] : rec.extentLba;
                    long total = 0;
                    if (layout != null) { for (long[] e : layout.extents) total += e[1]; } else total = rec.dataLength;
                    long zfSize = joliet ? -1 : zisofsSize(rec);
                    if (zfSize >= 0) {
                        if (layout == null) { layout = new FileLayout(); layout.extents.add(new long[]{rec.extentLba, rec.dataLength}); }
                        layout.zisofsSize = zfSize;
                    }
                    if (layout != null) layouts.put(firstLba, layout);
                    visitor.visit(path, false, firstLba, zfSize >= 0 ? zfSize : total, rec.recordingEpochSeconds);
                }
            }

            pos += rec.recordLength;
        }

        // Recurse into subdirectories after finishing the current level
        for (int i = 0; i < subdirs.size(); i++) {
            long[] sd = subdirs.get(i);
            walkDirectory(sd[0], sd[1], subdirPaths.get(i), visitor, joliet, visited, depth + 1);
        }
    }

    // =========================================================================
    // Rock Ridge directory relocation (CL / RE, rr_moved)
    // =========================================================================

    private boolean hasRrEntry(IsoDirectoryRecord rec, char c0, char c1) throws IOException {
        return RockRidgeParser.findEntry(rec, new RockRidgeParser.SectorReader() {
            public byte[] readBytes(long lba, long offset, int length) throws IOException {
                return readBytesAt(lba, offset, length);
            }
        }, c0, c1) != null;
    }

    /** Sector of the relocated directory named by a "CL" entry, -1 if absent. */
    private long relocatedLba(IsoDirectoryRecord rec) throws IOException {
        byte[] cl = RockRidgeParser.findEntry(rec, new RockRidgeParser.SectorReader() {
            public byte[] readBytes(long lba, long offset, int length) throws IOException {
                return readBytesAt(lba, offset, length);
            }
        }, 'C', 'L');
        if (cl == null || cl.length < 8) return -1;
        return IsoDirectoryRecord.readUint32LE(cl, 4);
    }

    /** Directory length taken from the "." record at the start of the directory at {@code lba}. */
    private long selfLength(long lba) throws IOException {
        byte[] first = readBytesAt(lba, 0, IsoConstants.SECTOR_SIZE);
        IsoDirectoryRecord dot = IsoDirectoryRecord.parse(first, 0);
        if (dot == null) throw new ArcanaCorruptedException("ISO: Rock Ridge relocated directory at sector " + lba + " has no '.' record");
        return dot.dataLength;
    }

    /**
     * True for the "rr_moved" folder of the root (genisoimage, xorriso use "rr_moved" or
     * ".rr_moved") when it holds relocated directories (RE) and nothing else: it is then hidden.
     */
    private boolean isRelocationDir(IsoDirectoryRecord rec, String parentPath, String name) throws IOException {
        if (!parentPath.isEmpty() || !(name.equals("rr_moved") || name.equals(".rr_moved"))) return false;
        byte[] dir = readExtent(rec.extentLba, rec.dataLength);
        int pos = 0;
        int relocated = 0;
        while (pos < dir.length) {
            IsoDirectoryRecord r = IsoDirectoryRecord.parse(dir, pos);
            if (r == null) {
                int next = ((pos / IsoConstants.SECTOR_SIZE) + 1) * IsoConstants.SECTOR_SIZE;
                if (next <= pos) break;
                pos = next;
                continue;
            }
            boolean isDot = r.rawIdentifier.length == 1 && (r.rawIdentifier[0] == 0x00 || r.rawIdentifier[0] == 0x01);
            if (!isDot) {
                if (!r.isDirectory() || !hasRrEntry(r, 'R', 'E')) return false;
                relocated++;
            }
            pos += r.recordLength;
        }
        return relocated > 0;
    }

    /**
     * Resolves the best available name for a record: Rock Ridge NM (if present)
     * beats Joliet, which beats the plain ISO 9660 name.
     */
    private String resolveName(IsoDirectoryRecord rec, boolean joliet) throws IOException {
        // Rock Ridge NM (only meaningful in the primary, non-Joliet tree)
        if (!joliet) {
            String rr = RockRidgeParser.extractAlternateName(rec, new RockRidgeParser.SectorReader() {
                public byte[] readBytes(long lba, long offset, int length) throws IOException {
                    return readBytesAt(lba, offset, length);
                }
            });
            if (rr != null && !rr.isEmpty()) {
                return rr;
            }
            return rec.getIso9660Name();
        }
        return rec.getJolietName();
    }

    // =========================================================================
    // File data access
    // =========================================================================

    /**
     * Reads the full data of a file given its extent and length.
     *
     * @param extentLba  starting sector
     * @param dataLength length in bytes
     * @return file bytes
     */
    public byte[] readFileData(long extentLba, long dataLength) throws IOException {
        if (dataLength < 0 || dataLength > Integer.MAX_VALUE - 8) throw new IOException("ISO: file of " + dataLength + " bytes too large to read in memory, use copyFileData");
        return readBytesAt(extentLba, 0, (int) dataLength);
    }

    /**
     * Copies the data of a file directly into an output stream, sector by
     * sector, avoiding a large in-memory buffer for big files.
     *
     * @param extentLba  starting sector
     * @param dataLength length in bytes
     * @param out        destination stream
     */
    public void copyFileData(long extentLba, long dataLength, java.io.OutputStream out) throws IOException {
        FileLayout layout = layouts.get(extentLba);
        if (layout != null) {
            if (layout.zisofsSize >= 0) {
                copyZisofs(layout, out);
            } else {
                for (long[] e : layout.extents) copyExtent(e[0], e[1], out);
            }
            return;
        }
        copyExtent(extentLba, dataLength, out);
    }

    private void copyExtent(long extentLba, long dataLength, java.io.OutputStream out) throws IOException {
        long remaining = dataLength;
        long pos = extentLba * IsoConstants.SECTOR_SIZE;
        byte[] buf = new byte[IsoConstants.SECTOR_SIZE];
        raf.seek(pos);
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int read = raf.read(buf, 0, toRead);
            if (read < 0) {
                throw new IOException("Unexpected EOF while reading ISO file data");
            }
            out.write(buf, 0, read);
            remaining -= read;
        }
    }

    // =========================================================================
    // zisofs (transparent compression, Rock Ridge "ZF")
    // =========================================================================

    /** Uncompressed size from a "ZF" entry with algorithm "pz", -1 if absent. */
    private long zisofsSize(IsoDirectoryRecord rec) throws IOException {
        byte[] zf = RockRidgeParser.findEntry(rec, new RockRidgeParser.SectorReader() {
            public byte[] readBytes(long lba, long offset, int length) throws IOException {
                return readBytesAt(lba, offset, length);
            }
        }, 'Z', 'F');
        if (zf == null || zf.length < 16) return -1;
        if (zf[4] != 'p' || zf[5] != 'z') throw new ArcanaUnsupportedFormatException("ISO: unsupported transparent compression '" + (char) zf[4] + (char) zf[5] + "' for " + rec.getIso9660Name());
        return IsoDirectoryRecord.readUint32LE(zf, 8);
    }

    /**
     * zisofs file: 16-byte header (magic, size, header size / 4, log2 block size),
     * then (blocks + 1) little-endian offsets; each block is a zlib stream, an empty
     * block stands for zeros.
     */
    private void copyZisofs(FileLayout layout, java.io.OutputStream out) throws IOException {
        long[] ext = layout.extents.get(0);
        long base = ext[0] * IsoConstants.SECTOR_SIZE;
        long compLen = ext[1];
        long size = layout.zisofsSize;
        if (size == 0) return;
        if (compLen < 16) throw new ArcanaCorruptedException("ISO: truncated zisofs header");
        byte[] hdr = new byte[16];
        raf.seek(base);
        raf.readFully(hdr);
        if (!matches(hdr, 0, ZISOFS_MAGIC)) throw new ArcanaCorruptedException("ISO: bad zisofs header");
        int hdrSize = (hdr[12] & 0xff) * 4;
        int log2 = hdr[13] & 0xff;
        if (log2 < 15 || log2 > 17) throw new ArcanaCorruptedException("ISO: bad zisofs block size 2^" + log2);
        int blockSize = 1 << log2;
        long nBlocks = (size + blockSize - 1) / blockSize;
        if (hdrSize + (nBlocks + 1) * 4 > compLen) throw new ArcanaCorruptedException("ISO: truncated zisofs block table");
        byte[] table = new byte[(int) ((nBlocks + 1) * 4)];
        raf.seek(base + hdrSize);
        raf.readFully(table);
        byte[] outBuf = new byte[blockSize];
        byte[] inBuf = new byte[blockSize * 2];
        Inflater inf = new Inflater();
        try {
            long remaining = size;
            for (int b = 0; b < nBlocks; b++) {
                long start = IsoDirectoryRecord.readUint32LE(table, b * 4);
                long end = IsoDirectoryRecord.readUint32LE(table, b * 4 + 4);
                int want = (int) Math.min(blockSize, remaining);
                if (end < start || end > compLen || end - start > inBuf.length) throw new ArcanaCorruptedException("ISO: bad zisofs block pointer");
                if (end == start) {
                    java.util.Arrays.fill(outBuf, 0, want, (byte) 0);
                } else {
                    int clen = (int) (end - start);
                    raf.seek(base + start);
                    raf.readFully(inBuf, 0, clen);
                    inf.reset();
                    inf.setInput(inBuf, 0, clen);
                    int got = 0;
                    try {
                        while (got < want && !inf.finished()) {
                            int n = inf.inflate(outBuf, got, want - got);
                            if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                            got += n;
                        }
                    } catch (DataFormatException e) {
                        throw new ArcanaCorruptedException("ISO: corrupted zisofs block " + b + ": " + e.getMessage(), e);
                    }
                    if (got != want) throw new ArcanaCorruptedException("ISO: zisofs block " + b + " gives " + got + " bytes instead of " + want);
                }
                out.write(outBuf, 0, want);
                remaining -= want;
            }
        } finally {
            inf.end();
        }
    }

    // =========================================================================
    // Low-level sector I/O
    // =========================================================================

    private byte[] readSector(int sector) throws IOException {
        byte[] buf = new byte[IsoConstants.SECTOR_SIZE];
        raf.seek((long) sector * IsoConstants.SECTOR_SIZE);
        raf.readFully(buf);
        return buf;
    }

    /** Reads a directory extent; its length is checked against MAX_DIRECTORY_SIZE before allocation. */
    private byte[] readExtent(long extentLba, long dataLength) throws IOException {
        if (dataLength < 0 || dataLength > MAX_DIRECTORY_SIZE) {
            throw new ArcanaCorruptedException("ISO: directory at sector " + extentLba + " has an invalid length (" + dataLength + " bytes, limit " + MAX_DIRECTORY_SIZE + ")");
        }
        return readBytesAt(extentLba, 0, (int) dataLength);
    }

    private byte[] readBytesAt(long lba, long offset, int length) throws IOException {
        long pos = lba * IsoConstants.SECTOR_SIZE + offset;
        if (pos + length > raf.length()) {
            throw new ArcanaCorruptedException("ISO: image truncated: " + length + " bytes at offset " + pos + " are past the end of the file (" + raf.length() + " bytes)");
        }
        byte[] buf = new byte[length];
        raf.seek(pos);
        raf.readFully(buf);
        return buf;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static boolean matches(byte[] buf, int offset, byte[] expected) {
        if (offset + expected.length > buf.length) return false;
        for (int i = 0; i < expected.length; i++) {
            if (buf[offset + i] != expected[i]) return false;
        }
        return true;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }
}
