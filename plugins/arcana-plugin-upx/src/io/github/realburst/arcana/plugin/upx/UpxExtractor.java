/*
 * Copyright 2026 Stephane Bury.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * UPX layout reference: UPX 5.2.1 src/packhead.cpp, src/p_unix.cpp, src/pefile.cpp.
 */
package io.github.realburst.arcana.plugin.upx;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.Adler32;

/**
 * Decodes UPX data and reconstructs supported PE32/PE32+ files. Some ELF
 * variants retain consecutive decoded extents in a .bin analysis output.
 * Never executes the input or any code from it.
 */
public final class UpxExtractor implements ArchiveExtractor {
    private static final int MAGIC = 0x21585055; // UPX!
    private static final int MAX_BLOCK = 64 * 1024 * 1024;
    private static final long MAX_OUTPUT = 256L * 1024 * 1024;

    public void extract(File archive, File destination) throws IOException {
        // Complete validation before creating any destination entry.
        Result result = process(archive, null);
        try (OutputStream out = PluginSupport.openOutput(destination, outputName(archive, result.pe))) {
            Result written = process(archive, out);
            if (written.expanded != result.expanded || written.compressed != result.compressed)
                throw new IOException("Input file changed during extraction");
        }
    }

    public void extract(InputStream in, File destination) throws IOException {
        throw new IOException("UPX requires random access; use extract(File, File)");
    }

    public List<ArcanaEntry> list(File archive) throws IOException {
        Result r = process(archive, null);
        return Collections.singletonList(new ArcanaEntry.Builder(outputName(archive, r.pe)).compressedSize(r.compressed).uncompressedSize(r.expanded).build());
    }

    public boolean supportsStream() { return false; }

    private static String outputName(File file, boolean pe) {
        String name = file.getName();
        if (!pe) return name + ".upx-decoded.bin";
        int dot = name.lastIndexOf('.');
        if (dot >= 0) {
            String ext = name.substring(dot).toLowerCase(java.util.Locale.ROOT);
            if (ext.equals(".exe") || ext.equals(".dll") || ext.equals(".sys"))
                return name.substring(0, dot) + ".unpacked" + name.substring(dot);
        }
        return name + ".unpacked.exe";
    }

    private static Result process(File file, OutputStream out) throws IOException {
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            if (in.length() < 128) throw new IOException("UPX executable is too short");
            int a = in.readUnsignedByte(), b = in.readUnsignedByte();
            if (a == 'M' && b == 'Z') return pe(in, out);
            if (a == 0x7f && b == 'E' && in.readUnsignedByte() == 'L' && in.readUnsignedByte() == 'F' && elfLittleEndian(in))
                return elf(in, out);
            throw new IOException("Only PE and ELF UPX executables are supported");
        }
    }

    private static Result pe(RandomAccessFile in, OutputStream out) throws IOException {
        long size = in.length();
        long peOff = le32(in, 0x3c);
        if (peOff < 64 || peOff + 24 > size || le32(in, peOff) != 0x4550)
            throw new IOException("Invalid PE header");
        int count = le16(in, peOff + 6), optional = le16(in, peOff + 20);
        long sections = peOff + 24 + optional;
        if (count < 2 || count > 96 || sections + count * 40L > size || !sectionName(in, sections, "UPX0") || !sectionName(in, sections + 40, "UPX1"))
            throw new IOException("Missing or invalid UPX0/UPX1 sections");
        long raw = le32(in, sections + 40 + 20);
        if (raw < 64 || raw >= size) throw new IOException("Invalid UPX1 offset");
        Header header = null;
        // UPX places the header in a 64-byte window immediately before UPX1.
        for (long p = raw - 64; p + 32 <= raw; ++p) {
            if (le32(in, p) != MAGIC) continue;
            Header candidate = header(in, p);
            if (candidate != null && candidate.format < 128 && p + 32 + candidate.cSize <= size) {
                header = candidate;
                break;
            }
        }
        if (header == null) throw new IOException("Missing or corrupt UPX PE header");
        if (header.filter != 0 && header.filter != 0x49 && header.filter != 0x26)
            throw new IOException("Unsupported UPX PE filter 0x" + Integer.toHexString(header.filter));
        if (header.cSize > MAX_BLOCK || header.uSize > MAX_OUTPUT || header.cSize <= 0)
            throw new IOException("PE block size exceeds limit");
        byte[] compressed = read(in, header.offset + 32, (int)header.cSize);
        byte[] decoded = decode(compressed, (int)header.uSize, header.method);
        checkAdler(compressed, header.cAdler, "compressed PE block");
        checkAdler(decoded, header.uAdler, "decoded PE block");
        byte[] restored = PeRebuilder.rebuild(in, decoded, peOff, sections, count, optional, header.filter, header.filterCto);
        if (out != null) out.write(restored);
        return new Result(header.cSize, restored.length, true);
    }

    private static Result elf(RandomAccessFile in, OutputStream out) throws IOException {
        long size = in.length();
        Header h = null;
        long overlay = -1;
        // PackHeader is followed by a 4-byte overlay offset; some ELF variants
        // append additional bytes after that pair.
        for (long p = Math.max(0, size - 65536); p + 36 <= size; ++p) {
            if (le32(in, p) == MAGIC) {
                Header candidate = header(in, p);
                long o = candidate == null ? -1 : le32(in, p + 32);
                if (candidate != null && o >= 12 && o + 24 < p && le32(in, o - 8) == MAGIC && candidate.format < 128) {
                    h = candidate;
                    overlay = o;
                }
            }
        }
        if (h == null) throw new IOException("Missing or corrupt UPX ELF PackHeader");
        long origSize = le32(in, overlay + 4), blockSize = le32(in, overlay + 8);
        int loaderSize = le16(in, overlay - 4);
        if (origSize == 0 || blockSize == 0 || blockSize > MAX_BLOCK || origSize > MAX_OUTPUT)
            throw new IOException("UPX ELF p_info exceeds limits");
        long position = overlay + 12, consumed = 0, expanded = 0;
        Adler32 cAdler = new Adler32(), uAdler = new Adler32();
        int blocks = 0;
        boolean skippedLoader = false;
        List<byte[]> loadBlocks = new ArrayList<byte[]>(), gapBlocks = new ArrayList<byte[]>();
        while (position < h.offset) {
            if (position + 8 <= h.offset && le32(in, position) == 0 && le32(in, position + 4) == MAGIC) break;
            Block next = block(in, position, h.offset, blockSize);
            if (next == null) {
                // The loader is recorded in l_info; do not scan arbitrary bytes
                // inside it, where plausible compressed blocks may occur.
                if (!skippedLoader && loaderSize > 0 && position + loaderSize < h.offset) {
                    position += loaderSize;
                    skippedLoader = true;
                    next = block(in, position, h.offset, blockSize);
                    // Some LZMA loaders add a short alignment/prefix field
                    // after the size recorded in l_info.
                    for (int pad = 0; next == null && pad < 16 && position + 1 < h.offset; pad++) {
                        ++position;
                        next = block(in, position, h.offset, blockSize);
                    }
                }
                if (next == null) throw new IOException("Missing UPX ELF block or unsupported filter/method at offset " + position);
            }
            if (++blocks > 65536 || expanded + next.decoded.length > origSize)
                throw new IOException("UPX decompression limits exceeded");
            cAdler.update(next.compressed);
            uAdler.update(next.decoded);
            (skippedLoader ? gapBlocks : loadBlocks).add(next.decoded);
            consumed += next.compressed.length;
            expanded += next.decoded.length;
            position = next.end;
        }
        if (position + 8 > h.offset || h.offset - position > 16
                || le32(in, position) != 0 || le32(in, position + 4) != MAGIC
                || expanded != origSize || (cAdler.getValue() & 0xffffffffL) != h.cAdler
                || (uAdler.getValue() & 0xffffffffL) != h.uAdler)
            throw new IOException("Invalid UPX ELF checksum");
        byte[] image = rebuildElf64(loadBlocks, gapBlocks, (int)origSize);
        if (image == null) {
            // Other ELF variants retain their validated decoded extents for
            // analysis, without claiming to be reconstructed executables.
            if (out != null) {
                for (byte[] part : loadBlocks) out.write(part);
                for (byte[] part : gapBlocks) out.write(part);
            }
        } else if (out != null) out.write(image);
        return new Result(consumed, expanded, false);
    }

    /** Reassemble the common ELF64 ET_EXEC layout used by UPX 5.2.1. */
    private static byte[] rebuildElf64(List<byte[]> loads, List<byte[]> gaps, int size) {
        if (loads.isEmpty()) return null;
        byte[] header = loads.get(0);
        if (header.length < 64 || header[4] != 2 || header[5] != 1 || u16(header, 16) != 2 || u16(header, 18) != 62) return null;
        long phoff = u64(header, 32);
        int ent = u16(header, 54), n = u16(header, 56);
        if (phoff != 64 || ent != 56 || n < 1 || n > 256 || phoff + (long)ent * n != header.length || header.length > size) return null;
        List<int[]> spans = new ArrayList<int[]>();
        for (int i = 0; i < n; ++i) {
            int p = (int)phoff + i * ent;
            if (u32(header, p) != 1) continue; // PT_LOAD
            long off = u64(header, p + 8), len = u64(header, p + 32);
            if (off < 0 || len < 0 || off > size || len > size - off) return null;
            spans.add(new int[] {(int)off, (int)(off + len)});
        }
        if (spans.isEmpty() || spans.get(0)[0] != 0 || spans.get(0)[1] < header.length) return null;
        byte[] image = new byte[size];
        System.arraycopy(header, 0, image, 0, header.length);
        int loadIndex = 1, gapIndex = 0, lastEnd = 0;
        for (int[] span : spans) {
            if (span[0] < lastEnd) return null;
            int from = Math.max(span[0], header.length);
            if (span[1] > from) {
                int next = copyBlocks(loads, loadIndex, image, from, span[1]);
                if (next < 0) return null;
                loadIndex = next;
            }
            lastEnd = span[1];
        }
        if (loadIndex != loads.size()) return null;
        lastEnd = 0;
        for (int[] span : spans) {
            if (span[0] > lastEnd) {
                int next = copyBlocks(gaps, gapIndex, image, lastEnd, span[0]);
                if (next < 0) return null;
                gapIndex = next;
            }
            lastEnd = span[1];
        }
        if (size > lastEnd) {
            gapIndex = copyBlocks(gaps, gapIndex, image, lastEnd, size);
            if (gapIndex < 0) return null;
        }
        return gapIndex == gaps.size() ? image : null;
    }

    private static int copyBlocks(List<byte[]> blocks, int index, byte[] dst, int from, int to) {
        while (from < to) {
            if (index >= blocks.size() || blocks.get(index).length > to - from) return -1;
            byte[] block = blocks.get(index++);
            System.arraycopy(block, 0, dst, from, block.length);
            from += block.length;
        }
        return index;
    }

    private static int u16(byte[] b, int p) { 
       return (b[p] & 255) | (b[p+1] & 255) << 8; 
    }
    
    private static long u64(byte[] b, int p) {
        long lo = u32(b, p), hi = u32(b, p + 4);
        return hi == 0 ? lo : Long.MAX_VALUE;
    }

    private static Block block(RandomAccessFile in, long p, long limit, long blockSize) throws IOException {
        if (p < 0 || p + 12 > limit) return null;
        long u = le32(in, p), c = le32(in, p + 4);
        if (u == 0 || u > blockSize || c == 0 || c > u || c > MAX_BLOCK || p + 12 + c > limit)
            return null;
        in.seek(p + 8);
        int method = in.readUnsignedByte(), filter = in.readUnsignedByte();
        int cto = in.readUnsignedByte(), unused = in.readUnsignedByte();
        if (filter != 0 || cto != 0 || unused != 0 || (c < u && !isSupportedMethod(method)) || (c == u && method != 0)) return null;
        byte[] compressed = read(in, p + 12, (int)c);
        byte[] decoded;
        try { decoded = c == u ? compressed : decode(compressed, (int)u, method); }
        catch (IOException badCandidate) { return null; }
        return new Block(compressed, decoded, p + 12 + c);
    }

    private static boolean isNrv(int m) { 
       return m >= 2 && m <= 10; 
    }
    
    private static boolean isSupportedMethod(int m) { 
       return isNrv(m) || m == 14; 
    }

    private static byte[] decode(byte[] data, int uSize, int method) throws IOException {
        if (isNrv(method)) return NrvDecoder.decode(data, uSize, method);
        if (method == 14) return UpxLzmaDecoder.decode(data, uSize);
        throw new IOException("Unsupported UPX method " + method);
    }

    private static Header header(RandomAccessFile in, long p) throws IOException {
        if (p < 0 || p + 32 > in.length()) return null;
        byte[] bytes = read(in, p, 32);
        if (u32(bytes, 0) != MAGIC || (bytes[4] & 255) < 10 || (bytes[4] & 255) > 14)
            return null;
        int sum = 0;
        for (int i = 4; i < 31; ++i) sum += bytes[i] & 255;
        if (sum % 251 != (bytes[31] & 255)) return null;
        return new Header(p, bytes[5] & 255, bytes[6] & 255, bytes[28] & 255, bytes[29] & 255, u32(bytes, 16), u32(bytes, 20), u32(bytes, 8), u32(bytes, 12));
    }

    private static void checkAdler(byte[] data, long expected, String context) throws IOException {
        Adler32 a = new Adler32(); a.update(data);
        if (a.getValue() != expected) throw new IOException("Checksum mismatch: " + context);
    }

    private static boolean sectionName(RandomAccessFile in, long pos, String s) throws IOException {
        byte[] bytes = read(in, pos, 8);
        for (int i = 0; i < s.length(); ++i) if (bytes[i] != s.charAt(i)) return false;
        return bytes[s.length()] == 0;
    }

    private static boolean elfLittleEndian(RandomAccessFile in) throws IOException {
        in.seek(5);
        return in.readUnsignedByte() == 1;
    }

    private static byte[] read(RandomAccessFile in, long pos, int count) throws IOException {
        if (pos < 0 || count < 0 || pos > in.length() - count) throw new IOException("UPX read outside input file");
        byte[] result = new byte[count]; in.seek(pos); in.readFully(result); return result;
    }

    private static int le16(RandomAccessFile in, long pos) throws IOException {
        in.seek(pos); return in.readUnsignedByte() | in.readUnsignedByte() << 8;
    }

    private static long le32(RandomAccessFile in, long pos) throws IOException {
        in.seek(pos);
        return (in.readUnsignedByte() | in.readUnsignedByte() << 8 | in.readUnsignedByte() << 16 | in.readUnsignedByte() << 24) & 0xffffffffL;
    }

    private static long u32(byte[] b, int p) {
        return ((b[p] & 255) | (b[p+1] & 255) << 8 | (b[p+2] & 255) << 16 | (b[p+3] & 255) << 24) & 0xffffffffL;
    }

    private static final class Header {
        final long offset, uSize, cSize, uAdler, cAdler;
        final int format, method, filter, filterCto;
        Header(long o, int f, int m, int ft, int cto, long u, long c, long ua, long ca) {
            offset=o; format=f; method=m; filter=ft; filterCto=cto;
            uSize=u; cSize=c; uAdler=ua; cAdler=ca;
        }
    }

    private static final class Block {
        final byte[] compressed, decoded;
        final long end;
        Block(byte[] c, byte[] d, long e) { compressed=c; decoded=d; end=e; }
    }

    private static final class Result {
        final long compressed, expanded;
        final boolean pe;
        Result(long c, long e, boolean isPe) { compressed=c; expanded=e; pe=isPe; }
    }
}
