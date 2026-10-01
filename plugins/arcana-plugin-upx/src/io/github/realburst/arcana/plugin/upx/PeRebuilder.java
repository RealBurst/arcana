/*
 * Copyright 2026 Stephane Bury and contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Adapted from UPX 5.2.1 src/pefile.cpp and src/packer_r.cpp.
 */
package io.github.realburst.arcana.plugin.upx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Rebuilds supported UPX PE32/PE32+ images into a normal PE file. */
final class PeRebuilder {
    private static final int MAX_FILE = 256 * 1024 * 1024;
    private PeRebuilder() { }

    static byte[] rebuild(RandomAccessFile source, byte[] image, long peOffset,
                          long packedSections, int packedCount, int optional,
                          int filter, int filterCto) throws IOException {
        int ntSize = 24 + optional;
        boolean pe64 = optional == 240;
        if (!pe64 && optional != 224) throw bad("Unsupported PE optional header size");
        int dir = pe64 ? 0x88 : 0x78;
        int pointerSize = pe64 ? 8 : 4;
        int skip = (int)u32(image, image.length - 4);
        range(image, skip, ntSize);
        byte[] nt = new byte[ntSize];
        System.arraycopy(image, skip, nt, 0, ntSize);
        if (u32(nt, 0) != 0x4550 || u16(nt, 20) != optional
                || u16(nt, 24) != (pe64 ? 0x20b : 0x10b)
                || u32(nt, pe64 ? 0x84 : 0x74) != 16)
            throw bad("Invalid original PE header");
        int n = u16(nt, 6), sectionStart = skip + ntSize;
        if (n < 1 || n > 96) throw bad("Invalid PE section count");
        range(image, sectionStart, n * 40 + 4);
        byte[] sections = new byte[n * 40];
        System.arraycopy(image, sectionStart, sections, 0, sections.length);
        long rvamin = u32(sections, 12);
        if (filter == 0x49 || filter == 0x26) {
            long codebase = u32(nt, 0x2c), codesize = u32(nt, 0x1c);
            if (codesize > 0x00ffffffL || codesize > image.length)
                throw bad("Invalid filtered code size");
            int start = imageOffset(image, codebase, rvamin, (int)codesize);
            unfilterCto(image, start, (int)codesize, (int)(codebase-rvamin), filterCto, filter == 0x49);
        }
        int meta = sectionStart + sections.length;
        int fileAlign = (int)u32(nt, 0x3c);
        if (fileAlign < 1 || fileAlign > 65536 || (fileAlign & (fileAlign - 1)) != 0)
            throw bad("Invalid PE file alignment");

        long importRva = dirRva(nt, dir, 1), importSize = dirSize(nt, dir, 1);
        if (importRva != 0 && importSize > 20) {
            range(image, meta, 8);
            rebuildImports(source, image, nt, sections, packedSections, packedCount,
                    dirRvaPacked(source, peOffset, dir, 1),
                    (int)u32(image, meta), (int)u32(image, meta + 4),
                    rvamin, pointerSize);
            meta += 8;
        }

        long relocRva = dirRva(nt, dir, 5), relocSize = dirSize(nt, dir, 5);
        int packedFlags = readU16(source, peOffset + 22);
        if ((packedFlags & 1) != 0) {
            put16(nt, 22, u16(nt, 22) | 1);
            put32(nt, dir + 5 * 8, 0); put32(nt, dir + 5 * 8 + 4, 0);
        } else if (relocRva != 0 && relocSize != 0) {
            if (relocSize == 8) {
                int at = imageOffset(image, relocRva, rvamin, 8);
                System.arraycopy(new byte[] {0,0,0,0,8,0,0,0}, 0, image, at, 8);
            } else {
                range(image, meta, 5);
                rebuildRelocs(image, nt, dir, (int)u32(image, meta), image[meta+4] & 255,
                        rvamin, pe64);
                meta += 5;
            }
        }

        long resourceRva = dirRva(nt, dir, 2), resourceSize = dirSize(nt, dir, 2);
        long packedResourceRva = dirRvaPacked(source, peOffset, dir, 2);
        if (resourceRva != 0 && resourceSize != 0 && packedResourceRva != 0) {
            range(image, meta, 2);
            if (u16(image, meta) != 0)
                throw bad("UPX icon resource transformation is unsupported");
            meta += 2;
            rebuildResources(source, image, resourceRva, packedResourceRva,
                    packedSections, packedCount, rvamin);
        }

        // Matches UPX unpack0: remove the generated IAT/bound import directories.
        for (int index : new int[] {12, 11}) {
            put32(nt, dir + index * 8, 0);
            put32(nt, dir + index * 8 + 4, 0);
        }
        put32(nt, 0x58, 0); // CheckSum
        long headers = align(peOffset + ntSize + n * 40L, fileAlign);
        if (headers > MAX_FILE || headers > rvamin) throw bad("Invalid PE header size");
        put32(nt, 0x54, headers); // SizeOfHeaders

        long length = headers;
        for (int i = 0; i < n; i++) {
            int p = i * 40;
            long raw = u32(sections, p + 20), count = u32(sections, p + 16);
            if (raw != 0) {
                long end = raw + align(count, fileAlign);
                if (end > MAX_FILE || end < raw) throw bad("PE section exceeds size limit");
                length = Math.max(length, end);
                imageOffset(image, u32(sections, p + 12), rvamin, (int)align(count, fileAlign));
            }
        }
        if (peOffset > headers || length > MAX_FILE) throw bad("DOS stub exceeds PE header size");
        long lastPacked = packedSections + (packedCount - 1L) * 40;
        long packedAlign = readU32(source, peOffset + 0x3c);
        if (packedAlign < 1 || packedAlign > 65536 || (packedAlign & (packedAlign - 1)) != 0)
            throw bad("Invalid packed PE alignment");
        long overlayStart = align(readU32(source, lastPacked + 20)
                + readU32(source, lastPacked + 16), (int)packedAlign);
        if (overlayStart > source.length()) throw bad("Invalid PE overlay offset");
        long overlay = source.length() - overlayStart;
        if (length + overlay > MAX_FILE) throw bad("PE overlay exceeds size limit");
        byte[] result = new byte[(int)(length + overlay)];
        source.seek(0);
        source.readFully(result, 0, (int)peOffset);
        System.arraycopy(nt, 0, result, (int)peOffset, ntSize);
        System.arraycopy(sections, 0, result, (int)peOffset + ntSize, sections.length);
        for (int i = 0; i < n; i++) {
            int p = i * 40;
            long raw = u32(sections, p + 20);
            if (raw == 0) continue;
            int count = (int)align(u32(sections, p + 16), fileAlign);
            int from = imageOffset(image, u32(sections, p + 12), rvamin, count);
            System.arraycopy(image, from, result, (int)raw, count);
        }
        if (overlay > 0) {
            source.seek(overlayStart);
            source.readFully(result, (int)length, (int)overlay);
        }
        return result;
    }

    private static void rebuildImports(RandomAccessFile in, byte[] image, byte[] nt,
                                       byte[] sections, long packedSections, int packedCount,
                                       long packedImportRva, int imdata, int namesRva,
                                       long rvamin, int width) throws IOException {
        if (namesRva != 0) throw bad("Unsupported UPX import name table");
        long packedBase = packedRvaToFile(in, packedSections, packedCount, packedImportRva);
        int importDesc = imageOffset(image, dirRva(nt, width == 8 ? 0x88 : 0x78, 1), rvamin, 20);
        int p = imdata, count = 0;
        while (true) {
            range(image, p, 4);
            long dllOffset = u32(image, p);
            if (dllOffset == 0) break;
            if (++count > 512) throw bad("Too many imported libraries");
            range(image, p, 8);
            long iat = u32(image, p + 4) + rvamin;
            int desc = importDesc + (count - 1) * 20;
            range(image, desc, 20);
            long dllNameRva = u32(image, desc + 12);
            byte[] dllName = readCString(in, packedBase + dllOffset, 4096);
            System.arraycopy(dllName, 0, image,
                    imageOffset(image, dllNameRva, rvamin, dllName.length), dllName.length);
            put32(image, desc + 16, iat);
            p += 8;
            int imported = 0;
            while (true) {
                range(image, p, 1);
                int tag = image[p] & 255;
                int at = imageOffset(image, iat + (long)imported * width, rvamin, width);
                if (tag == 0) { putWord(image, at, 0, width); ++p; break; }
                if (++imported > 65536) throw bad("Too many imports");
                if (tag == 1) {
                    byte[] name = cString(image, p + 1, 4096);
                    long pointer = word(image, at, width);
                    int target = imageOffset(image, pointer + 2, rvamin, name.length);
                    System.arraycopy(name, 0, image, target, name.length);
                    p += 1 + name.length;
                } else if (tag == 255) {
                    range(image, p, 3);
                    putWord(image, at, u16(image, p+1) | (width == 8 ? Long.MIN_VALUE : 0x80000000L), width);
                    p += 3;
                } else {
                    range(image, p, 5);
                    long src = packedBase + u32(image, p+1);
                    byte[] raw = new byte[width];
                    in.seek(src); in.readFully(raw);
                    putWord(image, at, word(raw, 0, width), width);
                    p += 5;
                }
            }
        }
    }

    /** UPX filters 0x26 and 0x49: x86/x64 relative call/jump reversal. */
    private static void unfilterCto(byte[] b, int start, int size, int add, int cto, boolean jcc) {
        int lastcall = 0;
        for (int i = 0; i < size - 5; i++) {
            int opcode = b[start+i] & 255;
            boolean branch = opcode == 0xe8 || opcode == 0xe9
                    || (jcc && i > 0 && i != lastcall && (b[start+i-1] & 255) == 0x0f
                    && opcode >= 0x80 && opcode <= 0x8f);
            if (!branch) continue;
            if ((b[start+i+1] & 255) == cto) {
                long value = ((b[start+i+1] & 255L) << 24)
                        | ((b[start+i+2] & 255L) << 16)
                        | ((b[start+i+3] & 255L) << 8)
                        | (b[start+i+4] & 255L);
                put32(b, start+i+1, value - i - 1 - add - ((long)cto << 24));
                i += 4;
                lastcall = i + 1;
            }
        }
    }

    private static void rebuildRelocs(byte[] image, byte[] nt, int dir, int source,
                                      int flags, long rvamin, boolean pe64) throws IOException {
        if ((flags & 6) != 0) throw bad("16-bit relocations are unsupported");
        int p = source, pc = -4;
        List<Integer> positions = new ArrayList<Integer>();
        while (true) {
            range(image, p, 1);
            int v = image[p] & 255;
            if (v == 0) break;
            long delta;
            if (v < 240) { delta = v; ++p; }
            else {
                range(image, p, 3);
                delta = (v & 15) * 65536L + u16(image, p + 1);
                p += 3;
                if (delta == 0) { range(image, p, 4); delta = u32(image, p); p += 4; }
            }
            if (delta < 4 || delta > image.length || positions.size() > 1000000)
                throw bad("Invalid relocation delta");
            pc = (int)((long)pc + delta);
            range(image, pc, pe64 ? 8 : 4);
            positions.add(pc);
        }
        long base = pe64 ? word(nt, 0x30, 8) : word(nt, 0x34, 4);
        for (int pos : positions) {
            if (pe64) putWord(image, pos, Long.reverseBytes(word(image, pos, 8)) + base + rvamin, 8);
            else putWord(image, pos, (Integer.reverseBytes((int)word(image, pos, 4)) & 0xffffffffL) + base + rvamin, 4);
        }
        ByteArrayOutputStream reloc = new ByteArrayOutputStream();
        int page = -1;
        ByteArrayOutputStream block = null;
        for (int pos : positions) {
            long rva = pos + rvamin;
            int nextPage = (int)(rva & ~4095L);
            if (block == null || page != nextPage) {
                if (block != null) writeRelocBlock(reloc, block, page);
                page = nextPage;
                block = new ByteArrayOutputStream();
            }
            int entry = ((pe64 ? 10 : 3) << 12) | ((int)rva & 4095);
            block.write(entry & 255); block.write(entry >>> 8);
        }
        if (block != null) writeRelocBlock(reloc, block, page);
        byte[] bytes = reloc.toByteArray();
        long rva = dirRva(nt, dir, 5);
        System.arraycopy(bytes, 0, image, imageOffset(image, rva, rvamin, bytes.length), bytes.length);
        put32(nt, dir + 5 * 8 + 4, bytes.length);
    }

    private static void writeRelocBlock(ByteArrayOutputStream out, ByteArrayOutputStream entries, int page) {
        byte[] body = entries.toByteArray();
        int size = 8 + body.length, aligned = (size + 3) & ~3;
        for (int shift = 0; shift < 32; shift += 8) out.write(page >>> shift);
        for (int shift = 0; shift < 32; shift += 8) out.write(aligned >>> shift);
        out.write(body, 0, body.length);
        for (int i = size; i < aligned; i++) out.write(0);
    }

    private static void rebuildResources(RandomAccessFile in, byte[] image,
                                         long originalRva, long packedRva,
                                         long sectionTable, int count, long rvamin) throws IOException {
        int last = (count - 1) * 40;
        long sectionVa = readU32(in, sectionTable + last + 12);
        long sectionRaw = readU32(in, sectionTable + last + 20);
        long sectionSize = readU32(in, sectionTable + last + 16);
        if (sectionSize <= 0 || sectionSize > 32 * 1024 * 1024 || packedRva < sectionVa)
            throw bad("Invalid UPX resource section");
        byte[] packed = new byte[(int)sectionSize];
        in.seek(sectionRaw); in.readFully(packed);
        int root = (int)(packedRva - sectionVa);
        ResourceTree tree = new ResourceTree(packed, root);
        tree.visit(0, 0);
        int dirLength = (tree.directoryEnd + 3) & ~3;
        int dest = imageOffset(image, originalRva, rvamin, dirLength);
        range(packed, root, dirLength);
        System.arraycopy(packed, root, image, dest, dirLength);
        for (int entry : tree.leaves) {
            long dataRva = u32(packed, entry);
            // Only uncompressed resources were moved into the packed section.
            // Compressed resources already reside in the decoded PE image.
            if (dataRva <= packedRva) continue;
            int bytes = (int)u32(packed, entry + 4);
            int copied = (int)align(bytes, 4);
            long off = dataRva - sectionVa;
            if (bytes < 0 || off < 4 || off + copied > packed.length) throw bad("UPX resource outside packed section");
            long oldRva = u32(packed, (int)off - 4);
            int target = imageOffset(image, oldRva, rvamin, copied);
            System.arraycopy(packed, (int)off, image, target, copied);
            put32(image, dest + entry - root, oldRva);
        }
    }

    private static final class ResourceTree {
        final byte[] input;
        final int root;
        final Set<Integer> seen = new HashSet<Integer>();
        final List<Integer> leaves = new ArrayList<Integer>();
        int directoryEnd;
        ResourceTree(byte[] b, int p) { input=b; root=p; }
        void visit(int offset, int depth) throws IOException {
            if (depth > 16 || !seen.add(offset) || seen.size() > 4096)
                throw bad("Invalid UPX resource tree");
            int p = root + offset;
            range(input, p, 16);
            int count = u16(input,p+12) + u16(input,p+14);
            if (count > 4096) throw bad("Too many resources");
            range(input,p,16+count*8);
            directoryEnd = Math.max(directoryEnd,offset+16+count*8);
            for (int i=0;i<count;i++) {
                int e=p+16+8*i;
                long name=u32(input,e), value=u32(input,e+4);
                if ((name & 0x80000000L)!=0) {
                    int q=root+(int)(name&0x7fffffffL);
                    range(input,q,2);
                    int len=u16(input,q);
                    range(input,q+2,len*2);
                    directoryEnd=Math.max(directoryEnd,(q-root)+2+len*2);
                }
                int child=(int)(value&0x7fffffffL);
                if ((value&0x80000000L)!=0) visit(child,depth+1);
                else {
                    range(input,root+child,16);
                    leaves.add(root+child);
                    directoryEnd=Math.max(directoryEnd,child+16);
                }
            }
        }
    }

    private static long packedRvaToFile(RandomAccessFile in, long table, int n, long rva) throws IOException {
        for (int i=0;i<n;i++) {
            long p=table+40L*i, va=readU32(in,p+12), size=readU32(in,p+16);
            if (rva>=va && rva-va<size) return readU32(in,p+20)+(rva-va);
        }
        throw bad("UPX RVA not found");
    }
    private static long dirRvaPacked(RandomAccessFile in, long pe, int dir, int index) throws IOException {
        return readU32(in, pe + dir + index*8);
    }
    private static long dirRva(byte[] nt,int dir,int index) { return u32(nt,dir+index*8); }
    private static long dirSize(byte[] nt,int dir,int index) { return u32(nt,dir+index*8+4); }
    private static int imageOffset(byte[] image,long rva,long rvamin,int count) throws IOException {
        long off=rva-rvamin;
        if (off<0 || off>image.length-count) throw bad("PE RVA outside decoded image");
        return (int)off;
    }
    private static byte[] cString(byte[] b,int p,int limit) throws IOException {
        if (p<0 || p>=b.length) throw bad("PE string outside decoded image");
        int end=p;
        while (end<b.length && end-p<limit && b[end]!=0) ++end;
        if (end==b.length || end-p==limit) throw bad("Unterminated PE string");
        byte[] result=new byte[end-p+1];System.arraycopy(b,p,result,0,result.length);return result;
    }
    private static byte[] readCString(RandomAccessFile in,long p,int limit) throws IOException {
        if (p<0 || p>=in.length()) throw bad("UPX string outside input file");
        in.seek(p);ByteArrayOutputStream b=new ByteArrayOutputStream();
        for (int i=0;i<limit;i++) {
            int v=in.read();if (v<0) throw bad("Truncated UPX string");
            b.write(v);if (v==0) return b.toByteArray();
        }
        throw bad("UPX string exceeds length limit");
    }
    private static void range(byte[] b,int p,int n) throws IOException {
        if (p<0 || n<0 || p>b.length-n) throw bad("PE data outside decoded image");
    }
    private static long align(long n,int a) { return (n+a-1)&~(long)(a-1); }
    private static int u16(byte[] b,int p) { return (b[p]&255)|(b[p+1]&255)<<8; }
    private static long u32(byte[] b,int p) {
        return ((b[p]&255)|(b[p+1]&255)<<8|(b[p+2]&255)<<16|(b[p+3]&255)<<24)&0xffffffffL;
    }
    private static long word(byte[] b,int p,int n) {
        long v=0;for (int i=0;i<n;i++)v|=(long)(b[p+i]&255)<<(8*i);return v;
    }
    private static void put16(byte[] b,int p,int v) { b[p]=(byte)v;b[p+1]=(byte)(v>>>8); }
    private static void put32(byte[] b,int p,long v) {
        for(int i=0;i<4;i++)b[p+i]=(byte)(v>>>(8*i));
    }
    private static void putWord(byte[] b,int p,long v,int n) {
        for(int i=0;i<n;i++)b[p+i]=(byte)(v>>>(8*i));
    }
    private static int readU16(RandomAccessFile in,long p) throws IOException {
        in.seek(p);return in.readUnsignedByte()|in.readUnsignedByte()<<8;
    }
    private static long readU32(RandomAccessFile in,long p) throws IOException {
        in.seek(p);return (in.readUnsignedByte()|in.readUnsignedByte()<<8
                |in.readUnsignedByte()<<16|in.readUnsignedByte()<<24)&0xffffffffL;
    }
    private static IOException bad(String reason) { return new IOException(reason); }
}
