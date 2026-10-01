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
package be.stef.arcana.formats.carve;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Minimal parser of a Windows PE image (EXE, DLL, SYS, EFI) located at any
 * offset of a file: computes where the image ends, so that executables glued
 * one after the other can be separated, and where the overlay (data appended
 * after the image, e.g. the archive of a self-extracting executable) begins.
 *
 * <p>Image size = the largest of: the headers, the raw data of every section,
 * the COFF symbol table (MinGW builds) and the Authenticode certificate when it
 * directly follows the image.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class PeImage {

    /** Offset of the image in the file. */
    public final long offset;
    /** End of headers + sections + symbols, relative to {@link #offset} (overlay starts here). */
    public final long sectionsEnd;
    /** Size of the image including a certificate glued to it, relative to {@link #offset}. */
    public final long size;
    /** Certificate table (Authenticode) relative position and size, 0 if none. */
    public final long certOffset, certSize;
    public final boolean dll, pe64;
    public final int machine, subsystem;
    /** Name found in the export directory (DLLs) or the version resource, or null. */
    public final String name;

    private PeImage(final long offset, final long sectionsEnd, final long size, final long certOffset, final long certSize, final boolean dll, final boolean pe64, final int machine, final int subsystem, final String name) {
        this.offset = offset;
        this.sectionsEnd = sectionsEnd;
        this.size = size;
        this.certOffset = certOffset;
        this.certSize = certSize;
        this.dll = dll;
        this.pe64 = pe64;
        this.machine = machine;
        this.subsystem = subsystem;
        this.name = name;
    }

    /** Usual file extension: dll, sys, efi or exe. */
    public String extension() {
        if (dll) return "dll";
        if (subsystem == 1) return "sys";
        if (subsystem >= 10 && subsystem <= 13) return "efi";
        return "exe";
    }

    /** Short description, e.g. "PE32+ DLL x64". */
    public String describe() {
        final String arch;
        switch (machine) {
            case 0x014C: arch = "x86"; break;
            case 0x8664: arch = "x64"; break;
            case 0xAA64: arch = "ARM64"; break;
            case 0x01C0: case 0x01C4: arch = "ARM"; break;
            case 0x0200: arch = "IA64"; break;
            default: arch = String.format("machine 0x%04X", machine);
        }
        return (pe64 ? "PE32+ " : "PE32 ") + extension().toUpperCase() + " " + arch + (name != null ? " (" + name + ")" : "");
    }

    /**
     * Parses a PE image starting at {@code off} ("MZ"), or returns null if the
     * bytes there are not a plausible PE image.
     */
    public static PeImage parse(final ByteSource s, final long off) throws IOException {
        if (s.u16le(off) != 0x5A4D) return null; // "MZ"
        final long lfanew = s.u32le(off + 0x3C);
        if (lfanew < 0x40 || lfanew > 0x10000 || (lfanew & 3) != 0) return null;
        final long pe = off + lfanew;
        if (s.u32le(pe) != 0x00004550L) return null; // "PE\0\0"
        final int machine = s.u16le(pe + 4);
        final int nSections = s.u16le(pe + 6);
        final long symPtr = s.u32le(pe + 12);
        final long symCount = s.u32le(pe + 16);
        final int optSize = s.u16le(pe + 20);
        final int characteristics = s.u16le(pe + 22);
        if (nSections <= 0 || nSections > 96 || optSize < 0x60) return null;
        final long opt = pe + 24;
        final int magic = s.u16le(opt);
        final boolean pe64;
        if (magic == 0x10B) pe64 = false;
        else if (magic == 0x20B) pe64 = true;
        else return null;
        final int subsystem = s.u16le(opt + 68);
        final long sizeOfHeaders = s.u32le(opt + 60);
        final long nDirs = s.u32le(opt + (pe64 ? 108 : 92));
        final long dirs = opt + (pe64 ? 112 : 96);
        final long fileLen = s.length() - off;

        // Sections
        final long secTable = opt + optSize;
        final long[] va = new long[nSections], vsize = new long[nSections], raw = new long[nSections], rawSize = new long[nSections];
        long end = Math.max(sizeOfHeaders, secTable + nSections * 40L - off);
        for (int i = 0; i < nSections; i++) {
            final long sec = secTable + i * 40L;
            vsize[i] = s.u32le(sec + 8);
            va[i] = s.u32le(sec + 12);
            rawSize[i] = s.u32le(sec + 16);
            raw[i] = s.u32le(sec + 20);
            if (rawSize[i] < 0 || raw[i] < 0) return null;
            if (rawSize[i] > 0) {
                if (raw[i] + rawSize[i] > fileLen + 0x1000) return null; // far beyond the file: not a PE (or badly truncated)
                end = Math.max(end, raw[i] + rawSize[i]);
            }
        }
        // COFF symbol table + string table (MinGW, debug builds)
        if (symPtr > 0 && symCount > 0 && symCount < 0x1000000) {
            final long strTable = symPtr + symCount * 18;
            final long strSize = s.u32le(off + strTable);
            if (strTable <= fileLen && strSize >= 4 && strTable + strSize <= fileLen) end = Math.max(end, strTable + strSize);
        }
        final long sectionsEnd = end;
        // Certificate (security directory: FILE offset, not RVA)
        long certOff = 0, certSize = 0, size = end;
        if (nDirs > 4) {
            certOff = s.u32le(dirs + 4 * 8);
            certSize = s.u32le(dirs + 4 * 8 + 4);
            if (certOff > 0 && certSize > 0 && certOff + certSize <= fileLen) {
                // glued to the image (8-byte alignment padding allowed): part of the file
                if (certOff >= end && certOff - end < 8) size = certOff + certSize;
            } else {
                certOff = 0;
                certSize = 0;
            }
        }
        final boolean dll = (characteristics & 0x2000) != 0;
        String name = null;
        try {
            if (dll && nDirs > 0) name = exportName(s, off, dirs, va, vsize, raw, rawSize);
            if (name == null && nDirs > 2) name = versionOriginalName(s, off, dirs, va, vsize, raw, rawSize);
        } catch (final IOException | RuntimeException e) {
            name = null; // names are only a convenience
        }
        return new PeImage(off, sectionsEnd, size, certOff, certSize, dll, pe64, machine, subsystem, name);
    }

    /** File position (absolute) of an RVA, or -1. */
    private static long rvaToFile(final long off, final long rva, final long[] va, final long[] vsize, final long[] raw, final long[] rawSize) {
        for (int i = 0; i < va.length; i++) {
            final long len = Math.max(vsize[i], rawSize[i]);
            if (rva >= va[i] && rva < va[i] + len) {
                final long delta = rva - va[i];
                if (delta >= rawSize[i]) return -1;
                return off + raw[i] + delta;
            }
        }
        return -1;
    }

    private static String exportName(final ByteSource s, final long off, final long dirs, final long[] va, final long[] vsize, final long[] raw, final long[] rawSize) throws IOException {
        final long rva = s.u32le(dirs);
        if (rva <= 0) return null;
        final long exp = rvaToFile(off, rva, va, vsize, raw, rawSize);
        if (exp < 0) return null;
        final long nameAt = rvaToFile(off, s.u32le(exp + 12), va, vsize, raw, rawSize);
        return nameAt < 0 ? null : cleanName(asciiZ(s, nameAt, 260));
    }

    /** OriginalFilename of the version resource (RT_VERSION), or null. */
    private static String versionOriginalName(final ByteSource s, final long off, final long dirs, final long[] va, final long[] vsize, final long[] raw, final long[] rawSize) throws IOException {
        final long rsrcRva = s.u32le(dirs + 2 * 8);
        if (rsrcRva <= 0) return null;
        final long root = rvaToFile(off, rsrcRva, va, vsize, raw, rawSize);
        if (root < 0) return null;
        long entry = findEntry(s, root, root, 16); // RT_VERSION
        if (entry < 0) return null;
        entry = firstEntry(s, root, entry);        // name level
        if (entry < 0) return null;
        entry = firstEntry(s, root, entry);        // language level -> data entry
        if (entry < 0) return null;
        final long dataRva = s.u32le(entry);
        final long dataSize = s.u32le(entry + 4);
        final long data = rvaToFile(off, dataRva, va, vsize, raw, rawSize);
        if (data < 0 || dataSize <= 0 || dataSize > 1 << 20) return null;
        final byte[] blob = s.bytes(data, (int) dataSize);
        if (blob == null) return null;
        final byte[] key = "OriginalFilename\0".getBytes(StandardCharsets.UTF_16LE);
        outer:
        for (int i = 0; i + key.length <= blob.length; i += 2) {
            for (int k = 0; k < key.length; k++) if (blob[i + k] != key[k]) continue outer;
            int v = (i + key.length + 3) & ~3; // value is 32-bit aligned (relative to the blob, itself aligned)
            final StringBuilder sb = new StringBuilder();
            while (v + 1 < blob.length) {
                final char c = (char) ((blob[v] & 0xFF) | ((blob[v + 1] & 0xFF) << 8));
                if (c == 0) break;
                sb.append(c);
                v += 2;
                if (sb.length() > 260) return null;
            }
            return cleanName(sb.toString());
        }
        return null;
    }

    /** Resource directory at {@code dir}: position of the entry with this ID, or -1. */
    private static long findEntry(final ByteSource s, final long root, final long dir, final int id) throws IOException {
        final int named = s.u16le(dir + 12);
        final int ids = s.u16le(dir + 14);
        if (named < 0 || ids < 0 || named + ids > 4096) return -1;
        for (int i = 0; i < named + ids; i++) {
            final long e = dir + 16 + i * 8L;
            if (s.u32le(e) == id) return subdirOrData(s, root, e);
        }
        return -1;
    }

    private static long firstEntry(final ByteSource s, final long root, final long dir) throws IOException {
        final int n = s.u16le(dir + 12) + s.u16le(dir + 14);
        if (n <= 0 || n > 4096) return -1;
        return subdirOrData(s, root, dir + 16);
    }

    private static long subdirOrData(final ByteSource s, final long root, final long entry) throws IOException {
        final long v = s.u32le(entry + 4);
        if (v < 0) return -1;
        return root + (v & 0x7FFFFFFFL);
    }

    private static String asciiZ(final ByteSource s, final long pos, final int max) throws IOException {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < max; i++) {
            final int c = s.u8(pos + i);
            if (c <= 0) break;
            if (c < 0x20 || c > 0x7E) return null;
            sb.append((char) c);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /** Keeps a plain file name (no path, no characters forbidden on Windows). */
    static String cleanName(final String n) {
        if (n == null) return null;
        String t = n.trim();
        final int slash = Math.max(t.lastIndexOf('/'), t.lastIndexOf('\\'));
        if (slash >= 0) t = t.substring(slash + 1);
        t = t.replaceAll("[\\x00-\\x1F<>:\"|?*]", "_");
        return t.isEmpty() || t.equals(".") || t.equals("..") ? null : t;
    }
}
