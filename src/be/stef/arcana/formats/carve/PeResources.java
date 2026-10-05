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
package be.stef.arcana.formats.carve;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Resources of a Windows PE image (resource directory, data directory 2), as
 * described in the Microsoft PE/COFF specification: a three-level tree (type,
 * name, language) whose leaves give the RVA and size of the data.
 *
 * @author Stef
 * @since 1.0.5
 */
public final class PeResources {

    /** A resource and the position of its data in the file. */
    public static final class Resource {
        /** Type: standard name ("RCDATA", "ICON"...), custom name, or "#id". */
        public final String type;
        /** Name, or the identifier in decimal. */
        public final String name;
        public final int typeId;
        public final int lang;
        public final long offset;
        public final long size;

        Resource(final String type, final int typeId, final String name, final int lang, final long offset, final long size) {
            this.type = type;
            this.typeId = typeId;
            this.name = name;
            this.lang = lang;
            this.offset = offset;
            this.size = size;
        }

        /** True for the resources of the user interface (icons, dialogs, strings, version, manifest...). */
        public boolean isStandardUi() {
            switch (typeId) {
                case 1: case 2: case 3: case 4: case 5: case 6: case 8: case 9: case 11: case 12: case 14: case 16: case 17: case 21: case 22: case 23: case 24: case 240: case 241:
                    return true;
                default:
                    return false;
            }
        }

        @Override
        public String toString() {
            return type + "/" + name + "/" + lang + " at 0x" + Long.toHexString(offset) + " (" + size + " bytes)";
        }
    }

    private static final String[] TYPES = {null, "CURSOR", "BITMAP", "ICON", "MENU", "DIALOG", "STRING", "FONTDIR", "FONT", "ACCELERATOR", "RCDATA", "MESSAGETABLE", "GROUP_CURSOR", null, "GROUP_ICON", null, "VERSION", "DLGINCLUDE", null, "PLUGPLAY", "VXD", "ANICURSOR", "ANIICON", "HTML", "MANIFEST"};

    private static final int MAX_RESOURCES = 20000;

    private PeResources() {
    }

    /** Resources of the PE image at the start of the file; empty if it has none or is not a PE image. */
    public static List<Resource> read(final ByteSource s) throws IOException {
        if (s.length() < 0x40 || s.u16le(0) != 0x5A4D) return Collections.emptyList();
        final long pe = s.u32le(0x3C);
        if (pe < 0x40 || pe > 0x10000 || pe + 24 > s.length() || s.u32le(pe) != 0x00004550L) return Collections.emptyList();
        final int nSections = s.u16le(pe + 6);
        final int optSize = s.u16le(pe + 20);
        final long opt = pe + 24;
        final int magic = s.u16le(opt);
        if (magic != 0x10B && magic != 0x20B || nSections <= 0 || nSections > 96) return Collections.emptyList();
        final boolean pe64 = magic == 0x20B;
        final long nDirs = s.u32le(opt + (pe64 ? 108 : 92));
        if (nDirs <= 2) return Collections.emptyList();
        final long dirRva = s.u32le(opt + (pe64 ? 112 : 96) + 16);
        if (dirRva == 0) return Collections.emptyList();
        final long[][] sections = new long[nSections][];
        final long table = opt + optSize;
        for (int i = 0; i < nSections; i++) {
            final long sec = table + i * 40L;
            sections[i] = new long[] {s.u32le(sec + 12), s.u32le(sec + 8), s.u32le(sec + 20), s.u32le(sec + 16)};
        }
        final long root = toFile(sections, dirRva, 16, s.length());
        if (root < 0) return Collections.emptyList();
        final List<Resource> out = new ArrayList<Resource>();
        final Set<Long> seen = new HashSet<Long>();
        for (final long[] t : entries(s, root, root, seen)) {
            if ((t[1] & 0x80000000L) == 0) continue;
            final int typeId = (t[0] & 0x80000000L) != 0 ? -1 : (int) t[0];
            final String type = typeId < 0 ? name(s, root, t[0]) : typeId < TYPES.length && TYPES[typeId] != null ? TYPES[typeId] : "#" + typeId;
            for (final long[] n : entries(s, root, root + (t[1] & 0x7FFFFFFFL), seen)) {
                if ((n[1] & 0x80000000L) == 0) continue;
                final String name = (n[0] & 0x80000000L) != 0 ? name(s, root, n[0]) : Long.toString(n[0]);
                for (final long[] l : entries(s, root, root + (n[1] & 0x7FFFFFFFL), seen)) {
                    if ((l[1] & 0x80000000L) != 0) continue;
                    final long leaf = root + l[1];
                    if (leaf + 16 > s.length()) continue;
                    final long size = s.u32le(leaf + 4);
                    final long data = toFile(sections, s.u32le(leaf), size, s.length());
                    if (data < 0) continue;
                    out.add(new Resource(type, typeId, name, (int) (l[0] & 0xFFFF), data, size));
                    if (out.size() >= MAX_RESOURCES) return out;
                }
            }
        }
        return out;
    }

    /** Entries of a directory: {name or id, offset of subdirectory (high bit) or data entry}. */
    private static List<long[]> entries(final ByteSource s, final long root, final long dir, final Set<Long> seen) throws IOException {
        final List<long[]> list = new ArrayList<long[]>();
        if (!seen.add(dir) || dir + 16 > s.length()) return list;
        final int count = s.u16le(dir + 12) + s.u16le(dir + 14);
        for (int i = 0; i < count && dir + 16 + i * 8L + 8 <= s.length(); i++) {
            list.add(new long[] {s.u32le(dir + 16 + i * 8L), s.u32le(dir + 20 + i * 8L)});
        }
        return list;
    }

    /** Name of an entry (UTF-16 counted string). */
    private static String name(final ByteSource s, final long root, final long ref) throws IOException {
        final long p = root + (ref & 0x7FFFFFFFL);
        if (p + 2 > s.length()) return "?";
        final int len = Math.min(s.u16le(p), 256);
        if (p + 2 + len * 2L > s.length()) return "?";
        return new String(s.bytes(p + 2, len * 2), StandardCharsets.UTF_16LE);
    }

    /** File position of an RVA whose len bytes lie in the raw data of a section, or -1. */
    private static long toFile(final long[][] sections, final long rva, final long len, final long fileLen) {
        for (final long[] sec : sections) {
            final long span = Math.max(sec[1], sec[3]);
            if (rva >= sec[0] && rva < sec[0] + span) {
                final long off = rva - sec[0];
                if (off + len > sec[3]) return -1;
                final long pos = sec[2] + off;
                return pos + len <= fileLen ? pos : -1;
            }
        }
        return -1;
    }
}
