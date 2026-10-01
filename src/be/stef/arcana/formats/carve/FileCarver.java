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

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Splits a file made of several files placed one after the other (executables
 * and DLLs glued together, installers, self-extracting archives, firmware
 * blobs, unknown containers...).
 *
 * <p>The file is scanned for known signatures. For each candidate, the format
 * structure is parsed to compute the <b>exact</b> size of the embedded file
 * (headers, section table, central directory, chunk list...): a signature alone
 * is never enough, so random bytes looking like "MZ" or "PK" are not cut out.
 * Recognized files are not searched inside (a DLL embedded in the resources of
 * an EXE stays in the EXE). Bytes between recognized files are kept as
 * "unknown" pieces, so that nothing is lost: concatenating the pieces gives the
 * original file back (except the zero-filled gaps, which are not written).</p>
 *
 * <p>.NET single-file bundles are split with their manifest: each file gets its
 * real path (DLL, .deps.json, .runtimeconfig.json, resources in their culture
 * sub-directory), compressed files are inflated.</p>
 *
 * <p>Recognized: PE (EXE/DLL/SYS/EFI, with overlay and certificate), MS-DOS
 * MZ, ELF, ZIP (and JAR/APK/DOCX...), 7z, RAR 4/5, CAB, GZIP, XZ, OLE compound
 * files (MSI, DOC, XLS), PNG, JPEG, GIF, PDF, RIFF (WAV, AVI, ANI).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class FileCarver {

    /** One piece of the file. */
    public static final class Item {
        public final long offset;
        public final long length;
        /** Short type ("pe", "zip", "unknown"...). */
        public final String type;
        public final String extension;
        public final String description;
        /** Name found inside the file (DLL export name, OriginalFilename...), or null. */
        public final String name;
        /** True if the structure announces more bytes than the file contains. */
        public final boolean truncated;
        /** Relative path to write the piece to (file of a .NET bundle), or null for the numbered name. */
        public final String path;
        /** True if the bytes are raw deflate (compressed file of a .NET bundle). */
        public final boolean deflated;

        Item(final long offset, final long length, final String type, final String extension, final String description, final String name, final boolean truncated) {
            this(offset, length, type, extension, description, name, truncated, null, false);
        }

        Item(final long offset, final long length, final String type, final String extension, final String description, final String name, final boolean truncated, final String path, final boolean deflated) {
            this.offset = offset;
            this.length = length;
            this.type = type;
            this.extension = extension;
            this.description = description;
            this.name = name;
            this.truncated = truncated;
            this.path = path;
            this.deflated = deflated;
        }

        public boolean isUnknown() {
            return "unknown".equals(type);
        }

        /** True for a gap made only of 0x00 bytes (alignment padding): listed but not written by split. */
        public boolean isPadding() {
            return "padding".equals(type);
        }

        @Override
        public String toString() {
            return String.format("0x%08X %12d  %-8s %s%s", offset, length, type, description, truncated ? " [TRUNCATED]" : "");
        }
    }

    private static final int SCAN_BUFFER = 1 << 20;

    /**
     * A carving probe contributed by a plugin: recognizes the plugin's format at
     * a given position of a scanned file, so that a format Arcana does not know
     * natively can still be cut out by {@code arcana s}.
     */
    public interface FormatProbe {
        /** Possible first bytes of the format (unsigned 0-255), to speed up the scan. */
        int[] leadBytes();

        /** If a file of this format starts exactly at {@code p}, its description; otherwise null. */
        Probe probeAt(ByteSource s, long p) throws IOException;
    }

    /** Result of a {@link FormatProbe}: a recognized piece starting at the probed position. */
    public static final class Probe {
        public final long length;
        public final String type;
        public final String extension;
        public final String description;
        public final String name;

        public Probe(final long length, final String type, final String extension, final String description, final String name) {
            this.length = length;
            this.type = type;
            this.extension = extension;
            this.description = description;
            this.name = name;
        }
    }

    private static final java.util.List<FormatProbe> PROBES = new java.util.concurrent.CopyOnWriteArrayList<FormatProbe>();

    /** Registers a carving probe (called by the plugin manager when plugins are loaded). */
    public static void addProbe(final FormatProbe p) {
        if (p != null) PROBES.add(p);
    }

    /** Removes every registered carving probe. */
    public static void clearProbes() {
        PROBES.clear();
    }

    private FileCarver() {}

    // =========================================================================
    // Public API
    // =========================================================================

    /** Lists the pieces of {@code file} (recognized files and unknown gaps), in file order. */
    public static List<Item> scan(final File file) throws IOException {
        try (ByteSource s = new ByteSource(file)) {
            return scan(s);
        }
    }

    /**
     * Writes every piece of {@code file} into {@code outDir} (created if needed),
     * named {@code NNN_0xOFFSET[_name].ext}.
     *
     * @return the pieces written
     */
    public static List<Item> split(final File file, final File outDir) throws IOException {
        if (!outDir.isDirectory() && !outDir.mkdirs()) throw new IOException("Cannot create directory " + outDir);
        try (ByteSource s = new ByteSource(file)) {
            final List<Item> items = scan(s);
            final byte[] buf = new byte[65536];
            int index = 0;
            int count = 0;
            for (final Item it : items) if (!it.isPadding() && it.path == null) count++;
            for (final Item it : items) {
                if (it.isPadding()) continue;
                final File target;
                if (it.path != null) {
                    target = SafePathBuilder.buildSafePath(outDir, it.path);
                    IOHelper.mkdirs(target.getParentFile());
                } else {
                    target = new File(outDir, fileName(index++, it, count));
                }
                if (it.deflated) {
                    try (InputStream in = new InflaterInputStream(new SourceStream(s, it.offset, it.length), new Inflater(true), 65536); OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                        int n;
                        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    }
                    continue;
                }
                try (OutputStream out = new BufferedOutputStream(new FileOutputStream(target), 65536)) {
                    long pos = it.offset;
                    final long end = it.offset + it.length;
                    while (pos < end) {
                        final int n = s.read(pos, buf, 0, (int) Math.min(buf.length, end - pos));
                        if (n <= 0) break;
                        out.write(buf, 0, n);
                        pos += n;
                    }
                }
            }
            return items;
        }
    }

    /** Output file name of a piece: 000_0x0003A200_name.ext */
    static String fileName(final int index, final Item it, final int count) {
        final String num = String.format(count > 999 ? "%04d" : "%03d", index);
        final StringBuilder sb = new StringBuilder(num).append(String.format("_0x%08X", it.offset));
        if (it.name != null) {
            String n = it.name;
            final String dotExt = "." + it.extension;
            if (n.toLowerCase().endsWith(dotExt.toLowerCase())) n = n.substring(0, n.length() - dotExt.length());
            if (n.length() > 80) n = n.substring(0, 80);
            sb.append('_').append(n);
        } else if (it.isUnknown()) {
            sb.append("_unknown");
        }
        return sb.append('.').append(it.extension).toString();
    }

    // =========================================================================
    // Scan
    // =========================================================================

    static List<Item> scan(final ByteSource s) throws IOException {
        final List<Item> items = new ArrayList<Item>();
        final DotNetBundle.Manifest bundle = DotNetBundle.find(s);
        if (bundle != null) scanBundle(s, bundle, items);
        else scanRange(s, 0, s.length(), items);
        return items;
    }

    /** .NET single-file bundle: the files listed by the manifest, the rest (apphost, gaps) scanned as usual. */
    private static void scanBundle(final ByteSource s, final DotNetBundle.Manifest m, final List<Item> items) throws IOException {
        final List<DotNetBundle.Entry> entries = new ArrayList<DotNetBundle.Entry>(m.entries);
        Collections.sort(entries, new Comparator<DotNetBundle.Entry>() {
            @Override
            public int compare(final DotNetBundle.Entry a, final DotNetBundle.Entry b) {
                return Long.compare(a.offset, b.offset);
            }
        });
        long cursor = 0;
        for (final DotNetBundle.Entry e : entries) {
            if (e.offset < cursor) continue; // overlapping entry: already written by the previous one
            if (e.offset > cursor) scanRange(s, cursor, e.offset, items);
            items.add(bundleItem(s, e));
            cursor = e.offset + e.storedSize();
        }
        if (m.start > cursor) scanRange(s, cursor, m.start, items);
        final String desc = ".NET single-file bundle manifest (" + m.entries.size() + " files, version " + m.major + ")" + (m.missing > 0 ? ", apphost missing: " + m.missing + " bytes cut off at the start" : "");
        items.add(new Item(m.start, m.end - m.start, "manifest", "bin", desc, "bundle_manifest", false));
        // Authenticode signature of the apphost, written after the manifest: the PKCS#7 data as a .p7b file
        long rest = m.end;
        final PeImage host = s.u8(0) == 'M' && s.u8(1) == 'Z' ? PeImage.parse(s, 0) : null;
        if (host != null && host.certSize > 8 && host.certOffset >= m.end && host.certOffset + host.certSize <= s.length()) {
            if (host.certOffset > rest) scanRange(s, rest, host.certOffset, items);
            items.add(new Item(host.certOffset, 8, "padding", "bin", "WIN_CERTIFICATE header (not written)", null, false));
            items.add(new Item(host.certOffset + 8, host.certSize - 8, "cert", "p7b", "Authenticode signature of the apphost (PKCS#7)", "signature", false));
            rest = host.certOffset + host.certSize;
        }
        if (rest < s.length()) scanRange(s, rest, s.length(), items);
    }

    private static Item bundleItem(final ByteSource s, final DotNetBundle.Entry e) throws IOException {
        final String path = e.path.replace('\\', '/');
        final int slash = path.lastIndexOf('/');
        final String base = path.substring(slash + 1);
        final int dot = base.lastIndexOf('.');
        final String ext = dot > 0 ? base.substring(dot + 1) : "bin";
        final String[] kinds = {"file", "assembly", "native library", "deps.json", "runtimeconfig.json", "symbols"};
        final String kind = e.type >= 0 && e.type < kinds.length ? kinds[e.type] : "file";
        if (e.compressedSize > 0) {
            return new Item(e.offset, e.compressedSize, "dotnet", ext, path + " - " + kind + ", deflated (" + e.size + " bytes)", base, false, path, true);
        }
        final Item id = e.size > 0 ? identify(s, e.offset) : null;
        final String type = id != null ? id.type : ext.equalsIgnoreCase("json") ? "json" : "dotnet";
        return new Item(e.offset, e.size, type, ext, path + " - " + kind, base, false, path, false);
    }

    /** Scans {@code [from, to)} for recognized files; the rest becomes unknown or padding pieces. */
    private static void scanRange(final ByteSource s, final long from, final long to, final List<Item> items) throws IOException {
        final long len = to;
        final boolean[] cand = candidateTable();
        final byte[] buf = new byte[SCAN_BUFFER];
        long gapStart = from;
        long pos = from;
        while (pos < len) {
            final int n = s.read(pos, buf, 0, (int) Math.min(buf.length, len - pos));
            if (n <= 0) break;
            boolean jumped = false;
            for (int i = 0; i < n; i++) {
                final int c = buf[i] & 0xFF;
                if (!cand[c]) continue;
                final long p = pos + i;
                Item it = identify(s, p);
                if (it == null || it.length <= 0) continue;
                if (p + it.length > len) it = new Item(p, len - p, it.type, it.extension, it.description, it.name, true);
                if (p > gapStart) items.add(unknown(s, gapStart, p - gapStart));
                items.add(it);
                gapStart = p + it.length;
                pos = gapStart;
                jumped = true;
                break;
            }
            if (!jumped) pos += n;
        }
        if (gapStart < len) items.add(unknown(s, gapStart, len - gapStart));
    }

    /** Gap between recognized files: "padding" if it only holds 0x00 bytes, else "unknown". */
    private static Item unknown(final ByteSource s, final long off, final long length) throws IOException {
        if (allZero(s, off, length)) return new Item(off, length, "padding", "bin", "zero bytes only (not written)", null, false);
        return new Item(off, length, "unknown", "bin", "unrecognized data", null, false);
    }

    private static boolean allZero(final ByteSource s, final long off, final long length) throws IOException {
        final byte[] buf = new byte[(int) Math.min(65536, Math.max(1, length))];
        long pos = off;
        final long end = off + length;
        while (pos < end) {
            final int n = s.read(pos, buf, 0, (int) Math.min(buf.length, end - pos));
            if (n <= 0) return false;
            for (int i = 0; i < n; i++) if (buf[i] != 0) return false;
            pos += n;
        }
        return true;
    }

    /** First bytes of the built-in signatures, plus the lead bytes of the registered probes. */
    private static boolean[] candidateTable() {
        final boolean[] t = new boolean[256];
        for (final int c : new int[] {'M', 0x7F, 'P', '7', 'R', 0x1F, 0xFD, 0x89, 0xFF, 'G', '%', 0xD0}) t[c] = true;
        for (final FormatProbe probe : PROBES) {
            final int[] lb = safeLeads(probe);
            if (lb != null) for (final int b : lb) if (b >= 0 && b < 256) t[b] = true;
        }
        return t;
    }

    private static int[] safeLeads(final FormatProbe p) {
        try {
            return p.leadBytes();
        } catch (final RuntimeException e) {
            return null;
        }
    }

    /** Recognizes a file starting at {@code p} of {@code s}, or returns null (used by the SFX extractor). */
    public static Item identifyAt(final ByteSource s, final long p) throws IOException {
        return identify(s, p);
    }

    /** Recognizes a file starting at {@code p} (built-in formats then plugin probes), or returns null. */
    static Item identify(final ByteSource s, final long p) throws IOException {
        final Item builtin = identifyBuiltin(s, p);
        if (builtin != null) return builtin;
        if (!PROBES.isEmpty()) {
            final int c0 = s.u8(p);
            for (final FormatProbe probe : PROBES) {
                final int[] lb = safeLeads(probe);
                boolean lead = lb == null;
                if (lb != null) for (final int b : lb) if ((b & 0xFF) == c0) { lead = true; break; }
                if (!lead) continue;
                try {
                    final Probe r = probe.probeAt(s, p);
                    if (r != null && r.length > 0) return new Item(p, r.length, r.type, r.extension, r.description, r.name, false);
                } catch (final RuntimeException ignored) {
                    // a faulty probe must not break carving
                }
            }
        }
        return null;
    }

    /** Recognizes a built-in file format starting at {@code p}, or returns null. */
    private static Item identifyBuiltin(final ByteSource s, final long p) throws IOException {
        final int c0 = s.u8(p);
        final int c1 = s.u8(p + 1);
        switch (c0) {
            case 'M':
                if (c1 == 'Z') return mz(s, p);
                if (c1 == 'S') return cab(s, p);
                return null;
            case 0x7F:
                return c1 == 'E' ? elf(s, p) : null;
            case 'P':
                return c1 == 'K' ? zip(s, p) : null;
            case '7':
                return c1 == 'z' ? sevenZ(s, p) : null;
            case 'R':
                if (c1 == 'a') return rar(s, p);
                if (c1 == 'I') return riff(s, p);
                return null;
            case 0x1F:
                return c1 == 0x8B ? gzip(s, p) : null;
            case 0xFD:
                return c1 == '7' ? xz(s, p) : null;
            case 0x89:
                return c1 == 'P' ? png(s, p) : null;
            case 0xFF:
                return c1 == 0xD8 ? jpeg(s, p) : null;
            case 'G':
                return c1 == 'I' ? gif(s, p) : null;
            case '%':
                return c1 == 'P' ? pdf(s, p) : null;
            case 0xD0:
                return c1 == 0xCF ? ole(s, p) : null;
            default:
                return null;
        }
    }

    /** Item clipped to the end of the file. */
    private static Item item(final ByteSource s, final long off, final long announced, final String type, final String ext, final String desc, final String name) {
        final long avail = s.length() - off;
        final boolean truncated = announced > avail;
        return new Item(off, truncated ? avail : announced, type, ext, desc, name, truncated);
    }

    // =========================================================================
    // Executables
    // =========================================================================

    private static Item mz(final ByteSource s, final long p) throws IOException {
        final PeImage pe = PeImage.parse(s, p);
        if (pe != null) return item(s, p, pe.size, "pe", pe.extension(), pe.describe(), pe.name);
        // MS-DOS executable (no PE header): size from the page count
        final int lastPage = s.u16le(p + 2);
        final int pages = s.u16le(p + 4);
        final int hdrParas = s.u16le(p + 8);
        final int relocTable = s.u16le(p + 0x18);
        if (lastPage < 0 || lastPage >= 512 || pages <= 0 || hdrParas < 2 || (relocTable != 0x1C && relocTable != 0x40 && relocTable != 0x3E)) return null;
        final long size = lastPage == 0 ? pages * 512L : (pages - 1) * 512L + lastPage;
        if (size < hdrParas * 16L) return null;
        return item(s, p, size, "mz", "exe", "MS-DOS executable", null);
    }

    private static Item elf(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 'L' || s.u8(p + 3) != 'F') return null;
        final int cls = s.u8(p + 4), data = s.u8(p + 5), version = s.u8(p + 6);
        if ((cls != 1 && cls != 2) || (data != 1 && data != 2) || version != 1) return null;
        final boolean le = data == 1, is64 = cls == 2;
        final int type = u16(s, p + 16, le);
        final int machine = u16(s, p + 18, le);
        final long phoff = is64 ? u64(s, p + 32, le) : u32(s, p + 28, le);
        final long shoff = is64 ? u64(s, p + 40, le) : u32(s, p + 32, le);
        final int ehsize = u16(s, p + (is64 ? 52 : 40), le);
        final int phentsize = u16(s, p + (is64 ? 54 : 42), le);
        final int phnum = u16(s, p + (is64 ? 56 : 44), le);
        final int shentsize = u16(s, p + (is64 ? 58 : 46), le);
        final int shnum = u16(s, p + (is64 ? 60 : 48), le);
        if (ehsize < 52 || phnum > 4096 || shnum > 65535 || (phnum > 0 && phentsize < 32) || (shnum > 0 && shentsize < 40)) return null;
        long end = ehsize;
        boolean interp = false;
        if (phnum > 0) {
            end = Math.max(end, phoff + (long) phnum * phentsize);
            for (int i = 0; i < phnum; i++) {
                final long ph = p + phoff + (long) i * phentsize;
                if (u32(s, ph, le) == 3) interp = true; // PT_INTERP: a program (PIE executables are ET_DYN)
                final long off = is64 ? u64(s, ph + 8, le) : u32(s, ph + 4, le);
                final long fsz = is64 ? u64(s, ph + 32, le) : u32(s, ph + 16, le);
                if (off < 0 || fsz < 0) return null;
                end = Math.max(end, off + fsz);
            }
        }
        if (shnum > 0) {
            end = Math.max(end, shoff + (long) shnum * shentsize);
            for (int i = 0; i < shnum; i++) {
                final long sh = p + shoff + (long) i * shentsize;
                final long shType = u32(s, sh + 4, le);
                if (shType == 8) continue; // SHT_NOBITS (.bss) has no file data
                final long off = is64 ? u64(s, sh + 24, le) : u32(s, sh + 16, le);
                final long sz = is64 ? u64(s, sh + 32, le) : u32(s, sh + 20, le);
                if (off < 0 || sz < 0) return null;
                end = Math.max(end, off + sz);
            }
        }
        if (end > (s.length() - p) + (1L << 20)) return null; // far beyond the file: not an ELF
        final boolean pie = type == 3 && interp;
        final String kind = type == 1 ? "object" : type == 2 ? "executable" : pie ? "executable (PIE)" : type == 3 ? "shared object" : type == 4 ? "core" : "file";
        return item(s, p, end, "elf", type == 3 && !pie ? "so" : type == 1 ? "o" : "elf", "ELF " + (is64 ? "64" : "32") + "-bit " + kind + String.format(" (machine 0x%X)", machine), null);
    }

    private static int u16(final ByteSource s, final long p, final boolean le) throws IOException {
        return le ? s.u16le(p) : s.u16be(p);
    }

    private static long u32(final ByteSource s, final long p, final boolean le) throws IOException {
        return le ? s.u32le(p) : s.u32be(p);
    }

    private static long u64(final ByteSource s, final long p, final boolean le) throws IOException {
        final long a = u32(s, p, le), b = u32(s, p + 4, le);
        if (a < 0 || b < 0) return -1;
        return le ? a | (b << 32) : (a << 32) | b;
    }

    // =========================================================================
    // Archives
    // =========================================================================

    private static final byte[] ZIP_LOCAL = {'P', 'K', 3, 4};
    private static final byte[] ZIP_EOCD = {'P', 'K', 5, 6};

    private static Item zip(final ByteSource s, final long p) throws IOException {
        if (!s.matches(p, ZIP_LOCAL)) return null;
        final int version = s.u16le(p + 4);
        final int method = s.u16le(p + 8);
        final int nameLen = s.u16le(p + 26);
        if (version > 100 || nameLen <= 0 || nameLen > 4096 || (method > 20 && method != 93 && method != 95 && method != 96 && method != 97 && method != 98 && method != 99)) return null;
        for (int i = 0; i < nameLen; i++) {
            final int c = s.u8(p + 30 + i);
            if (c < 0x20 && c != 0) return null; // entry names are printable (UTF-8 or CP437)
        }
        long from = p + 30;
        boolean anyEocd = false;
        long firstPlausible = -1;
        while (true) {
            final long e = s.indexOf(ZIP_EOCD, from, s.length());
            if (e < 0) break;
            anyEocd = true;
            final long cdSize = s.u32le(e + 12);
            final long cdOffset = s.u32le(e + 16);
            final int commentLen = s.u16le(e + 20);
            long cdStart = e - cdSize;
            long relOffset = cdOffset;
            if (cdOffset == 0xFFFFFFFFL && s.u32le(e - 20) == 0x07064B50L) {
                // ZIP64: the real values are in the ZIP64 end of central directory record
                final long z64 = s.u64le(e - 20 + 8);
                final long z64Pos = p + z64;
                if (s.u32le(z64Pos) == 0x06064B50L) {
                    cdStart = z64Pos - s.u64le(z64Pos + 40);
                    relOffset = s.u64le(z64Pos + 48);
                }
            }
            if (commentLen >= 0 && cdStart >= p && (cdSize == 0 || s.u32le(cdStart) == 0x02014B50L)) {
                final long end = e + 22 + commentLen;
                if (cdStart == p + relOffset) return item(s, p, end - p, "zip", "zip", "ZIP archive", null); // offsets relative to this ZIP: it is ours
                if (firstPlausible < 0) firstPlausible = end;
            }
            from = e + 4;
        }
        if (firstPlausible > 0) return item(s, p, firstPlausible - p, "zip", "zip", "ZIP archive (offsets relative to a container)", null);
        // No end of central directory at all: a truncated ZIP (the local entries are still readable)
        if (!anyEocd) return item(s, p, s.length() - p + 1, "zip", "zip", "ZIP archive", null);
        return null;
    }

    private static final byte[] SEVEN_Z = {'7', 'z', (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C};

    private static Item sevenZ(final ByteSource s, final long p) throws IOException {
        if (!s.matches(p, SEVEN_Z)) return null;
        final byte[] h = s.bytes(p + 12, 20);
        if (h == null) return null;
        final CRC32 crc = new CRC32();
        crc.update(h);
        if (crc.getValue() != s.u32le(p + 8)) return null;
        final long nho = s.u64le(p + 12), nhs = s.u64le(p + 20);
        if (nho < 0 || nhs < 0) return null;
        return item(s, p, 32 + nho + nhs, "7z", "7z", "7-Zip archive", null);
    }

    private static final byte[] RAR4 = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
    private static final byte[] RAR5 = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};

    private static Item rar(final ByteSource s, final long p) throws IOException {
        if (s.matches(p, RAR5)) return rar5(s, p);
        if (s.matches(p, RAR4)) return rar4(s, p);
        return null;
    }

    private static Item rar4(final ByteSource s, final long p) throws IOException {
        long pos = p + 7;
        final long len = s.length();
        boolean sawMain = false;
        while (pos + 7 <= len) {
            final int type = s.u8(pos + 2);
            final int flags = s.u16le(pos + 3);
            final int headSize = s.u16le(pos + 5);
            if (type < 0x72 || type > 0x7B || headSize < 7) break;
            if (type == 0x73) sawMain = true;
            long total = headSize;
            if (type == 0x74 || type == 0x7A) {
                long pack = s.u32le(pos + 7);
                if ((flags & 0x100) != 0) pack |= s.u32le(pos + 32) << 32;
                total += pack;
            } else if ((flags & 0x8000) != 0) {
                total += s.u32le(pos + 7);
            }
            pos += total;
            if (type == 0x7B) break;
        }
        if (!sawMain) return null;
        return item(s, p, pos - p, "rar", "rar", "RAR 4 archive", null);
    }

    private static Item rar5(final ByteSource s, final long p) throws IOException {
        long pos = p + 8;
        final long len = s.length();
        int blocks = 0;
        while (pos + 6 <= len) {
            final long[] v = new long[2];
            long q = pos + 4; // after CRC32
            if (!vint(s, q, v)) break;
            final long headSize = v[0];
            q += v[1];
            final long headStart = q;
            if (headSize < 2 || headSize > (1 << 21)) break;
            if (!vint(s, q, v)) break;
            final long type = v[0];
            q += v[1];
            if (!vint(s, q, v)) break;
            final long flags = v[0];
            q += v[1];
            long dataSize = 0;
            if ((flags & 1) != 0) { if (!vint(s, q, v)) break; q += v[1]; }
            if ((flags & 2) != 0) { if (!vint(s, q, v)) break; dataSize = v[0]; }
            if (type < 1 || type > 5) break;
            blocks++;
            if (type == 4) { pos = len; break; } // encrypted headers: the rest cannot be walked
            pos = headStart + headSize + dataSize;
            if (type == 5) break; // end of archive
        }
        if (blocks == 0) return null;
        return item(s, p, pos - p, "rar", "rar", "RAR 5 archive", null);
    }

    /** RAR5 variable-length integer: v[0] = value, v[1] = byte count. */
    private static boolean vint(final ByteSource s, final long pos, final long[] v) throws IOException {
        long value = 0;
        for (int i = 0; i < 10; i++) {
            final int b = s.u8(pos + i);
            if (b < 0) return false;
            value |= (long) (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                v[0] = value;
                v[1] = i + 1;
                return true;
            }
        }
        return false;
    }

    private static Item cab(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 'C' || s.u8(p + 3) != 'F' || s.u32le(p + 4) != 0) return null;
        final long size = s.u32le(p + 8);
        if (s.u8(p + 24) != 3 || s.u8(p + 25) != 1 || size < 36) return null;
        return item(s, p, size, "cab", "cab", "Microsoft Cabinet", null);
    }

    private static Item gzip(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 8) return null;
        final int flags = s.u8(p + 3);
        if ((flags & 0xE0) != 0) return null;
        long q = p + 10;
        String name = null;
        if ((flags & 4) != 0) q += 2 + s.u16le(q);
        if ((flags & 8) != 0) {
            final StringBuilder sb = new StringBuilder();
            while (s.u8(q) > 0 && sb.length() < 1024) sb.append((char) s.u8(q++));
            q++;
            name = PeImage.cleanName(sb.toString());
        }
        if ((flags & 16) != 0) { while (s.u8(q) > 0) q++; q++; }
        if ((flags & 2) != 0) q += 2;
        // Inflate to find where the deflate data ends
        final Inflater inf = new Inflater(true);
        try {
            final byte[] in = new byte[65536];
            final byte[] out = new byte[65536];
            long fed = q;
            while (!inf.finished()) {
                if (inf.needsInput()) {
                    final int n = s.read(fed, in, 0, in.length);
                    if (n <= 0) return item(s, p, s.length() - p + 1, "gzip", "gz", "GZIP data", name); // truncated
                    inf.setInput(in, 0, n);
                    fed += n;
                }
                if (inf.inflate(out) == 0 && inf.needsDictionary()) return null;
            }
            final long end = fed - inf.getRemaining() + 8;
            return item(s, p, end - p, "gzip", "gz", "GZIP data", name);
        } catch (final DataFormatException e) {
            return null;
        } finally {
            inf.end();
        }
    }

    private static Item xz(final ByteSource s, final long p) throws IOException {
        final byte[] magic = {(byte) 0xFD, '7', 'z', 'X', 'Z', 0};
        if (!s.matches(p, magic)) return null;
        final byte[] flags = s.bytes(p + 6, 2);
        if (flags == null || flags[0] != 0) return null;
        final CRC32 crc = new CRC32();
        crc.update(flags);
        if (crc.getValue() != s.u32le(p + 8)) return null;
        // Footer: CRC32(4) backward size(4) flags(2) "YZ", 4-byte aligned
        long from = p + 12;
        final byte[] yz = {'Y', 'Z'};
        while (true) {
            final long y = s.indexOf(yz, from, s.length());
            if (y < 0) return item(s, p, s.length() - p + 1, "xz", "xz", "XZ data", null); // truncated
            final long footer = y - 10;
            if (((y + 2 - p) & 3) == 0 && footer >= p + 12 && s.u8(footer + 8) == 0 && s.u8(footer + 9) == (flags[1] & 0xFF)) {
                final byte[] f = s.bytes(footer + 4, 6);
                final CRC32 c = new CRC32();
                c.update(f);
                if (c.getValue() == s.u32le(footer)) {
                    long end = y + 2;
                    // stream padding (multiple of 4 zero bytes) belongs to the stream
                    while (s.u32le(end) == 0 && end + 4 <= s.length()) end += 4;
                    return item(s, p, end - p, "xz", "xz", "XZ data", null);
                }
            }
            from = y + 1;
        }
    }

    // =========================================================================
    // Documents and images
    // =========================================================================

    private static Item ole(final ByteSource s, final long p) throws IOException {
        final byte[] magic = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
        if (!s.matches(p, magic)) return null;
        final int shift = s.u16le(p + 30);
        if (shift != 9 && shift != 12) return null;
        final int ss = 1 << shift;
        final long fatSectors = s.u32le(p + 44);
        if (fatSectors <= 0 || fatSectors > 1 << 20) return null;
        // FAT sector numbers: 109 in the header, then the DIFAT chain
        final List<Long> fat = new ArrayList<Long>();
        for (int i = 0; i < 109 && fat.size() < fatSectors; i++) fat.add(s.u32le(p + 76 + i * 4L));
        long difat = s.u32le(p + 68);
        int guard = 0;
        while (fat.size() < fatSectors && difat < 0xFFFFFFFAL && guard++ < 100000) {
            final long base = p + (difat + 1) * ss;
            for (int i = 0; i < ss / 4 - 1 && fat.size() < fatSectors; i++) fat.add(s.u32le(base + i * 4L));
            difat = s.u32le(base + ss - 4);
        }
        long maxSector = -1;
        for (int f = 0; f < fat.size(); f++) {
            final long fs = fat.get(f);
            if (fs < 0 || fs >= 0xFFFFFFFAL) continue;
            maxSector = Math.max(maxSector, fs);
            final long base = p + (fs + 1) * ss;
            for (int i = 0; i < ss / 4; i++) {
                final long v = s.u32le(base + i * 4L);
                if (v >= 0 && v != 0xFFFFFFFFL) maxSector = Math.max(maxSector, (long) f * (ss / 4) + i);
            }
        }
        if (maxSector < 0) return null;
        return item(s, p, (maxSector + 2) * ss, "ole", "ole", "OLE compound file (MSI, DOC, XLS...)", null);
    }

    private static Item png(final ByteSource s, final long p) throws IOException {
        final byte[] sig = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        if (!s.matches(p, sig)) return null;
        long q = p + 8;
        while (true) {
            final long len = s.u32be(q);
            if (len < 0 || len > 0x7FFFFFFFL) return null;
            for (int i = 4; i < 8; i++) {
                final int c = s.u8(q + i);
                if (c < 0) return item(s, p, s.length() - p + 1, "png", "png", "PNG image", null);
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return null;
            }
            final boolean iend = s.u32be(q + 4) == 0x49454E44L;
            q += 12 + len;
            if (iend) return item(s, p, q - p, "png", "png", "PNG image", null);
            if (q > s.length()) return item(s, p, q - p, "png", "png", "PNG image", null);
        }
    }

    private static Item jpeg(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 0xFF) return null;
        long q = p + 2;
        final long len = s.length();
        while (q + 4 <= len) {
            if (s.u8(q) != 0xFF) return null;
            final int m = s.u8(q + 1);
            if (m == 0xD9) return item(s, p, q + 2 - p, "jpeg", "jpg", "JPEG image", null);
            if (m == 0xFF) { q++; continue; }
            if (m >= 0xD0 && m <= 0xD7 || m == 0x01) { q += 2; continue; }
            final int segLen = s.u16be(q + 2);
            if (segLen < 2) return null;
            q += 2 + segLen;
            if (m == 0xDA) {
                // entropy-coded data: up to the next marker that is not a stuffed 0xFF00 or a restart marker
                while (q + 1 < len) {
                    if (s.u8(q) == 0xFF) {
                        final int n = s.u8(q + 1);
                        if (n != 0 && !(n >= 0xD0 && n <= 0xD7) && n != 0xFF) break;
                    }
                    q++;
                }
            }
        }
        return item(s, p, len - p + 1, "jpeg", "jpg", "JPEG image", null);
    }

    private static Item gif(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 'F' || s.u8(p + 3) != '8' || (s.u8(p + 4) != '7' && s.u8(p + 4) != '9') || s.u8(p + 5) != 'a') return null;
        long q = p + 13;
        final int lsd = s.u8(p + 10);
        if ((lsd & 0x80) != 0) q += 3L * (1 << ((lsd & 7) + 1));
        final long len = s.length();
        while (q < len) {
            final int b = s.u8(q);
            if (b == 0x3B) return item(s, p, q + 1 - p, "gif", "gif", "GIF image", null);
            if (b == 0x21) {
                q += 2;
            } else if (b == 0x2C) {
                final int flags = s.u8(q + 9);
                q += 10;
                if ((flags & 0x80) != 0) q += 3L * (1 << ((flags & 7) + 1));
                q += 1; // LZW minimum code size
            } else {
                return null;
            }
            // sub-blocks
            while (true) {
                final int n = s.u8(q);
                if (n < 0) return item(s, p, len - p + 1, "gif", "gif", "GIF image", null);
                q += 1 + n;
                if (n == 0) break;
            }
        }
        return item(s, p, len - p + 1, "gif", "gif", "GIF image", null);
    }

    private static Item pdf(final ByteSource s, final long p) throws IOException {
        if (!s.matches(p, new byte[] {'%', 'P', 'D', 'F', '-'})) return null;
        final byte[] eof = {'%', '%', 'E', 'O', 'F'};
        long from = p + 5;
        long end = -1;
        while (true) {
            final long e = s.indexOf(eof, from, s.length());
            if (e < 0) break;
            long q = e + 5;
            while (s.u8(q) == '\r' || s.u8(q) == '\n' || s.u8(q) == ' ') q++;
            end = q;
            // incremental update: another body follows ("N 0 obj", "xref")
            final int c = s.u8(q);
            if (!(c >= '0' && c <= '9') && c != 'x') break;
            from = q;
        }
        if (end < 0) return item(s, p, s.length() - p + 1, "pdf", "pdf", "PDF document", null);
        return item(s, p, end - p, "pdf", "pdf", "PDF document", null);
    }

    private static Item riff(final ByteSource s, final long p) throws IOException {
        if (s.u8(p + 2) != 'F' || s.u8(p + 3) != 'F') return null;
        final long size = s.u32le(p + 4);
        final StringBuilder form = new StringBuilder();
        for (int i = 8; i < 12; i++) {
            final int c = s.u8(p + i);
            if (c < 0x20 || c > 0x7E) return null;
            form.append((char) c);
        }
        final String f = form.toString().trim();
        final String ext = f.equalsIgnoreCase("WAVE") ? "wav" : f.equalsIgnoreCase("AVI") ? "avi" : f.equalsIgnoreCase("ACON") ? "ani" : f.equalsIgnoreCase("WEBP") ? "webp" : "riff";
        return item(s, p, 8 + size + (size & 1), "riff", ext, "RIFF " + f, null);
    }

    /** Stream over {@code [offset, offset + length)} of a byte source. */
    static final class SourceStream extends InputStream {
        private final ByteSource s;
        private long pos;
        private final long end;

        SourceStream(final ByteSource s, final long offset, final long length) {
            this.s = s;
            this.pos = offset;
            this.end = offset + length;
        }

        @Override
        public int read() throws IOException {
            if (pos >= end) return -1;
            return s.u8(pos++);
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (pos >= end) return -1;
            final int n = s.read(pos, b, off, (int) Math.min(len, end - pos));
            if (n <= 0) return -1;
            pos += n;
            return n;
        }
    }
}
