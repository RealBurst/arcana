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
package be.stef.arcana.analyze;

import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Identifies archives and compressed streams by their signature, and refines a
 * few of them: the RAR major version, and the real kind of a ZIP container
 * (JAR, APK, docx/xlsx/pptx, EPUB...).
 *
 * @author Stef
 * @since 1.4
 */
public final class ArchiveAnalyzer implements ArcanaAnalyzer {

    @Override
    public String getId() {
        return "arcana.archive";
    }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        final int c0 = s.u8(0), c1 = s.u8(1);
        if (c0 == 'P' && c1 == 'K' && (s.u8(2) == 3 || s.u8(2) == 5 || s.u8(2) == 7)) return zip(s, fileName);
        if (c0 == 'R' && c1 == 'a' && s.u8(2) == 'r' && s.u8(3) == '!') return rar(s);
        if (c0 == '7' && c1 == 'z' && s.u8(2) == 0xBC && s.u8(3) == 0xAF) return sevenZip(s);
        if (c0 == 0x1F && c1 == 0x8B) return simple("archive", "GZIP", "GZIP compressed stream");
        if (c0 == 0xFD && c1 == '7' && s.u8(2) == 'z' && s.u8(3) == 'X') return simple("archive", "XZ", "XZ compressed stream");
        if (c0 == 'B' && c1 == 'Z' && s.u8(2) == 'h') return bzip2(s);
        if (c0 == 0x28 && c1 == 0xB5 && s.u8(2) == 0x2F && s.u8(3) == 0xFD) return simple("archive", "Zstandard", "Zstandard compressed stream");
        if (c0 == 0x04 && c1 == 0x22 && s.u8(2) == 0x4D && s.u8(3) == 0x18) return simple("archive", "LZ4", "LZ4 frame");
        if (c0 == 'M' && c1 == 'S' && s.u8(2) == 'C' && s.u8(3) == 'F') return cab(s);
        if (c0 == 0x1F && (c1 == 0x9D || c1 == 0xA0)) return simple("archive", "compress", "Unix compress (.Z) stream");
        if (matchAt(s, 257, "ustar")) return simple("archive", "TAR", "TAR (POSIX ustar) archive");
        if (c0 == '!' && c1 == '<' && matchAt(s, 0, "!<arch>")) return ar(s);
        if (isLha(s)) return lha(s);
        return null;
    }

    private static Identification zip(final ByteSource s, final String fileName) throws IOException {
        final int versionNeeded = s.u16le(4);
        final Identification.Builder b = Identification.of("archive", "ZIP")
                .description("ZIP archive")
                .detail("minimum version to extract", (versionNeeded / 10) + "." + (versionNeeded % 10));
        // Refine by well-known member names near the start of the archive.
        final String name = fileName != null ? fileName.toLowerCase() : "";
        if (contains(s, "AndroidManifest.xml") && contains(s, "classes.dex")) {
            return b.type("APK").description("Android application package (ZIP)").detail("category", "Android app").build();
        }
        if (matchAt(s, 30, "mimetypeapplication/epub+zip")) {
            return b.type("EPUB").description("EPUB e-book (ZIP)").build();
        }
        if (contains(s, "[Content_Types].xml")) {
            if (name.endsWith(".docx") || contains(s, "word/document.xml")) return b.type("DOCX").description("Word document (Office Open XML)").build();
            if (name.endsWith(".xlsx") || contains(s, "xl/workbook.xml")) return b.type("XLSX").description("Excel workbook (Office Open XML)").build();
            if (name.endsWith(".pptx") || contains(s, "ppt/presentation.xml")) return b.type("PPTX").description("PowerPoint presentation (Office Open XML)").build();
            return b.type("OOXML").description("Office Open XML document (ZIP)").build();
        }
        if (contains(s, "META-INF/MANIFEST.MF") && (name.endsWith(".jar") || name.endsWith(".war") || name.endsWith(".ear"))) {
            return b.type("JAR").description("Java archive (ZIP)").build();
        }
        return b.build();
    }

    private static Identification rar(final ByteSource s) throws IOException {
        // "Rar!\x1A\x07" then 0x00 (RAR 4.x) or 0x01 0x00 (RAR 5.0)
        final boolean v5 = s.u8(6) == 0x01 && s.u8(7) == 0x00;
        return Identification.of("archive", "RAR")
                .version(v5 ? "5" : "4")
                .description("RAR archive, version " + (v5 ? "5.0" : "1.5-4.x"))
                .build();
    }

    private static Identification sevenZip(final ByteSource s) throws IOException {
        final int major = s.u8(6), minor = s.u8(7);
        return Identification.of("archive", "7-Zip")
                .version(major + "." + String.format("%02d", minor))
                .description("7-Zip archive (format version " + major + "." + String.format("%02d", minor) + ")")
                .build();
    }

    private static Identification bzip2(final ByteSource s) throws IOException {
        final int level = s.u8(3);
        final String block = level >= '1' && level <= '9' ? (level - '0') * 100 + " KB" : null;
        return Identification.of("archive", "bzip2").description("bzip2 compressed stream").detail("block size", block).build();
    }

    private static Identification cab(final ByteSource s) throws IOException {
        final int minor = s.u8(24), major = s.u8(25);
        final int folders = s.u16le(26), files = s.u16le(28);
        return Identification.of("archive", "Cabinet")
                .version(major + "." + minor)
                .description("Microsoft Cabinet (CAB) archive")
                .detail("files", files)
                .detail("folders", folders)
                .build();
    }

    private static Identification ar(final ByteSource s) throws IOException {
        // Debian packages are "ar" archives beginning with debian-binary.
        if (matchAt(s, 8, "debian-binary")) return Identification.of("archive", "DEB").description("Debian package (ar archive)").build();
        return Identification.of("archive", "AR").description("Unix ar archive (static library or package)").build();
    }

    private static boolean isLha(final ByteSource s) throws IOException {
        // "-lhX-" or "-lzX-" at offset 2
        if (s.u8(2) != '-' || s.u8(6) != '-') return false;
        final int a = s.u8(3), b = s.u8(4);
        return (a == 'l') && (b == 'h' || b == 'z');
    }

    private static Identification lha(final ByteSource s) throws IOException {
        final byte[] m = s.bytes(2, 5);
        final String method = m != null ? new String(m, StandardCharsets.US_ASCII) : "-lh?-";
        return Identification.of("archive", "LHA")
                .description("LHA/LZH archive (method " + method + ")")
                .detail("method", method)
                .build();
    }

    private static Identification simple(final String cat, final String type, final String desc) {
        return Identification.of(cat, type).description(desc).build();
    }

    private static boolean matchAt(final ByteSource s, final long pos, final String text) throws IOException {
        final byte[] want = text.getBytes(StandardCharsets.US_ASCII);
        return s.matches(pos, want);
    }

    /** True if {@code text} appears in the first 64 KB of the file (member names of a ZIP). */
    private static boolean contains(final ByteSource s, final String text) throws IOException {
        return s.indexOf(text.getBytes(StandardCharsets.US_ASCII), 0, Math.min(s.length(), 1 << 16)) >= 0;
    }
}
