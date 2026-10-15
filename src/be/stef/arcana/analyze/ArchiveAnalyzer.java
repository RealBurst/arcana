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

import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.dmg.DmgContent;
import be.stef.arcana.formats.dmg.UdifImage;
import be.stef.arcana.formats.hfs.HfsPlusReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Identifies archives and compressed streams by their signature, and refines a
 * few of them: the RAR major version, the real kind of a ZIP container
 * (JAR, APK, docx/xlsx/pptx, EPUB...), the format and partitions of an Apple
 * disk image.
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
        // first: the data fork of a disk image may start with any stream ("BZh"...)
        final Identification dmg = dmg(s);
        if (dmg != null) return dmg;
        final int c0 = s.u8(0), c1 = s.u8(1);
        if (c0 == 'P' && c1 == 'K' && (s.u8(2) == 3 || s.u8(2) == 5 || s.u8(2) == 7)) return zip(s, fileName);
        if (c0 == 'R' && c1 == 'a' && s.u8(2) == 'r' && s.u8(3) == '!') return rar(s);
        if (c0 == '7' && c1 == 'z' && s.u8(2) == 0xBC && s.u8(3) == 0xAF) return sevenZip(s);
        if (c0 == 0x1F && c1 == 0x8B) return simple("archive", "GZIP", "GZIP compressed stream");
        if (c0 == 0xFD && c1 == '7' && s.u8(2) == 'z' && s.u8(3) == 'X') return simple("archive", "XZ", "XZ compressed stream");
        if (c0 == 'B' && c1 == 'Z' && s.u8(2) == 'h') return bzip2(s);
        if (c0 == 0x28 && c1 == 0xB5 && s.u8(2) == 0x2F && s.u8(3) == 0xFD) return simple("archive", "Zstandard", "Zstandard compressed stream");
        if (c0 == 0x04 && c1 == 0x22 && s.u8(2) == 0x4D && s.u8(3) == 0x18) return simple("archive", "LZ4", "LZ4 frame");
        if (c0 == 'L' && c1 == 'Z' && s.u8(2) == 'I' && s.u8(3) == 'P') return lzip(s);
        if (c0 == 0x89 && s.u32be(1) == 0x4C5A4F00L && s.u32be(5) == 0x0D0A1A0AL) return lzop(s);
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

    private static Identification lzip(final ByteSource s) throws IOException {
        // "LZIP", version, coded dictionary size (2^(bits 0-4) minus bits 5-7 sixteenths)
        final int coded = s.u8(5);
        final long base = 1L << (coded & 0x1F);
        final long dict = base - (base / 16) * (coded >>> 5);
        return Identification.of("archive", "lzip").version(String.valueOf(s.u8(4))).description("lzip compressed stream (LZMA)").detail("dictionary size", dict >= 1024 ? (dict / 1024) + " KB" : dict + " bytes").build();
    }

    private static Identification lzop(final ByteSource s) throws IOException {
        // version (16-bit BE) at 9; method at 15 from version 0x0940 on, else at 13
        final int version = s.u16be(9);
        final int method = s.u8(version >= 0x0940 ? 15 : 13);
        final String m = method == 1 ? "LZO1X-1" : method == 2 ? "LZO1X-1(15)" : method == 3 ? "LZO1X-999" : "method " + method;
        return Identification.of("archive", "lzop").version(String.format("%X.%X%X", version >> 12, (version >> 8) & 0xF, (version >> 4) & 0xF)).description("lzop compressed stream (LZO)").detail("method", m).build();
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

    /** Apple disk image: "koly" trailer, or encrypted / sparse image header. */
    private static Identification dmg(final ByteSource s) throws IOException {
        final UdifImage.Input in = new UdifImage.Input() {
            @Override
            public long length() {
                return s.length();
            }

            @Override
            public int read(final long pos, final byte[] b, final int off, final int len) throws IOException {
                return s.read(pos, b, off, len);
            }

            @Override
            public void close() {
                // the caller owns the source
            }
        };
        final String kind = UdifImage.probe(in);
        if (kind == null) return null;
        final Identification.Builder b = Identification.of("archive", "DMG");
        if (kind.equals("encrypted")) return b.description("Apple disk image, encrypted (AES): not supported").detail("encrypted", "yes (not supported)").build();
        if (kind.equals("sparse")) return b.description("Apple sparse disk image (.sparseimage): not supported").build();
        try (UdifImage img = new UdifImage(in)) {
            b.version(String.valueOf(img.getVersion())).description("Apple disk image (UDIF), " + img.getFormatName());
            b.detail("format", img.getFormatName());
            final int v = img.getImageVariant();
            b.detail("image variant", v == 1 ? "1 (device image)" : v == 2 ? "2 (partition image)" : String.valueOf(v));
            b.detail("size", img.getSectorCount() * UdifImage.SECTOR + " bytes (" + img.getSectorCount() + " sectors)");
            b.detail("data fork checksum", img.getDataForkChecksumType() == UdifImage.CHECKSUM_CRC32 ? String.format("CRC32 %08x", img.getDataForkChecksum()) : "type " + img.getDataForkChecksumType());
            b.detail("partitions", img.getPartitions().size());
            for (final DmgContent.Item it : DmgContent.plan(img)) {
                final UdifImage.Partition p = it.partition;
                String d;
                if (it.kind == DmgContent.SCHEME) {
                    d = "partition scheme, not extracted";
                } else if (it.kind == DmgContent.EMPTY) {
                    d = "empty, not extracted";
                } else if (it.kind == DmgContent.HFS) {
                    final HfsPlusReader r = new HfsPlusReader(DmgContent.view(img.openPartition(p), it));
                    d = (r.getSignature().equals("HX") ? "HFSX" : "HFS+") + " volume \"" + r.getVolumeName() + "\" (signature " + r.getSignature() + ", version " + r.getVersion() + ", " + r.getFileCount() + " files, " + r.getFolderCount() + " folders" + (r.isJournaled() ? ", journaled" : "") + ")";
                    r.walk(e -> { });
                    if (r.getResourceForkCount() > 0) d += ", " + r.getResourceForkCount() + " resource fork(s) not extracted";
                    if (r.getDirectoryLinkCount() > 0) d += ", " + r.getDirectoryLinkCount() + " directory hard link(s) not extracted";
                } else {
                    d = (it.fileSystem != null ? it.fileSystem : "unknown file system") + ", extracted as a raw image: " + it.target;
                }
                b.detail("partition " + p.id + (it.subIndex >= 0 ? "." + it.subIndex : ""), it.name + ": " + d);
            }
        } catch (final ArcanaUnsupportedFormatException e) {
            b.description("Apple disk image (UDIF): " + e.getMessage());
        } catch (final IOException e) {
            b.detail("error", e.getMessage());
        }
        return b.build();
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
