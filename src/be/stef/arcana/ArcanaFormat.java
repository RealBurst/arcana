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
package be.stef.arcana;

/**
 * Enumeration of archive formats supported by Arcana.
 *
 * <p>Each constant carries the file extensions commonly associated with the
 * format and a human-readable label.  The {@link be.stef.arcana.detector.ArchiveDetector}
 * uses magic-byte signatures as the primary detection mechanism and falls back
 * to extension matching when the signature is ambiguous (e.g. plain TAR).</p>
 *
 * @author Stef
 * @since 1.0
 */
public enum ArcanaFormat {

    /** ZIP archive (.zip, .jar, .war, .ear). Decompressed via java.util.zip. */
    ZIP("ZIP", new String[]{"zip", "jar", "war", "ear"}),

    /** GZIP-compressed single file (.gz). Decompressed via java.util.zip. */
    GZIP("GZIP", new String[]{"gz", "gzip"}),

    /** BZIP2-compressed single file (.bz2). Pure-Java decompressor. */
    BZIP2("BZIP2", new String[]{"bz2", "bzip2"}),

    /** TAR archive, uncompressed (.tar). Pure-Java reader. */
    TAR("TAR", new String[]{"tar"}),

    /** TAR archive compressed with GZIP (.tar.gz, .tgz). */
    TAR_GZ("TAR+GZIP", new String[]{"tar.gz", "tgz"}),

    /** TAR archive compressed with BZIP2 (.tar.bz2, .tbz2). */
    TAR_BZ2("TAR+BZIP2", new String[]{"tar.bz2", "tbz2", "tbz"}),

    /** RAR archive, version 4 or 5 (.rar). Decompressed via unrar5j engine. */
    RAR("RAR", new String[]{"rar"}),

    /** Zstandard-compressed single file (.zst). Pure-Java decompressor. */
    ZSTD("Zstandard", new String[]{"zst", "zstd"}),

    /** Format could not be determined from magic bytes or extension. */
    SEVEN_Z("7-Zip", new String[]{"7z"}),
    
    /** XZ-compressed single file (.xz). Pure-Java decompressor (XZ for Java). */
    XZ("XZ", new String[]{"xz"}),

    /** TAR archive compressed with XZ (.tar.xz, .txz). */
    TAR_XZ("TAR+XZ", new String[]{"tar.xz", "txz"}),

    /** LZ4-compressed single file (.lz4). Pure-Java decompressor (LZ4 Frame format). */
    LZ4("LZ4", new String[]{"lz4"}),

    /** TAR archive compressed with LZ4 (.tar.lz4, .tlz4). */
    TAR_LZ4("TAR+LZ4", new String[]{"tar.lz4", "tlz4"}),

    /** TAR archive compressed with Zstandard (.tar.zst, .tzst). */
    TAR_ZSTD("TAR+Zstandard", new String[]{"tar.zst", "tzst"}),

    /** Snappy-compressed single file (.snappy). Pure-Java decompressor. */
    SNAPPY("Snappy", new String[]{"snappy"}),

    /** CPIO archive (.cpio). Supports SVR4 newc (070701/070702) and old ASCII odc (070707) formats. */
    CPIO("CPIO", new String[]{"cpio"}),

    /** Raw LZMA stream (.lzma). Single-file decompressor. */
    LZMA("LZMA", new String[]{"lzma"}),

    /** Unix compress (.Z). LZW algorithm. Single-file decompressor. */
    Z("Unix compress", new String[]{"Z"}),

    /** Unix AR archive (.a) and Debian package (.deb). */
    AR("AR", new String[]{"a", "deb"}),

    /** RPM package (.rpm). CPIO payload with gzip/bzip2/xz/zstd/lzma compression. */
    RPM("RPM", new String[]{"rpm"}),

    /** XAR archive (.xar). Apple eXtensible ARchive with XML TOC. */
    XAR("XAR", new String[]{"xar"}),

    /** ISO 9660 disc image (.iso), with Joliet and Rock Ridge support. Pure-Java reader. */
    ISO("ISO 9660", new String[]{"iso"}),
    
    /** LHA/LZH archive (.lzh, .lha). Extraction: -lh0- to -lh7-. Compression: -lh5-. */
    LHA("LHA/LZH", new String[]{"lzh", "lha"}),

    /** Microsoft Cabinet archive (.cab). MSZIP and LZX extraction; MSZIP-only creation. */
    CAB("Cabinet", new String[]{"cab"}),

    /** Brotli-compressed single file (.br). Extraction only (no pure-Java encoder). */
    BROTLI("Brotli", new String[]{"br"}),

    /** TAR archive compressed with Brotli (.tar.br, .tbr). Extraction only. */
    TAR_BROTLI("TAR+Brotli", new String[]{"tar.br", "tbr"}),

    /** Self-extracting executable (Windows EXE carrying a ZIP, RAR, 7z, CAB... archive). */
    SFX("Self-extracting executable", new String[]{"exe"}),

    UNKNOWN("Unknown", new String[]{});

    // -------------------------------------------------------------------------

    private final String label;
    private final String[] extensions;

    ArcanaFormat(String label, String[] extensions) {
        this.label  = label;
        this.extensions = extensions;
    }

    /**
     * Returns the human-readable name of this format (e.g. {@code "TAR+GZIP"}).
     *
     * @return format label
     */
    public String getLabel() {
        return label;
    }

    /**
     * Returns the file extensions associated with this format (lower-case, without dot).
     *
     * @return array of extensions, never null, may be empty
     */
    public String[] getExtensions() {
        return extensions;
    }

    /**
     * Returns whether the given file extension (without leading dot, case-insensitive)
     * is associated with this format.
     *
     * @param ext file extension to test
     * @return {@code true} if this format recognises the extension
     */
    public boolean matchesExtension(String ext) {
        if (ext == null) return false;
        String lower = ext.toLowerCase();
        for (String e : extensions) {
            if (e.equals(lower)) return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return label;
    }
}
