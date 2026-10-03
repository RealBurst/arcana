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
package be.stef.arcana.detector;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import be.stef.arcana.ArcanaFormat;

/**
 * Detects the {@link ArcanaFormat} of an archive.
 *
 * <h3>Detection strategy</h3>
 * <ol>
 *   <li><strong>Magic bytes</strong> (primary) - reads the first few bytes of
 *       the file and compares them against known signatures.  This is reliable
 *       regardless of the file extension.</li>
 *   <li><strong>File extension</strong> (fallback) - used when magic bytes are
 *       ambiguous or not available (e.g. plain TAR has no signature).</li>
 * </ol>
 *
 * <h3>Magic byte signatures</h3>
 * <pre>
 *   RAR4  : 52 61 72 21 1A 07 00
 *   RAR5  : 52 61 72 21 1A 07 01 00
 *   ZIP   : 50 4B 03 04
 *   GZIP  : 1F 8B
 *   BZIP2 : 42 5A 68 ('B','Z','h')
 *   ZSTD  : FD 2F B5 28 (little-endian magic 0xFD2FB528)
 *   TAR   : 75 73 74 61 72 at offset 257 ("ustar")
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public final class ArchiveDetector {

    // ---- Magic byte constants ----
    private static final byte[] MAGIC_RAR4  = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
    private static final byte[] MAGIC_RAR5  = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
    private static final byte[] MAGIC_ZIP   = {0x50, 0x4B, 0x03, 0x04};
    private static final byte[] MAGIC_GZIP  = {0x1F, (byte) 0x8B};
    private static final byte[] MAGIC_BZIP2 = {0x42, 0x5A, 0x68};
    private static final byte[] MAGIC_7Z    = {0x37, 0x7A, (byte)0xBC, (byte)0xAF, 0x27, 0x1C};
    private static final byte[] MAGIC_ZSTD  = {(byte) 0xFD, 0x2F, (byte) 0xB5, 0x28};
    private static final byte[] MAGIC_TAR   = {0x75, 0x73, 0x74, 0x61, 0x72}; // "ustar" at offset 257
    private static final byte[] MAGIC_XZ    = {(byte) 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
    private static final byte[] MAGIC_LZ4    = {0x04, 0x22, 0x4D, 0x18};
    private static final byte[] MAGIC_SNAPPY   = {(byte) 0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59};
    private static final byte[] MAGIC_LZMA     = {0x5D};                           // props byte 0x5D (most common)
    private static final byte[] MAGIC_Z        = {0x1F, (byte) 0x9D};              // Unix compress
    private static final byte[] MAGIC_AR       = {0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A}; // "!<arch>\n"
    private static final byte[] MAGIC_RPM      = {(byte) 0xED, (byte) 0xAB, (byte) 0xEE, (byte) 0xDB};
    private static final byte[] MAGIC_XAR      = {0x78, 0x61, 0x72, 0x21};         // "xar!"
    private static final byte[] MAGIC_CPIO_NEWC = {0x30, 0x37, 0x30, 0x37, 0x30, 0x31}; // "070701"
    private static final byte[] MAGIC_CPIO_CRC  = {0x30, 0x37, 0x30, 0x37, 0x30, 0x32}; // "070702"
    private static final byte[] MAGIC_CPIO_ODC  = {0x30, 0x37, 0x30, 0x37, 0x30, 0x37}; // "070707"
    private static final byte[] MAGIC_CAB       = {0x4D, 0x53, 0x43, 0x46};             // "MSCF"
    private static final byte[] MAGIC_WIM       = {0x4D, 0x53, 0x57, 0x49, 0x4D, 0x00, 0x00, 0x00}; // "MSWIM\0\0\0"
    private static final byte[] MAGIC_SQUASHFS  = {0x68, 0x73, 0x71, 0x73};             // "hsqs" (SquashFS 4, little-endian)

    /** Number of bytes to read for magic-byte detection (must cover TAR offset 257+5). */
    private static final int PROBE_SIZE = 264;

    private ArchiveDetector() {}

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Detects the format of the given file.
     *
     * <p>The file must be readable.  At most {@value #PROBE_SIZE} bytes are read
     * for the magic-byte probe.</p>
     *
     * @param file archive file to inspect
     * @return detected format, or {@link ArcanaFormat#UNKNOWN} if unrecognised
     * @throws IOException if the file cannot be opened or read
     */
    /**
     * Detects the format from the file content only (magic bytes, ISO 9660
     * signature), without looking at the extension.
     *
     * @since 1.3
     */
    public static ArcanaFormat detectByContent(File file) throws IOException {
        ArcanaFormat byMagic = detectByMagic(readProbe(file));
        if (byMagic != ArcanaFormat.UNKNOWN) return byMagic;
        return discFormat(file);
    }

    /**
     * Detects the format from the magic bytes, then the ISO 9660 signature, then
     * the file extension.
     *
     * @param file the archive to inspect
     * @return the detected format, or UNKNOWN
     * @throws IOException if the file cannot be opened or read
     */
    public static ArcanaFormat detect(File file) throws IOException {
        byte[] probe = readProbe(file);
        ArcanaFormat byMagic = detectByMagic(probe);
        if (byMagic != ArcanaFormat.UNKNOWN) return byMagic;
        ArcanaFormat disc = discFormat(file);
        if (disc != ArcanaFormat.UNKNOWN) return disc;
        // Magic bytes did not match - fall back to extension
        return detectByExtension(file.getName());
    }

    /**
     * Disc images, recognized by the volume descriptors from sector 16 on (2048-byte
     * sectors): UDF when a "NSR02" / "NSR03" descriptor is present (UDF-only images and
     * UDF bridge discs such as DVDs and Windows install media, whose ISO 9660 part may
     * be incomplete), else ISO 9660 ("CD001").
     */
    private static ArcanaFormat discFormat(File file) {
        if (isUdf(file)) return ArcanaFormat.UDF;
        return isIso9660(file) ? ArcanaFormat.ISO : ArcanaFormat.UNKNOWN;
    }

    private static boolean isUdf(File file) {
        if (file.length() < 34 * 2048L) return false;
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(file, "r")) {
            byte[] id = new byte[5];
            // Volume Recognition Sequence (ECMA-167 2/8.3): BEA01, then NSR0x, then TEA01
            for (int sector = 16; sector < 32; sector++) {
                raf.seek(sector * 2048L + 1);
                raf.readFully(id);
                String s = new String(id, java.nio.charset.StandardCharsets.US_ASCII);
                if (s.equals("NSR02") || s.equals("NSR03")) return true;
                if (s.equals("TEA01")) return false;
                if (id[0] == 0 && id[1] == 0) continue; // 4096-byte sectors: descriptors every other 2 KiB
                if (!s.equals("BEA01") && !s.equals("CD001") && !s.equals("CDW02") && !s.equals("BOOT2")) return false;
            }
            return false;
        } catch (java.io.IOException e) {
            return false;
        }
    }

    private static boolean isIso9660(File file) {
       if (file.length() < 32769L + 5L) return false;
       try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(file, "r")) {
           raf.seek(32769L);
           byte[] id = new byte[5];
           raf.readFully(id);
           return id[0] == 'C' && id[1] == 'D' && id[2] == '0' && id[3] == '0' && id[4] == '1';
       } catch (java.io.IOException e) {
           return false;
       }
    }
    
    /**
     * Detects the format from a probe byte array (already read by the caller).
     *
     * <p>Useful when the caller has already read the beginning of the stream
     * and can provide it here without re-opening the file.</p>
     *
     * @param probe first bytes of the archive (should be at least {@value #PROBE_SIZE} bytes when available)
     * @return detected format, or {@link ArcanaFormat#UNKNOWN}
     */
    public static ArcanaFormat detectByMagic(byte[] probe) {
        if (probe == null || probe.length == 0) return ArcanaFormat.UNKNOWN;

        // RAR5 must be checked before RAR4 (RAR5 prefix is a superset of RAR4 prefix)
        if (startsWith(probe, MAGIC_RAR5))  return ArcanaFormat.RAR;
        if (startsWith(probe, MAGIC_RAR4))  return ArcanaFormat.RAR;
        if (startsWith(probe, MAGIC_ZIP))   return ArcanaFormat.ZIP;
        if (startsWith(probe, MAGIC_GZIP))  return detectGzipOrTarGz(probe);
        if (startsWith(probe, MAGIC_BZIP2)) return detectBzip2OrTarBz2(probe);
        if (startsWith(probe, MAGIC_7Z))    return ArcanaFormat.SEVEN_Z;
        if (startsWith(probe, MAGIC_ZSTD))  return ArcanaFormat.ZSTD;
        if (startsWith(probe, MAGIC_XZ))    return detectXzOrTarXz(probe);
        if (startsWith(probe, MAGIC_LZ4))   return detectLz4OrTarLz4(probe);
        if (startsWith(probe, MAGIC_SNAPPY))    return ArcanaFormat.SNAPPY;
        if (startsWith(probe, MAGIC_CPIO_NEWC) || startsWith(probe, MAGIC_CPIO_CRC) || startsWith(probe, MAGIC_CPIO_ODC)) return ArcanaFormat.CPIO;
        if (startsWith(probe, MAGIC_Z))     return ArcanaFormat.Z;
        if (startsWith(probe, MAGIC_AR))    return ArcanaFormat.AR;
        if (startsWith(probe, MAGIC_RPM))   return ArcanaFormat.RPM;
        if (startsWith(probe, MAGIC_XAR))   return ArcanaFormat.XAR;
        // LZMA: magic is just the props byte 0x5D -- ambiguous, rely on extension
        if (startsWith(probe, MAGIC_CAB))   return ArcanaFormat.CAB;
        if (startsWith(probe, MAGIC_WIM))   return ArcanaFormat.WIM;
        if (startsWith(probe, MAGIC_SQUASHFS)) return ArcanaFormat.SQUASHFS;
        // LHA: bytes[2..4] = '-','l','h' (0x2D 0x6C 0x68)
        if (probe.length > 4
                && probe[2] == (byte) 0x2D
                && probe[3] == (byte) 0x6C
                && probe[4] == (byte) 0x68) return ArcanaFormat.LHA;
        if (hasTarMagic(probe))             return ArcanaFormat.TAR;
        // Windows executable: possibly a self-extracting archive (checked by SfxExtractor)
        if (probe.length > 1 && probe[0] == 'M' && probe[1] == 'Z') return ArcanaFormat.SFX;
        if (probe.length > 3 && probe[0] == 0x7F && probe[1] == 'E' && probe[2] == 'L' && probe[3] == 'F') return ArcanaFormat.SFX;

        return ArcanaFormat.UNKNOWN;
    }

    /**
     * Detects the format from a file name (extension-based fallback).
     *
     * @param fileName file name or path (only the extension is used)
     * @return detected format, or {@link ArcanaFormat#UNKNOWN}
     */
    public static ArcanaFormat detectByExtension(String fileName) {
        if (fileName == null) return ArcanaFormat.UNKNOWN;
        String lower = fileName.toLowerCase();

        // Multi-part extensions must be checked before single extensions
        if (lower.endsWith(".tar.gz")  || lower.endsWith(".tgz"))           return ArcanaFormat.TAR_GZ;
        if (lower.endsWith(".tar.xz") || lower.endsWith(".txz"))            return ArcanaFormat.TAR_XZ;
        if (lower.endsWith(".tar.bz2") || lower.endsWith(".tbz2") || lower.endsWith(".tbz")) return ArcanaFormat.TAR_BZ2;
        if (lower.endsWith(".tar.br")  || lower.endsWith(".tbr"))           return ArcanaFormat.TAR_BROTLI;
        if (lower.endsWith(".tar") || lower.endsWith(".gem")) return ArcanaFormat.TAR;
        if (lower.endsWith(".rar") || lower.endsWith(".cbr")) return ArcanaFormat.RAR;
        // ZIP and ZIP-based formats
        if (lower.endsWith(".zip") || lower.endsWith(".jar") || lower.endsWith(".war") || lower.endsWith(".ear")
         || lower.endsWith(".apk") || lower.endsWith(".ipa") || lower.endsWith(".xpi") || lower.endsWith(".crx")
         || lower.endsWith(".vsix") || lower.endsWith(".nupkg") || lower.endsWith(".kmz") || lower.endsWith(".aar")
         || lower.endsWith(".whl") || lower.endsWith(".egg") || lower.endsWith(".cbz")
         || lower.endsWith(".xps") || lower.endsWith(".oxps") || lower.endsWith(".fcstd") || lower.endsWith(".3mf")
         // Microsoft Office Open XML
         || lower.endsWith(".docx") || lower.endsWith(".docm") || lower.endsWith(".dotx") || lower.endsWith(".dotm")
         || lower.endsWith(".xlsx") || lower.endsWith(".xlsm") || lower.endsWith(".xltx") || lower.endsWith(".xltm")
         || lower.endsWith(".pptx") || lower.endsWith(".pptm") || lower.endsWith(".potx") || lower.endsWith(".potm")
         // OpenDocument formats
         || lower.endsWith(".odt") || lower.endsWith(".ods") || lower.endsWith(".odp") || lower.endsWith(".odg")
         || lower.endsWith(".odf") || lower.endsWith(".odb") || lower.endsWith(".odc") || lower.endsWith(".odm")
         // eBook
         || lower.endsWith(".epub")
        ) return ArcanaFormat.ZIP;
        if (lower.endsWith(".gz")  || lower.endsWith(".gzip"))              return ArcanaFormat.GZIP;
        if (lower.endsWith(".bz2") || lower.endsWith(".bzip2"))             return ArcanaFormat.BZIP2;
        if (lower.endsWith(".7z") || lower.endsWith(".cb7"))              return ArcanaFormat.SEVEN_Z;
        if (lower.endsWith(".xz"))                                          return ArcanaFormat.XZ;
        if (lower.endsWith(".tar.zst") || lower.endsWith(".tzst"))          return ArcanaFormat.TAR_ZSTD;
        if (lower.endsWith(".zst") || lower.endsWith(".zstd"))              return ArcanaFormat.ZSTD;
        if (lower.endsWith(".tar.lz4") || lower.endsWith(".tlz4"))          return ArcanaFormat.TAR_LZ4;
        if (lower.endsWith(".lz4"))                                         return ArcanaFormat.LZ4;
        if (lower.endsWith(".snappy"))                                      return ArcanaFormat.SNAPPY;
        if (lower.endsWith(".cpio"))                                        return ArcanaFormat.CPIO;
        if (lower.endsWith(".lzma"))                                        return ArcanaFormat.LZMA;
        if (lower.endsWith(".z"))                                           return ArcanaFormat.Z;
        if (lower.endsWith(".a") || lower.endsWith(".deb"))                return ArcanaFormat.AR;
        if (lower.endsWith(".rpm"))                                         return ArcanaFormat.RPM;
        if (lower.endsWith(".xar"))                                         return ArcanaFormat.XAR;
        if (lower.endsWith(".lzh") || lower.endsWith(".lha"))               return ArcanaFormat.LHA;
        if (lower.endsWith(".cab"))                                         return ArcanaFormat.CAB;
        if (lower.endsWith(".br"))                                          return ArcanaFormat.BROTLI;
        if (lower.endsWith(".iso"))                                         return ArcanaFormat.ISO;
        if (lower.endsWith(".udf"))                                         return ArcanaFormat.UDF;
        if (lower.endsWith(".wim") || lower.endsWith(".swm") || lower.endsWith(".esd")) return ArcanaFormat.WIM;
        if (lower.endsWith(".sqfs") || lower.endsWith(".squashfs") || lower.endsWith(".snap")) return ArcanaFormat.SQUASHFS;
        return ArcanaFormat.UNKNOWN;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * A GZIP stream may contain a TAR inside it (.tar.gz).  Since we cannot
     * decompress at detection time, we rely on the extension as the tie-breaker.
     * The magic-byte result is GZIP by default; the extractor layer handles
     * TAR_GZ by chaining GzipExtractor and TarExtractor.
     *
     * <p>This method is intentionally simple: returning GZIP here is correct
     * because {@link be.stef.arcana.Arcana} will promote GZIP to TAR_GZ
     * when the extension says .tar.gz or .tgz.</p>
     */
    private static ArcanaFormat detectGzipOrTarGz(byte[] probe) {
        // Magic says GZIP - let Arcana refine via extension if needed
        return ArcanaFormat.GZIP;
    }

    
    private static ArcanaFormat detectXzOrTarXz(byte[] probe) { 
       return ArcanaFormat.XZ; 
    }

    /** Same rationale as detectGzipOrTarGz: extension resolves LZ4 vs TAR_LZ4. */
    private static ArcanaFormat detectLz4OrTarLz4(byte[] probe) {
        return ArcanaFormat.LZ4;
    }
    
    /** Same rationale as detectGzipOrTarGz for BZIP2 vs TAR_BZ2. */
    private static ArcanaFormat detectBzip2OrTarBz2(byte[] probe) {
        return ArcanaFormat.BZIP2;
    }

    /**
     * Returns {@code true} if {@code probe} contains the TAR "ustar" signature
     * at byte offset 257.
     */
    private static boolean hasTarMagic(byte[] probe) {
        if (probe.length < 257 + MAGIC_TAR.length) return false;
        for (int i = 0; i < MAGIC_TAR.length; i++) {
            if (probe[257 + i] != MAGIC_TAR[i]) return false;
        }
        return true;
    }

    /**
     * Returns {@code true} if {@code data} starts with all bytes in {@code prefix}.
     */
    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    /**
     * Opens {@code file} and reads up to {@value #PROBE_SIZE} bytes for magic detection.
     */
    private static byte[] readProbe(File file) throws IOException {
        byte[] buf = new byte[PROBE_SIZE];
        try (InputStream in = new FileInputStream(file)) {
            int read = 0;
            int n;
            while (read < buf.length && (n = in.read(buf, read, buf.length - read)) != -1) {
                read += n;
            }
            if (read == buf.length) return buf;
            byte[] trimmed = new byte[read];
            System.arraycopy(buf, 0, trimmed, 0, read);
            return trimmed;
        }
    }
}