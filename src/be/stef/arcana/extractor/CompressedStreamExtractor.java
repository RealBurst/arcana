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
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.brotli.BrotliInputStream;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.cpio.CpioEntry;
import be.stef.arcana.formats.cpio.CpioInputStream;
import be.stef.arcana.formats.lz4.LZ4InputStream;
import be.stef.arcana.formats.snappy.SnappyInputStream;
import be.stef.arcana.formats.tar.TarInputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.ParallelXZInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import be.stef.arcana.formats.zstd.ZstdInputStream;
import be.stef.arcana.util.CloseShieldInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Wraps a single-stream compression format (GZIP, BZIP2, XZ, LZMA, Zstandard,
 * LZ4, Snappy, Brotli) and unpacks the archive it contains, if any.
 *
 * <p>The first 512 decompressed bytes are inspected:</p>
 * <ul>
 *   <li>TAR header (ustar magic or valid v7 header checksum) - the TAR is extracted;</li>
 *   <li>CPIO magic (070701, 070702, 070707) - the CPIO is extracted;</li>
 *   <li>anything else - the wrapped single-file extractor is used unchanged.</li>
 * </ul>
 *
 * <p>This covers cpio.gz / cpio.xz / cpio.zst (initramfs), tar.lzma, tar.sz, and
 * TAR archives whose name does not say so (backup.gz containing a TAR, ...),
 * without a dedicated {@link ArcanaFormat} value for each combination.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class CompressedStreamExtractor implements ArchiveExtractor {

    private static final int BUFFER_SIZE = 65536;
    private static final int PEEK_SIZE   = 512;

    private enum Inner { TAR, CPIO, NONE }

    private final ArcanaFormat     format;
    private final ArchiveExtractor single;

    /**
     * @param format outer compression format (must satisfy {@link #isStreamFormat(ArcanaFormat)})
     * @param single extractor used when the content is not an archive
     */
    public CompressedStreamExtractor(final ArcanaFormat format, final ArchiveExtractor single) {
        if (!isStreamFormat(format)) throw new IllegalArgumentException("Not a single-stream compression format: " + format);
        this.format = format;
        this.single = single;
    }

    /** True for the formats handled by {@link #openDecompressed(ArcanaFormat, InputStream)}. */
    public static boolean isStreamFormat(final ArcanaFormat f) {
        switch (f) {
            case GZIP: case BZIP2: case XZ: case LZMA: case ZSTD: case LZ4: case SNAPPY: case BROTLI:
                return true;
            default:
                return false;
        }
    }

    /** Opens a decompressing stream for a single-stream compression format. */
    public static InputStream openDecompressed(final ArcanaFormat f, final InputStream in) throws IOException {
        switch (f) {
            case GZIP:   return new GZIPInputStream(in, BUFFER_SIZE);
            case BZIP2:  return new BZip2InputStream(in);
            case XZ:     return new XZInputStream(in);
            case LZMA:   return new LZMAInputStream(in);
            case ZSTD:   return new ZstdInputStream(in);
            case LZ4:    return new LZ4InputStream(in);
            case SNAPPY: return new SnappyInputStream(in);
            case BROTLI: return new BrotliInputStream(in);
            default:     throw new ArcanaUnsupportedFormatException("Not a single-stream compression format: " + f);
        }
    }

    @Override
    public boolean supportsStream() {
        return true;
    }

    // =========================================================================
    // extract
    // =========================================================================

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        final BufferedInputStream in = openPeekable(archive);
        if (in != null) {
            try {
                final Inner inner = detect(in);
                if (inner == Inner.TAR)  { extractTar(in, destination); return; }
                if (inner == Inner.CPIO) { extractCpio(in, destination); return; }
            } finally {
                in.close();
            }
        }
        single.extract(archive, destination); // plain compressed file (or unreadable: let it report the error)
    }

    /**
     * The inner archive ends before the compressed stream does (TAR end blocks,
     * CPIO trailer): the rest is read so that the compressor verifies its trailing
     * checksum (gzip CRC32, xz check, LZ4 content checksum...).
     */
    private static void extractTar(final InputStream in, final File destination) throws IOException {
        new TarExtractor().extractFrom(new TarInputStream(new CloseShieldInputStream(in)), destination);
        IOHelper.drain(in);
    }

    private static void extractCpio(final InputStream in, final File destination) throws IOException {
        new CpioExtractor().extract(new CloseShieldInputStream(in), destination);
        IOHelper.drain(in);
    }

    @Override
    public void extract(final InputStream raw, final File destination) throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(ReadAheadInputStream.wrap(openDecompressed(format, raw)), BUFFER_SIZE)) { // decompression runs ahead in its own thread
            final Inner inner = detect(in);
            if (inner == Inner.TAR)  { extractTar(in, destination); return; }
            if (inner == Inner.CPIO) { extractCpio(in, destination); return; }
            IOHelper.mkdirs(destination);
            try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(SafePathBuilder.buildSafePath(destination, "output")), BUFFER_SIZE)) {
                IOHelper.copy(in, out);
            }
        }
    }

    // =========================================================================
    // list
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final BufferedInputStream in = openPeekable(archive);
        if (in != null) {
            try {
                final Inner inner = detect(in);
                if (inner == Inner.TAR)  return new TarExtractor().list(in, tarFormat());
                if (inner == Inner.CPIO) return listCpio(in);
            } finally {
                in.close();
            }
        }
        return single.list(archive);
    }

    private static List<ArcanaEntry> listCpio(final InputStream in) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        final CpioInputStream cis = new CpioInputStream(in);
        CpioEntry entry;
        while ((entry = cis.getNextEntry()) != null) {
            if (!entry.getName().isEmpty()) {
                result.add(new ArcanaEntry.Builder(entry.getName()).compressedSize(entry.getSize()).uncompressedSize(entry.getSize()).lastModifiedTime(entry.getModificationTime()).directory(entry.isDirectory()).format(ArcanaFormat.CPIO).build());
            }
            cis.closeEntry();
        }
        return result;
    }

    // =========================================================================
    // Content detection
    // =========================================================================

    /** Opens the decompressed stream, or returns null if the header cannot be read (the single-file extractor then reports the error). */
    private BufferedInputStream openPeekable(final File archive) {
        InputStream fis = null;
        try {
            if (format == ArcanaFormat.XZ) return new BufferedInputStream(ReadAheadInputStream.wrap(ParallelXZInputStream.open(archive)), BUFFER_SIZE); // multi-block: several threads
            fis = new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE);
            return new BufferedInputStream(ReadAheadInputStream.wrap(openDecompressed(format, fis)), BUFFER_SIZE); // decompression runs ahead in its own thread
        } catch (final IOException e) {
            if (fis != null) try { fis.close(); } catch (final IOException ignored) { /* nothing */ }
            return null;
        }
    }

    private static Inner detect(final BufferedInputStream in) throws IOException {
        final byte[] h = new byte[PEEK_SIZE];
        in.mark(PEEK_SIZE);
        int n = 0;
        while (n < PEEK_SIZE) {
            final int r = in.read(h, n, PEEK_SIZE - n);
            if (r < 0) break;
            n += r;
        }
        in.reset();
        if (n >= 6 && h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && (h[5] == '1' || h[5] == '2' || h[5] == '7')) return Inner.CPIO;
        if (n == PEEK_SIZE && isTarHeader(h)) return Inner.TAR;
        return Inner.NONE;
    }

    /** POSIX/GNU "ustar" magic, or an old v7 header whose checksum is valid. */
    static boolean isTarHeader(final byte[] h) {
        if (h[0] == 0) return false;
        if (h[257] == 'u' && h[258] == 's' && h[259] == 't' && h[260] == 'a' && h[261] == 'r') return true;
        final long stored = parseOctal(h, 148, 8);
        if (stored < 0) return false;
        long sum = 0;
        for (int i = 0; i < PEEK_SIZE; i++) sum += (i >= 148 && i < 156) ? ' ' : (h[i] & 0xFF);
        return sum == stored;
    }

    private static long parseOctal(final byte[] b, final int off, final int len) {
        int i = off;
        final int end = off + len;
        while (i < end && (b[i] == ' ' || b[i] == 0)) i++;
        if (i == end) return -1;
        long v = 0;
        int digits = 0;
        for (; i < end; i++) {
            final int c = b[i];
            if (c == ' ' || c == 0) break;
            if (c < '0' || c > '7') return -1;
            v = (v << 3) + (c - '0');
            digits++;
        }
        return digits == 0 ? -1 : v;
    }

    private ArcanaFormat tarFormat() {
        switch (format) {
            case GZIP:   return ArcanaFormat.TAR_GZ;
            case BZIP2:  return ArcanaFormat.TAR_BZ2;
            case XZ:     return ArcanaFormat.TAR_XZ;
            case ZSTD:   return ArcanaFormat.TAR_ZSTD;
            case LZ4:    return ArcanaFormat.TAR_LZ4;
            case BROTLI: return ArcanaFormat.TAR_BROTLI;
            default:     return ArcanaFormat.TAR;
        }
    }
}
