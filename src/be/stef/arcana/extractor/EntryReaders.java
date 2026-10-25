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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.ArchiveItem;
import be.stef.arcana.ArchiveReader;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.cpio.CpioEntry;
import be.stef.arcana.formats.cpio.CpioInputStream;
import be.stef.arcana.formats.sevenz.SevenZEntry;
import be.stef.arcana.formats.sevenz.SevenZFile;
import be.stef.arcana.formats.sevenz.SevenZMethodConfiguration;
import be.stef.arcana.formats.tar.TarEntry;
import be.stef.arcana.formats.tar.TarInputStream;
import be.stef.arcana.formats.xz.ParallelXZInputStream;
import be.stef.arcana.formats.zip.ZipArchiveReader;
import be.stef.arcana.util.CloseShieldInputStream;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.ExtractionLimits;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.List;

/**
 * The {@link ArchiveReader} implementations: entry by entry for ZIP, 7z, RAR
 * ({@link RarArchiveReader}), TAR, CPIO and the single-stream compressors (with a TAR or CPIO inside, or a
 * single file), and through a temporary directory for every other format.
 *
 * @author Stef
 * @since 1.1.0
 */
public final class EntryReaders {

    private static final int BUFFER_SIZE = 65536;

    private EntryReaders() {
    }

    /**
     * Reader of an archive file of a known format.
     *
     * @param format    format of the archive (a built-in format)
     * @param archive   the archive
     * @param password  password, or null
     * @param extractor extractor of the format, used by the temporary-directory fallback
     * @param limits    limits of the reader, or null for the global ones
     */
    public static ArchiveReader open(final ArcanaFormat format, final File archive, final byte[] password, final ArchiveExtractor extractor, final ExtractionLimits.Values limits) throws IOException {
        final long size = archive.length();
        switch (format) {
            case ZIP:
                return new ZipReader(archive, new ZipExtractor(password), limits, null);
            case SEVEN_Z:
                return new SevenZReader(new SevenZExtractor(password).open(archive), size, limits);
            case RAR:
                return new RarArchiveReader(archive, password == null ? null : new String(password, java.nio.charset.StandardCharsets.UTF_8), limits, null);
            case TAR:
                return new TarReader(new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE), ArcanaFormat.TAR, size, limits, false);
            case CPIO:
                return new CpioReader(new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE), size, limits, false);
            default:
                final ArcanaFormat stream = streamFormatOf(format);
                if (stream != null) return compressed(stream, openDecompressed(stream, archive), baseName(archive.getName()), size, limits);
                return fallback(format, archive, extractor, limits, null);
        }
    }

    /**
     * Reader of an archive read from a stream. TAR, CPIO and the compressed
     * formats are read as they arrive; the others are first copied to a
     * temporary file (deleted by {@link ArchiveReader#close()}).
     */
    public static ArchiveReader open(final ArcanaFormat format, final InputStream in, final byte[] password, final ArchiveExtractor extractor, final ExtractionLimits.Values limits) throws IOException {
        if (format == ArcanaFormat.TAR) return new TarReader(in, ArcanaFormat.TAR, 0L, limits, false);
        if (format == ArcanaFormat.CPIO) return new CpioReader(in, 0L, limits, false);
        final ArcanaFormat stream = streamFormatOf(format);
        if (stream != null) return compressed(stream, new BufferedInputStream(CompressedStreamExtractor.openDecompressed(stream, in), BUFFER_SIZE), "data", 0L, limits);
        final File tmp = File.createTempFile("arcana-", ".tmp");
        try {
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), BUFFER_SIZE)) {
                IOHelper.copy(in, out);
            }
            if (format == ArcanaFormat.ZIP) return new ZipReader(tmp, new ZipExtractor(password), limits, tmp);
            if (format == ArcanaFormat.SEVEN_Z) return new SevenZReader(new SevenZExtractor(password).open(tmp), tmp.length(), limits, tmp);
            if (format == ArcanaFormat.RAR) return new RarArchiveReader(tmp, password == null ? null : new String(password, java.nio.charset.StandardCharsets.UTF_8), limits, tmp);
            return fallback(format, tmp, extractor, limits, tmp);
        } catch (final IOException | RuntimeException e) {
            if (!tmp.delete()) tmp.deleteOnExit();
            throw e;
        }
    }

    /** Reader that extracts the archive to a temporary directory (plugins and the formats without a streaming reader). */
    public static ArchiveReader fallback(final ArcanaFormat format, final File archive, final ArchiveExtractor extractor, final ExtractionLimits.Values limits, final File deleteOnClose) throws IOException {
        return new TempDirReader(format, archive, extractor, limits, deleteOnClose);
    }

    // =========================================================================
    // Format helpers
    // =========================================================================

    /** Compression format of a "TAR + compressor" format or of a single-stream format, else null. */
    static ArcanaFormat streamFormatOf(final ArcanaFormat f) {
        switch (f) {
            case TAR_GZ:     return ArcanaFormat.GZIP;
            case TAR_BZ2:    return ArcanaFormat.BZIP2;
            case TAR_XZ:     return ArcanaFormat.XZ;
            case TAR_LZ4:    return ArcanaFormat.LZ4;
            case TAR_ZSTD:   return ArcanaFormat.ZSTD;
            case TAR_BROTLI: return ArcanaFormat.BROTLI;
            case TAR_LZIP:   return ArcanaFormat.LZIP;
            case TAR_LZOP:   return ArcanaFormat.LZOP;
            default:         return CompressedStreamExtractor.isStreamFormat(f) ? f : null;
        }
    }

    private static BufferedInputStream openDecompressed(final ArcanaFormat stream, final File archive) throws IOException {
        if (stream == ArcanaFormat.XZ) return new BufferedInputStream(ReadAheadInputStream.wrap(ParallelXZInputStream.open(archive)), BUFFER_SIZE);
        final InputStream fis = new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE);
        try {
            return new BufferedInputStream(ReadAheadInputStream.wrap(CompressedStreamExtractor.openDecompressed(stream, fis)), BUFFER_SIZE);
        } catch (final IOException | RuntimeException e) {
            fis.close();
            throw e;
        }
    }

    /** TAR or CPIO inside the decompressed stream, else one entry holding the decompressed data. */
    private static ArchiveReader compressed(final ArcanaFormat stream, final BufferedInputStream in, final String name, final long size, final ExtractionLimits.Values limits) throws IOException {
        try {
            final byte[] h = new byte[512];
            in.mark(h.length);
            int n = 0;
            while (n < h.length) {
                final int r = in.read(h, n, h.length - n);
                if (r < 0) break;
                n += r;
            }
            in.reset();
            if (n >= 6 && h[0] == '0' && h[1] == '7' && h[2] == '0' && h[3] == '7' && h[4] == '0' && (h[5] == '1' || h[5] == '2' || h[5] == '7')) return new CpioReader(in, size, limits, true);
            if (n == h.length && CompressedStreamExtractor.isTarHeader(h)) return new TarReader(in, tarFormat(stream), size, limits, true);
            return new SingleReader(stream, in, name, size, limits);
        } catch (final IOException | RuntimeException e) {
            in.close();
            throw e;
        }
    }

    private static ArcanaFormat tarFormat(final ArcanaFormat stream) {
        switch (stream) {
            case GZIP:   return ArcanaFormat.TAR_GZ;
            case BZIP2:  return ArcanaFormat.TAR_BZ2;
            case XZ:     return ArcanaFormat.TAR_XZ;
            case ZSTD:   return ArcanaFormat.TAR_ZSTD;
            case LZ4:    return ArcanaFormat.TAR_LZ4;
            case BROTLI: return ArcanaFormat.TAR_BROTLI;
            case LZIP:   return ArcanaFormat.TAR_LZIP;
            case LZOP:   return ArcanaFormat.TAR_LZOP;
            default:     return ArcanaFormat.TAR;
        }
    }

    /** "notes.txt.gz" gives "notes.txt", "data.bin" gives "data". */
    private static String baseName(final String archiveName) {
        final int dot = archiveName.lastIndexOf('.');
        return dot > 0 ? archiveName.substring(0, dot) : archiveName + ".out";
    }

    /** Fails if an entry stream ends before its announced size (a damaged archive can end early). */
    private static final class SizeCheckStream extends FilterInputStream {
        private final long expected;
        private final String name;
        private long count;

        SizeCheckStream(final InputStream in, final long expected, final String name) {
            super(in);
            this.expected = expected;
            this.name = name;
        }

        @Override
        public int read() throws IOException {
            final int b = super.read();
            if (b >= 0) count++;
            else check();
            return b;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = super.read(b, off, len);
            if (n > 0) count += n;
            else if (n < 0) check();
            return n;
        }

        private void check() throws ArcanaCorruptedException {
            if (expected >= 0 && count != expected) throw new ArcanaCorruptedException("Entry '" + name + "' is truncated: " + count + " bytes instead of " + expected);
        }
    }

    // =========================================================================
    // ZIP
    // =========================================================================

    private static final class ZipReader extends ArchiveReader {
        private final ZipArchiveReader zip;
        private final ZipExtractor extractor;
        private final Iterator<ZipArchiveReader.Entry> entries;
        private final File deleteOnClose;

        ZipReader(final File archive, final ZipExtractor extractor, final ExtractionLimits.Values limits, final File deleteOnClose) throws IOException {
            super(ArcanaFormat.ZIP, archive.length(), limits);
            this.zip = new ZipArchiveReader(archive);
            this.extractor = extractor;
            this.entries = zip.getEntries().iterator();
            this.deleteOnClose = deleteOnClose;
        }

        @Override
        public boolean isStreaming() {
            return true;
        }

        @Override
        protected ArchiveItem readNext() {
            if (!entries.hasNext()) return null;
            final ZipArchiveReader.Entry e = entries.next();
            return item(ZipExtractor.toArcanaEntry(e), e.isDirectory() ? null : () -> extractor.openEntry(zip, e));
        }

        @Override
        protected void release() throws IOException {
            try {
                zip.close();
            } finally {
                if (deleteOnClose != null && !deleteOnClose.delete()) deleteOnClose.deleteOnExit();
            }
        }
    }

    // =========================================================================
    // 7z
    // =========================================================================

    private static final class SevenZReader extends ArchiveReader {
        private final SevenZFile sz;
        private final File deleteOnClose;

        SevenZReader(final SevenZFile sz, final long size, final ExtractionLimits.Values limits) {
            this(sz, size, limits, null);
        }

        SevenZReader(final SevenZFile sz, final long size, final ExtractionLimits.Values limits, final File deleteOnClose) {
            super(ArcanaFormat.SEVEN_Z, size, limits);
            this.sz = sz;
            this.deleteOnClose = deleteOnClose;
        }

        @Override
        public boolean isStreaming() {
            return true;
        }

        @Override
        protected ArchiveItem readNext() throws IOException {
            final SevenZEntry e = sz.getNextEntry();
            if (e == null) return null;
            final String name = e.getName() != null ? e.getName() : sz.getDefaultName();
            int mode = -1;
            if (e.getHasWindowsAttributes() && (e.getWindowsAttributes() & 0x8000) != 0) mode = e.getWindowsAttributes() >>> 16;
            final ArcanaEntry entry = new ArcanaEntry.Builder(name).compressedSize(e.getCompressedSize()).uncompressedSize(e.getSize()).lastModifiedTime(e.getHasLastModifiedDate() ? e.getLastModifiedTime() : -1L).directory(e.isDirectory()).crc32(e.getHasCrc() ? e.getCrcValue() : -1L).method(methods(e)).mode(mode).format(ArcanaFormat.SEVEN_Z).build();
            final boolean data = !e.isDirectory() && e.hasStream();
            return item(entry, data ? () -> new SizeCheckStream(new CloseShieldInputStream(sz.getInputStream(e)), e.getSize(), name) : () -> new java.io.ByteArrayInputStream(new byte[0]));
        }

        /** "LZMA2", "BCJ_X86_FILTER+LZMA", "AES256SHA256+LZMA2"... (coders in the order they are applied when decoding), or null. */
        private static String methods(final SevenZEntry e) {
            final StringBuilder sb = new StringBuilder();
            try {
                final Iterable<? extends SevenZMethodConfiguration> list = e.getContentMethods();
                if (list == null) return null;
                for (final SevenZMethodConfiguration m : list) {
                    if (sb.length() > 0) sb.append('+');
                    sb.append(m.getMethod());
                }
            } catch (final RuntimeException ignored) {
                return null;
            }
            return sb.length() > 0 ? sb.toString() : null;
        }

        @Override
        protected void release() throws IOException {
            try {
                sz.close();
            } finally {
                if (deleteOnClose != null && !deleteOnClose.delete()) deleteOnClose.deleteOnExit();
            }
        }
    }

    // =========================================================================
    // TAR
    // =========================================================================

    private static final class TarReader extends ArchiveReader {
        private final InputStream in;
        private final TarInputStream tis;
        private final boolean drainAtEnd;

        /**
         * @param drainAtEnd the TAR is inside a compressed stream: read it to its
         *                   end so that the compressor checks its trailer (CRC...)
         */
        TarReader(final InputStream in, final ArcanaFormat format, final long size, final ExtractionLimits.Values limits, final boolean drainAtEnd) {
            super(format, size, limits);
            this.in = in;
            this.tis = new TarInputStream(new CloseShieldInputStream(in));
            this.drainAtEnd = drainAtEnd;
        }

        @Override
        public boolean isStreaming() {
            return true;
        }

        @Override
        protected ArchiveItem readNext() throws IOException {
            final TarEntry e = tis.getNextTarEntry();
            if (e == null) {
                if (drainAtEnd) IOHelper.drain(in);
                return null;
            }
            final boolean link = e.isSymbolicLink() || e.isLink();
            final long mtime = e.getModTime() != null ? e.getModTime().getTime() / 1000L : -1L;
            final ArcanaEntry entry = new ArcanaEntry.Builder(e.getName()).compressedSize(e.getSize()).uncompressedSize(e.getSize()).lastModifiedTime(mtime).directory(e.isDirectory()).mode(e.getMode()).linkTarget(link ? e.getLinkName() : null).format(getFormat()).build();
            return item(entry, e.isDirectory() ? null : () -> new CloseShieldInputStream(tis));
        }

        @Override
        protected void release() throws IOException {
            in.close();
        }
    }

    // =========================================================================
    // CPIO
    // =========================================================================

    private static final class CpioReader extends ArchiveReader {
        private final InputStream in;
        private final CpioInputStream cis;
        private final boolean drainAtEnd;
        private boolean started;

        CpioReader(final InputStream in, final long size, final ExtractionLimits.Values limits, final boolean drainAtEnd) {
            super(ArcanaFormat.CPIO, size, limits);
            this.in = in;
            this.cis = new CpioInputStream(new CloseShieldInputStream(in));
            this.drainAtEnd = drainAtEnd;
        }

        @Override
        public boolean isStreaming() {
            return true;
        }

        @Override
        protected ArchiveItem readNext() throws IOException {
            CpioEntry e;
            do {
                if (started) cis.closeEntry();
                started = true;
                e = cis.getNextEntry();
                if (e == null) {
                    if (drainAtEnd) IOHelper.drain(in);
                    return null;
                }
            } while (e.getName().isEmpty());
            final String target = e.isSymbolicLink() ? new String(IOHelper.readFully(new CloseShieldInputStream(cis)), java.nio.charset.StandardCharsets.UTF_8) : null;
            final ArcanaEntry entry = new ArcanaEntry.Builder(e.getName()).compressedSize(e.getSize()).uncompressedSize(e.getSize()).lastModifiedTime(e.getModificationTime()).directory(e.isDirectory()).mode(e.getMode()).linkTarget(target).format(ArcanaFormat.CPIO).build();
            return item(entry, e.isDirectory() || target != null ? null : () -> new CloseShieldInputStream(cis));
        }

        @Override
        protected void release() throws IOException {
            in.close();
        }
    }

    // =========================================================================
    // Single compressed file
    // =========================================================================

    private static final class SingleReader extends ArchiveReader {
        private final InputStream in;
        private final String name;
        private boolean done;

        SingleReader(final ArcanaFormat format, final InputStream in, final String name, final long size, final ExtractionLimits.Values limits) {
            super(format, size, limits);
            this.in = in;
            this.name = name;
        }

        @Override
        public boolean isStreaming() {
            return true;
        }

        @Override
        protected ArchiveItem readNext() {
            if (done) return null;
            done = true;
            return item(new ArcanaEntry.Builder(name).format(getFormat()).build(), () -> new CloseShieldInputStream(in));
        }

        @Override
        protected void release() throws IOException {
            in.close();
        }
    }

    // =========================================================================
    // Temporary directory (every other format, plugins)
    // =========================================================================

    /**
     * The entries of the listing, in its order, then the extracted files the
     * listing does not show (a listing can miss entries: a RAR file continued
     * in the next volume, for instance), in name order.
     */
    private static final class TempDirReader extends ArchiveReader {
        private final File dir;
        private final Iterator<ArcanaEntry> entries;
        private final File deleteOnClose;
        private final ArcanaFormat format;
        private final java.util.Set<String> served = new java.util.HashSet<String>();
        private Iterator<File> extra;

        TempDirReader(final ArcanaFormat format, final File archive, final ArchiveExtractor extractor, final ExtractionLimits.Values limits, final File deleteOnClose) throws IOException {
            super(format, archive.length(), limits);
            if (extractor == null) throw new ArcanaUnsupportedFormatException("No extractor for " + format);
            this.format = format;
            this.deleteOnClose = deleteOnClose;
            this.dir = Files.createTempDirectory("arcana-reader-").toFile();
            try {
                try (ExtractionGuard.Scope scope = ExtractionGuard.begin(archive, limits)) {
                    extractor.extract(archive, dir);
                }
                final List<ArcanaEntry> list = extractor.list(archive);
                this.entries = list.iterator();
            } catch (final IOException | RuntimeException e) {
                deleteTree(dir);
                throw e;
            }
        }

        @Override
        public boolean isStreaming() {
            return false;
        }

        @Override
        protected ArchiveItem readNext() throws IOException {
            if (!entries.hasNext()) return readExtra();
            final ArcanaEntry e = entries.next();
            if (e.isDirectory()) return item(e, null);
            final File f = SafePathBuilder.buildSafePath(dir, e.getName());
            served.add(f.getAbsolutePath());
            return item(e, () -> {
                if (!f.isFile()) throw new ArcanaUnsupportedFormatException("Entry '" + e.getName() + "' was not extracted (not supported, or stored outside the archive)");
                return new BufferedInputStream(new FileInputStream(f), BUFFER_SIZE);
            });
        }

        /** Next extracted file that the listing did not show, or null. */
        private ArchiveItem readExtra() {
            if (extra == null) {
                final List<File> files = new java.util.ArrayList<File>();
                collect(dir, files);
                java.util.Collections.sort(files);
                extra = files.iterator();
            }
            while (extra.hasNext()) {
                final File f = extra.next();
                if (served.contains(f.getAbsolutePath())) continue;
                final String name = dir.toPath().relativize(f.toPath()).toString().replace(File.separatorChar, '/');
                final ArcanaEntry e = new ArcanaEntry.Builder(name).uncompressedSize(f.length()).lastModifiedTime(f.lastModified() / 1000L).format(format).build();
                return item(e, () -> new BufferedInputStream(new FileInputStream(f), BUFFER_SIZE));
            }
            return null;
        }

        private static void collect(final File d, final List<File> out) {
            final File[] children = d.listFiles();
            if (children == null) return;
            for (final File c : children) {
                if (Files.isSymbolicLink(c.toPath())) continue;
                if (c.isDirectory()) collect(c, out);
                else if (c.isFile()) out.add(c);
            }
        }

        @Override
        protected void release() {
            deleteTree(dir);
            if (deleteOnClose != null && !deleteOnClose.delete()) deleteOnClose.deleteOnExit();
        }

        private static void deleteTree(final File f) {
            final File[] children = f.isDirectory() && !Files.isSymbolicLink(f.toPath()) ? f.listFiles() : null;
            if (children != null) for (final File c : children) deleteTree(c);
            if (!f.delete()) f.deleteOnExit();
        }
    }
}
