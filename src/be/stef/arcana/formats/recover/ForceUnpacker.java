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
package be.stef.arcana.formats.recover;

import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.extractor.CompressedStreamExtractor;
import be.stef.arcana.extractor.SfxExtractor;
import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.xz.SeekableInputStream;
import be.stef.arcana.formats.xz.SeekableXZInputStream;
import be.stef.arcana.util.IOHelper;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Forced extraction of a damaged archive: recovers as much as possible instead
 * of stopping at the first error, and reports how reliable each file is.
 *
 * <p>Strategies by format:</p>
 * <ul>
 *   <li><b>ZIP</b>: local headers searched one by one (central directory not
 *       needed), each entry decoded as far as possible, CRC checked;</li>
 *   <li><b>TAR</b>: damaged headers skipped, resynchronization on the next valid
 *       header (at any offset);</li>
 *   <li><b>bzip2 / tar.bz2</b>: every 900 KB block decoded separately (lost
 *       blocks only lose their own data), then TAR recovery;</li>
 *   <li><b>xz / tar.xz</b>: every block decoded separately when the index is
 *       readable, otherwise decoding up to the damage;</li>
 *   <li><b>gzip, zstd, lz4, lzma, brotli, snappy</b> (and their TAR): decoding up
 *       to the damage (these formats cannot restart after it), then TAR recovery
 *       of what was decoded;</li>
 *   <li><b>7z</b>: entries decoded separately (a damaged solid block only loses
 *       its own files); header lost: raw decoding of the data, names lost;</li>
 *   <li><b>self-extracting executables</b>: the embedded archive is recovered;</li>
 *   <li><b>other formats</b> (RAR, CAB, ISO...): normal extraction, keeping
 *       everything written before the error (for solid RAR archives, nothing
 *       after a damaged point can be decoded).</li>
 * </ul>
 *
 * @author Stef
 * @since 1.3
 */
public final class ForceUnpacker {

    /** Normal extraction, used for the formats without a dedicated strategy. */
    public interface Extractor {
        void extract(File archive, File destination) throws IOException;
    }

    private ForceUnpacker() {}

    /**
     * Recovers what can be recovered from {@code archive} into {@code dest} and
     * writes the report ({@link RecoveryReport#REPORT_FILE}) there.
     *
     * @param format  detected (or forced) format of the archive
     * @param normal  normal extractor, for formats without a recovery strategy
     * @param password archive password (7z), or null
     */
    public static RecoveryReport unpack(final File archive, final File dest, final ArcanaFormat format, final Extractor normal, final byte[] password) throws IOException {
        IOHelper.mkdirs(dest);
        final RecoveryReport report = run(archive, dest, format, normal, archive.getName(), password);
        report.writeTo(dest);
        return report;
    }

    /**
     * Recovers a plugin format with the plugin's own {@link ArchiveRecoverer}.
     * The recoverer writes the files and describes each one; this method turns
     * them into the report.
     */
    public static RecoveryReport unpack(final File archive, final File dest, final String displayName, final ArchiveRecoverer recoverer) throws IOException {
        IOHelper.mkdirs(dest);
        final RecoveryReport report = new RecoveryReport(displayName, "plugin recovery strategy");
        try {
            final List<RecoveredFile> files = recoverer.recover(archive, dest);
            if (files != null) for (final RecoveredFile f : files) {
                report.add(f.name, f.status != null ? f.status : RecoveryReport.Status.UNVERIFIED, f.bytesWritten, -1, f.message);
            }
        } catch (final ArcanaLimitExceededException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            report.note("Plugin recovery stopped: " + e.getClass().getSimpleName() + (e.getMessage() != null ? " - " + e.getMessage() : ""));
        }
        report.writeTo(dest);
        return report;
    }

    private static RecoveryReport run(final File archive, final File dest, final ArcanaFormat format, final Extractor normal, final String displayName, final byte[] password) throws IOException {
        final Outputs out = new Outputs(dest);
        switch (format) {
            case SEVEN_Z: {
                final RecoveryReport r = new RecoveryReport(displayName, "7z: entries decoded separately (raw decoding if the header is lost)");
                SevenZRecovery.recover(archive, out, r, password);
                return r;
            }
            case ZIP: {
                final RecoveryReport r = new RecoveryReport(displayName, "ZIP: local headers scanned one by one");
                ZipRecovery.recover(archive, out, r);
                return r;
            }
            case TAR: {
                final RecoveryReport r = new RecoveryReport(displayName, "TAR: header resynchronization");
                TarRecovery.recover(archive, out, r, false);
                return r;
            }
            case BZIP2: case TAR_BZ2: {
                final RecoveryReport r = new RecoveryReport(displayName, "bzip2: blocks decoded separately");
                final File tmp = File.createTempFile("arcana-recover-", ".bin");
                try {
                    final BZip2Recovery.Result res;
                    try (OutputStream o = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
                        res = BZip2Recovery.salvage(archive, o);
                    }
                    r.note(res.good + " bzip2 block(s) recovered, " + res.lost + " lost" + (res.lost > 0 ? " (about 900 KB of data each)" : ""));
                    content(tmp, out, r, res.lost > 0, res.lost == 0 && res.good > 0, stripExtension(displayName), res.lost > 0 ? res.lost + " block(s) lost" : null);
                } finally {
                    delete(tmp);
                }
                return r;
            }
            case XZ: case TAR_XZ: {
                final RecoveryReport r = new RecoveryReport(displayName, "xz: blocks decoded separately (or up to the damage)");
                final File tmp = File.createTempFile("arcana-recover-", ".bin");
                try {
                    final int[] lost = {0};
                    boolean complete = xzBlocks(archive, tmp, r, lost);
                    if (!complete && lost[0] < 0) complete = stream(ArcanaFormat.XZ, archive, tmp, r); // index unreadable: sequential
                    content(tmp, out, r, lost[0] > 0, complete && lost[0] == 0, stripExtension(displayName), lost[0] > 0 ? lost[0] + " block(s) lost" : complete ? null : "decoding stopped on the damage");
                } finally {
                    delete(tmp);
                }
                return r;
            }
            case GZIP: case TAR_GZ: case ZSTD: case TAR_ZSTD: case LZ4: case TAR_LZ4: case LZMA: case BROTLI: case TAR_BROTLI: case SNAPPY: {
                final RecoveryReport r = new RecoveryReport(displayName, "stream decoded up to the damage (this format cannot restart after it)");
                final File tmp = File.createTempFile("arcana-recover-", ".bin");
                try {
                    final boolean complete = stream(baseFormat(format), archive, tmp, r);
                    content(tmp, out, r, false, complete, stripExtension(displayName), complete ? null : "decoding stopped on the damage");
                } finally {
                    delete(tmp);
                }
                return r;
            }
            case SFX: {
                final SfxExtractor.Payload p;
                try {
                    p = SfxExtractor.locate(archive);
                } catch (final IOException e) {
                    final RecoveryReport r = new RecoveryReport(displayName, "self-extracting executable");
                    r.note("No embedded archive found: " + e.getMessage());
                    return r;
                }
                final File tmp = copyRange(archive, p.offset, p.length, p.format);
                try {
                    final RecoveryReport r = run(tmp, dest, p.format, normal, displayName + " -> " + p.description, password);
                    return r;
                } finally {
                    delete(tmp);
                }
            }
            default:
                return generic(archive, dest, normal, displayName);
        }
    }

    // =========================================================================
    // Strategies
    // =========================================================================

    /** Decompresses {@code archive} into {@code tmp} up to the first error. @return true if complete */
    private static boolean stream(final ArcanaFormat base, final File archive, final File tmp, final RecoveryReport r) throws IOException {
        try (InputStream raw = new BufferedInputStream(new FileInputStream(archive), 65536);
             OutputStream o = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
            final byte[] buf = new byte[65536];
            long total = 0;
            InputStream in = null;
            try {
                in = CompressedStreamExtractor.openDecompressed(base, raw);
                int n;
                while ((n = in.read(buf)) > 0) {
                    o.write(buf, 0, n);
                    total += n;
                }
                return true;
            } catch (final ArcanaLimitExceededException e) {
                throw e;
            } catch (final IOException | RuntimeException e) {
                r.note("Decoding stopped after " + total + " bytes: " + e.getClass().getSimpleName() + (e.getMessage() != null ? " - " + e.getMessage() : ""));
                return false;
            }
        }
    }

    /**
     * Decodes every xz block separately (index needed).
     *
     * @param lost receives the number of lost blocks, or -1 if the index is unreadable
     * @return true if every block was decoded
     */
    private static boolean xzBlocks(final File archive, final File tmp, final RecoveryReport r, final int[] lost) throws IOException {
        final SeekableXZInputStream x;
        try {
            x = new SeekableXZInputStream(new FileSeekable(archive));
        } catch (final IOException | RuntimeException e) {
            lost[0] = -1;
            r.note("xz index unreadable (" + e.getMessage() + "): sequential decoding");
            return false;
        }
        int good = 0;
        try (OutputStream o = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
            final byte[] buf = new byte[65536];
            for (int b = 0; b < x.getBlockCount(); b++) {
                // a fresh reader per block: an error leaves the reader unusable
                try (SeekableXZInputStream bx = new SeekableXZInputStream(new FileSeekable(archive))) {
                    bx.seekToBlock(b);
                    long left = bx.getBlockSize(b);
                    final ByteArrayOutputStreamEx block = new ByteArrayOutputStreamEx();
                    while (left > 0) {
                        final int n = bx.read(buf, 0, (int) Math.min(buf.length, left));
                        if (n < 0) throw new IOException("block truncated");
                        block.write(buf, 0, n);
                        left -= n;
                    }
                    block.writeTo(o);
                    good++;
                } catch (final ArcanaLimitExceededException e) {
                    throw e;
                } catch (final IOException | RuntimeException e) {
                    lost[0]++;
                }
            }
        } finally {
            x.close();
        }
        r.note(good + " xz block(s) recovered, " + lost[0] + " lost");
        return lost[0] == 0;
    }

    /** Decoded content: a TAR is recovered entry by entry, anything else is one file. */
    private static void content(final File data, final Outputs out, final RecoveryReport r, final boolean holes, final boolean complete, final String name, final String message) throws IOException {
        if (data.length() >= 512 && looksLikeTar(data)) {
            r.note("The decoded data is a TAR archive: TAR recovery applied" + (holes ? " (with holes)" : ""));
            TarRecovery.recover(data, out, r, holes, complete && !holes);
            return;
        }
        if (data.length() == 0) {
            r.add(name, RecoveryReport.Status.LOST, 0, -1, message != null ? message : "no data could be decoded");
            return;
        }
        try (InputStream in = new BufferedInputStream(new FileInputStream(data), 65536); OutputStream o = out.file(name)) {
            IOHelper.copy(in, o);
        }
        r.add(name, complete ? RecoveryReport.Status.OK : RecoveryReport.Status.PARTIAL, data.length(), -1, message);
    }

    private static boolean looksLikeTar(final File f) throws IOException {
        try (ByteSource s = new ByteSource(f)) {
            if (TarRecovery.validHeader(s, 0)) return true;
            final byte[] m = s.bytes(257, 5);
            return m != null && new String(m, java.nio.charset.StandardCharsets.US_ASCII).equals("ustar");
        }
    }

    /** Normal extraction; everything written before an error is kept and listed. */
    private static RecoveryReport generic(final File archive, final File dest, final Extractor normal, final String displayName) throws IOException {
        final RecoveryReport r = new RecoveryReport(displayName, "normal extraction, keeping everything written before the error");
        final java.util.Set<Path> before = new java.util.HashSet<Path>(regularFiles(dest));
        String error = null;
        try {
            normal.extract(archive, dest);
        } catch (final ArcanaLimitExceededException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            error = e.getClass().getSimpleName() + (e.getMessage() != null ? " - " + e.getMessage() : "");
            r.note("Extraction stopped: " + error);
            r.note("The files were checked by the format's own checksums as they were extracted, but the last one written may be incomplete.");
            r.note("For solid archives (7z, RAR), the files after the damaged point cannot be decoded.");
        }
        for (final Path p : regularFiles(dest)) {
            if (before.contains(p)) continue; // not written by this extraction
            final String rel = dest.toPath().relativize(p).toString().replace('\\', '/');
            r.add(rel, error == null ? RecoveryReport.Status.OK : RecoveryReport.Status.UNVERIFIED, p.toFile().length(), -1, null);
        }
        return r;
    }

    private static List<Path> regularFiles(final File dir) throws IOException {
        final List<Path> files = new ArrayList<Path>();
        if (!dir.isDirectory()) return files;
        try (java.util.stream.Stream<Path> w = Files.walk(dir.toPath())) {
            w.filter(Files::isRegularFile).filter(p -> !p.getFileName().toString().equals(RecoveryReport.REPORT_FILE)).forEach(files::add);
        }
        return files;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static ArcanaFormat baseFormat(final ArcanaFormat f) {
        switch (f) {
            case TAR_GZ:     return ArcanaFormat.GZIP;
            case TAR_BZ2:    return ArcanaFormat.BZIP2;
            case TAR_XZ:     return ArcanaFormat.XZ;
            case TAR_ZSTD:   return ArcanaFormat.ZSTD;
            case TAR_LZ4:    return ArcanaFormat.LZ4;
            case TAR_BROTLI: return ArcanaFormat.BROTLI;
            default:         return f;
        }
    }

    static String stripExtension(final String name) {
        final String n = new File(name).getName();
        final int dot = n.lastIndexOf('.');
        String base = dot > 0 ? n.substring(0, dot) : n + ".out";
        if (base.toLowerCase().endsWith(".tar")) base = base.substring(0, base.length() - 4);
        return base;
    }

    private static File copyRange(final File f, final long off, final long len, final ArcanaFormat fmt) throws IOException {
        final String ext = fmt.getExtensions().length > 0 ? fmt.getExtensions()[0] : "bin";
        final File tmp = File.createTempFile("arcana-recover-", "." + ext);
        try (ByteSource s = new ByteSource(f); OutputStream o = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
            final byte[] buf = new byte[65536];
            long p = off;
            while (p < off + len) {
                final int n = s.read(p, buf, 0, (int) Math.min(buf.length, off + len - p));
                if (n <= 0) break;
                o.write(buf, 0, n);
                p += n;
            }
        }
        return tmp;
    }

    private static void delete(final File f) {
        if (!f.delete()) f.deleteOnExit();
    }

    /** ByteArrayOutputStream that can be copied without an extra array. */
    private static final class ByteArrayOutputStreamEx extends java.io.ByteArrayOutputStream {
        ByteArrayOutputStreamEx() {
            super(1 << 20);
        }
    }

    /** SeekableInputStream over a RandomAccessFile. */
    private static final class FileSeekable extends SeekableInputStream {
        private final RandomAccessFile raf;

        FileSeekable(final File f) throws IOException {
            this.raf = new RandomAccessFile(f, "r");
        }

        @Override public int read() throws IOException { return raf.read(); }
        @Override public int read(final byte[] b, final int off, final int len) throws IOException { return raf.read(b, off, len); }
        @Override public long length() throws IOException { return raf.length(); }
        @Override public long position() throws IOException { return raf.getFilePointer(); }
        @Override public void seek(final long pos) throws IOException { raf.seek(pos); }
        @Override public void close() throws IOException { raf.close(); }
    }
}
