/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.deflate64.Deflate64InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import be.stef.arcana.formats.ppmd.Ppmd8;
import be.stef.arcana.formats.zip.AesZipInputStream;
import be.stef.arcana.formats.zip.ZipArchiveReader;
import be.stef.arcana.formats.zip.ZipCryptoInputStream;
import be.stef.arcana.formats.zstd.ZstdInputStream;
import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ParallelRunner;
import be.stef.arcana.util.ProgressOutputStream;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Extractor for ZIP archives (.zip, .jar, .war, .ear, ...).
 *
 * <p>Reads the central directory with {@link ZipArchiveReader} (no
 * {@link java.util.zip.ZipFile}, no reflection). Supported compression methods:</p>
 * <ul>
 *   <li>0 Stored, 8 Deflated, 9 Deflate64</li>
 *   <li>12 BZIP2, 14 LZMA, 93 Zstandard, 95 XZ</li>
 * </ul>
 * <p>Supported encryption: ZipCrypto and WinZip AES-128/192/256 (method 99), with any
 * of the methods above underneath. Supply a password via {@link #ZipExtractor(byte[])};
 * without one, encrypted entries throw {@link ArcanaEncryptedException}. The size and
 * the CRC-32 of every entry are verified (CRC except WinZip AE-2, which stores none),
 * and so is the authentication code of WinZip AES entries.</p>
 */
public class ZipExtractor implements ArchiveExtractor {

    private static final int METHOD_STORED   = 0;
    private static final int METHOD_DEFLATED = 8;
    private static final int METHOD_DEFLATE64 = 9;
    private static final int METHOD_BZIP2    = 12;
    private static final int METHOD_LZMA     = 14;
    private static final int METHOD_ZSTD     = 93;
    private static final int METHOD_XZ       = 95;
    private static final int METHOD_PPMD     = 98;
    private static final int METHOD_AES      = 99;

    private static final int BUFFER_SIZE     = 65536;

    private final byte[] password;

    public ZipExtractor() { this(null); }
    public ZipExtractor(final byte[] password) { this.password = password; }

    /** Streams are copied to a temporary file (the central directory is at the end of the archive). */
    @Override public boolean supportsStream() { return true; }

    // ---- list ----

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (ZipArchiveReader zip = new ZipArchiveReader(archive)) {
            for (final ZipArchiveReader.Entry e : zip.getEntries()) result.add(toArcanaEntry(e));
        }
        return result;
    }

    // ---- extract(File, File) ----

    /**
     * Extracts every entry. Since 1.3 the entries are decoded in parallel (one
     * entry per thread, like RAR5) when {@link ArcanaConcurrency#threads} allows it:
     * ZIP entries are independent, so the result is identical. The first error (in
     * archive order) stops the extraction, as in the sequential mode.
     */
    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (ZipArchiveReader zip = new ZipArchiveReader(archive)) {
            // Pass 1 (sequential): directories and parent directories, target of each file
            final List<FileJob> jobs = new ArrayList<FileJob>();
            final Map<File, FileJob> lastByTarget = new HashMap<File, FileJob>();
            for (final ZipArchiveReader.Entry e : zip.getEntries()) {
                final File target = SafePathBuilder.buildSafePath(destination, e.getName());
                if (e.isDirectory()) { IOHelper.mkdirs(target); continue; }
                IOHelper.mkdirs(target.getParentFile());
                final FileJob job = new FileJob(zip, e, target);
                jobs.add(job);
                lastByTarget.put(target, job);
            }
            final int threads = Math.min(jobs.size(), ArcanaConcurrency.workersFor(WORKER_MEMORY));
            if (threads <= 1) {
                for (final FileJob job : jobs) job.extract(true);
                return;
            }
            // Pass 2 (parallel): the same name stored twice is written once (the last
            // copy wins, as in the sequential mode where it overwrites the first one)
            final List<FileJob> unique = new ArrayList<FileJob>(jobs.size());
            for (final FileJob job : jobs) if (lastByTarget.get(job.target) == job) unique.add(job);
            ParallelRunner.runAll(unique, threads);
        }
    }

    /** Memory for one worker: buffers + the largest usual decoder (LZMA/XZ dictionary). */
    private static final long WORKER_MEMORY = 64L << 20;

    /** Extraction of one file entry. */
    private final class FileJob implements ParallelRunner.IOTask {
        final ZipArchiveReader zip;
        final ZipArchiveReader.Entry entry;
        final File target;

        FileJob(final ZipArchiveReader zip, final ZipArchiveReader.Entry entry, final File target) {
            this.zip = zip;
            this.entry = entry;
            this.target = target;
        }

        @Override
        public void run() throws IOException {
            extract(false);
        }

        /** @param progress live progress bar (sequential mode); otherwise one line when the file is done */
        void extract(final boolean progress) throws IOException {
            if (progress) {
                try (InputStream in = openEntry(zip, entry);
                     ProgressOutputStream out = new ProgressOutputStream(new BufferedOutputStream(ExtractionGuard.open(target), BUFFER_SIZE), entry.getSize(), entry.getName())) {
                    IOHelper.copy(in, out);
                    out.finish();
                }
                return;
            }
            final long start = System.nanoTime();
            try (InputStream in = openEntry(zip, entry);
                 OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), BUFFER_SIZE)) {
                IOHelper.copy(in, out);
            }
            // Live bars of several threads would overwrite each other: one complete line per file
            final String line = "[==============================] " + ProgressOutputStream.formatSize(entry.getSize()) + " 100% (" + entry.getName() + ") -> " + ProgressOutputStream.formatDuration((System.nanoTime() - start) / 1_000_000L);
            synchronized (System.out) {
                System.out.println(line);
            }
        }
    }

    // ---- extract(InputStream, File) ----

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final File tmp = File.createTempFile("arcana-", ".zip");
        try {
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), BUFFER_SIZE)) {
                IOHelper.copy(in, out);
            }
            extract(tmp, destination);
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    // ---- entry decoding ----

    /** Returns the decrypted, decompressed and CRC-checked content of an entry. */
    private InputStream openEntry(final ZipArchiveReader zip, final ZipArchiveReader.Entry e) throws IOException {
        int method = e.getMethod();
        InputStream raw;
        AesZipInputStream aes = null;
        if (e.isEncrypted()) {
            if (password == null) throw new ArcanaEncryptedException("Encrypted ZIP entry '" + e.getName() + "' - supply a password");
            if (e.isStrongEncryption()) throw new ArcanaUnsupportedFormatException("PKWARE strong encryption is not supported (entry '" + e.getName() + "')");
            if (method == METHOD_AES) {
                if (!e.isAes()) throw new ArcanaCorruptedException("AES entry without AES extra field: '" + e.getName() + "'");
                try {
                    aes = new AesZipInputStream(zip.openRaw(e, 0), password, e.getAesStrength(), e.getCompressedSize());
                    raw = aes;
                } catch (final GeneralSecurityException gse) {
                    throw new IOException("AES setup failed: " + gse.getMessage(), gse);
                } catch (final IOException ioe) {
                    if (ioe.getMessage() != null && ioe.getMessage().startsWith("Wrong password")) throw new ArcanaEncryptedException("Wrong password for ZIP entry '" + e.getName() + "'", ioe);
                    throw ioe;
                }
                method = e.getAesMethod();
            } else {
                final ZipCryptoInputStream zc = new ZipCryptoInputStream(zip.openRaw(e, 0), password);
                final int expected = e.hasDataDescriptor() ? (e.getDosTime() >>> 8) & 0xFF : (int) (e.getCrc() >>> 24) & 0xFF;
                if (zc.getCheckByte() != expected) throw new ArcanaEncryptedException("Wrong password for ZIP entry '" + e.getName() + "'");
                raw = zc;
            }
        } else {
            raw = zip.openRaw(e, 0);
        }
        final InputStream data = decompress(method, raw, e);
        final boolean checkCrc = !(e.isAes() && e.getAesVendorVersion() == 2); // AE-2: CRC field is 0 by design
        return new EntryCheckInputStream(data, checkCrc, e.getCrc(), e.getSize(), e.getName(), aes);
    }

    private static InputStream decompress(final int method, final InputStream raw, final ZipArchiveReader.Entry e) throws IOException {
        switch (method) {
            case METHOD_STORED:   return raw;
            case METHOD_DEFLATED: return new RawInflaterInputStream(raw);
            case METHOD_DEFLATE64: return new Deflate64InputStream(raw, true);
            case METHOD_BZIP2:    return new BZip2InputStream(raw);
            case METHOD_LZMA:     return openLzma(raw, e);
            case METHOD_ZSTD:     return new ZstdInputStream(raw);
            case METHOD_XZ:       return new XZInputStream(raw);
            case METHOD_PPMD:     return openPpmd(raw, e);
            default:              throw new ArcanaUnsupportedFormatException("ZIP compression method " + method + methodName(method) + " not supported (entry '" + e.getName() + "')");
        }
    }

    /**
     * ZIP LZMA (method 14): 2-byte LZMA SDK version, 2-byte properties size (5),
     * 5-byte properties (lc/lp/pb byte + dictionary size), then raw LZMA data.
     * General purpose bit 1 = the stream ends with an end-of-stream marker.
     */
    private static InputStream openLzma(final InputStream raw, final ZipArchiveReader.Entry e) throws IOException {
        final byte[] h = IOHelper.readExactly(raw, 4);
        final int propsSize = (h[2] & 0xFF) | ((h[3] & 0xFF) << 8);
        if (propsSize != 5) throw new ArcanaCorruptedException("Invalid LZMA properties size " + propsSize + " (entry '" + e.getName() + "')");
        final byte[] props = IOHelper.readExactly(raw, 5);
        final int dictSize = (props[1] & 0xFF) | ((props[2] & 0xFF) << 8) | ((props[3] & 0xFF) << 16) | ((props[4] & 0xFF) << 24);
        final long uncompSize = (e.getFlags() & 0x02) != 0 ? -1L : e.getSize();
        return new LZMAInputStream(raw, uncompSize, props[0], dictSize);
    }

    /**
     * ZIP PPMd (method 98): PPMd variant I revision 2. A 16-bit little-endian
     * header gives the model order (bits 0-3, + 1), the memory in MB (bits 4-11,
     * + 1) and the restore method (bits 12-15), then the range-coded data.
     */
    private static InputStream openPpmd(final InputStream raw, final ZipArchiveReader.Entry e) throws IOException {
        final byte[] h = IOHelper.readExactly(raw, 2);
        final int v = (h[0] & 0xFF) | ((h[1] & 0xFF) << 8);
        final int order = (v & 0x0F) + 1;
        final int memMb = ((v >>> 4) & 0xFF) + 1;
        final int restore = v >>> 12;
        if (order < Ppmd8.MIN_ORDER || restore > Ppmd8.RESTORE_CUT_OFF) throw new ArcanaUnsupportedFormatException("ZIP PPMd parameters not supported (order " + order + ", restore method " + restore + ") for entry '" + e.getName() + "'");
        final Ppmd8 model = new Ppmd8(new BufferedInputStream(raw, 65536), order, memMb << 20, restore);
        final long size = e.getSize();
        return new InputStream() {
            private long left = size;

            @Override
            public int read() throws IOException {
                if (left <= 0) return -1;
                final int c = model.decodeSymbol();
                if (c < 0) throw new ArcanaCorruptedException("PPMd data error in entry '" + e.getName() + "'");
                left--;
                return c;
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                if (left <= 0) return -1;
                final int n = (int) Math.min(len, left);
                for (int i = 0; i < n; i++) {
                    final int c = model.decodeSymbol();
                    if (c < 0) throw new ArcanaCorruptedException("PPMd data error in entry '" + e.getName() + "'");
                    b[off + i] = (byte) c;
                }
                left -= n;
                return n;
            }

            @Override
            public void close() throws IOException {
                raw.close();
            }
        };
    }

    private static String methodName(final int method) {
        switch (method) {
            case METHOD_PPMD:      return " (PPMd var.I)";
            default:               return "";
        }
    }

    private static ArcanaEntry toArcanaEntry(final ZipArchiveReader.Entry e) {
        return new ArcanaEntry.Builder(e.getName())
                .compressedSize(e.getCompressedSize()).uncompressedSize(e.getSize())
                .lastModifiedTime(e.getLastModifiedSeconds())
                .directory(e.isDirectory()).crc32(e.getCrc()).format(ArcanaFormat.ZIP).build();
    }

    // ---- stream helpers ----

    /** Raw deflate (no zlib header). Feeds one dummy byte at end of input, as required by Inflater in nowrap mode. */
    private static final class RawInflaterInputStream extends InflaterInputStream {
        private boolean dummySent;

        RawInflaterInputStream(final InputStream in) {
            super(in, new Inflater(true), BUFFER_SIZE);
        }

        @Override
        protected void fill() throws IOException {
            len = in.read(buf, 0, buf.length);
            if (len == -1) {
                if (dummySent) throw new EOFException("Unexpected end of deflated ZIP entry");
                buf[0] = 0;
                len = 1;
                dummySent = true;
            }
            inf.setInput(buf, 0, len);
        }

        @Override
        public void close() throws IOException {
            try { super.close(); } finally { inf.end(); }
        }
    }

    /**
     * Checks the entry against its central directory record: never more bytes than the
     * declared size (checked while reading, so a lying header cannot inflate the output),
     * exactly that size at end of stream, the CRC-32 and, for WinZip AES, the
     * authentication code (AE-2 has no CRC: the code is its only integrity check).
     */
    private static final class EntryCheckInputStream extends FilterInputStream {
        private final CRC32 crc = new CRC32();
        private final boolean checkCrc;
        private final long expectedCrc;
        private final long expectedSize;
        private final String name;
        private final AesZipInputStream aes; // null when the entry is not AES-encrypted
        private long count;
        private boolean checked;

        EntryCheckInputStream(final InputStream in, final boolean checkCrc, final long expectedCrc, final long expectedSize, final String name, final AesZipInputStream aes) {
            super(in);
            this.aes = aes;
            this.checkCrc = checkCrc;
            this.expectedCrc = expectedCrc;
            this.expectedSize = expectedSize;
            this.name = name;
        }

        @Override
        public int read() throws IOException {
            final int b = in.read();
            if (b < 0) check(); else update(1, (byte) b, null, 0);
            return b;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = in.read(b, off, len);
            if (n < 0) check(); else update(n, (byte) 0, b, off);
            return n;
        }

        private void update(final int n, final byte single, final byte[] b, final int off) throws ArcanaCorruptedException {
            count += n;
            // (a size wrong by a multiple of 4 GB is a known writer bug: tolerated, the CRC still decides)
            if (count > expectedSize && (count - expectedSize) % (1L << 32) != 0 && expectedSize < (1L << 32)) throw new ArcanaCorruptedException("ZIP entry '" + name + "' produces more data than its declared size (" + expectedSize + " bytes)");
            if (b == null) crc.update(single); else crc.update(b, off, n);
        }

        private void check() throws IOException {
            if (checked) return;
            checked = true;
            if ((count & 0xFFFFFFFFL) != (expectedSize & 0xFFFFFFFFL)) throw new ArcanaCorruptedException("ZIP entry '" + name + "' has " + count + " bytes instead of " + expectedSize);
            if (checkCrc && crc.getValue() != expectedCrc) throw new ArcanaCorruptedException("CRC mismatch for ZIP entry '" + name + "' (expected " + Long.toHexString(expectedCrc) + ", got " + Long.toHexString(crc.getValue()) + ")");
            if (aes != null && !aes.isAuthentic()) throw new ArcanaCorruptedException("Authentication code mismatch for ZIP entry '" + name + "' (wrong data or modified archive)");
        }
    }
}
