/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.compressor;

import be.stef.arcana.formats.zip.AesZipOutputStream;
import be.stef.arcana.formats.zip.ZipCryptoOutputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ProgressInputStream;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Compresses files and directories into ZIP archives.
 *
 * <p>Three encryption modes are available:</p>
 * <ul>
 *   <li>{@link #ENCRYPT_NONE} (default): standard ZIP, no encryption.</li>
 *   <li>{@link #ENCRYPT_ZIPCRYPTO}: PKWare traditional encryption. Compatible with
 *       all ZIP tools but cryptographically weak (avoid for sensitive data).</li>
 *   <li>{@link #ENCRYPT_AES256}: WinZip AES-256 (AE-2). Strong encryption; supported
 *       by 7-Zip, WinRAR, WinZip, and most modern ZIP tools.</li>
 * </ul>
 *
 * <p>Usage:</p>
 * <pre>
 *     new ZipCompressor().compress(source, archive);                           // plain
 *     new ZipCompressor(password).compress(source, archive);                  // AES-256
 *     new ZipCompressor(password, ZipCompressor.ENCRYPT_ZIPCRYPTO)            // ZipCrypto
 *             .compress(source, archive);
 * </pre>
 */
public final class ZipCompressor implements ArchiveCompressor {

    /** No encryption (default). */
    public static final int ENCRYPT_NONE      = 0;
    /** PKWare traditional encryption (ZipCrypto). Weak but universally compatible. */
    public static final int ENCRYPT_ZIPCRYPTO = 1;
    /** WinZip AES-256 (AE-2). Recommended when encryption is required. */
    public static final int ENCRYPT_AES256    = 2;

    private static final int AES_STRENGTH = AesZipOutputStream.AES_256;

    // ZIP local file header signature
    private static final int SIGN_LFH  = 0x04034b50;
    // ZIP central directory header signature
    private static final int SIGN_CDH  = 0x02014b50;
    // ZIP end of central directory signature
    private static final int SIGN_EOCD = 0x06054b50;
    // Data descriptor, ZIP64 end of central directory record and locator signatures
    private static final int SIGN_DD     = 0x08074b50;
    private static final int SIGN_EOCD64 = 0x06064b50;
    private static final int SIGN_LOC64  = 0x07064b50;

    private static final long ZIP64_MAGIC = 0xFFFFFFFFL;

    private static final int METHOD_DEFLATE  = 8;
    private static final int METHOD_AES      = 99;   // WinZip AES
    private static final int VERSION_DEFLATE = 20;
    private static final int VERSION_ZIP64   = 45;   // ZIP64 extensions
    private static final int VERSION_AES     = 51;   // requires ZIP 5.1+

    private static final int GP_ENCRYPTED = 0x0001;
    private static final int GP_DESCRIPTOR = 0x0008;
    private static final int GP_UTF8      = 0x0800;

    private final byte[] password;
    private final int    encryptMode;

    /** Creates a ZipCompressor with no encryption. */
    public ZipCompressor() { this.password = null; this.encryptMode = ENCRYPT_NONE; }

    /** Creates a ZipCompressor with AES-256 encryption. */
    public ZipCompressor(final byte[] password) { this.password = password; this.encryptMode = ENCRYPT_AES256; }

    /** Creates a ZipCompressor with the specified encryption mode. */
    public ZipCompressor(final byte[] password, final int encryptMode) { this.password = password; this.encryptMode = encryptMode; }

    @Override
    public boolean supportsDirectories() { return true; }

    @Override
    public void compress(final File source, final File archive) throws IOException {
        try (final FileOutputStream fos = new FileOutputStream(archive)) {
            compress(source, fos);
        }
    }

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        if (encryptMode == ENCRYPT_NONE) { compressPlain(source, out); }
        else                             { compressEncrypted(source, out); }
    }

    // =========================================================================
    // Plain mode: delegate to standard ZipOutputStream
    // =========================================================================

    private void compressPlain(final File source, final OutputStream out) throws IOException {
        final File abs  = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final File base = abs.isDirectory() ? abs : abs.getParentFile();
        final BufferedOutputStream bos = new BufferedOutputStream(out);
        final ZipOutputStream zos = new ZipOutputStream(bos);
        zos.setLevel(Deflater.DEFAULT_COMPRESSION);
        if (abs.isDirectory()) { addDirPlain(base, abs, zos); }
        else                   { addFilePlain(base, abs, zos); }
        zos.finish(); // finalise the ZIP structure without closing the underlying stream
        bos.flush();  // push the buffered tail (central directory) to the caller's stream
    }

    private void addDirPlain(final File base, final File dir, final ZipOutputStream zos) throws IOException {
        final File[] children = dir.listFiles();
        if (children == null) return;
        Arrays.sort(children);
        for (final File child : children) {
            if (child.isDirectory()) {
                final ZipEntry entry = new ZipEntry(relativePath(base, child) + "/");
                entry.setTime(child.lastModified());
                zos.putNextEntry(entry); zos.closeEntry();
                addDirPlain(base, child, zos);
            } else {
                addFilePlain(base, child, zos);
            }
        }
    }

    private void addFilePlain(final File base, final File file, final ZipOutputStream zos) throws IOException {
        final ZipEntry entry = new ZipEntry(relativePath(base, file));
        entry.setTime(file.lastModified());
        zos.putNextEntry(entry);
        try (final ProgressInputStream pis = new ProgressInputStream(new FileInputStream(file), file.length(), file.getName())) {
            IOHelper.copy(pis, zos);
            pis.finish();
        }
        zos.closeEntry();
    }

    // =========================================================================
    // Encrypted mode: raw ZIP writer
    //   For each entry: local header -> file streamed through deflate and
    //   encryption -> data descriptor (CRC and sizes are only known at the end).
    //   ZIP64 records are written when sizes, offsets or the entry count need them.
    // =========================================================================

    /** Central directory entry, collected while writing local records. */
    private static final class CDRecord {
        final long   localOffset;
        final long   crc32;
        final long   compressedSize;
        final long   uncompressedSize;
        final int    dosTime;
        final int    dosDate;
        final int    method;
        final int    gpFlags;
        final int    versionNeeded;
        final byte[] name;
        final byte[] extra;
        CDRecord(final long lo, final long c32, final long cs, final long us, final int dt, final int dd, final int meth, final int gp, final int ver, final byte[] n, final byte[] ex) {
            localOffset = lo; crc32 = c32; compressedSize = cs; uncompressedSize = us;
            dosTime = dt; dosDate = dd; method = meth; gpFlags = gp; versionNeeded = ver;
            name = n; extra = ex;
        }
    }

    private void compressEncrypted(final File source, final OutputStream out) throws IOException {
        final File abs  = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final File base = abs.isDirectory() ? abs : abs.getParentFile();
        final List<File> files = new ArrayList<File>();
        collectFiles(abs, files);

        final List<CDRecord> cdRecords = new ArrayList<CDRecord>();
        final CountingOutputStream bos = new CountingOutputStream(new BufferedOutputStream(out)); // bos.count = current offset

        for (final File file : files) {
            final String name      = relativePath(base, file);
            if (file.isDirectory()) {
                // Directory entry: stored, empty, never encrypted (keeps empty directories)
                final byte[] dirName = (name + "/").getBytes("UTF-8");
                final int[] dirTime = toDosDateTime(file.lastModified());
                final long dirOffset = bos.count;
                writeInt(bos, SIGN_LFH);
                writeShort(bos, VERSION_DEFLATE);
                writeShort(bos, GP_UTF8);
                writeShort(bos, 0);
                writeShort(bos, dirTime[0]);
                writeShort(bos, dirTime[1]);
                writeInt(bos, 0);
                writeInt(bos, 0);
                writeInt(bos, 0);
                writeShort(bos, dirName.length);
                writeShort(bos, 0);
                bos.write(dirName);
                cdRecords.add(new CDRecord(dirOffset, 0L, 0L, 0L, dirTime[0], dirTime[1], 0, GP_UTF8, VERSION_DEFLATE, dirName, new byte[0]));
                continue;
            }
            final byte[] nameBytes = name.getBytes("UTF-8");
            final byte[] extraBytes = encryptMode == ENCRYPT_AES256 ? buildAesExtra() : new byte[0];
            final int[] dosDateTime = toDosDateTime(file.lastModified());

            // ZIP64 sizes when the entry may reach 4 GiB (deflate and encryption add a little to incompressible data)
            final long fileLength = file.length();
            final boolean zip64Entry = fileLength + (fileLength >>> 10) + 1024 >= ZIP64_MAGIC;
            // Local ZIP64 extra field: both sizes, 0 here (the real values are in the data descriptor)
            final byte[] localExtra = zip64Entry ? concat(zip64Extra(new long[]{0L, 0L}), extraBytes) : extraBytes;

            final int gpFlags = GP_ENCRYPTED | GP_DESCRIPTOR | GP_UTF8;
            final int method  = encryptMode == ENCRYPT_AES256 ? METHOD_AES     : METHOD_DEFLATE;
            final int version = encryptMode == ENCRYPT_AES256 ? VERSION_AES    : zip64Entry ? VERSION_ZIP64 : VERSION_DEFLATE;

            // Write local file header (CRC and sizes follow the data, in the data descriptor)
            final long localOffset = bos.count;
            writeInt(bos, SIGN_LFH);
            writeShort(bos, version);
            writeShort(bos, gpFlags);
            writeShort(bos, method);
            writeShort(bos, dosDateTime[0]);
            writeShort(bos, dosDateTime[1]);
            writeInt(bos, 0);
            writeInt(bos, zip64Entry ? (int) ZIP64_MAGIC : 0);
            writeInt(bos, zip64Entry ? (int) ZIP64_MAGIC : 0);
            writeShort(bos, nameBytes.length);
            writeShort(bos, localExtra.length);
            bos.write(nameBytes);
            bos.write(localExtra);

            // Stream: file -> CRC-32 -> raw deflate -> encryption -> archive
            final long dataStart = bos.count;
            final OutputStream encrypted;
            AesZipOutputStream aes = null;
            if (encryptMode == ENCRYPT_AES256) {
                try {
                    aes = new AesZipOutputStream(bos, password, AES_STRENGTH);
                } catch (final GeneralSecurityException e) { throw new IOException("AES-256 encryption failed: " + e.getMessage(), e); }
                encrypted = aes;
            } else {
                // ENCRYPT_ZIPCRYPTO with a data descriptor: the check byte is the high byte of the DOS time
                encrypted = new ZipCryptoOutputStream(bos, password, (dosDateTime[0] >>> 8) & 0xFF);
            }
            final Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, true); // nowrap=true: raw deflate
            final long crc32;
            final long uncompressedSize;
            try {
                final DeflaterOutputStream dos = new DeflaterOutputStream(encrypted, def, IOHelper.BUFFER_SIZE);
                try (final ProgressInputStream pis = new ProgressInputStream(new FileInputStream(file), fileLength, file.getName())) {
                    final CheckedInputStream cis = new CheckedInputStream(pis, new CRC32());
                    IOHelper.copy(cis, dos);
                    pis.finish();
                    crc32 = cis.getChecksum().getValue();
                }
                dos.finish(); // not close(): the archive stream stays open
                if (aes != null) aes.finish();
                uncompressedSize = def.getBytesRead();
            } finally {
                def.end();
            }
            final long compressedSize = bos.count - dataStart;
            if (!zip64Entry && (compressedSize >= ZIP64_MAGIC || uncompressedSize >= ZIP64_MAGIC)) throw new IOException("File '" + name + "' grew to 4 GiB or more while it was compressed: archive not usable");

            // AE-2: CRC field is 0 (integrity via HMAC only)
            final long headerCrc = encryptMode == ENCRYPT_AES256 ? 0L : crc32;

            // Data descriptor (8-byte sizes when the local header has a ZIP64 extra field)
            writeInt(bos, SIGN_DD);
            writeInt(bos, (int) headerCrc);
            if (zip64Entry) {
                writeLong(bos, compressedSize);
                writeLong(bos, uncompressedSize);
            } else {
                writeInt(bos, (int) compressedSize);
                writeInt(bos, (int) uncompressedSize);
            }

            cdRecords.add(new CDRecord(localOffset, headerCrc, compressedSize, uncompressedSize, dosDateTime[0], dosDateTime[1], method, gpFlags, version, nameBytes, extraBytes));
        }

        // Write central directory
        final long cdOffset = bos.count;
        for (final CDRecord r : cdRecords) {
            // ZIP64 extra field: only the values that do not fit, in the order of the specification
            final boolean bigU = r.uncompressedSize >= ZIP64_MAGIC;
            final boolean bigC = r.compressedSize >= ZIP64_MAGIC;
            final boolean bigO = r.localOffset >= ZIP64_MAGIC;
            final List<Long> big = new ArrayList<Long>();
            if (bigU) big.add(r.uncompressedSize);
            if (bigC) big.add(r.compressedSize);
            if (bigO) big.add(r.localOffset);
            final long[] values = new long[big.size()];
            for (int i = 0; i < values.length; i++) values[i] = big.get(i);
            final byte[] extra = values.length == 0 ? r.extra : concat(zip64Extra(values), r.extra);
            final int version = values.length == 0 ? r.versionNeeded : Math.max(r.versionNeeded, VERSION_ZIP64);

            writeInt(bos, SIGN_CDH);
            writeShort(bos, version);  // version made by
            writeShort(bos, version);  // version needed
            writeShort(bos, r.gpFlags);
            writeShort(bos, r.method);
            writeShort(bos, r.dosTime);
            writeShort(bos, r.dosDate);
            writeInt(bos, (int) r.crc32);
            writeInt(bos, bigC ? (int) ZIP64_MAGIC : (int) r.compressedSize);
            writeInt(bos, bigU ? (int) ZIP64_MAGIC : (int) r.uncompressedSize);
            writeShort(bos, r.name.length);
            writeShort(bos, extra.length);
            writeShort(bos, 0);   // comment length
            writeShort(bos, 0);   // disk number start
            writeShort(bos, 0);   // internal attributes
            writeInt(bos, 0);     // external attributes
            writeInt(bos, bigO ? (int) ZIP64_MAGIC : (int) r.localOffset);
            bos.write(r.name);
            bos.write(extra);
        }
        final long cdSize = bos.count - cdOffset;
        final int  count  = cdRecords.size();

        // ZIP64 end of central directory record and locator, when a value does not fit the classic record
        final boolean zip64End = count >= 0xFFFF || cdSize >= ZIP64_MAGIC || cdOffset >= ZIP64_MAGIC;
        if (zip64End) {
            final long eocd64Offset = bos.count;
            writeInt(bos, SIGN_EOCD64);
            writeLong(bos, 44L);                   // size of the remaining record
            writeShort(bos, VERSION_ZIP64);        // version made by
            writeShort(bos, VERSION_ZIP64);        // version needed
            writeInt(bos, 0);                      // disk number
            writeInt(bos, 0);                      // disk with start of CD
            writeLong(bos, count);                 // entries on disk
            writeLong(bos, count);                 // total entries
            writeLong(bos, cdSize);
            writeLong(bos, cdOffset);
            writeInt(bos, SIGN_LOC64);
            writeInt(bos, 0);                      // disk with the ZIP64 end record
            writeLong(bos, eocd64Offset);
            writeInt(bos, 1);                      // total number of disks
        }

        // Write end of central directory (0xFFFF / 0xFFFFFFFF: see the ZIP64 record)
        writeInt(bos, SIGN_EOCD);
        writeShort(bos, 0);                    // disk number
        writeShort(bos, 0);                    // disk with start of CD
        writeShort(bos, Math.min(count, 0xFFFF));     // entries on disk
        writeShort(bos, Math.min(count, 0xFFFF));     // total entries
        writeInt(bos, cdSize >= ZIP64_MAGIC ? (int) ZIP64_MAGIC : (int) cdSize);
        writeInt(bos, cdOffset >= ZIP64_MAGIC ? (int) ZIP64_MAGIC : (int) cdOffset);
        writeShort(bos, 0);                    // comment length

        bos.flush(); // flush without closing the underlying stream
    }

    /** ZIP64 extended information extra field (tag 0x0001) holding the given 8-byte values. */
    private static byte[] zip64Extra(final long[] values) {
        final byte[] extra = new byte[4 + 8 * values.length];
        extra[0] = 0x01; extra[1] = 0x00;                        // tag 0x0001 (LE)
        extra[2] = (byte) (8 * values.length); extra[3] = 0x00;  // data size
        for (int i = 0; i < values.length; i++) {
            for (int b = 0; b < 8; b++) extra[4 + 8 * i + b] = (byte) (values[i] >>> (8 * b));
        }
        return extra;
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /**
     * Builds the WinZip AES extra data record (tag 0x9901) for AES-256 with deflate.
     * This field goes into both the local file header and the central directory header.
     */
    private static byte[] buildAesExtra() {
        // Total: 4 bytes tag+size + 7 bytes data = 11 bytes
        final byte[] extra = new byte[11];
        extra[0]  = 0x01; extra[1] = (byte) 0x99;  // tag  0x9901 (LE)
        extra[2]  = 0x07; extra[3] = 0x00;          // data size = 7
        extra[4]  = 0x02; extra[5] = 0x00;          // version = 2 (AE-2, no CRC)
        extra[6]  = 0x41; extra[7] = 0x45;          // vendor 'A','E'
        extra[8]  = 0x03;                            // strength = AES-256
        extra[9]  = 0x08; extra[10] = 0x00;         // actual compression method = deflate
        return extra;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void collectFiles(final File current, final List<File> out) {
        if (current.isFile()) { out.add(current); return; }
        final File[] children = current.listFiles();
        if (children == null) return;
        Arrays.sort(children);
        for (final File child : children) {
            if (child.isDirectory()) out.add(child); // directory entry before its content
            collectFiles(child, out);
        }
    }

    private static String relativePath(final File base, final File file) {
        final String basePath = base.getAbsolutePath().replace('\\', '/');
        final String filePath = file.getAbsolutePath().replace('\\', '/');
        if (filePath.startsWith(basePath + "/")) return filePath.substring(basePath.length() + 1);
        return file.getName();
    }

    private static void writeShort(final OutputStream os, final int v) throws IOException {
        os.write(v & 0xFF);
        os.write((v >> 8) & 0xFF);
    }

    private static void writeInt(final OutputStream os, final int v) throws IOException {
        os.write(v & 0xFF);
        os.write((v >> 8) & 0xFF);
        os.write((v >> 16) & 0xFF);
        os.write((v >> 24) & 0xFF);
    }

    private static void writeLong(final OutputStream os, final long v) throws IOException {
        writeInt(os, (int) v);
        writeInt(os, (int) (v >>> 32));
    }

    /** Counts the bytes written (offsets of the raw writer); never closes the target stream. */
    private static final class CountingOutputStream extends FilterOutputStream {
        long count;
        CountingOutputStream(final OutputStream out) { super(out); }
        @Override public void write(final int b) throws IOException { out.write(b); count++; }
        @Override public void write(final byte[] b, final int off, final int len) throws IOException { out.write(b, off, len); count += len; }
        @Override public void close() throws IOException { flush(); }
    }

    private static int[] toDosDateTime(final long millis) {
        final java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.setTimeInMillis(millis);
        final int year   = cal.get(java.util.Calendar.YEAR);
        final int month  = cal.get(java.util.Calendar.MONTH) + 1;
        final int day    = cal.get(java.util.Calendar.DAY_OF_MONTH);
        final int hour   = cal.get(java.util.Calendar.HOUR_OF_DAY);
        final int minute = cal.get(java.util.Calendar.MINUTE);
        final int second = cal.get(java.util.Calendar.SECOND);
        final int dosTime = (hour << 11) | (minute << 5) | (second >> 1);
        final int dosDate = ((Math.max(year, 1980) - 1980) << 9) | (month << 5) | day;
        return new int[]{dosTime, dosDate};
    }
}