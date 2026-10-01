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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
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

    private static final int METHOD_DEFLATE  = 8;
    private static final int METHOD_AES      = 99;   // WinZip AES
    private static final int VERSION_DEFLATE = 20;
    private static final int VERSION_AES     = 51;   // requires ZIP 5.1+

    private static final int GP_ENCRYPTED = 0x0001;
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
    //   For each entry: read to memory -> deflate -> encrypt -> write raw headers
    //   The buffering avoids two-pass reading (needed to know sizes before header).
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
        long currentOffset = 0;

        final BufferedOutputStream bos = new BufferedOutputStream(out);

        for (final File file : files) {
            final String name      = relativePath(base, file);
            if (file.isDirectory()) {
                // Directory entry: stored, empty, never encrypted (keeps empty directories)
                final byte[] dirName = (name + "/").getBytes("UTF-8");
                final int[] dirTime = toDosDateTime(file.lastModified());
                final long dirOffset = currentOffset;
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
                currentOffset += 30L + dirName.length;
                cdRecords.add(new CDRecord(dirOffset, 0L, 0L, 0L, dirTime[0], dirTime[1], 0, GP_UTF8, VERSION_DEFLATE, dirName, new byte[0]));
                continue;
            }
            final byte[] nameBytes = name.getBytes("UTF-8");
            final byte[] extraBytes = encryptMode == ENCRYPT_AES256 ? buildAesExtra() : new byte[0];

            // Step 1: read uncompressed data, compute CRC32
            final byte[] uncompressed = readFile(file);
            final long   crc32        = computeCrc32(uncompressed);

            // Step 2: deflate (raw, no zlib wrapper)
            final byte[] compressed = deflateRaw(uncompressed);

            // Step 3: encrypt
            final byte[] encryptedData;
            if (encryptMode == ENCRYPT_AES256) {
                final ByteArrayOutputStream aesOut = new ByteArrayOutputStream();
                try {
                    final AesZipOutputStream aes = new AesZipOutputStream(aesOut, password, AES_STRENGTH);
                    aes.write(compressed);
                    aes.finish();
                } catch (final Exception e) { throw new IOException("AES-256 encryption failed: " + e.getMessage(), e); }
                encryptedData = aesOut.toByteArray();
            } else {
                // ENCRYPT_ZIPCRYPTO: ZipCryptoOutputStream writes 12-byte header then encrypted data
                final ByteArrayOutputStream cryptoOut = new ByteArrayOutputStream();
                final int checkByte = (int)((crc32 >>> 24) & 0xFF);
                final ZipCryptoOutputStream crypto = new ZipCryptoOutputStream(cryptoOut, password, checkByte);
                crypto.write(compressed);
                crypto.flush();
                encryptedData = cryptoOut.toByteArray();
            }

            final long compressedSize   = encryptedData.length;
            final long uncompressedSize = uncompressed.length;

            final int gpFlags = GP_ENCRYPTED | GP_UTF8;
            final int method  = encryptMode == ENCRYPT_AES256 ? METHOD_AES     : METHOD_DEFLATE;
            final int version = encryptMode == ENCRYPT_AES256 ? VERSION_AES    : VERSION_DEFLATE;
            // AE-2: CRC field in local header is 0 (integrity via HMAC only)
            final long headerCrc = encryptMode == ENCRYPT_AES256 ? 0L : crc32;

            final int[] dosDateTime = toDosDateTime(file.lastModified());

            // Write local file header
            final long localOffset = currentOffset;
            writeInt(bos, SIGN_LFH);
            writeShort(bos, version);
            writeShort(bos, gpFlags);
            writeShort(bos, method);
            writeShort(bos, dosDateTime[0]);
            writeShort(bos, dosDateTime[1]);
            writeInt(bos, (int) headerCrc);
            writeInt(bos, (int) compressedSize);
            writeInt(bos, (int) uncompressedSize);
            writeShort(bos, nameBytes.length);
            writeShort(bos, extraBytes.length);
            bos.write(nameBytes);
            bos.write(extraBytes);
            bos.write(encryptedData);

            currentOffset += 30L + nameBytes.length + extraBytes.length + compressedSize;

            cdRecords.add(new CDRecord(localOffset, headerCrc, compressedSize, uncompressedSize, dosDateTime[0], dosDateTime[1], method, gpFlags, version, nameBytes, extraBytes));
        }

        // Write central directory
        final long cdOffset = currentOffset;
        long cdSize = 0;
        for (final CDRecord r : cdRecords) {
            writeInt(bos, SIGN_CDH);
            writeShort(bos, r.versionNeeded);  // version made by
            writeShort(bos, r.versionNeeded);  // version needed
            writeShort(bos, r.gpFlags);
            writeShort(bos, r.method);
            writeShort(bos, r.dosTime);
            writeShort(bos, r.dosDate);
            writeInt(bos, (int) r.crc32);
            writeInt(bos, (int) r.compressedSize);
            writeInt(bos, (int) r.uncompressedSize);
            writeShort(bos, r.name.length);
            writeShort(bos, r.extra.length);
            writeShort(bos, 0);   // comment length
            writeShort(bos, 0);   // disk number start
            writeShort(bos, 0);   // internal attributes
            writeInt(bos, 0);     // external attributes
            writeInt(bos, (int) r.localOffset);
            bos.write(r.name);
            bos.write(r.extra);
            cdSize += 46L + r.name.length + r.extra.length;
        }

        // Write end of central directory
        writeInt(bos, SIGN_EOCD);
        writeShort(bos, 0);                    // disk number
        writeShort(bos, 0);                    // disk with start of CD
        writeShort(bos, cdRecords.size());     // entries on disk
        writeShort(bos, cdRecords.size());     // total entries
        writeInt(bos, (int) cdSize);
        writeInt(bos, (int) cdOffset);
        writeShort(bos, 0);                    // comment length

        bos.flush(); // flush without closing the underlying stream
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

    private static byte[] readFile(final File file) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream((int) Math.min(file.length(), Integer.MAX_VALUE));
        try (final ProgressInputStream pis = new ProgressInputStream(new FileInputStream(file), file.length(), file.getName())) {
            IOHelper.copy(pis, baos);
            pis.finish();
        }
        return baos.toByteArray();
    }

    private static byte[] deflateRaw(final byte[] data) throws IOException {
        final Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, true); // nowrap=true: raw deflate
        def.setInput(data);
        def.finish();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length / 2 + 64);
        final byte[] buf = new byte[8192];
        while (!def.finished()) {
            final int n = def.deflate(buf);
            if (n > 0) baos.write(buf, 0, n);
        }
        def.end();
        return baos.toByteArray();
    }

    private static long computeCrc32(final byte[] data) {
        final CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
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