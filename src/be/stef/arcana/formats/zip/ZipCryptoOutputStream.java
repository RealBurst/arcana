/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.zip;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Encrypts a stream using ZipCrypto (PKWare traditional encryption).
 *
 * <p>On construction, writes the 12-byte encryption header to the underlying
 * stream. After that, all bytes written are encrypted before being forwarded.
 * The last byte of the header encodes the check value (high byte of CRC32).</p>
 *
 * <p>Note: ZipCrypto is considered cryptographically weak. Prefer
 * {@link AesZipOutputStream} (WinZip AES-256) for new archives.</p>
 */
public final class ZipCryptoOutputStream extends FilterOutputStream {

    private static final int K0_INIT = 305419896;
    private static final int K1_INIT = 591751049;
    private static final int K2_INIT = 878082192;

    private static final int[] CRC_TABLE = buildCrcTable();

    private int key0 = K0_INIT;
    private int key1 = K1_INIT;
    private int key2 = K2_INIT;

    private static int[] buildCrcTable() {
        final int[] t = new int[256];
        for (int i = 0; i < 256; i++) {
            int n = i;
            for (int j = 0; j < 8; j++) n = (n & 1) != 0 ? (n >>> 1) ^ 0xEDB88320 : n >>> 1;
            t[i] = n;
        }
        return t;
    }

    private static int crc32b(final int crc, final int b) { return (crc >>> 8) ^ CRC_TABLE[(crc ^ b) & 0xFF]; }

    private void updateKeys(final int b) {
        key0 = crc32b(key0, b);
        key1 = (key1 + (key0 & 0xFF)) & 0xFFFFFFFF;
        key1 = (int)(((key1 & 0xFFFFFFFFL) * 134775813L + 1L) & 0xFFFFFFFFL);
        key2 = crc32b(key2, (key1 >>> 24) & 0xFF);
    }

    private int encryptByte(final int plainByte) {
        final int t = (key2 | 2) & 0xFFFF;
        final int keyStreamByte = ((t * (t ^ 1)) >>> 8) & 0xFF;
        final int cipherByte = plainByte ^ keyStreamByte;
        updateKeys(plainByte);
        return cipherByte;
    }

    /**
     * Creates a ZipCryptoOutputStream and writes the 12-byte encryption header.
     *
     * @param out       the underlying output stream
     * @param password  the ZIP password
     * @param crc32High the high byte of the entry CRC32, used as check value
     * @throws IOException if the header cannot be written
     */
    public ZipCryptoOutputStream(final OutputStream out, final byte[] password, final int crc32High) throws IOException {
        super(out);
        for (final byte b : password) updateKeys(b & 0xFF);
        final byte[] header = new byte[12];
        new SecureRandom().nextBytes(header);
        header[11] = (byte) crc32High;
        for (int i = 0; i < 12; i++) out.write(encryptByte(header[i] & 0xFF));
    }

    @Override public void write(final int b) throws IOException { out.write(encryptByte(b & 0xFF)); }

    @Override
    public void write(final byte[] buf, final int off, final int len) throws IOException {
        final byte[] enc = new byte[len];
        for (int i = 0; i < len; i++) enc[i] = (byte) encryptByte(buf[off + i] & 0xFF);
        out.write(enc, 0, len);
    }
}
