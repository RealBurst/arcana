/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.zip;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Decrypts a ZipCrypto (PKWare traditional encryption) stream.
 *
 * <p>Positioned at the start of the 12-byte encryption header on entry;
 * after construction the stream delivers plaintext bytes directly.</p>
 *
 * <p>Algorithm: PKWARE App Note section 6.1.
 * Init: K0=305419896, K1=591751049, K2=878082192.
 * The 12-byte header is consumed and decrypted in the constructor.</p>
 */
public final class ZipCryptoInputStream extends FilterInputStream {

    private static final int K0_INIT = 305419896;
    private static final int K1_INIT = 591751049;
    private static final int K2_INIT = 878082192;

    private static final int[] CRC_TABLE = buildCrcTable();

    private int key0 = K0_INIT;
    private int key1 = K1_INIT;
    private int key2 = K2_INIT;

    private final int checkByte;

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

    private int decryptByte() { final int t = (key2 | 2) & 0xFFFF; return ((t * (t ^ 1)) >>> 8) & 0xFF; }

    public ZipCryptoInputStream(final InputStream in, final byte[] password) throws IOException {
        super(in);
        for (final byte b : password) updateKeys(b & 0xFF);
        final byte[] hdr = new byte[12];
        int off = 0;
        while (off < 12) { final int n = in.read(hdr, off, 12-off); if (n<0) throw new IOException("Truncated ZipCrypto header"); off+=n; }
        for (int i = 0; i < 12; i++) { final int p = (hdr[i]&0xFF)^decryptByte(); updateKeys(p); hdr[i]=(byte)p; }
        checkByte = hdr[11] & 0xFF;
    }

    /** The decrypted byte 11 of the header; used to verify the password. */
    public int getCheckByte() { return checkByte; }

    @Override
    public int read() throws IOException {
        final int b = in.read(); if (b<0) return -1;
        final int p = (b^decryptByte())&0xFF; updateKeys(p); return p;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        final int n = in.read(buf, off, len); if (n<0) return -1;
        for (int i=0;i<n;i++) { final int p=(buf[off+i]&0xFF)^decryptByte(); updateKeys(p); buf[off+i]=(byte)p; }
        return n;
    }

    @Override
    public long skip(final long n) throws IOException {
        long s=0; final byte[] b=new byte[(int)Math.min(n,4096)];
        while(s<n){final int r=read(b,0,(int)Math.min(b.length,n-s));if(r<0)break;s+=r;} return s;
    }
}
