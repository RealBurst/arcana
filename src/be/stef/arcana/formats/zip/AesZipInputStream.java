/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.zip;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

/**
 * Decrypts a WinZip AES-encrypted ZIP entry (AE-1 / AE-2, PKWARE Extra Field 0x9901).
 *
 * <p>Format (before compressed data):</p>
 * <ul>
 *   <li>Salt: 8 bytes (AES-128), 12 bytes (AES-192), or 16 bytes (AES-256)</li>
 *   <li>Password-verification value: 2 bytes</li>
 * </ul>
 * <p>After compressed data:</p>
 * <ul>
 *   <li>Authentication code: 10 bytes (HMAC-SHA1 truncated)</li>
 * </ul>
 *
 * <p>Keys derived via PBKDF2-HMAC-SHA1 with 1000 iterations.</p>
 */
public final class AesZipInputStream extends FilterInputStream {

    /** AES key strength constants (same as WinZip AES extra field). */
    public static final int AES_128 = 1;
    public static final int AES_192 = 2;
    public static final int AES_256 = 3;

    private static final int ITERATIONS = 1000;
    private static final int VERIFY_LENGTH = 2;
    private static final int AUTH_LENGTH   = 10;

    private final WinZipAesCtr ctr;
    private final byte[]  singleBuf = new byte[1];

    /**
     * Creates an AesZipInputStream and reads + discards the salt and verification bytes.
     *
     * @param in         raw stream positioned at the start of the salt
     * @param password   ZIP password
     * @param aesStrength 1=AES-128, 2=AES-192, 3=AES-256
     * @throws IOException                if the stream is truncated or the password is wrong
     * @throws GeneralSecurityException   if the JRE lacks AES/CTR support
     */
    public AesZipInputStream(final InputStream in, final byte[] password, final int aesStrength)
            throws IOException, GeneralSecurityException {
        super(in);
        final int keyLenBytes = aesStrength == AES_256 ? 32 : aesStrength == AES_192 ? 24 : 16;
        final int saltLen = keyLenBytes / 2;

        // Read salt
        final byte[] salt = readExactly(in, saltLen);

        // Derive keys: PBKDF2 produces keyLen + keyLen + 2 bytes
        // [0..keyLen-1] = AES key, [keyLen..2*keyLen-1] = HMAC key, [2*keyLen..] = verify bytes
        final int derivedLen = keyLenBytes * 2 + VERIFY_LENGTH;
        final KeySpec spec = new PBEKeySpec(bytesToChars(password), salt, ITERATIONS, derivedLen * 8);
        final byte[] derived = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();

        // Verify password
        final byte[] storedVerify = readExactly(in, VERIFY_LENGTH);
        if (storedVerify[0] != derived[derivedLen - 2] || storedVerify[1] != derived[derivedLen - 1]) {
            throw new IOException("Wrong password for AES-encrypted ZIP entry");
        }

        // Set up AES/CTR cipher (WinZip uses CTR mode with little-endian counter starting at 1)
        final SecretKey aesKey = new SecretKeySpec(derived, 0, keyLenBytes, "AES");
        // WinZip CTR: little-endian counter starting at 1 (JCE AES/CTR is big-endian, not usable)
        ctr = new WinZipAesCtr(aesKey);
    }

    @Override
    public int read() throws IOException {
        final int n = read(singleBuf, 0, 1);
        return n < 0 ? -1 : singleBuf[0] & 0xFF;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        final int n = in.read(buf, off, len);
        if (n < 0) return -1;
        try {
            ctr.process(buf, off, n);
        } catch (final Exception e) {
            throw new IOException("AES decryption error: " + e.getMessage(), e);
        }
        return n;
    }

    // ---- helpers ----

    private static byte[] readExactly(final InputStream in, final int n) throws IOException {
        final byte[] buf = new byte[n];
        int off = 0;
        while (off < n) { final int r = in.read(buf, off, n-off); if (r<0) throw new IOException("Truncated AES ZIP header"); off+=r; }
        return buf;
    }

    private static char[] bytesToChars(final byte[] bytes) {
        final char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) chars[i] = (char)(bytes[i] & 0xFF);
        return chars;
    }
}
