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
import javax.crypto.spec.SecretKeySpec;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Encrypts a stream using WinZip AES encryption (AE-2 variant, no CRC in header).
 *
 * <p>Data written to the underlying stream in order:</p>
 * <ol>
 *   <li>Salt (8/12/16 bytes depending on key strength)</li>
 *   <li>Password-verification value (2 bytes)</li>
 *   <li>Encrypted data (AES-CTR, counter starting at 1 little-endian)</li>
 *   <li>Authentication code (10 bytes HMAC-SHA1, written by {@link #finish()})</li>
 * </ol>
 *
 * <p>The caller MUST call {@link #finish()} after writing all data.</p>
 */
public final class AesZipOutputStream extends FilterOutputStream {

    public static final int AES_128 = 1;
    public static final int AES_192 = 2;
    public static final int AES_256 = 3;

    private static final int ITERATIONS  = 1000;
    private static final int AUTH_LENGTH = 10;
    private static final int VERIFY_LEN  = 2;

    private final WinZipAesCtr ctr;
    private final Mac     hmac;
    private boolean       finished = false;

    /** Salt length in bytes for each key strength (1=AES-128, 2=AES-192, 3=AES-256). */
    public static int saltSize(final int strength) {
        return strength == AES_256 ? 16 : strength == AES_192 ? 12 : 8;
    }

    /** Total overhead before the data: salt + verification bytes. */
    public static int headerSize(final int strength) { return saltSize(strength) + VERIFY_LEN; }

    /** Overhead after the data: HMAC-SHA1 truncated to 10 bytes. */
    public static int trailerSize() { return AUTH_LENGTH; }

    /**
     * Creates an AesZipOutputStream. Writes salt + verification bytes to the underlying stream.
     *
     * @param out      underlying stream
     * @param password ZIP password (raw bytes, used as is by PBKDF2: UTF-8 for WinZip and 7-Zip)
     * @param strength {@link #AES_128}, {@link #AES_192}, or {@link #AES_256}
     */
    public AesZipOutputStream(final OutputStream out, final byte[] password, final int strength) throws IOException, GeneralSecurityException {
        super(out);
        final int keyLen   = strength == AES_256 ? 32 : strength == AES_192 ? 24 : 16;
        final int saltLen  = keyLen / 2;
        final byte[] salt  = new byte[saltLen];
        new SecureRandom().nextBytes(salt);

        final int derivedLen = keyLen * 2 + VERIFY_LEN;
        final byte[] derived = AesZipInputStream.pbkdf2HmacSha1(password, salt, ITERATIONS, derivedLen);

        out.write(salt);
        out.write(derived, derivedLen - VERIFY_LEN, VERIFY_LEN);

        // WinZip CTR: little-endian counter starting at 1 (JCE AES/CTR is big-endian, not usable)
        final SecretKey aesKey = new SecretKeySpec(derived, 0, keyLen, "AES");
        ctr = new WinZipAesCtr(aesKey);

        hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(derived, keyLen, keyLen, "HmacSHA1"));
    }

    @Override public void write(final int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }

    @Override
    public void write(final byte[] buf, final int off, final int len) throws IOException {
        try {
            final byte[] enc = new byte[len];
            System.arraycopy(buf, off, enc, 0, len);
            ctr.process(enc, 0, len);
            hmac.update(enc);
            out.write(enc);
        } catch (final Exception e) { throw new IOException("AES-CTR encryption error: " + e.getMessage(), e); }
    }

    /**
     * Finalises encryption and writes the 10-byte HMAC-SHA1 authentication code.
     * Must be called after all plaintext bytes have been written.
     */
    public void finish() throws IOException {
        if (finished) return;
        finished = true;
        try {
            final byte[] auth = hmac.doFinal();
            out.write(auth, 0, AUTH_LENGTH);
        } catch (final Exception e) { throw new IOException("AES-CTR finish error: " + e.getMessage(), e); }
    }
}
