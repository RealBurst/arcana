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
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

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
 * <p>Keys derived via PBKDF2-HMAC-SHA1 with 1000 iterations over the raw password
 * bytes (UTF-8 for WinZip and 7-Zip). The authentication code (HMAC-SHA1 of the
 * encrypted data with the derived HMAC key) is computed while reading and compared
 * by {@link #isAuthentic()}.</p>
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
    private final Mac     hmac;
    private final byte[]  singleBuf = new byte[1];
    private long          dataLeft; // encrypted bytes not read yet (the authentication code follows them)

    /**
     * Creates an AesZipInputStream and reads + discards the salt and verification bytes.
     *
     * @param in          raw stream positioned at the start of the salt, holding the whole entry payload
     * @param password    ZIP password (raw bytes, UTF-8 for WinZip and 7-Zip)
     * @param aesStrength 1=AES-128, 2=AES-192, 3=AES-256
     * @param payloadSize compressed size of the entry: salt + verifier + encrypted data + authentication code
     * @throws IOException                if the stream is truncated or the password is wrong
     * @throws GeneralSecurityException   if the JRE lacks AES/CTR support
     */
    public AesZipInputStream(final InputStream in, final byte[] password, final int aesStrength, final long payloadSize)
            throws IOException, GeneralSecurityException {
        super(in);
        final int keyLenBytes = aesStrength == AES_256 ? 32 : aesStrength == AES_192 ? 24 : 16;
        final int saltLen = keyLenBytes / 2;
        dataLeft = payloadSize - saltLen - VERIFY_LENGTH - AUTH_LENGTH;
        if (dataLeft < 0) throw new IOException("Truncated AES ZIP header");

        // Read salt
        final byte[] salt = readExactly(in, saltLen);

        // Derive keys: PBKDF2 produces keyLen + keyLen + 2 bytes
        // [0..keyLen-1] = AES key, [keyLen..2*keyLen-1] = HMAC key, [2*keyLen..] = verify bytes
        final int derivedLen = keyLenBytes * 2 + VERIFY_LENGTH;
        final byte[] derived = pbkdf2HmacSha1(password, salt, ITERATIONS, derivedLen);

        // Verify password
        final byte[] storedVerify = readExactly(in, VERIFY_LENGTH);
        if (storedVerify[0] != derived[derivedLen - 2] || storedVerify[1] != derived[derivedLen - 1]) {
            throw new IOException("Wrong password for AES-encrypted ZIP entry");
        }

        // Set up AES/CTR cipher (WinZip uses CTR mode with little-endian counter starting at 1)
        final SecretKey aesKey = new SecretKeySpec(derived, 0, keyLenBytes, "AES");
        // WinZip CTR: little-endian counter starting at 1 (JCE AES/CTR is big-endian, not usable)
        ctr = new WinZipAesCtr(aesKey);

        hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(derived, keyLenBytes, keyLenBytes, "HmacSHA1"));
    }

    @Override
    public int read() throws IOException {
        final int n = read(singleBuf, 0, 1);
        return n < 0 ? -1 : singleBuf[0] & 0xFF;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        if (dataLeft <= 0) return -1;
        final int n = in.read(buf, off, (int) Math.min(len, dataLeft));
        if (n < 0) throw new IOException("Truncated AES-encrypted ZIP entry");
        dataLeft -= n;
        try {
            hmac.update(buf, off, n); // the code covers the encrypted bytes
            ctr.process(buf, off, n);
        } catch (final Exception e) {
            throw new IOException("AES decryption error: " + e.getMessage(), e);
        }
        return n;
    }

    /**
     * Reads the encrypted bytes not consumed by the decoder (they still count in
     * the code), then the 10-byte authentication code, and compares it with the
     * HMAC-SHA1 of the encrypted data. Call once, after the decoder has finished.
     *
     * @return true when the stored code matches
     * @throws IOException if the entry is truncated
     */
    public boolean isAuthentic() throws IOException {
        final byte[] skip = new byte[8192];
        while (dataLeft > 0) {
            final int n = in.read(skip, 0, (int) Math.min(skip.length, dataLeft));
            if (n < 0) throw new IOException("Truncated AES-encrypted ZIP entry");
            hmac.update(skip, 0, n);
            dataLeft -= n;
        }
        final byte[] stored = readExactly(in, AUTH_LENGTH);
        final byte[] computed = hmac.doFinal();
        final byte[] expected = new byte[AUTH_LENGTH];
        System.arraycopy(computed, 0, expected, 0, AUTH_LENGTH);
        return MessageDigest.isEqual(stored, expected);
    }

    /**
     * PBKDF2-HMAC-SHA1 (RFC 8018) over the raw password bytes. The JDK
     * "PBKDF2WithHmacSHA1" takes a char[] and encodes it itself, which cannot
     * represent arbitrary bytes (a UTF-8 password would be encoded twice).
     */
    static byte[] pbkdf2HmacSha1(final byte[] password, final byte[] salt, final int iterations, final int length) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance("HmacSHA1");
        // SecretKeySpec refuses an empty key; HMAC pads the key with zeros, so {0} is the same key
        mac.init(new SecretKeySpec(password.length == 0 ? new byte[1] : password, "HmacSHA1"));
        final int hLen = mac.getMacLength();
        final byte[] out = new byte[length];
        final byte[] u = new byte[hLen];
        final byte[] t = new byte[hLen];
        for (int block = 1, pos = 0; pos < length; block++, pos += hLen) {
            mac.update(salt);
            mac.update(new byte[]{(byte) (block >>> 24), (byte) (block >>> 16), (byte) (block >>> 8), (byte) block});
            mac.doFinal(u, 0);
            System.arraycopy(u, 0, t, 0, hLen);
            for (int i = 1; i < iterations; i++) {
                mac.update(u);
                mac.doFinal(u, 0);
                for (int j = 0; j < hLen; j++) t[j] ^= u[j];
            }
            System.arraycopy(t, 0, out, pos, Math.min(hLen, length - pos));
        }
        return out;
    }

    // ---- helpers ----

    private static byte[] readExactly(final InputStream in, final int n) throws IOException {
        final byte[] buf = new byte[n];
        int off = 0;
        while (off < n) { final int r = in.read(buf, off, n-off); if (r<0) throw new IOException("Truncated AES ZIP header"); off+=r; }
        return buf;
    }
}
