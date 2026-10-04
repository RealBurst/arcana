/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.innosetup;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encryption of Inno Setup installers.
 *
 * <ul>
 *   <li>Up to 6.3: RC4 per chunk, key = SHA-1(8-byte chunk salt + password),
 *       first 1000 key stream bytes dropped; password check = SHA-1("PasswordCheckHash"
 *       + header salt + password).</li>
 *   <li>6.4 and later: XChaCha20, key = PBKDF2-HMAC-SHA256(password, salt,
 *       iterations, 32); the 24-byte nonce of a chunk is the base nonce with its
 *       first 8 bytes xored with the chunk offset and the next 4 with its first
 *       slice (-1 for the password test, -2 and -3 for the two header blocks
 *       when everything is encrypted).</li>
 * </ul>
 *
 * <p>The password is hashed as UTF-16LE in Unicode installers, as single
 * bytes in the old ANSI ones.</p>
 */
final class InnoCrypto {

    private InnoCrypto() {
    }

    // =========================================================================
    // Cipher streams
    // =========================================================================

    /** A stream cipher: the same call encrypts and decrypts. */
    interface Cipher {
        void crypt(byte[] b, int off, int len);
    }

    /** Decrypts what is read through it. */
    static InputStream decrypting(final InputStream in, final Cipher c) {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                final byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                final int n = in.read(b, off, len);
                if (n > 0) c.crypt(b, off, n);
                return n;
            }

            @Override
            public void close() throws IOException {
                in.close();
            }
        };
    }

    // =========================================================================
    // RC4 (up to 6.3)
    // =========================================================================

    static Cipher rc4(final byte[] salt, final byte[] password) throws IOException {
        final MessageDigest sha1 = digest("SHA-1");
        sha1.update(salt);
        sha1.update(password);
        final byte[] key = sha1.digest();
        final int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        for (int i = 0, j = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xff)) & 0xff;
            final int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }
        final Cipher c = new Cipher() {
            private int i;
            private int j;

            @Override
            public void crypt(final byte[] b, final int off, final int len) {
                for (int k = off; k < off + len; k++) {
                    i = (i + 1) & 0xff;
                    j = (j + s[i]) & 0xff;
                    final int t = s[i];
                    s[i] = s[j];
                    s[j] = t;
                    b[k] ^= s[(s[i] + s[j]) & 0xff];
                }
            }
        };
        c.crypt(new byte[1000], 0, 1000);
        return c;
    }

    /** Password check of the RC4 era. */
    static boolean rc4PasswordOk(final byte[] headerSalt, final byte[] expectedSha1, final byte[] password) throws IOException {
        final MessageDigest sha1 = digest("SHA-1");
        sha1.update("PasswordCheckHash".getBytes("US-ASCII"));
        sha1.update(headerSalt);
        sha1.update(password);
        return MessageDigest.isEqual(sha1.digest(), expectedSha1);
    }

    // =========================================================================
    // XChaCha20 (6.4 and later)
    // =========================================================================

    static byte[] deriveKey(final byte[] password, final byte[] salt, final int iterations) throws IOException {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            byte[] p = password;
            if (p.length > 64) p = digest("SHA-256").digest(p);
            // SecretKeySpec refuses an empty key; HMAC pads keys with zeros to 64 bytes, so it is the same key
            mac.init(new SecretKeySpec(p.length == 0 ? new byte[64] : p, "HmacSHA256"));
            mac.update(salt);
            mac.update(new byte[] {0, 0, 0, 1});
            byte[] u = mac.doFinal();
            final byte[] f = u.clone();
            for (int i = 1; i < iterations; i++) {
                u = mac.doFinal(u);
                for (int k = 0; k < f.length; k++) f[k] ^= u[k];
            }
            return f;
        } catch (final GeneralSecurityException e) {
            throw new IOException("HMAC-SHA256 not available: " + e.getMessage(), e);
        }
    }

    /** XChaCha20 for a chunk at (offset, firstSlice), counter 0. */
    static Cipher xchacha(final byte[] key, final byte[] baseNonce, final long startOffset, final int firstSlice) {
        final byte[] nonce = baseNonce.clone();
        for (int i = 0; i < 8; i++) nonce[i] ^= (byte) (startOffset >>> (8 * i));
        for (int i = 0; i < 4; i++) nonce[8 + i] ^= (byte) (firstSlice >>> (8 * i));
        // HChaCha20 on the first 16 nonce bytes gives the sub-key
        final int[] st = new int[16];
        st[0] = 0x61707865;
        st[1] = 0x3320646e;
        st[2] = 0x79622d32;
        st[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) st[4 + i] = le32(key, 4 * i);
        for (int i = 0; i < 4; i++) st[12 + i] = le32(nonce, 4 * i);
        rounds(st);
        final int[] state = new int[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int i = 0; i < 4; i++) state[4 + i] = st[i];
        for (int i = 0; i < 4; i++) state[8 + i] = st[12 + i];
        state[12] = 0;
        state[13] = 0;
        state[14] = le32(nonce, 16);
        state[15] = le32(nonce, 20);
        return new Cipher() {
            private final byte[] stream = new byte[64];
            private int pos = 64;

            @Override
            public void crypt(final byte[] b, final int off, final int len) {
                for (int k = off; k < off + len; k++) {
                    if (pos == 64) {
                        final int[] x = state.clone();
                        rounds(x);
                        for (int i = 0; i < 16; i++) {
                            final int v = x[i] + state[i];
                            stream[4 * i] = (byte) v;
                            stream[4 * i + 1] = (byte) (v >>> 8);
                            stream[4 * i + 2] = (byte) (v >>> 16);
                            stream[4 * i + 3] = (byte) (v >>> 24);
                        }
                        if (++state[12] == 0) state[13]++;
                        pos = 0;
                    }
                    b[k] ^= stream[pos++];
                }
            }
        };
    }

    /** Password check of 6.4 and later: an encrypted 32-bit zero with first slice -1. */
    static boolean xchachaPasswordOk(final byte[] key, final byte[] baseNonce, final int expected) {
        final byte[] zero = new byte[4];
        xchacha(key, baseNonce, 0, -1).crypt(zero, 0, 4);
        return le32(zero, 0) == expected;
    }

    private static void rounds(final int[] x) {
        for (int i = 0; i < 10; i++) {
            qr(x, 0, 4, 8, 12);
            qr(x, 1, 5, 9, 13);
            qr(x, 2, 6, 10, 14);
            qr(x, 3, 7, 11, 15);
            qr(x, 0, 5, 10, 15);
            qr(x, 1, 6, 11, 12);
            qr(x, 2, 7, 8, 13);
            qr(x, 3, 4, 9, 14);
        }
    }

    private static void qr(final int[] x, final int a, final int b, final int c, final int d) {
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = Integer.rotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = Integer.rotateLeft(x[b] ^ x[c], 7);
    }

    // =========================================================================

    static MessageDigest digest(final String name) throws IOException {
        try {
            return MessageDigest.getInstance(name);
        } catch (final GeneralSecurityException e) {
            throw new IOException(name + " not available", e);
        }
    }

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }
}
