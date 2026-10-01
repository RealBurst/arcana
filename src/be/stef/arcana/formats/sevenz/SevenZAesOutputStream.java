/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.sevenz;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Encrypts data using AES-256-CBC, compatible with the 7-Zip archive format.
 *
 * <h3>Protocol</h3>
 * <ol>
 *   <li>Instantiate: generates a random 16-byte salt and 16-byte IV.</li>
 *   <li>Write all LZMA2-compressed bytes via {@link #write}.</li>
 *   <li>The AES-256 key (SHA-256, 2^19 rounds) is derived on the first write and
 *       the data is encrypted and written as it arrives.</li>
 *   <li>Call {@link #finish()}: pads to 16-byte boundary with zeros and writes the
 *       last block. <strong>Must be called exactly once.</strong></li>
 *   <li>Call {@link #getAesProperties()} to obtain the 34-byte property block that
 *       must be embedded in the 7z folder header.</li>
 *   <li>Call {@link #getEncryptedSize()} to know the padded, encrypted byte count
 *       (needed for kPackInfo in the 7z header).</li>
 * </ol>
 *
 * <h3>Key derivation (identical to 7-Zip's AES256SHA256 decoder)</h3>
 * <pre>
 *   SHA-256 updated with (password + salt + roundCounter_LE) x 2^numCyclesPower
 * </pre>
 *
 * <h3>AES properties block (34 bytes)</h3>
 * <pre>
 *   byte  0   : numCyclesPower (19) | 0x80 (hasSalt) | 0x40 (hasIV) = 0xD3
 *   byte  1   : ((saltLen-1) << 4) | (ivLen-1) = 0xFF  (both 16 bytes)
 *   bytes 2-17: salt  (16 random bytes)
 *   bytes 18-33: IV   (16 random bytes)
 * </pre>
 *
 * <h3>Method ID in 7z folder header</h3>
 * <pre>
 *   { 0x06, 0xF1, 0x07, 0x01 }  (AES256SHA256, 4 bytes, big-endian)
 * </pre>
 */
public final class SevenZAesOutputStream extends FilterOutputStream {

    /** 7-Zip default: 2^19 = 524 288 SHA-256 rounds. */
    private static final long NUM_CYCLES_POWER = 19L;
    private static final int  SALT_LEN         = 16;
    private static final int  IV_LEN           = 16;
    private static final int  AES_BLOCK        = 16;

    /** Raw method ID bytes as stored in the 7z folder header (big-endian). */
    public static final byte[] METHOD_ID = { 0x06, (byte) 0xF1, 0x07, 0x01 };

    private final byte[]               password;
    private final byte[]               salt;
    private final byte[]               iv;
    private Cipher                     cipher;          // created on the first write (key derivation is slow)
    private final byte[]               one = new byte[1];
    private long                       rawSize = 0;     // LZMA2 bytes received
    private boolean                    finished = false;

    /**
     * Creates a SevenZAesOutputStream.
     *
     * <p>Since 1.3 the data is encrypted and written <b>as it arrives</b> (AES-CBC
     * is a stream of 16-byte blocks): nothing is kept in memory, so archives of
     * any size can be encrypted.</p>
     *
     * @param out      stream that will receive the AES-encrypted bytes
     * @param password the archive password (raw bytes, e.g. {@code password.getBytes("UTF-8")})
     */
    public SevenZAesOutputStream(final OutputStream out, final byte[] password) {
        super(out);
        this.password = password;
        this.salt = new byte[SALT_LEN];
        this.iv   = new byte[IV_LEN];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);
    }

    private Cipher cipher() throws IOException {
        if (cipher == null) {
            try {
                final byte[] key = deriveKey(password, salt, NUM_CYCLES_POWER);
                final Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                cipher = c;
            } catch (final Exception e) {
                throw new IOException("7z AES-256-CBC encryption failed: " + e.getMessage(), e);
            }
        }
        return cipher;
    }

    @Override
    public void write(final int b) throws IOException {
        one[0] = (byte) b;
        write(one, 0, 1);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        if (finished) throw new IOException("SevenZAesOutputStream already finished");
        if (len <= 0) return;
        // The cipher keeps the incomplete last block internally (NoPadding)
        final byte[] enc = cipher().update(b, off, len);
        rawSize += len;
        if (enc != null && enc.length > 0) out.write(enc);
    }

    /**
     * Pads the data to a 16-byte boundary (zero fill, 7-Zip convention) and writes
     * the last encrypted block. Does not close the underlying stream.
     *
     * @throws IOException              if an I/O error occurs
     * @throws IllegalStateException    if called more than once
     */
    public void finish() throws IOException {
        if (finished) throw new IllegalStateException("SevenZAesOutputStream already finished");
        finished = true;
        try {
            final int rem = (int) (rawSize % AES_BLOCK);
            final byte[] pad = new byte[rem == 0 ? 0 : AES_BLOCK - rem];
            final byte[] last = cipher().doFinal(pad);
            if (last != null && last.length > 0) out.write(last);
        } catch (final IOException e) {
            throw e;
        } catch (final Exception e) {
            throw new IOException("7z AES-256-CBC encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the 34-byte AES property block to embed in the 7z folder header,
     * immediately after the method ID and before the bind pairs.
     * Valid only after the constructor has run (does not require {@link #finish()}).
     *
     * @return 34-byte array: [0xD3, 0xFF, salt[16], iv[16]]
     */
    public byte[] getAesProperties() {
        final byte[] props = new byte[2 + SALT_LEN + IV_LEN];
        // byte 0: numCyclesPower in bits 5-0, bit 7=hasSalt, bit 6=hasIV
        props[0] = (byte) (NUM_CYCLES_POWER | 0x80 | 0x40);  // 19 | 0xC0 = 0xD3
        // byte 1: (saltLen-1) in high nibble, (ivLen-1) in low nibble
        props[1] = (byte) (((SALT_LEN - 1) << 4) | (IV_LEN - 1));  // (15<<4)|15 = 0xFF
        System.arraycopy(salt, 0, props, 2,            SALT_LEN);
        System.arraycopy(iv,   0, props, 2 + SALT_LEN, IV_LEN);
        return props;
    }

    /**
     * Returns the byte count that will be written by {@link #finish()}.
     * This equals the LZMA2-compressed data size padded up to the next 16-byte boundary.
     * Use this value for {@code kPackInfo} -> {@code kSize} in the 7z header.
     * Valid only after all source data has been written (before or after {@link #finish()}).
     */
    public long getEncryptedSize() {
        final long raw = rawSize;
        final long rem = raw % AES_BLOCK;
        return rem == 0 ? raw : raw + (AES_BLOCK - rem);
    }

    // -------------------------------------------------------------------------
    // Key derivation - delegates to AES256SHA256Decoder so both sides stay identical
    // -------------------------------------------------------------------------

    /**
     * Derives the 32-byte AES key exactly like 7-Zip: password decoded as UTF-8 then
     * re-encoded in UTF-16LE, and each of the 2^numCyclesPower SHA-256 rounds hashes
     * salt + password + 8-byte little-endian round counter (salt FIRST).
     */
    static byte[] deriveKey(final byte[] password, final byte[] salt, final long numCyclesPower) {
        final char[] chars = new String(password, StandardCharsets.UTF_8).toCharArray();
        return AES256SHA256Decoder.sha256Password(chars, (int) numCyclesPower, salt);
    }
}
