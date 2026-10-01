/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.zip;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * AES-CTR keystream as used by WinZip AES (AE-1 / AE-2).
 *
 * <p>WinZip increments a 128-bit counter in <b>little-endian</b> order,
 * starting at 1. The JCE "AES/CTR/NoPadding" transformation increments in
 * big-endian order, so it only matches for the very first 16-byte block and
 * produces garbage afterwards. This class builds the keystream manually from
 * AES/ECB so the counter layout is exactly the WinZip one.</p>
 *
 * <p>CTR is symmetric: the same {@link #process(byte[], int, int)} call
 * encrypts and decrypts.</p>
 *
 * @author Stef
 */
final class WinZipAesCtr {

    private final Cipher ecb;
    private final byte[] counter   = new byte[16];
    private final byte[] keystream = new byte[16];
    private int          ksPos     = 16; // forces a new block on first use

    WinZipAesCtr(final SecretKey key) throws GeneralSecurityException {
        ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, key);
    }

    /** XORs {@code len} bytes of {@code buf} in place with the keystream. */
    void process(final byte[] buf, final int off, final int len) throws GeneralSecurityException {
        for (int i = 0; i < len; i++) {
            if (ksPos == 16) nextBlock();
            buf[off + i] ^= keystream[ksPos++];
        }
    }

    private void nextBlock() throws GeneralSecurityException {
        // little-endian increment: counter goes 1, 2, 3 ... from byte 0 upward
        for (int i = 0; i < 16; i++) { if (++counter[i] != 0) break; }
        ecb.doFinal(counter, 0, 16, keystream, 0);
        ksPos = 0;
    }
}
