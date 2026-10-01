/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana.formats.rar.rar4.crypto;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RAR4 AES-128 CBC decryption support.
 *
 * <p>Key derivation: the password (UTF-16LE) concatenated with an 8-byte salt
 * is hashed with SHA-1 iterated 0x40000 times. The AES key comes from the final
 * digest (with a byte-swap), and the IV is built from digest bytes sampled at
 * 16 checkpoints during the iteration.</p>
 *
 * @author Stef
 * @since 1.0
 */
public final class Rar4Crypto {

    private static final int HASH_ROUNDS = 0x40000;

    private Rar4Crypto() {}

    /**
     * Builds an AES-128 CBC decipher from a password and salt.
     *
     * @param password the archive password
     * @param salt     the 8-byte salt
     * @return an initialized Cipher in DECRYPT_MODE (AES/CBC/NoPadding)
     */
    public static Cipher buildDecipher(String password, byte[] salt) throws Exception {
        byte[] aesInit = new byte[16];
        byte[] aesKey  = new byte[16];

        int rawLen = 2 * password.length();
        byte[] rawPsw = new byte[rawLen + 8];
        byte[] pwd = password.getBytes("ISO-8859-1");
        for (int i = 0; i < password.length(); i++) {
            rawPsw[i * 2]     = pwd[i];
            rawPsw[i * 2 + 1] = 0;
        }
        System.arraycopy(salt, 0, rawPsw, rawLen, 8);

        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        final int xh = HASH_ROUNDS / 16;

        for (int i = 0; i < HASH_ROUNDS; i++) {
            sha.update(rawPsw);
            sha.update((byte) i);
            sha.update((byte) (i >>> 8));
            sha.update((byte) (i >>> 16));
            if (i % xh == 0) {
                MessageDigest clone = (MessageDigest) sha.clone();
                byte[] d = clone.digest();
                aesInit[i / xh] = d[19];
            }
        }
        byte[] digest = sha.digest();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                aesKey[i * 4 + j] = (byte) (((digest[i * 4] * 0x1000000) & 0xff000000
                        | ((digest[i * 4 + 1] * 0x10000) & 0xff0000)
                        | ((digest[i * 4 + 2] * 0x100) & 0xff00)
                        |  (digest[i * 4 + 3] & 0xff)) >>> (j * 8));
            }
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(aesInit));
        return cipher;
    }
}