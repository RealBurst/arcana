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
package be.stef.arcana.formats.rar.rar5.crypto;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import be.stef.arcana.exceptions.RarDecryptException;
import be.stef.arcana.formats.rar.rar5.extra.Rar5ExtraCrypto;


/**
 * Cryptographic operations for RAR5 archives.
 * 
 * <p>RAR5 uses the following encryption scheme:</p>
 * <ul>
 *   <li>AES-256 in CBC mode (Cipher Block Chaining)</li>
 *   <li>PBKDF2-HMAC-SHA256 for key derivation</li>
 *   <li>HMAC-SHA256 for optional authentication (MAC)</li>
 * </ul>
 * 
 * <p>RAR5 uses a custom PBKDF2 scheme with three separate derivations:</p>
 * <ul>
 *   <li>AES Key: iterations = 2^kdfIterationExponent</li>
 *   <li>HashKey: iterations = 2^kdfIterationExponent + 16</li>
 *   <li>PswCheck: iterations = 2^kdfIterationExponent + 32</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public final class Rar5Crypto {
    private static final int KEY_SIZE = 32;  // AES-256 = 256 bits = 32 bytes
    private static final int IV_SIZE = 16;   // AES block size = 128 bits = 16 bytes
    private static final int PSW_CHECK_OFFSET = 32;
    private static final int PSW_CHECK_SIZE = 8;
    private static final int PSW_CHECKSUM_SIZE = 4;
    
    private Rar5Crypto() {
    }
    
    /**
     * Derives an AES encryption key from a password using PBKDF2.
     * <p>RAR5 uses PBKDF2-HMAC-SHA256 with 2^kdfIterationExponent iterations.</p>
     * 
     * @param password the password
     * @param salt the 16-byte salt
     * @param kdfIterationExponent iteration count exponent (actual iterations = 2^kdfIterationExponent)
     * @return the derived 32-byte AES key
     * @throws Exception if key derivation fails
     */
    public static byte[] deriveKey(String password, byte[] salt, int kdfIterationExponent) throws Exception {
        int iterations = 1 << kdfIterationExponent;
        return pbkdf2Sha256(password, salt, iterations, KEY_SIZE);
    }
    
    /**
     * Derives both the AES Key and the HashKey from a single PBKDF2 run (64 bytes total).
     * 
     * @param password the password
     * @param salt the 16-byte salt
     * @param kdfIterationExponent the log2 of the number of PBKDF2 iterations
     * @return container with derived keys
     * @throws Exception if key derivation fails
     */
    public static Rar5DerivedKeys deriveAllKeys(String password, byte[] salt, int kdfIterationExponent) throws Exception {
        // 1. Compute the iteration count: 2 ^ kdfIterationExponent
        int iterations = 1 << kdfIterationExponent;
        
        // 2. Total derived key length: 32 bytes (AES key) + 32 bytes (hash key) = 64 bytes (512 bits)
        int totalKeyLengthBits = 64 * 8; 
        
        // 3. Call PBKDF2 once (contiguous derivation)
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, totalKeyLengthBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); 
        byte[] totalDerivedKey = skf.generateSecret(spec).getEncoded();
        
        // 4. Split the keys
        byte[] aesKey = Arrays.copyOfRange(totalDerivedKey, 0, 32);
        byte[] hashKey = Arrays.copyOfRange(totalDerivedKey, 32, 64);
        
        return new Rar5DerivedKeys(aesKey, hashKey);
    }
    
    /**
     * Verifies if the password is correct using the stored password check value.
     * 
     * <p>RAR5 uses a custom PBKDF2 scheme where iterations continue and XOR accumulates
     * separately for each derived value.</p>
     */
    public static boolean verifyPassword(String password, Rar5ExtraCrypto crypto) throws Exception {
        return verifyPassword(password, crypto, false);
    }
    
    /**
     * Verifies password with optional debug output.
     */
    public static boolean verifyPassword(String password, Rar5ExtraCrypto crypto, boolean debug) throws Exception {
        if (!crypto.hasPasswordCheck()) {
            if (debug) System.out.println("    No password check value stored");
            return true;
        }
        
        byte[] storedCheck = crypto.getPasswordCheck();
        if (storedCheck == null || storedCheck.length < PSW_CHECK_SIZE + PSW_CHECKSUM_SIZE) {
            if (debug) System.out.println("    Invalid password check length: " + (storedCheck == null ? "null" : storedCheck.length));
            return true;
        }
        
        if (debug) {
            System.out.println("    Stored PasswordCheck (12 bytes): " + bytesToHex(storedCheck));
            System.out.println("    Stored PswCheck[0:8]: " + bytesToHex(Arrays.copyOf(storedCheck, PSW_CHECK_SIZE)));
            System.out.println("    Stored Checksum[8:12]: " + bytesToHex(Arrays.copyOfRange(storedCheck, PSW_CHECK_SIZE, PSW_CHECK_SIZE + PSW_CHECKSUM_SIZE)));
        }
        
        // First verify the integrity of the stored check value itself
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] storedCheckHash = sha256.digest(Arrays.copyOf(storedCheck, PSW_CHECK_SIZE));
        
        if (debug) {
            System.out.println("    SHA256(stored[0:8])[0:4]: " + bytesToHex(Arrays.copyOf(storedCheckHash, PSW_CHECKSUM_SIZE)));
        }
        
        boolean integrityOk = true;
        for (int i = 0; i < PSW_CHECKSUM_SIZE; i++) {
            if (storedCheckHash[i] != storedCheck[PSW_CHECK_SIZE + i]) {
                integrityOk = false;
                break;
            }
        }
        
        if (debug) {
            System.out.println("    Integrity check: " + (integrityOk ? "PASSED" : "FAILED"));
        }
        
        if (!integrityOk) {
            return true; // Cannot verify if corrupted
        }
        
        // 2. Full PBKDF2 computation (base + 32 iterations)
        int baseIterations = 1 << crypto.getKdfIterationExponent();
        // Use the standard Java implementation directly (works fine here)
        byte[] fullHash = pbkdf2Sha256(password, crypto.getSalt(), baseIterations + PSW_CHECK_OFFSET, KEY_SIZE);
        
        if (debug) {
            System.out.println("    Full PBKDF2 output (32 bytes): " + bytesToHex(fullHash));
        }

        // 3. XOR "Folding"
        // Fold the 32 bytes into 8 bytes by XOR-ing them together
        byte[] calculatedCheck = new byte[PSW_CHECK_SIZE];
        for (int i = 0; i < KEY_SIZE; i++) {
            calculatedCheck[i % PSW_CHECK_SIZE] ^= fullHash[i];
        }

        if (debug) {
             System.out.println("    Calculated PswCheck (Folded): " + bytesToHex(calculatedCheck));
        }
        
        // 4. Comparaison
        boolean match = true;
        for (int i = 0; i < PSW_CHECK_SIZE; i++) {
            if (calculatedCheck[i] != storedCheck[i]) {
                match = false;
                break;
            }
        }
        
        return match;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i] & 0xFF));
        }
        return sb.toString().trim();
    }
    
    /**
     * PBKDF2 with HMAC-SHA256.
     * 
     * @param password the password
     * @param salt the salt
     * @param iterations number of iterations
     * @param keyLength desired key length in bytes
     * @return the derived key
     * @throws Exception if derivation fails
     */
    private static byte[] pbkdf2Sha256(String password, byte[] salt, int iterations, int keyLength) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength * 8);
        return factory.generateSecret(spec).getEncoded();
    }
    
    /**
     * Container for all RAR5 derived keys.
     */
    public static class Rar5DerivedKeys {
        private final byte[] aesKey;
        private final byte[] hashKey;
        
        public Rar5DerivedKeys(byte[] aesKey, byte[] hashKey) {
            this.aesKey = aesKey;
            this.hashKey = hashKey;
        }
        
        /** @return the 32-byte AES-256 encryption key */
        public byte[] getAesKey() {
            return aesKey;
        }
        
        /** @return the 32-byte hash key for HMAC verification */
        public byte[] getHashKey() {
            return hashKey;
        }
    }
    
    /**
     * Decrypts data using AES-256-CBC.
     * 
     * @param encryptedData the encrypted data (must be multiple of 16 bytes)
     * @param key the 32-byte AES key
     * @param iv the 16-byte initialization vector
     * @return the decrypted data
     * @throws Exception if decryption fails
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        if (encryptedData.length % 16 != 0) {
            throw new RarDecryptException("Encrypted data size must be multiple of 16 bytes, got: " + encryptedData.length);
        }
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        return cipher.doFinal(encryptedData);
    }
    
    /**
     * Decrypts file data.
     * 
     * <p><b>Important:</b> For file data, the IV is used directly without modification.
     * This is different from file name decryption which XORs the IV with the file index.</p>
     * 
     * @param encryptedData the encrypted file data
     * @param key the derived AES key for this file
     * @param iv the IV from the file's crypto extra record
     * @return the decrypted data (still compressed)
     * @throws Exception if decryption fails
     */
    public static byte[] decryptFileData(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        return decrypt(encryptedData, key, iv);
    }
    
    /**
     * Decrypts an encrypted file name.
     * 
     * <p><b>Note:</b> For file names, the IV is XORed with the file index to create
     * a unique IV for each file. This prevents identical file names from producing
     * identical ciphertext.</p>
     * 
     * @param encryptedName the encrypted file name bytes
     * @param key the AES key
     * @param baseIV the base IV from the crypto record
     * @param fileIndex the index of this file in the archive
     * @return the decrypted file name
     * @throws Exception if decryption fails
     */
    public static String decryptFileName(byte[] encryptedName, byte[] key, byte[] baseIV, long fileIndex) throws Exception {
        byte[] fileIV = Arrays.copyOf(baseIV, IV_SIZE);
        for (int i = 0; i < 8; i++) {
            fileIV[i] ^= (byte) ((fileIndex >> (i * 8)) & 0xFF);
        }
        
        byte[] decryptedName = decrypt(encryptedName, key, fileIV);
        
        int length = decryptedName.length;
        for (int i = 0; i < decryptedName.length; i++) {
            if (decryptedName[i] == 0) {
                length = i;
                break;
            }
        }
        
        return new String(decryptedName, 0, length, "UTF-8");
    }
    
    /**
     * Verifies data integrity using HMAC-SHA256.
     * 
     * @param data the data to verify
     * @param key the MAC key
     * @param expectedMAC the expected MAC value
     * @return true if MAC matches, false otherwise
     * @throws Exception if verification fails
     */
    public static boolean verifyMAC(byte[] data, byte[] key, byte[] expectedMAC) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKey);
        byte[] computedMAC = mac.doFinal(data);
        
        return Arrays.equals(computedMAC, expectedMAC);
    }
    

    /**
     * Container for derived encryption and hash/MAC keys used for file blocks.
     * La HashKey est requise pour le masquage CRC.
     */
    public static class DerivedKeys {
        private final byte[] encryptionKey;
        private final byte[] hashMacKey; // Used for HashKey (CRC XOR) and MAC

        public DerivedKeys(byte[] encryptionKey, byte[] hashMacKey) {
            this.encryptionKey = encryptionKey;
            this.hashMacKey = hashMacKey;
        }
        
        /**
         * @return the 32-byte AES encryption key
         */
        public byte[] getEncryptionKey() {
            return encryptionKey;
        }
        
        /**
         * @return the 32-byte Hash/MAC key (pour CRC XOR et MAC).
         */
        public byte[] getHashMacKey() {
            return hashMacKey;
        }
        
        /**
         * @return the MAC key (alias for compatibility)
         */
        public byte[] getMacKey() {
            return hashMacKey;
        }
    }
    
    /**
     * Derives encryption and Hash/MAC keys from a password and crypto parameters.
     * <p>Uses contiguous 64-byte PBKDF2 derivation for AES Key (first 32 bytes)
     * and HashKey/MAC Key (next 32 bytes).</p>
     * @param password the password
     * @param crypto the encryption parameters from the file's extra area
     * @return container with derived keys (AES Key and HashKey)
     * @throws Exception if key derivation fails
     */
    public static DerivedKeys deriveKeys(String password, Rar5ExtraCrypto crypto) throws Exception {
        if (crypto.getAlgorithm() != 0) {
            throw new RarDecryptException("Unsupported encryption algorithm: " + crypto.getAlgorithm());
        }
        
        int iterations = 1 << crypto.getKdfIterationExponent();
        // 64 bytes total: 32 bytes for AES Key + 32 bytes for HashKey
        int totalKeyLengthBits = 64 * 8; 
        
        // PBKDF2 call for 64 contiguous bytes
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), crypto.getSalt(), iterations, totalKeyLengthBits);
        byte[] totalDerivedKey = factory.generateSecret(spec).getEncoded();
        
        // Split the keys (contiguous derivation yields the correct sequence)
        byte[] encKey = Arrays.copyOfRange(totalDerivedKey, 0, 32);
        byte[] hashKey = Arrays.copyOfRange(totalDerivedKey, 32, 64); // key used for CRC XOR and MAC
        
        return new DerivedKeys(encKey, hashKey);
    }
    
  
    /**
     * Converts a CRC32 value to a tweaked/masked CRC using HMAC-SHA256.
     * 
     * <p>RAR5 uses this for encrypted files with unencrypted headers to prevent
     * guessing file contents based on checksums.</p>
     * 
     * @param crc32 the calculated CRC32 of the decompressed data
     * @param hashKey the 32-byte HashKey derived from PBKDF2
     * @return the tweaked CRC32 value (4 bytes as long)
     * @throws Exception if HMAC calculation fails
     */
    public static long convertCrcToTweakedCrc(long crc32, byte[] hashKey) throws Exception {
        byte[] crcBytes = new byte[4];
        crcBytes[0] = (byte) (crc32 & 0xFF);
        crcBytes[1] = (byte) ((crc32 >> 8) & 0xFF);
        crcBytes[2] = (byte) ((crc32 >> 16) & 0xFF);
        crcBytes[3] = (byte) ((crc32 >> 24) & 0xFF);
        
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(hashKey, "HmacSHA256");
        hmac.init(keySpec);
        byte[] mac = hmac.doFinal(crcBytes);
        
        // Return first 4 bytes as unsigned long (little-endian)
        return (mac[0] & 0xFFL) | 
               ((mac[1] & 0xFFL) << 8) | 
               ((mac[2] & 0xFFL) << 16) | 
               ((mac[3] & 0xFFL) << 24);
    }
    
    /**
     * Verifies the CRC of an encrypted file with unencrypted headers.
     * 
     * @param calculatedCrc CRC32 calculated on decompressed data
     * @param storedCrc CRC32 stored in archive (tweaked)
     * @param hashKey the 32-byte HashKey from PBKDF2 derivation
     * @return true if CRC matches
     */
    public static boolean verifyTweakedCrc(long calculatedCrc, long storedCrc, byte[] hashKey) throws Exception {
        long tweakedCrc = convertCrcToTweakedCrc(calculatedCrc, hashKey);
        return tweakedCrc == storedCrc;
    }
    
    
    /**
     * Derives encryption and Hash keys from a password and crypto parameters.
     * Used for crypted files / clear headers. Thank's to Dmitry Glavatskikh (7-zip forum ;-) )
     * 
     * @param password the password 
     * @param crypto the encryption parameters from the file's extra area
     * @return array with derived keys (HashKey)
     * @throws Exception if key derivation fails
     */
    public static byte[] deriveCrcHashKeyN16_Standard(String password, Rar5ExtraCrypto crypto) throws Exception {
        final int CRC_HASH_KEY_OFFSET_STANDARD = 16; 
        int baseIterations = 1 << crypto.getKdfIterationExponent(); 
        int iterations = baseIterations + CRC_HASH_KEY_OFFSET_STANDARD; // N + 16
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final int KEY_SIZE = 32; 
        KeySpec spec = new PBEKeySpec(password.toCharArray(), crypto.getSalt(), iterations, KEY_SIZE * 8); 
        byte[] derivedKey = factory.generateSecret(spec).getEncoded();
        return derivedKey;
    }


    /**
     * Transforms the computed raw CRC into a verifiable MAC stored in the header.
     */
    public static boolean verifyCrcWithHMAC(long calculatedCrc, long expectedCrc, byte[] hashKey) {
        try {
            // 1. Prepare the raw (calculated) CRC in little-endian (RawPut4)
            byte[] rawCrc = ByteBuffer.allocate(4)
                                      .order(ByteOrder.LITTLE_ENDIAN)
                                      .putInt((int) calculatedCrc)
                                      .array();

            // 2. Initialize HMAC-SHA256 with the HashKey (N+16)
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hashKey, "HmacSHA256"));
            
            // 3. Compute the digest (hmac_sha256(Key, ..., RawCRC, ...))
            byte[] digest = mac.doFinal(rawCrc);
            
            // 4. Fold the 32-byte digest into a 4-byte integer
            int finalHmacCrc = 0;
            for (int i = 0; i < digest.length; i++) {
                // XOR the digest byte at the matching position (0, 8, 16 or 24 bits)
                finalHmacCrc ^= (digest[i] & 0xFF) << ((i & 3) * 8);
            }
            
            // 5. Compare with the expected CRC stored in the archive
            // Convert to long to avoid sign issues during display/comparison
            return (finalHmacCrc & 0xFFFFFFFFL) == expectedCrc;
            
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Creates a decrypting InputStream for streaming AES-256-CBC decryption.
     */
    public static InputStream createDecryptingStream(InputStream encryptedInput, byte[] key, byte[] iv) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return new CipherInputStream(encryptedInput, cipher);
        } catch (Exception e) {
            return null;
        }
    }
    
    
}
