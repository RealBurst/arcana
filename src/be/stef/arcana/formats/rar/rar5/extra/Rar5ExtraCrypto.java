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
package be.stef.arcana.formats.rar.rar5.extra;

import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * Encryption information from a RAR5 file's extra area.
 * 
 * <p>This record contains all parameters needed to decrypt a file:</p>
 * <ul>
 *   <li>Encryption algorithm (currently only AES-256 is supported)</li>
 *   <li>KDF iteration count (as power of 2)</li>
 *   <li>Salt for key derivation</li>
 *   <li>Initialization vector for AES-CBC</li>
 *   <li>Optional password verification value</li>
 * </ul>
 * 
 * <p>Structure: Algorithm(VInt), Flags(VInt), kdfIterationExponent(1 byte), Salt(16 bytes),
 * IV(16 bytes), PasswordCheck(12 bytes, optional)</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ExtraCrypto {
    private long algorithm;
    private long flags;
    private int kdfIterationExponent;
    private byte[] salt;
    private byte[] initVector;
    private byte[] passwordCheck;
    
    
    /**
     * Creates a Rar5ExtraCrypto instance for archive-level encryption (ARC_ENCRYPT block).
     * Used for password verification before decrypting headers.
     * 
     * @param algorithm encryption algorithm (0 = AES)
     * @param flags encryption flags
     * @param kdfIterationExponent KDF iteration count exponent
     * @param salt 16-byte salt
     * @param passwordCheck 12-byte password check value (or null)
     * @return configured instance
     */
    public static Rar5ExtraCrypto createForArchiveEncryption(long algorithm, long flags, int kdfIterationExponent, byte[] salt, byte[] passwordCheck) {
        Rar5ExtraCrypto crypto = new Rar5ExtraCrypto();
        crypto.algorithm = algorithm;
        crypto.flags = flags;
        crypto.kdfIterationExponent = kdfIterationExponent;
        crypto.salt = salt;
        crypto.initVector = new byte[16]; // Not needed for password verification
        crypto.passwordCheck = passwordCheck;
        return crypto;
    }
    
    
    /**
     * Parses encryption information from raw extra record data.
     * 
     * @param data the raw data buffer
     * @param offset starting position in the buffer
     * @param size number of bytes to parse
     * @return true if parsing succeeded, false otherwise
     */
    public boolean parse(byte[] data, int offset, int size) {
        try {
            int pos = offset;
            int end = offset + size;
            
            // Algorithm (VInt)
            VInt algoVInt = VIntReader.read(data, pos, end);
            if (algoVInt == null) {
                return false;
            }
            algorithm = algoVInt.value;
            pos += algoVInt.length;
            
            // Flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, end);
            if (flagsVInt == null) {
                return false;
            }
            flags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // KDF IterationExponent (1 byte) - represents 2^kdfIterationExponent iterations
            if (pos >= end) {
                return false;
            }
            kdfIterationExponent = data[pos] & 0xFF;
            pos++;
            
            // Salt (16 bytes)
            if (pos + Rar5Constants.SALT_SIZE > end) {
                return false;
            }
            salt = Utils.copyBytes(data, pos, Rar5Constants.SALT_SIZE);
            pos += Rar5Constants.SALT_SIZE;
            
            // Initialization Vector (16 bytes)
            if (pos + Rar5Constants.AES_BLOCK_SIZE > end) {
                return false;
            }
            initVector = Utils.copyBytes(data, pos, Rar5Constants.AES_BLOCK_SIZE);
            pos += Rar5Constants.AES_BLOCK_SIZE;
            
            // Password check value (12 bytes, optional)
            if (hasPasswordCheck()) {
                if (pos + Rar5Constants.CHECK_VALUE_SIZE > end) {
                    return false;
                }
                passwordCheck = Utils.copyBytes(data, pos, Rar5Constants.CHECK_VALUE_SIZE);
                pos += Rar5Constants.CHECK_VALUE_SIZE;
            }
            
            return pos == end;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Checks if password verification data is present.
     * 
     * @return true if password check value is available
     */
    public boolean hasPasswordCheck() {
        return (flags & Rar5Constants.CRYPTO_FLAG_PASSWORD_CHECK) != 0;
    }
    
    /**
     * Checks if MAC authentication is enabled.
     * 
     * @return true if HMAC verification should be performed
     */
    public boolean useMAC() {
        return (flags & Rar5Constants.CRYPTO_FLAG_USE_MAC) != 0;
    }
    
    /**
     * Returns the number of PBKDF2 iterations as a power of 2.
     * Actual iterations = 2^kdfIterationExponent
     * 
     * @return the KDF iteration count exponent
     */
    public int getKdfIterationExponent() {
        return kdfIterationExponent;
    }
    
    /**
     * Returns the actual number of PBKDF2 iterations.
     * 
     * @return 2^kdfIterationExponent iterations
     */
    public int getIterations() {
        return 1 << kdfIterationExponent;
    }
    
    /**
     * @return the encryption algorithm identifier (0 = AES)
     */
    public long getAlgorithm() {
        return algorithm;
    }
    
    /**
     * @return the raw flags value
     */
    public long getFlags() {
        return flags;
    }
    
    /**
     * @return the 16-byte salt for key derivation
     */
    public byte[] getSalt() {
        return salt;
    }
    
    /**
     * @return the 16-byte initialization vector for AES-CBC
     */
    public byte[] getInitVector() {
        return initVector;
    }
    
    /**
     * @return the 12-byte password verification value, or null if not present
     */
    public byte[] getPasswordCheck() {
        return passwordCheck;
    }
    
    // Legacy getter for compatibility
    public long getAlgo() {
        return algorithm;
    }
    
    @Override
    public String toString() {
        return String.format("Crypto[algo=%d, kdfIterationExponent=%d (2^%d=%d iter), hasPwdCheck=%b, useMAC=%b]",
            algorithm, kdfIterationExponent, kdfIterationExponent, getIterations(), hasPasswordCheck(), useMAC());
    }
}
