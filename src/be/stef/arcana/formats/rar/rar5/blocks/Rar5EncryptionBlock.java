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
package be.stef.arcana.formats.rar.rar5.blocks;

import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * Archive Encryption block for RAR5 archives with encrypted headers.
 * 
 * <p>This block appears at the beginning of encrypted archives (after the signature)
 * and contains the parameters needed to decrypt all subsequent blocks.</p>
 * 
 * <p>Structure:</p>
 * <ul>
 *   <li>Algorithm (VInt) - Encryption algorithm (0 = AES-256)</li>
 *   <li>Flags (VInt) - Encryption flags</li>
 *   <li>kdfIterationExponent (1 byte) - PBKDF2 iteration count as power of 2</li>
 *   <li>Salt (16 bytes) - Random salt for key derivation</li>
 *   <li>PasswordCheck (12 bytes, optional) - Password verification data</li>
 * </ul>
 * 
 * <p><b>Note:</b> The IV is NOT stored in this header. Each encrypted block
 * is preceded by its own 16-byte IV.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5EncryptionBlock extends Rar5Block {
    private long algorithm;
    private long cryptoFlags;
    private int kdfIterationExponent;
    private byte[] salt;
    private byte[] passwordCheck;
    
    @Override
    public boolean parseSpecificData(byte[] data, int offset, int endExclusive) {
        try {
            int pos = offset;
            
            // Algorithm (VInt)
            VInt algoVInt = VIntReader.read(data, pos, endExclusive);
            if (algoVInt == null) {
                return false;
            }
            algorithm = algoVInt.value;
            pos += algoVInt.length;
            
            // Crypto flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, endExclusive);
            if (flagsVInt == null) {
                return false;
            }
            cryptoFlags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // KDF IterationExponent (1 byte)
            if (pos >= endExclusive) {
                return false;
            }
            kdfIterationExponent = data[pos] & 0xFF;
            pos++;
            
            // Salt (16 bytes)
            if (pos + Rar5Constants.SALT_SIZE > endExclusive) {
                return false;
            }
            salt = Utils.copyBytes(data, pos, Rar5Constants.SALT_SIZE);
            pos += Rar5Constants.SALT_SIZE;
            
            // Password check (12 bytes, optional)
            if (hasPasswordCheck()) {
                if (pos + Rar5Constants.CHECK_VALUE_SIZE > endExclusive) {
                    return false;
                }
                passwordCheck = Utils.copyBytes(data, pos, Rar5Constants.CHECK_VALUE_SIZE);
                pos += Rar5Constants.CHECK_VALUE_SIZE;
            }
            
            return pos == endExclusive;
            
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
        return (cryptoFlags & Rar5Constants.CRYPTO_FLAG_PASSWORD_CHECK) != 0;
    }
    
    /**
     * Returns the number of PBKDF2 iterations.
     * 
     * @return 2^kdfIterationExponent iterations
     */
    public int getIterations() {
        return 1 << kdfIterationExponent;
    }
    
    /**
     * @return the encryption algorithm (0 = AES-256)
     */
    public long getAlgorithm() {
        return algorithm;
    }
    
    // Legacy getter
    public long getAlgo() {
        return algorithm;
    }
    
    /**
     * @return the crypto flags
     */
    public long getCryptoFlags() {
        return cryptoFlags;
    }
    
    /**
     * @return the KDF iteration count exponent
     */
    public int getKdfIterationExponent() {
        return kdfIterationExponent;
    }
    
    /**
     * @return the 16-byte salt
     */
    public byte[] getSalt() {
        return salt;
    }
    
    /**
     * @return the 12-byte password verification value, or null
     */
    public byte[] getPasswordCheck() {
        return passwordCheck;
    }
    
    /**
     * Note: Archive Encryption Header does NOT contain an IV.
     * The IV is placed before each encrypted block.
     * 
     * @return null (IV is not in this header)
     * @deprecated Use the IV from the encrypted block prefix instead
     */
    @Deprecated
    public byte[] getInitVector() {
        return null;
    }
}
