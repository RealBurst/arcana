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
 * File hash information from a RAR5 file's extra area.
 * 
 * <p>RAR5 supports BLAKE2sp hashes (32 bytes) for file integrity verification.
 * This provides stronger integrity checking than the standard CRC32.</p>
 * 
 * <p>Structure: HashType(VInt), Hash(32 bytes for BLAKE2sp)</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ExtraHash {
    private static final int BLAKE2SP_HASH_SIZE = 32;
    private long hashType;
    private byte[] hash;
    
    /**
     * Parses hash information from raw extra record data.
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
            
            // Hash type (VInt)
            VInt typeVInt = VIntReader.read(data, pos, end);
            if (typeVInt == null) {
                return false;
            }
            hashType = typeVInt.value;
            pos += typeVInt.length;
            
            // Hash value
            if (hashType == Rar5Constants.HASH_TYPE_BLAKE2SP) {
                // BLAKE2sp produces a 32-byte hash
                if (pos + BLAKE2SP_HASH_SIZE > end) {
                    return false;
                }
                hash = Utils.copyBytes(data, pos, BLAKE2SP_HASH_SIZE);
                pos += BLAKE2SP_HASH_SIZE;
            } else {
                // Unknown hash type - read all remaining bytes
                int remaining = end - pos;
                if (remaining > 0) {
                    hash = Utils.copyBytes(data, pos, remaining);
                    pos = end;
                }
            }
            
            return pos == end;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Checks if this is a BLAKE2sp hash.
     * 
     * @return true if hash type is BLAKE2sp
     */
    public boolean isBlake2sp() {
        return hashType == Rar5Constants.HASH_TYPE_BLAKE2SP;
    }
    
    /**
     * @return the hash type identifier
     */
    public long getHashType() {
        return hashType;
    }
    
    /**
     * @return the hash value bytes
     */
    public byte[] getHash() {
        return hash;
    }
    
    /**
     * Returns the hash type as a human-readable string.
     * 
     * @return hash type name
     */
    public String getHashTypeName() {
        if (hashType == Rar5Constants.HASH_TYPE_BLAKE2SP) {
            return "BLAKE2sp";
        }
        return "Unknown(" + hashType + ")";
    }
    
    @Override
    public String toString() {
        if (hash == null) {
            return "Hash[type=" + getHashTypeName() + ", no data]";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("Hash[type=").append(getHashTypeName());
        sb.append(", value=");
        
        // Show first 8 bytes of hash
        int showBytes = Math.min(8, hash.length);
        for (int i = 0; i < showBytes; i++) {
            sb.append(String.format("%02X", hash[i] & 0xFF));
        }
        if (hash.length > 8) {
            sb.append("...");
        }
        sb.append("]");
        
        return sb.toString();
    }
}
