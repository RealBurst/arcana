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

import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;

/**
 * File version information from a RAR5 file's extra area.
 * 
 * <p>This record stores file versioning information for archives
 * that maintain multiple versions of the same file.</p>
 * 
 * <p>Structure: Flags(VInt), Version(VInt)</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ExtraVersion {
    private long flags;
    private long version;
    
    /**
     * Parses version information from raw extra record data.
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
            
            // Flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, end);
            if (flagsVInt == null) {
                return false;
            }
            flags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // Version (VInt)
            VInt versionVInt = VIntReader.read(data, pos, end);
            if (versionVInt == null) {
                return false;
            }
            version = versionVInt.value;
            pos += versionVInt.length;
            
            return pos == end;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * @return the raw flags value
     */
    public long getFlags() {
        return flags;
    }
    
    /**
     * @return the version number
     */
    public long getVersion() {
        return version;
    }
    
    @Override
    public String toString() {
        return String.format("Version[flags=0x%X, version=%d]", flags, version);
    }
}
