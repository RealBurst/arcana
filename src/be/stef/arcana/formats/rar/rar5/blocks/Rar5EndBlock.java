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

import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * End of Archive block for RAR5 archives.
 * 
 * <p>This block marks the end of the archive and indicates whether
 * more volumes follow in a multi-volume archive set.</p>
 * 
 * <p>Structure: EndFlags (VInt)</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5EndBlock extends Rar5Block {
    private long endFlags;
    
    @Override
    public boolean parseSpecificData(byte[] data, int offset, int endExclusive) {
        try {
            int pos = offset;
            
            // End flags (VInt) - some writers omit the field entirely (header = type + flags only)
            if (pos >= endExclusive) {
                endFlags = 0;
                return true;
            }
            VInt flagsVInt = VIntReader.read(data, pos, endExclusive);
            if (flagsVInt == null) {
                return false;
            }
            endFlags = flagsVInt.value;
            pos += flagsVInt.length;
            
            return true; // trailing bytes (future fields) are ignored
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Checks if more volumes follow in the archive set.
     * 
     * @return true if this is not the last volume
     */
    public boolean hasMoreVolumes() {
        return (endFlags & Rar5Constants.END_FLAG_MORE_VOLS) != 0;
    }
    
    /**
     * @return the end block flags
     */
    public long getEndFlags() {
        return endFlags;
    }
}
