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
 * Extended timestamp information from a RAR5 file's extra area.
 * 
 * <p>RAR5 can store modification, creation, and access times in two formats:</p>
 * <ul>
 *   <li>Unix time (32-bit seconds since 1970, or 64-bit with nanoseconds)</li>
 *   <li>Windows FILETIME (64-bit, 100-nanosecond intervals since 1601)</li>
 * </ul>
 * 
 * <p>Structure: Flags(VInt), then MTime/CTime/ATime according to flags</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ExtraTime {
    private long flags;
    private long modificationTime;
    private long creationTime;
    private long accessTime;
    private boolean modificationTimeSet;
    private boolean creationTimeSet;
    private boolean accessTimeSet;
    
    /**
     * Parses timestamp information from raw extra record data.
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
            
            boolean unixFormat = (flags & Rar5Constants.TIME_FLAG_UNIX_TIME) != 0;
            boolean hasNanoseconds = (flags & Rar5Constants.TIME_FLAG_UNIX_NS) != 0;
            boolean hasMtime = (flags & Rar5Constants.TIME_FLAG_MTIME) != 0;
            boolean hasCtime = (flags & Rar5Constants.TIME_FLAG_CTIME) != 0;
            boolean hasAtime = (flags & Rar5Constants.TIME_FLAG_ATIME) != 0;
            
            // Determine timestamp size
            int timeSize;
            if (unixFormat && !hasNanoseconds) {
                timeSize = 4; // 32-bit Unix time
            } else {
                timeSize = 8; // 64-bit (Unix with ns or Windows FILETIME)
            }
            
            // Read modification time
            if (hasMtime) {
                if (pos + timeSize > end) {
                    return false;
                }
                modificationTime = readTime(data, pos, timeSize);
                modificationTimeSet = true;
                pos += timeSize;
            }
            
            // Read creation time
            if (hasCtime) {
                if (pos + timeSize > end) {
                    return false;
                }
                creationTime = readTime(data, pos, timeSize);
                creationTimeSet = true;
                pos += timeSize;
            }
            
            // Read access time
            if (hasAtime) {
                if (pos + timeSize > end) {
                    return false;
                }
                accessTime = readTime(data, pos, timeSize);
                accessTimeSet = true;
                pos += timeSize;
            }
            
            return pos == end;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    private long readTime(byte[] data, int offset, int size) {
        if (size == 4) {
            return Utils.readUInt32LE(data, offset);
        } else {
            return Utils.readUInt64LE(data, offset);
        }
    }
    
    /**
     * Checks if timestamps are in Unix format.
     * 
     * @return true if Unix format, false if Windows FILETIME
     */
    public boolean isUnixTime() {
        return (flags & Rar5Constants.TIME_FLAG_UNIX_TIME) != 0;
    }
    
    /**
     * Checks if nanosecond precision is available.
     * 
     * @return true if nanoseconds are included
     */
    public boolean hasNanoseconds() {
        return (flags & Rar5Constants.TIME_FLAG_UNIX_NS) != 0;
    }
    
    /**
     * @return the raw flags value
     */
    public long getFlags() {
        return flags;
    }
    
    /**
     * @return the modification time value
     */
    public long getModificationTime() {
        return modificationTime;
    }
    
    /**
     * @return the creation time value
     */
    public long getCreationTime() {
        return creationTime;
    }
    
    /**
     * @return the access time value
     */
    public long getAccessTime() {
        return accessTime;
    }
    
    /**
     * @return true if modification time is present
     */
    public boolean hasModificationTime() {
        return modificationTimeSet;
    }
    
    /**
     * @return true if creation time is present
     */
    public boolean hasCreationTime() {
        return creationTimeSet;
    }
    
    /**
     * @return true if access time is present
     */
    public boolean hasAccessTime() {
        return accessTimeSet;
    }
    
    // Legacy getters for compatibility
    public long getMtime() {
        return modificationTime;
    }
    
    public long getCtime() {
        return creationTime;
    }
    
    public long getAtime() {
        return accessTime;
    }
    
    public boolean hasMtime() {
        return modificationTimeSet;
    }
    
    public boolean hasCtime() {
        return creationTimeSet;
    }
    
    public boolean hasAtime() {
        return accessTimeSet;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Time[");
        
        if (modificationTimeSet) {
            sb.append("mtime=").append(modificationTime).append(" ");
        }
        if (creationTimeSet) {
            sb.append("ctime=").append(creationTime).append(" ");
        }
        if (accessTimeSet) {
            sb.append("atime=").append(accessTime).append(" ");
        }
        
        sb.append("format=").append(isUnixTime() ? "Unix" : "Windows");
        if (hasNanoseconds()) {
            sb.append("+ns");
        }
        sb.append("]");
        
        return sb.toString();
    }
}
