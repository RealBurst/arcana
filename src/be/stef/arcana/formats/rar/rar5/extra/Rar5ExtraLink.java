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

import java.nio.charset.StandardCharsets;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * Link information from a RAR5 file's extra area.
 * 
 * <p>RAR5 supports various types of links:</p>
 * <ul>
 *   <li>Unix symbolic links</li>
 *   <li>Windows symbolic links</li>
 *   <li>Windows junction points</li>
 *   <li>Hard links</li>
 *   <li>File copy references</li>
 * </ul>
 * 
 * <p>Structure: Type(VInt), Flags(VInt), NameLength(VInt), TargetName(bytes)</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5ExtraLink {
    private long type;
    private long flags;
    private String targetName;
    
    /**
     * Parses link information from raw extra record data.
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
            
            // Link type (VInt)
            VInt typeVInt = VIntReader.read(data, pos, end);
            if (typeVInt == null) {
                return false;
            }
            type = typeVInt.value;
            pos += typeVInt.length;
            
            // Flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, end);
            if (flagsVInt == null) {
                return false;
            }
            flags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // Target name length (VInt)
            VInt nameLenVInt = VIntReader.read(data, pos, end);
            if (nameLenVInt == null) {
                return false;
            }
            int nameLen = (int) nameLenVInt.value;
            pos += nameLenVInt.length;
            
            // Target name (UTF-8)
            if (pos + nameLen > end) {
                return false;
            }
            targetName = new String(data, pos, nameLen, StandardCharsets.UTF_8);
            pos += nameLen;
            
            return pos == end;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Checks if the link target is a directory.
     * 
     * @return true if target is a directory
     */
    public boolean isTargetDirectory() {
        return (flags & Rar5Constants.LINK_FLAG_TARGET_IS_DIR) != 0;
    }
    
    /**
     * Checks if this is a symbolic link (Unix or Windows).
     * 
     * @return true if this is a symbolic link
     */
    public boolean isSymbolicLink() {
        return type == Rar5Constants.LINK_TYPE_UNIX_SYMLINK ||
               type == Rar5Constants.LINK_TYPE_WIN_SYMLINK;
    }
    
    /**
     * Checks if this is a hard link.
     * 
     * @return true if this is a hard link
     */
    public boolean isHardLink() {
        return type == Rar5Constants.LINK_TYPE_HARD_LINK;
    }
    
    /**
     * Checks if this is a file copy reference.
     * 
     * @return true if this is a file copy
     */
    public boolean isFileCopy() {
        return type == Rar5Constants.LINK_TYPE_FILE_COPY;
    }
    
    /**
     * Checks if this is a Windows junction point.
     * 
     * @return true if this is a junction
     */
    public boolean isJunction() {
        return type == Rar5Constants.LINK_TYPE_WIN_JUNCTION;
    }
    
    /**
     * Returns the link type as a human-readable string.
     * 
     * @return link type name
     */
    public String getLinkTypeName() {
        switch ((int) type) {
            case Rar5Constants.LINK_TYPE_UNIX_SYMLINK:
                return "UnixSymLink";
            case Rar5Constants.LINK_TYPE_WIN_SYMLINK:
                return "WinSymLink";
            case Rar5Constants.LINK_TYPE_WIN_JUNCTION:
                return "WinJunction";
            case Rar5Constants.LINK_TYPE_HARD_LINK:
                return "HardLink";
            case Rar5Constants.LINK_TYPE_FILE_COPY:
                return "FileCopy";
            default:
                return "Unknown(" + type + ")";
        }
    }
    
    /**
     * @return the link type identifier
     */
    public long getType() {
        return type;
    }
    
    /**
     * @return the raw flags value
     */
    public long getFlags() {
        return flags;
    }
    
    /**
     * @return the link target path
     */
    public String getTargetName() {
        return targetName;
    }
    
    // Legacy getter
    public boolean isTargetDir() {
        return isTargetDirectory();
    }
    
    @Override
    public String toString() {
        return String.format("Link[type=%s, target=%s, isDir=%b]",
            getLinkTypeName(), targetName, isTargetDirectory());
    }
}
