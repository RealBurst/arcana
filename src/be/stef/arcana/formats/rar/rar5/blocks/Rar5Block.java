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
 * Base class for all RAR5 archive blocks.
 * 
 * <p>RAR5 archives consist of a sequence of blocks, each with a common header
 * structure followed by type-specific data. This class handles the common
 * header parsing and provides the framework for specific block types.</p>
 * 
 * <p>Common header structure:</p>
 * <ul>
 *   <li>CRC32 (4 bytes) - Header checksum</li>
 *   <li>HeaderSize (VInt) - Size of header data</li>
 *   <li>Type (VInt) - Block type identifier</li>
 *   <li>Flags (VInt) - Block flags</li>
 *   <li>ExtraSize (VInt, optional) - Size of extra area</li>
 *   <li>DataSize (VInt, optional) - Size of data area</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public abstract class Rar5Block {
    protected long crc32;
    protected long headerSize;
    protected int type;
    protected long flags;
    protected long extraSize;
    protected long dataSize;
    protected byte[] extraArea;
    
    // Position information
    protected long blockStartPosition;
    protected long headerDataStart;
    protected long dataStart;
    protected long dataEnd;
    
    /**
     * Parses the common header fields present in all RAR5 blocks.
     * 
     * @param data the raw archive data
     * @param offset starting position of header data (after CRC and size)
     * @param endExclusive end boundary of header data
     * @return position after common header, or -1 on error
     */
    public int parseCommonHeader(byte[] data, int offset, int endExclusive) {
        try {
            int pos = offset;
            
            // Type (VInt)
            VInt typeVInt = VIntReader.read(data, pos, endExclusive);
            if (typeVInt == null) {
                return -1;
            }
            type = (int) typeVInt.value;
            pos += typeVInt.length;
            
            // Flags (VInt)
            VInt flagsVInt = VIntReader.read(data, pos, endExclusive);
            if (flagsVInt == null) {
                return -1;
            }
            flags = flagsVInt.value;
            pos += flagsVInt.length;
            
            // Extra size (VInt, if EXTRA flag is set)
            if (hasExtra()) {
                VInt extraVInt = VIntReader.read(data, pos, endExclusive);
                if (extraVInt == null) {
                    return -1;
                }
                extraSize = extraVInt.value;
                pos += extraVInt.length;
            }
            
            // Data size (VInt, if DATA flag is set)
            if (hasData()) {
                VInt dataVInt = VIntReader.read(data, pos, endExclusive);
                if (dataVInt == null) {
                    return -1;
                }
                dataSize = dataVInt.value;
                pos += dataVInt.length;
            }
            
            return pos;
            
        } catch (Exception e) {
            return -1;
        }
    }
    
    /**
     * Parses type-specific data from the block.
     * Must be implemented by each block type.
     * 
     * @param data the raw archive data
     * @param offset starting position of specific data
     * @param endExclusive end boundary of header data
     * @return true if parsing succeeded, false otherwise
     */
    public abstract boolean parseSpecificData(byte[] data, int offset, int endExclusive);
    
    /**
     * Parses the extra area of the block.
     * Can be overridden by subclasses that need special extra area handling.
     * 
     * @param data the raw archive data
     * @param offset starting position of extra area
     * @param size size of extra area in bytes
     * @return true if parsing succeeded, false otherwise
     */
    protected boolean parseExtraArea(byte[] data, int offset, int size) {
        if (size > 0) {
            extraArea = new byte[size];
            System.arraycopy(data, offset, extraArea, 0, size);
        }
        return true;
    }
    
    // ========== Flag Helpers ==========
    
    /**
     * @return true if block has an extra area
     */
    public boolean hasExtra() {
        return (flags & Rar5Constants.HEADER_FLAG_EXTRA) != 0;
    }
    
    /**
     * @return true if block has a data area
     */
    public boolean hasData() {
        return (flags & Rar5Constants.HEADER_FLAG_DATA) != 0;
    }
    
    /**
     * @return true if block continues from previous volume
     */
    public boolean isPreviousVolume() {
        return (flags & Rar5Constants.HEADER_FLAG_PREV_VOL) != 0;
    }
    
    /**
     * @return true if block continues in next volume
     */
    public boolean isNextVolume() {
        return (flags & Rar5Constants.HEADER_FLAG_NEXT_VOL) != 0;
    }
    
    /**
     * @return true if block is split across volumes
     */
    public boolean isSplit() {
        return isPreviousVolume() || isNextVolume();
    }
    
    // ========== Getters ==========
    
    public long getCrc32() {
        return crc32;
    }
    
    public long getHeaderSize() {
        return headerSize;
    }
    
    public int getType() {
        return type;
    }
    
    public long getFlags() {
        return flags;
    }
    
    public long getExtraSize() {
        return extraSize;
    }
    
    public long getDataSize() {
        return dataSize;
    }
    
    public byte[] getExtraArea() {
        return extraArea;
    }
    
    public long getBlockStartPosition() {
        return blockStartPosition;
    }
    
    public long getHeaderDataStart() {
        return headerDataStart;
    }
    
    public long getDataStart() {
        return dataStart;
    }
    
    public long getDataEnd() {
        return dataEnd;
    }
    
    // Legacy getters for compatibility
    public long getBlockStartPos() {
        return blockStartPosition;
    }
    
    /**
     * Returns a human-readable name for this block type.
     * 
     * @return block type name
     */
    public String getTypeName() {
        switch (type) {
            case Rar5Constants.BLOCK_TYPE_MAIN_ARCHIVE:
                return "MainArchive";
            case Rar5Constants.BLOCK_TYPE_FILE:
                return "File";
            case Rar5Constants.BLOCK_TYPE_SERVICE:
                return "Service";
            case Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT:
                return "ArchiveEncryption";
            case Rar5Constants.BLOCK_TYPE_END_OF_ARC:
                return "EndOfArchive";
            default:
                return "Unknown(" + type + ")";
        }
    }
    
    // ========== Public setters for Rar5Reader ==========
    
    public void setCrc32(long crc32) {
        this.crc32 = crc32;
    }
    
    public void setHeaderSize(long headerSize) {
        this.headerSize = headerSize;
    }
    
    public void setBlockStartPosition(long pos) {
        this.blockStartPosition = pos;
    }
    
    public void setHeaderDataStart(long pos) {
        this.headerDataStart = pos;
    }
    
    public void setDataStart(long pos) {
        this.dataStart = pos;
    }
    
    public void setDataEnd(long pos) {
        this.dataEnd = pos;
    }
    
}
