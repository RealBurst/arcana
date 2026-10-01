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
package be.stef.arcana.formats.rar.rar4.blocks;

import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.rar4.Rar4Constants;

/**
 * Base class for all RAR4 archive blocks.
 *
 * <p>RAR4 block structure (common header):</p>
 * <pre>
 *   2 bytes : CRC16
 *   1 byte  : block type
 *   2 bytes : flags
 *   2 bytes : header size
 *  [4 bytes]: additional data size (present if FLAG_HAS_ADD_SIZE is set)
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public abstract class Rar4Block {
    // --- Parsed common header fields ---
    protected int  crc16;
    protected int  type;
    protected int  flags;
    protected int  headerSize;
    protected long addSize;       // Additional data size (0 if not present)

    // --- Absolute positions in the archive file ---
    protected long blockStart;   // Offset of first byte of this block (CRC16)
    protected long dataStart;    // Offset of first byte of additional data
    protected long dataEnd;      // Offset of first byte of next block

    /**
     * Parses the common 7-byte header (CRC16 + type + flags + headerSize).
     * Call this first, then parseSpecificData().
     *
     * @param buf    buffer containing block data
     * @param offset start offset in buffer
     * @param length available bytes from offset
     * @return number of bytes consumed, or -1 on error
     */
    public int parseCommonHeader(byte[] buf, int offset, int length) {
        if (length < 7) return -1;

        crc16      = readUInt16LE(buf, offset);
        type       = buf[offset + 2] & 0xFF;
        flags      = readUInt16LE(buf, offset + 3);
        headerSize = readUInt16LE(buf, offset + 5);

        int consumed = 7;

        // Additional data size field (4 bytes) present if FLAG_HAS_ADD_SIZE
        if ((flags & Rar4Constants.FLAG_HAS_ADD_SIZE) != 0) {
            if (length < 11) return -1;
            addSize = readUInt32LE(buf, offset + 7);
            consumed += 4;
        } else {
            addSize = 0;
        }

        return consumed;
    }

    /**
     * Parses block-specific data after the common header.
     * Implemented by each subclass.
     *
     * @param buf    buffer containing block data
     * @param offset offset just after the common header (after parseCommonHeader consumed bytes)
     * @param length remaining available bytes
     * @return true if parsing succeeded
     */
    public abstract boolean parseSpecificData(byte[] buf, int offset, int length);

    // --- Utility read methods (delegated to the shared Utils) ---

    protected static int readUInt16LE(byte[] buf, int offset) {
        return Utils.readUInt16LE(buf, offset);
    }

    protected static long readUInt32LE(byte[] buf, int offset) {
        return Utils.readUInt32LE(buf, offset);
    }

    // --- Getters ---

    public int  getCrc16()      { return crc16; }
    public int  getType()       { return type; }
    public int  getFlags()      { return flags; }
    public int  getHeaderSize() { return headerSize; }
    public long getAddSize()    { return addSize; }
    public long getBlockStart() { return blockStart; }
    public long getDataStart()  { return dataStart; }
    public long getDataEnd()    { return dataEnd; }

    // --- Setters (used by Rar4HeaderParser) ---

    public void setBlockStart(long blockStart) { this.blockStart = blockStart; }
    public void setDataStart(long dataStart)   { this.dataStart = dataStart; }
    public void setDataEnd(long dataEnd)       { this.dataEnd = dataEnd; }

    /**
     * @return true if this block has additional data (compressed file data, etc.)
     */
    public boolean hasAdditionalData() {
        return addSize > 0;
    }
}