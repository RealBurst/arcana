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
package be.stef.arcana.formats.rar.util;

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Utility class for reading Variable Integers (VInt) from RAR5 archives.
 * 
 * <p>RAR5 VInt encoding:</p>
 * <ul>
 *   <li>Each byte contains 7 bits of data in the low bits</li>
 *   <li>Bit 7 (0x80) is the continuation flag: 1 = more bytes follow, 0 = last byte</li>
 *   <li>Maximum 10 bytes (can encode up to 70 bits)</li>
 *   <li>Bytes are ordered LSB first (little-endian bit order)</li>
 * </ul>
 * 
 * <p>Example: Value 300 (0x12C) is encoded as [0xAC, 0x02]</p>
 * <ul>
 *   <li>0xAC = 10101100 -> continuation=1, data=0101100 (44)</li>
 *   <li>0x02 = 00000010 -> continuation=0, data=0000010 (2)</li>
 *   <li>Result: (2 &lt;&lt; 7) | 44 = 256 + 44 = 300</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public final class VIntReader {
    private static final int MAX_VINT_BYTES = 10;
    private static final int CONTINUATION_BIT = 0x80;
    private static final int DATA_MASK = 0x7F;
    
    private VIntReader() {
        // Utility class - no instantiation
    }
    
    /**
     * Calculates the encoded length of a value in VInt format.
     * 
     * @param value the value to measure
     * @return the number of bytes needed to encode this value (1-10)
     */
    public static int getLength(long value) {
        int length = 0;
        do {
            length++;
            value >>>= 7;  // Unsigned right shift
        } while (value != 0);
        return length;
    }
    
    /**
     * Reads a VInt from a byte array.
     * 
     * @param data the byte array
     * @param offset the starting offset
     * @param endExclusive the exclusive end boundary
     * @return the decoded VInt, or null if incomplete or invalid
     */
    public static VInt read(byte[] data, int offset, int endExclusive) {
        long value = 0L;
        int shift = 0;
        int length = 0;
        
        while (offset + length < endExclusive && length < MAX_VINT_BYTES) {
            int b = data[offset + length] & 0xFF;
            value |= (long) (b & DATA_MASK) << shift;
            length++;
            
            if ((b & CONTINUATION_BIT) == 0) {
                return new VInt(value, length);
            }
            shift += 7;
        }
        
        // Incomplete or too long VInt
        return null;
    }
    
    /**
     * Reads a VInt from a RandomAccessFile.
     * 
     * @param raf the file to read from
     * @return the decoded value, or -1 on EOF or error
     * @throws IOException if an I/O error occurs
     */
    public static long readVInt(RandomAccessFile raf) throws IOException {
        long value = 0;
        int shift = 0;
        
        for (int i = 0; i < MAX_VINT_BYTES; i++) {
            int b = raf.read();
            if (b == -1) {
                return -1;  // Unexpected EOF
            }
            
            value |= (long) (b & DATA_MASK) << shift;
            
            if ((b & CONTINUATION_BIT) == 0) {
                return value;
            }
            shift += 7;
        }
        
        return -1;  // VInt too long
    }
    
    /**
     * Result class for read-and-advance operations.
     */
    public static class ReadResult {
        public final long value;     //The decoded value
        public final int newOffset;  //The new offset after reading
        
        public ReadResult(long value, int newOffset) {
            this.value = value;
            this.newOffset = newOffset;
        }
    }
    
    /**
     * Reads a VInt and returns both the value and the new offset.
     * 
     * @param data the byte array
     * @param offset the starting offset
     * @param endExclusive the exclusive end boundary
     * @return result containing value and new offset, or null on error
     */
    public static ReadResult readAndAdvance(byte[] data, int offset, int endExclusive) {
        VInt vint = read(data, offset, endExclusive);
        if (vint == null) {
            return null;
        }
        return new ReadResult(vint.value, offset + vint.length);
    }
}
