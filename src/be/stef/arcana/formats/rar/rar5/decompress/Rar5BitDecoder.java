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
package be.stef.arcana.formats.rar.rar5.decompress;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Bit-level stream decoder for RAR5 decompression.
 * 
 * <p>This class provides bit-level reading operations required by the RAR5
 * decompression algorithm. It maintains an internal buffer and supports
 * various bit reading methods optimized for different scenarios.</p>
 * 
 * <p><b>WARNING:</b> This is a critical decompression component. The bit
 * manipulation algorithms have been carefully tuned and should not be
 * modified without thorough testing.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5BitDecoder {
    public static final int INPUT_BUFSIZE = 1 << 20;  //Input buffer size
    public static final int LOOK_AHEAD_SIZE = 16;     //Look-ahead buffer size for bit reading
    public static final int BUFFER_SIZE = INPUT_BUFSIZE + LOOK_AHEAD_SIZE;
    public byte[] buf;                // Current buffer
    public int bufPos;                // Current position in buffer
    public int bufCheckBlockPos;      // Check position for block boundary
    public int bitPos;                // Current bit position (0-7)
    public boolean wasFinished;       // True if input stream is exhausted
    public boolean minorError;        // True if minor decoding error occurred
    public int blockEndBits7;         // Block end bit position (0-7)
    public IOException hres;          // Last I/O exception, if any
    public int bufCheckPos;           // Buffer check position
    public int bufLim;                // Buffer limit (valid data end)
    public int bufBase;               // Buffer base position for processed size calculation
    public InputStream stream;        // Input stream
    public long processedSize;        // Total processed size in bytes
    public long blockEnd;             // Block end position
    private byte[] inputBuffer;
    
    /**
     * Creates a new bit decoder.
     */
    public Rar5BitDecoder() {
        inputBuffer = new byte[BUFFER_SIZE];
        buf = inputBuffer;
        init();
    }
    
    /**
     * Initializes/resets the decoder state.
     */
    public void init() {
        blockEnd = 0;
        blockEndBits7 = 0;
        bitPos = 0;
        processedSize = 0;
        bufPos = 0;
        bufLim = 0;
        bufCheckPos = 0;
        bufCheckBlockPos = 0;
        wasFinished = false;
        minorError = false;
        bufBase = 0;
    }
    
    /**
     * Copies state from another decoder.
     * 
     * @param other source decoder
     */
    public void copyFrom(Rar5BitDecoder other) {
        this.buf = other.buf;
        this.bufPos = other.bufPos;
        this.bufCheckBlockPos = other.bufCheckBlockPos;
        this.bitPos = other.bitPos;
        this.wasFinished = other.wasFinished;
        this.minorError = other.minorError;
        this.blockEndBits7 = other.blockEndBits7;
        this.bufCheckPos = other.bufCheckPos;
        this.bufLim = other.bufLim;
        this.bufBase = other.bufBase;
        this.processedSize = other.processedSize;
        this.blockEnd = other.blockEnd;
        this.stream = other.stream;
    }
    
    /**
     * Restores buffer position from another decoder.
     * 
     * @param other source decoder
     */
    public void restoreFrom(Rar5BitDecoder other) {
        this.buf = other.buf;
        this.bufPos = other.bufPos;
        this.bitPos = other.bitPos;
    }
    
    /**
     * Sets the check position for block boundary detection.
     */
    public void setCheckForBlock() {
        bufCheckBlockPos = bufCheckPos;
        if (bufCheckPos > bufPos) {
            long processed = getProcessedSizeRound();
            if (blockEnd < processed) {
                bufCheckBlockPos = bufPos;
            } else {
                long delta = blockEnd - processed;
                if ((bufCheckPos - bufPos) > delta) {
                    bufCheckBlockPos = bufPos + (int) delta;
                }
            }
        }
    }
    
    /**
     * Checks if reading has exceeded the block boundary.
     * 
     * @return true if block is over-read
     */
    public boolean isBlockOverRead() {
        long v = getProcessedSizeRound();
        if (v < blockEnd) return false;
        if (v > blockEnd) return true;
        return bitPos > blockEndBits7;
    }
    
    /**
     * Prepares buffer for reading, refilling if necessary.
     */
    public void prepare() {
        if (bufPos >= bufCheckPos) {
            prepare2();
        }
    }
    
    /**
     * Internal buffer preparation and refill logic.
     */
    public void prepare2() {
        if (bufPos > bufLim) return;
        
        int rem = bufLim - bufPos;
        if (rem != 0) {
            System.arraycopy(buf, bufPos, buf, 0, rem);
        }
        
        bufLim = rem;
        processedSize += bufPos;
        bufPos = 0;
        
        if (!wasFinished) {
            while (rem <= Rar5BitDecoder.LOOK_AHEAD_SIZE) {
                int toRead = BUFFER_SIZE - rem;
                try {
                    int bytesRead = stream.read(buf, rem, toRead);
                    if (bytesRead == -1 || bytesRead == 0) {
                        wasFinished = true;
                        break;
                    }
                    bufLim = rem + bytesRead;
                    rem += bytesRead;
                } catch (IOException e) {
                    hres = e;
                    wasFinished = true;
                    break;
                }
            }
        }
        
        // Fill pad zone with 0xFF
        Arrays.fill(buf, bufLim, Math.min(bufLim + Rar5BitDecoder.LOOK_AHEAD_SIZE, BUFFER_SIZE), (byte) 0xFF);
        
        if (rem < Rar5BitDecoder.LOOK_AHEAD_SIZE) {
            bufCheckPos = bufPos;
        } else {
            bufCheckPos = bufLim - Rar5BitDecoder.LOOK_AHEAD_SIZE;
        }
        
        setCheckForBlock();
    }
    
    /**
     * Checks if extra bits were read beyond valid data.
     * 
     * @return true if extra bits were read
     */
    public boolean extraBitsWereRead() {
        return bufPos >= bufLim && (bufPos > bufLim || bitPos != 0);
    }
    
    /**
     * Checks for input EOF error condition.
     * 
     * @return true if EOF error occurred
     */
    public boolean inputEofError() {
        return extraBitsWereRead();
    }
    
    /**
     * Returns the current bit position within the byte.
     * 
     * @return bit position (0-7)
     */
    public int getProcessedBits7() {
        return bitPos;
    }
    
    /**
     * Returns processed size rounded to byte boundary.
     * 
     * @return processed bytes
     */
    public long getProcessedSizeRound() {
        return processedSize + bufPos;
    }
    
    /**
     * Returns total processed size including partial byte.
     * 
     * @return processed size in bytes
     */
    public long getProcessedSize() {
        return processedSize + bufPos + ((bitPos + 7) >> 3);
    }
    
    /**
     * Aligns reading position to byte boundary.
     */
    public void alignToByte() {
        if (bitPos != 0) {
            int b = (buf[bufPos] & 0xFF) << bitPos;
            if ((b & 0xFF) != 0) {
                minorError = true;
            }
            bufPos++;
            bitPos = 0;
        }
    }
    
    /**
     * Reads a byte when already aligned.
     * 
     * @return the byte read
     */
    public byte readByteInAligned() {
        return buf[bufPos++];
    }
    
    /**
     * Gets bits without advancing position.
     * 
     * @param numBits number of bits to read (1-17)
     * @return the bits value
     */
    public int getValue(int numBits) {
//        if (numBits <= 0 || numBits > 17) {
//            throw new IllegalArgumentException("numBits must be between 1 and 17");
//        }
        
        int v = ((buf[bufPos] & 0xFF) << 16) |
                ((buf[bufPos + 1] & 0xFF) << 8) |
                (buf[bufPos + 2] & 0xFF);
        
        v >>= (24 - numBits - bitPos);
        return v & ((1 << numBits) - 1);
    }
    
    /**
     * Gets value positioned in high 32 bits for extended reading.
     * 
     * @return value in high bits
     */
    public int getValueInHigh32bits() {
        int v = ((buf[bufPos] & 0xFF) << 16) |
                ((buf[bufPos + 1] & 0xFF) << 8) |
                (buf[bufPos + 2] & 0xFF);
        return v << (8 + bitPos);
    }
    
    /**
     * Advances position by the specified number of bits.
     * 
     * @param numBits bits to advance
     */
//    public void movePos(int numBits) {
//        numBits += bitPos;
//        bufPos += numBits >> 3;
//        bitPos = numBits & 7;
//    }

    public void movePos(int numBits) {
       int total = numBits + bitPos;
       bufPos += total >>> 3;  // Division par 8 via shift
       bitPos = total & 7;     // Modulo 8 via masque
   }
    
    /**
     * Reads up to 9 bits and advances position.
     * 
     * @param numBits number of bits to read (0-9)
     * @return the bits value
     */
    public int readBits9(int numBits) {
        int v = ((buf[bufPos] & 0xFF) << 8) | (buf[bufPos + 1] & 0xFF);
        v &= 0xFFFF >> bitPos;
        numBits += bitPos;
        v >>= 16 - numBits;
        bufPos += numBits >> 3;
        bitPos = numBits & 7;
        return v;
    }
    
    /**
     * Reads up to 9 bits with fixed mask and advances position.
     * 
     * @param numBits number of bits to read (0-9)
     * @return the bits value
     */
    public int readBits9Fix(int numBits) {
        int mask = (1 << numBits) - 1;
        int v = ((buf[bufPos] & 0xFF) << 8) | (buf[bufPos + 1] & 0xFF);
        numBits += bitPos;
        v >>= 16 - numBits;
        bufPos += numBits >> 3;
        bitPos = numBits & 7;
        return v & mask;
    }
    
    /**
     * Reads up to 25 bits from pre-read high value.
     * 
     * @param numBits number of bits to read
     * @param v pre-read value from getValueInHigh32bits()
     * @return the bits value
     */
    public int readBitsBig25(int numBits, int v) {
        if (numBits == 0) return 0;
        
        int mask = (1 << numBits) - 1;
        int result = (v >>> (32 - numBits)) & mask;
        movePos(numBits);
        return result;
    }
    
    /**
     * Reads extended bits from pre-read high value.
     * Handles cases where numBits > 25 and bitPos > 0.
     * 
     * @param numBits number of bits to read
     * @param v pre-read value from getValueInHigh32bits()
     * @return the bits value
     */
    public int readBitsBig(int numBits, int v) {
        if (numBits == 0) return 0;
        
        // Include 4th byte for extended reading when needed
        if (bufPos + 3 < buf.length && bitPos > 0) {
            v |= (buf[bufPos + 3] & 0xFF) << bitPos;
        }
        
        int result = v >>> (32 - numBits);
        movePos(numBits);
        return result;
    }
    
    /**
     * Gets 15 bits for Huffman decoding (optimized, no validation).
     */
    public int getValueFast15() {
        int v = ((buf[bufPos] & 0xFF) << 16) |
                ((buf[bufPos + 1] & 0xFF) << 8) |
                (buf[bufPos + 2] & 0xFF);
        return (v >>> (9 - bitPos)) & 0x7FFF;
    }
    
    /**
     * Sets the input stream.
     * 
     * @param stream the input stream
     */
    public void setStream(InputStream stream) {
        this.stream = stream;
    }
}
