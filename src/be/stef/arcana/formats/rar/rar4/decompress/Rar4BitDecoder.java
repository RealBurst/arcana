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
package be.stef.arcana.formats.rar.rar4.decompress;

import java.io.IOException;
import java.io.InputStream;

/**
 * Sequential bit reader for RAR4 compressed streams.
 *
 * <p>RAR4 uses MSB-first (big-endian) bit ordering. The reader maintains
 * an internal byte buffer and exposes 16-bit and 32-bit windows into the
 * current bit position for Huffman and raw-bit decoding.</p>
 *
 * <p>The buffer is refilled transparently when the read position approaches
 * the end of valid data.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4BitDecoder {

    /** Internal buffer capacity. */
    private static final int BUF_CAPACITY  = 32768;

    /**
     * Threshold below which a refill should be triggered.
     * Leaves a safety margin at the end of the buffer.
     */
    private static final int REFILL_THRESHOLD = BUF_CAPACITY - 30;

    /** Raw byte buffer. Extra bytes at the end prevent out-of-bounds reads. */
    byte[]      buf;

    /** Current byte offset within {@link #buf}. */
    int         bytePos;

    /** Current bit offset within the current byte (0 = MSB, 7 = LSB). */
    int         bitOffset;

    /** Number of valid bytes in {@link #buf}. */
    int         bufEnd;

    /** Underlying compressed data stream. */
    private InputStream stream;

    public Rar4BitDecoder() {
        buf = new byte[BUF_CAPACITY + 8]; // +8 safety margin for multi-byte reads
    }

    /**
     * Binds this decoder to a new input stream and performs an initial buffer fill.
     *
     * @param stream the compressed data stream
     * @throws IOException if the initial read fails
     */
    public void init(InputStream stream) throws IOException {
       this.stream = stream;
       bytePos   = 0;
       bitOffset = 0;
       bufEnd    = 0;
       refill();
       bytePos   = 0;
       bitOffset = 0;
   }

    // -------------------------------------------------------------------------
    // Buffer management
    // -------------------------------------------------------------------------

    /**
     * Shifts unprocessed bytes to the front of the buffer and reads more data
     * from the underlying stream to fill the remaining capacity.
     *
     * @return true if data is available after the refill
     * @throws IOException if reading from the stream fails
     */
    public boolean refill() throws IOException {
        int remaining = bufEnd - bytePos;
        if (remaining < 0) remaining = 0;

        if (bytePos > 0 && remaining > 0) {
            System.arraycopy(buf, bytePos, buf, 0, remaining);
        }
        bytePos = 0;
        bufEnd  = remaining;

        int toRead    = BUF_CAPACITY - remaining;
        int bytesRead = stream.read(buf, remaining, toRead);
        if (bytesRead > 0) bufEnd += bytesRead;

        return bufEnd > 0;
    }

    /**
     * Returns true when the read position is close enough to the buffer end
     * that a refill should be performed before the next decode operation.
     */
    public boolean shouldRefill() {
        return bytePos > REFILL_THRESHOLD;
    }

    // -------------------------------------------------------------------------
    // Bit window access (MSB-first)
    // -------------------------------------------------------------------------

    /**
     * Returns a 16-bit window starting at the current bit position, without
     * advancing the position. The window is aligned to MSB-first ordering.
     *
     * <p>Equivalent to WinRAR's {@code getbits()} internal function.</p>
     */
    public int peek16() {
        int b0 = bytePos     < buf.length ? (buf[bytePos]     & 0xFF) : 0;
        int b1 = bytePos + 1 < buf.length ? (buf[bytePos + 1] & 0xFF) : 0;
        int b2 = bytePos + 2 < buf.length ? (buf[bytePos + 2] & 0xFF) : 0;
        return (((b0 << 16) | (b1 << 8) | b2) >>> (8 - bitOffset)) & 0xFFFF;
    }

    /**
     * Returns a 32-bit window starting at the current bit position, without
     * advancing the position.
     *
     * <p>Equivalent to WinRAR's {@code fgetbits()} internal function.</p>
     */
    public long peek32() {
        int b0 = bytePos     < buf.length ? (buf[bytePos]     & 0xFF) : 0;
        int b1 = bytePos + 1 < buf.length ? (buf[bytePos + 1] & 0xFF) : 0;
        int b2 = bytePos + 2 < buf.length ? (buf[bytePos + 2] & 0xFF) : 0;
        int b3 = bytePos + 3 < buf.length ? (buf[bytePos + 3] & 0xFF) : 0;
        long combined = (((long)b0 << 24) | ((long)b1 << 16) | ((long)b2 << 8) | b3);
        return (combined >>> (8 - bitOffset)) & 0xFFFFFFFFL;
    }

    // -------------------------------------------------------------------------
    // Position advancement
    // -------------------------------------------------------------------------

    /**
     * Advances the read position by {@code n} bits.
     *
     * @param n number of bits to skip (must be >= 0)
     */
    public void skip(int n) {
        int total  = bitOffset + n;
        bytePos   += total >>> 3;
        bitOffset  = total & 7;
    }

    /**
     * Reads {@code n} bits MSB-first and advances the position.
     *
     * @param n number of bits to read (1-16)
     * @return the bit value
     */
    public int readBits(int n) {
        int val = peek16() >>> (16 - n);
        skip(n);
        return val;
    }

    /**
     * Aligns the read position to the next byte boundary.
     * Any remaining bits in the current byte are discarded.
     */
    public void alignToByte() {
        skip((8 - bitOffset) & 7);
    }
}