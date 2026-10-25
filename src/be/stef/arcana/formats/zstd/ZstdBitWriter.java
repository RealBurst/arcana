/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.formats.zstd;

import java.util.Arrays;

/**
 * Bit stream written forward and read backward by the decoder (RFC 8878,
 * section 4.1): bits are packed from the least significant bit of each byte,
 * the bytes are written in order, and {@link #close()} adds the final 1 bit
 * that marks where the decoder starts. The value written last is the first
 * one the decoder reads.
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdBitWriter {

    private byte[] buf;
    private int pos;
    private long container;
    private int bitCount;

    ZstdBitWriter(final int capacity) {
        buf = new byte[Math.max(16, capacity)];
    }

    /** Starts a new stream in the same buffer. */
    void reset() {
        pos = 0;
        container = 0;
        bitCount = 0;
    }

    /** Appends the {@code nbBits} low bits of {@code value} (0 to 32 bits). */
    void addBits(final long value, final int nbBits) {
        container |= (value & ((1L << nbBits) - 1)) << bitCount;
        bitCount += nbBits;
        if (bitCount >= 32) {
            if (pos + 4 > buf.length) buf = Arrays.copyOf(buf, buf.length * 2);
            buf[pos] = (byte) container;
            buf[pos + 1] = (byte) (container >>> 8);
            buf[pos + 2] = (byte) (container >>> 16);
            buf[pos + 3] = (byte) (container >>> 24);
            pos += 4;
            container >>>= 32;
            bitCount -= 32;
        }
    }

    /** Adds the end mark and the last bits; returns the size of the stream in bytes. */
    int close() {
        addBits(1, 1);
        while (bitCount > 0) {
            if (pos + 1 > buf.length) buf = Arrays.copyOf(buf, buf.length * 2);
            buf[pos++] = (byte) container;
            container >>>= 8;
            bitCount -= 8;
        }
        bitCount = 0;
        container = 0;
        return pos;
    }

    byte[] buffer() {
        return buf;
    }
}
