/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Ported from org.apache.commons.compress.utils.BitInputStream
 * (Apache Commons Compress 1.28.0) to package be.stef.arcana.formats.bzip2
 * by Stephane Bury (2025).
 * Changes:
 *   - Renamed BZip2BitInputStream to avoid conflicts.
 *   - Replaced org.apache.commons.io.input.BoundedInputStream with a
 *     simple counting InputStream wrapper (no external dependency).
 *   - Retained only BIG_ENDIAN behaviour used by BZIP2 (ByteOrder
 *     parameter kept for API compatibility but LITTLE_ENDIAN path
 *     is preserved for completeness).
 */
package be.stef.arcana.formats.bzip2;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteOrder;

/**
 * Reads bits from an {@link InputStream}.
 *
 * <p>Used exclusively by {@link BZip2InputStream} which reads in
 * {@link ByteOrder#BIG_ENDIAN} order.</p>
 *
 * @NotThreadSafe
 */
final class BZip2BitInputStream implements Closeable {

    private static final int MAXIMUM_CACHE_SIZE = 63; // bits in long minus sign bit
    private static final long[] MASKS = new long[MAXIMUM_CACHE_SIZE + 1];

    static {
        for (int i = 1; i <= MAXIMUM_CACHE_SIZE; i++) {
            MASKS[i] = (MASKS[i - 1] << 1) + 1;
        }
    }

    // ---- Counting wrapper replaces commons-io BoundedInputStream ----
    private final InputStream in;
    private long bytesRead = 0;

    private final ByteOrder byteOrder;
    private long bitsCached;
    private int bitsCachedSize;

    BZip2BitInputStream(final InputStream in, final ByteOrder byteOrder) {
        this.in        = in;
        this.byteOrder = byteOrder;
    }

    /** Drops bits until the next bits will be read from a byte boundary. */
    void alignWithByteBoundary() {
        final int toSkip = bitsCachedSize % Byte.SIZE;
        if (toSkip > 0) {
            readCachedBits(toSkip);
        }
    }

    /**
     * Returns an estimate of the number of bits that can be read without blocking.
     *
     * @throws IOException if the underlying stream throws one when calling available
     */
    long bitsAvailable() throws IOException {
        return bitsCachedSize + (long) Byte.SIZE * in.available();
    }

    /** Returns the number of bits in the cache not yet consumed. */
    int bitsCached() {
        return bitsCachedSize;
    }

    /** Clears the bit cache. */
    void clearBitCache() {
        bitsCached     = 0;
        bitsCachedSize = 0;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    /** Returns the number of bytes read from the underlying stream (replaces BoundedInputStream.getCount()). */
    long getBytesRead() {
        return bytesRead;
    }

    private int readByte() throws IOException {
        int b = in.read();
        if (b >= 0) bytesRead++;
        return b;
    }

    private boolean ensureCache(final int count) throws IOException {
        while (bitsCachedSize < count && bitsCachedSize < 57) {
            final long nextByte = readByte();
            if (nextByte < 0) return true;
            if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
                bitsCached |= nextByte << bitsCachedSize;
            } else {
                bitsCached <<= Byte.SIZE;
                bitsCached |= nextByte;
            }
            bitsCachedSize += Byte.SIZE;
        }
        return false;
    }

    private long processBitsGreater57(final int count) throws IOException {
        final long bitsOut;
        final int overflowBits;
        long overflow = 0L;

        final int bitsToAddCount = count - bitsCachedSize;
        overflowBits = Byte.SIZE - bitsToAddCount;
        final long nextByte = readByte();
        if (nextByte < 0) return nextByte;

        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            final long bitsToAdd = nextByte & MASKS[bitsToAddCount];
            bitsCached |= bitsToAdd << bitsCachedSize;
            overflow = nextByte >>> bitsToAddCount & MASKS[overflowBits];
        } else {
            bitsCached <<= bitsToAddCount;
            final long bitsToAdd = nextByte >>> overflowBits & MASKS[bitsToAddCount];
            bitsCached |= bitsToAdd;
            overflow = nextByte & MASKS[overflowBits];
        }
        bitsOut        = bitsCached & MASKS[count];
        bitsCached     = overflow;
        bitsCachedSize = overflowBits;
        return bitsOut;
    }

    /** Reads and returns the next bit (0 or 1), or -1 at EOF. */
    int readBit() throws IOException {
        return (int) readBits(1);
    }

    /**
     * Reads and returns at most 63 bits.
     *
     * @param count number of bits to read (1..63)
     * @return the bits as a long, or -1 at EOF
     */
    long readBits(final int count) throws IOException {
        if (count < 0 || count > MAXIMUM_CACHE_SIZE) {
            throw new IOException("count must not be negative or greater than " + MAXIMUM_CACHE_SIZE);
        }
        if (ensureCache(count)) return -1;
        if (bitsCachedSize < count) return processBitsGreater57(count);
        return readCachedBits(count);
    }

    private long readCachedBits(final int count) {
        final long bitsOut;
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            bitsOut     = bitsCached & MASKS[count];
            bitsCached >>>= count;
        } else {
            bitsOut = bitsCached >> bitsCachedSize - count & MASKS[count];
        }
        bitsCachedSize -= count;
        return bitsOut;
    }
}
