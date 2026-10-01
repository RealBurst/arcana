/*
 * Copyright 2025 Stephane Bury - Derived from Apache Commons Compress
 * (BitInputStream.java, Apache License 2.0).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads individual bits from an {@link InputStream} in big-endian (MSB-first) order.
 *
 * <p>LZH compression (-lh4- to -lh7-) encodes commands and distances as a
 * stream of variable-width bit codes read MSB-first from successive bytes.
 * This class buffers the current byte and exposes {@link #readBits(int)} and
 * {@link #readBit()} for the decompressor.</p>
 *
 * <p>Derived from {@code org.apache.commons.compress.utils.BitInputStream}
 * (Apache License 2.0), simplified for LHA's big-endian-only requirement.</p>
 */
final class LhaBitInputStream extends FilterInputStream {

    private static final long MASKS[] = buildMasks();
    private static long[] buildMasks() {
        final long[] m = new long[64];
        for (int i = 0; i < 64; i++) m[i] = (1L << i) - 1;
        return m;
    }

    /** Bit buffer (up to 63 bits; MSBs hold the next bits to return). */
    private long bitBuffer   = 0;
    /** Number of valid bits currently in {@link #bitBuffer}. */
    private int  bitsInBuf  = 0;
    /** Total bytes read from the underlying stream. */
    private long bytesRead   = 0;

    /**
     * Creates a LhaBitInputStream wrapping the given input stream.
     *
     * @param in compressed-data stream
     */
    LhaBitInputStream(final InputStream in) { super(in); }

    /**
     * Reads between 1 and 63 bits from the stream.
     *
     * @param count number of bits to read (1-63)
     * @return the bits as an unsigned long, MSB at the highest position;
     *         {@code -1} if the stream is exhausted before all bits are read
     * @throws IOException              if an I/O error occurs
     * @throws IllegalArgumentException if {@code count < 1 || count > 63}
     */
    long readBits(final int count) throws IOException {
        if (count < 1 || count > 63) throw new IllegalArgumentException("count=" + count);
        while (bitsInBuf < count) {
            final int b = in.read();
            if (b < 0) return -1L;
            bytesRead++;
            bitBuffer = (bitBuffer << 8) | (b & 0xFF);
            bitsInBuf += 8;
        }
        bitsInBuf -= count;
        return (bitBuffer >>> bitsInBuf) & MASKS[count];
    }

    /**
     * Reads a single bit.
     *
     * @return 0 or 1; {@code -1} on end of stream
     * @throws IOException if an I/O error occurs
     */
    int readBit() throws IOException {
        final long v = readBits(1);
        return v < 0 ? -1 : (int) v;
    }

    /**
     * Discards any bits that have been buffered but not yet consumed so that
     * the next call to {@link #read()} returns the next whole byte.
     * The number of discarded bits is always between 0 and 7.
     */
    void alignWithByteBoundary() {
        bitsInBuf = bitsInBuf & ~7; // keep only whole buffered bytes
    }

    /** Returns the number of bytes read from the underlying stream so far. */
    long getBytesRead() { return bytesRead; }
}
