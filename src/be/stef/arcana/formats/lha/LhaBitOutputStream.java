/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Writes individual bits to an {@link OutputStream} in big-endian (MSB-first) order.
 *
 * <p>Symmetric counterpart of {@code LhaBitInputStream}.  Bits are accumulated
 * in an internal buffer and flushed a full byte at a time.  The caller must
 * call {@link #flush()} (or {@link #close()}) when finished to output any
 * remaining bits zero-padded to a byte boundary.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class LhaBitOutputStream extends FilterOutputStream {

    private int bitBuffer  = 0; // bits are placed from MSB
    private int bitsInBuf  = 0; // number of valid bits in bitBuffer (0-7)

    public LhaBitOutputStream(final OutputStream out) { super(out); }

    /**
     * Writes the {@code count} least-significant bits of {@code value}
     * to the stream, MSB first.
     *
     * @param value the bit value to write
     * @param count number of bits to write (1-16)
     * @throws IOException if an I/O error occurs
     */
    public void writeBits(final int value, final int count) throws IOException {
        int bits = count;
        int v    = value & ((1 << bits) - 1);
        // Shift value left to align MSB at bit position (bitsInBuf + bits - 1) in the buffer
        while (bits > 0) {
            final int space = 8 - bitsInBuf;
            if (bits >= space) {
                // Fill the current byte completely
                bitBuffer |= (v >>> (bits - space)) & ((1 << space) - 1);
                out.write(bitBuffer & 0xFF);
                bitBuffer = 0;
                bitsInBuf = 0;
                bits -= space;
            } else {
                // Partial byte fill
                bitBuffer |= (v & ((1 << bits) - 1)) << (space - bits);
                bitsInBuf += bits;
                bits = 0;
            }
        }
    }

    /** Writes a single bit (0 or 1). */
    public void writeBit(final int bit) throws IOException { writeBits(bit, 1); }

    /**
     * Flushes any remaining buffered bits as a zero-padded byte, then
     * flushes the underlying output stream.
     */
    @Override
    public void flush() throws IOException {
        if (bitsInBuf > 0) {
            out.write(bitBuffer & 0xFF);
            bitBuffer = 0;
            bitsInBuf = 0;
        }
        out.flush();
    }

    @Override
    public void close() throws IOException {
        flush();
        out.close();
    }

    /** Returns the number of bits that have not yet been written as a full byte. */
    public int getPendingBits() { return bitsInBuf; }
}
