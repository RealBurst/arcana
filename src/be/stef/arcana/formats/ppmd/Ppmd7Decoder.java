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
package be.stef.arcana.formats.ppmd;

import java.io.IOException;
import java.io.InputStream;
import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * PPMd variant H decoder with the 7-Zip range coder ("Ppmd7z"), as used by the
 * 7z PPMD method (id 03 04 01).
 *
 * <p>Java port of Ppmd7Dec.c by Igor Pavlov (public domain). The 7z coder
 * properties are 5 bytes: model order (1 byte) and memory size (4 bytes LE).
 * The stream carries no end marker by default: the caller must know the
 * uncompressed size.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class Ppmd7Decoder extends InputStream implements Ppmd7RangeDecoder {

    private static final long TOP = 1L << 24;

    private final InputStream in;
    private final Ppmd7 p;
    private long remaining;
    private long range;
    private long code;
    private boolean finished;

    /**
     * @param in        compressed data
     * @param order     model order (2..64)
     * @param memSize   model memory in bytes
     * @param outSize   uncompressed size, or -1 to decode until the end marker
     */
    public Ppmd7Decoder(final InputStream in, final int order, final int memSize, final long outSize) throws IOException {
        if (order < Ppmd7.MIN_ORDER || order > Ppmd7.MAX_ORDER) throw new ArcanaCorruptedException("PPMd: invalid model order " + order);
        this.in = in;
        this.p = new Ppmd7(memSize);
        this.p.init(order);
        this.remaining = outSize;
        if (outSize == 0) {
            finished = true;
            return;
        }
        code = 0;
        range = 0xFFFFFFFFL;
        if (readByte() != 0) throw new ArcanaCorruptedException("PPMd: invalid range coder header");
        for (int i = 0; i < 4; i++) code = ((code << 8) | readByte()) & 0xFFFFFFFFL;
        if (code == 0xFFFFFFFFL) throw new ArcanaCorruptedException("PPMd: invalid range coder header");
    }

    /** Builds a decoder from the 5-byte 7z coder properties. */
    public static Ppmd7Decoder fromProperties(final InputStream in, final byte[] props, final long outSize) throws IOException {
        if (props == null || props.length < 5) throw new ArcanaCorruptedException("PPMd: missing coder properties");
        final int order = props[0] & 0xFF;
        final long mem = (props[1] & 0xFFL) | ((props[2] & 0xFFL) << 8) | ((props[3] & 0xFFL) << 16) | ((props[4] & 0xFFL) << 24);
        if (mem < Ppmd7.MIN_MEM_SIZE || mem > Ppmd7.MAX_MEM_SIZE) throw new ArcanaCorruptedException("PPMd: unsupported memory size " + mem);
        return new Ppmd7Decoder(in, order, (int) mem, outSize);
    }

    /** Memory size in bytes declared by 7z coder properties (for memory-limit checks). */
    public static long memorySize(final byte[] props) {
        if (props == null || props.length < 5) return 0;
        return (props[1] & 0xFFL) | ((props[2] & 0xFFL) << 8) | ((props[3] & 0xFFL) << 16) | ((props[4] & 0xFFL) << 24);
    }

    @Override
    public int read() throws IOException {
        if (finished) return -1;
        final int sym = p.decodeSymbol(this);
        if (sym < 0) {
            finished = true;
            if (sym == -1 && remaining < 0) return -1; // end marker
            throw new ArcanaCorruptedException(sym == -1 ? "PPMd: unexpected end marker" : "PPMd: corrupted data");
        }
        if (remaining > 0 && --remaining == 0) finished = true;
        return sym;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        if (finished) return -1;
        int n = 0;
        while (n < len && !finished) {
            final int c = read();
            if (c < 0) break;
            b[off + n++] = (byte) c;
        }
        return n == 0 ? -1 : n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // ---- range decoder (7z flavour, Ppmd7z_RangeDec) ----

    private int readByte() throws IOException {
        final int c = in.read();
        return c < 0 ? 0 : c; // like 7-Zip: reading past the end yields zeros, errors surface as bad symbols
    }

    @Override
    public long getThreshold(final long total) {
        range = range / total;
        return code / range;
    }

    private void normalize() throws IOException {
        if (range < TOP) {
            code = ((code << 8) | readByte()) & 0xFFFFFFFFL;
            range = (range << 8) & 0xFFFFFFFFL;
            if (range < TOP) {
                code = ((code << 8) | readByte()) & 0xFFFFFFFFL;
                range = (range << 8) & 0xFFFFFFFFL;
            }
        }
    }

    @Override
    public void decode(final long start, final long size) throws IOException {
        code = (code - start * range) & 0xFFFFFFFFL;
        range = (range * size) & 0xFFFFFFFFL;
        normalize();
    }

    @Override
    public int decodeBit(final int size0) throws IOException {
        final long newBound = (range >>> 14) * size0;
        final int symbol;
        if (code < newBound) {
            symbol = 0;
            range = newBound;
        } else {
            symbol = 1;
            code -= newBound;
            range -= newBound;
        }
        normalize();
        return symbol;
    }

}
