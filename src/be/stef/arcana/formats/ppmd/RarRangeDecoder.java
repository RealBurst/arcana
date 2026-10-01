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

/**
 * Carry-less range decoder (Dmitry Subbotin) used by PPMd blocks in RAR 3.x/4.x
 * archives (the "Ppmd7a" flavour in 7-Zip terminology).
 *
 * <p>Bytes are pulled through {@link ByteIn}, because in RAR the PPMd data is
 * interleaved with the LZ bit stream of the same file.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class RarRangeDecoder implements Ppmd7RangeDecoder {

    /** Byte source (the RAR bit reader, byte-aligned while in PPMd mode). */
    public interface ByteIn {
        int read() throws IOException;
    }

    private static final long MASK = 0xFFFFFFFFL;
    private static final long TOP = 1L << 24;
    private static final long BOT = 1L << 15;

    private final ByteIn in;
    private long low;
    private long code;
    private long range;

    public RarRangeDecoder(final ByteIn in) {
        this.in = in;
    }

    /** RangeCoder::InitDecoder: reads 4 bytes. */
    public void init() throws IOException {
        low = 0;
        code = 0;
        range = MASK;
        for (int i = 0; i < 4; i++) code = ((code << 8) | (in.read() & 0xFF)) & MASK;
    }

    @Override
    public long getThreshold(final long total) {
        range = range / total;
        return ((code - low) & MASK) / range;
    }

    @Override
    public void decode(final long start, final long size) throws IOException {
        low = (low + start * range) & MASK;
        range = (range * size) & MASK;
        normalize();
    }

    @Override
    public int decodeBit(final int size0) throws IOException {
        final long total = Ppmd7.BIN_SCALE;
        if (getThreshold(total) < size0) {
            decode(0, size0);
            return 0;
        }
        decode(size0, total - size0);
        return 1;
    }

    /** ARI_DEC_NORMALIZE. */
    private void normalize() throws IOException {
        for (;;) {
            if ((low ^ ((low + range) & MASK)) >= TOP) {
                if (range >= BOT) return;
                range = (-low) & (BOT - 1);
            }
            code = ((code << 8) | (in.read() & 0xFF)) & MASK;
            range = (range << 8) & MASK;
            low = (low << 8) & MASK;
        }
    }
}
