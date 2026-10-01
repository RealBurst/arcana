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
package be.stef.arcana.formats.recover;

import be.stef.arcana.formats.bzip2.BZip2InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Block-level recovery of a damaged bzip2 file (same principle as bzip2recover).
 *
 * <p>bzip2 compresses blocks of up to 900 KB independently; each block starts
 * with the 48-bit magic 0x314159265359 (at any bit position) and carries its own
 * CRC. Every block is copied into a small stand-alone bzip2 stream and decoded
 * separately: a damaged block is lost (about 900 KB of data) but the others are
 * recovered, with their CRC verified.</p>
 *
 * @author Stef
 * @since 1.3
 */
final class BZip2Recovery {

    private static final long BLOCK_MAGIC = 0x314159265359L;
    private static final long EOS_MAGIC = 0x177245385090L;
    private static final long MASK48 = 0xFFFFFFFFFFFFL;

    /** Result: number of blocks recovered and lost. */
    static final class Result {
        int good;
        int lost;
    }

    private BZip2Recovery() {}

    /** Writes the data of every valid block of {@code bz2} to {@code out}, in order. */
    static Result salvage(final File bz2, final OutputStream out) throws IOException {
        final List<long[]> bounds = findBlocks(bz2); // {startBit, endBit}
        final Result r = new Result();
        if (bounds.isEmpty()) return r;
        try (InputStream in = new BufferedInputStream(new FileInputStream(bz2), 1 << 16)) {
            final BitReader br = new BitReader(in);
            for (final long[] b : bounds) {
                final long bits = b[1] - b[0];
                if (bits <= 80 || bits > 8L * 2_000_000) { r.lost++; br.skipTo(b[1]); continue; }
                br.skipTo(b[0]);
                final BitWriter w = new BitWriter();
                w.write(8, 'B'); w.write(8, 'Z'); w.write(8, 'h'); w.write(8, '9');
                long blockCrc = 0;
                for (long i = 0; i < bits; i++) {
                    final int bit = br.bit();
                    if (bit < 0) break;
                    if (i >= 48 && i < 80) blockCrc = (blockCrc << 1) | bit; // CRC follows the 48-bit magic
                    w.write(1, bit);
                }
                w.write(24, (int) (EOS_MAGIC >>> 24));
                w.write(24, (int) (EOS_MAGIC & 0xFFFFFF));
                w.write(32, (int) blockCrc); // combined CRC of a one-block stream = its block CRC
                try {
                    final byte[] data = decode(w.toByteArray());
                    out.write(data);
                    r.good++;
                } catch (final IOException | RuntimeException e) {
                    r.lost++;
                }
            }
        }
        return r;
    }

    private static byte[] decode(final byte[] stream) throws IOException {
        final ByteArrayOutputStream bo = new ByteArrayOutputStream(1 << 20);
        try (InputStream in = new BZip2InputStream(new ByteArrayInputStream(stream), false)) {
            final byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        }
        return bo.toByteArray();
    }

    /** Bit positions of every block: from its magic to the next block or end-of-stream magic. */
    private static List<long[]> findBlocks(final File f) throws IOException {
        final List<long[]> list = new ArrayList<long[]>();
        long start = -1;
        long reg = 0;
        long bitPos = 0;
        try (InputStream in = new BufferedInputStream(new FileInputStream(f), 1 << 16)) {
            int c;
            while ((c = in.read()) >= 0) {
                for (int k = 7; k >= 0; k--) {
                    reg = (reg << 1) | ((c >>> k) & 1);
                    bitPos++;
                    final long v = reg & MASK48;
                    if (bitPos >= 48 && (v == BLOCK_MAGIC || v == EOS_MAGIC)) {
                        final long at = bitPos - 48;
                        if (start >= 0) list.add(new long[] {start, at});
                        start = v == BLOCK_MAGIC ? at : -1;
                    }
                }
            }
        }
        if (start >= 0) list.add(new long[] {start, bitPos}); // truncated last block
        return list;
    }

    /** Sequential bit reader, MSB first. */
    private static final class BitReader {
        private final InputStream in;
        private long pos; // bits consumed
        private int cur;
        private int left;

        BitReader(final InputStream in) {
            this.in = in;
        }

        int bit() throws IOException {
            if (left == 0) {
                cur = in.read();
                if (cur < 0) return -1;
                left = 8;
            }
            left--;
            pos++;
            return (cur >>> left) & 1;
        }

        void skipTo(final long target) throws IOException {
            while (pos < target && left > 0) { left--; pos++; }
            final long bytes = (target - pos) / 8;
            long done = 0;
            while (done < bytes) {
                final long k = in.skip(bytes - done);
                if (k <= 0) {
                    if (in.read() < 0) return;
                    done++;
                } else {
                    done += k;
                }
            }
            pos += bytes * 8;
            while (pos < target) if (bit() < 0) return;
        }
    }

    /** Bit writer, MSB first. */
    private static final class BitWriter {
        private final ByteArrayOutputStream bo = new ByteArrayOutputStream(1 << 20);
        private int acc;
        private int n;

        void write(final int count, final int value) {
            for (int i = count - 1; i >= 0; i--) {
                acc = (acc << 1) | ((value >>> i) & 1);
                if (++n == 8) {
                    bo.write(acc);
                    acc = 0;
                    n = 0;
                }
            }
        }

        byte[] toByteArray() {
            if (n > 0) {
                bo.write(acc << (8 - n));
                acc = 0;
                n = 0;
            }
            return bo.toByteArray();
        }
    }
}
