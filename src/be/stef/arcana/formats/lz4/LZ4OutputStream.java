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
package be.stef.arcana.formats.lz4;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Pure-Java LZ4 frame writer (LZ4 Frame Format v1.6.x).
 *
 * <p>Frame layout produced:</p>
 * <ul>
 *   <li>Magic 0x184D2204, FLG = version 01 + independent blocks + content checksum,
 *       BD = 4 MB maximum block size, HC = header checksum (xxHash32).</li>
 *   <li>Blocks of at most 4 MB, each compressed independently with a greedy
 *       hash-table matcher (same approach as LZ4 "fast" level 1). A block that
 *       does not shrink is stored uncompressed (high bit of the size set).</li>
 *   <li>End mark (4 zero bytes) followed by the xxHash32 of the whole content.</li>
 * </ul>
 *
 * <p>{@link #finish()} writes the end of the frame without closing the
 * underlying stream; {@link #close()} finishes then closes it.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class LZ4OutputStream extends OutputStream {

    private static final int MAGIC = 0x184D2204;
    private static final int BLOCK_SIZE = 4 * 1024 * 1024;
    private static final int FLG = 0x40 | 0x20 | 0x04; // version 01, block independence, content checksum
    private static final int BD = 7 << 4;              // block max size 4 MB

    private static final int MIN_MATCH = 4;
    private static final int LAST_LITERALS = 5;        // last 5 bytes of a block are always literals
    private static final int MF_LIMIT = 12;            // last match must start >= 12 bytes before block end
    private static final int MAX_OFFSET = 65535;
    private static final int HASH_LOG = 16;

    private final OutputStream out;
    private final byte[] block = new byte[BLOCK_SIZE];
    private final byte[] comp = new byte[BLOCK_SIZE + BLOCK_SIZE / 255 + 16];
    private final int[] table = new int[1 << HASH_LOG];
    private final XxHash32 contentHash = new XxHash32(0);
    private int blockLen;
    private boolean headerWritten;
    private boolean finished;

    public LZ4OutputStream(final OutputStream out) {
        this.out = out;
    }

    @Override
    public void write(final int b) throws IOException {
        write(new byte[] { (byte) b }, 0, 1);
    }

    @Override
    public void write(final byte[] b, int off, int len) throws IOException {
        if (finished) throw new IOException("LZ4 stream already finished");
        writeHeaderIfNeeded();
        while (len > 0) {
            final int n = Math.min(len, BLOCK_SIZE - blockLen);
            System.arraycopy(b, off, block, blockLen, n);
            blockLen += n;
            off += n;
            len -= n;
            if (blockLen == BLOCK_SIZE) flushBlock();
        }
    }

    /** Writes the pending block, the end mark and the content checksum. Does not close the underlying stream. */
    public void finish() throws IOException {
        if (finished) return;
        writeHeaderIfNeeded();
        if (blockLen > 0) flushBlock();
        writeIntLE(0); // end mark
        writeIntLE(contentHash.digest());
        out.flush();
        finished = true;
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        try {
            finish();
        } finally {
            out.close();
        }
    }

    // ---- Frame ------------------------------------------------------------

    private void writeHeaderIfNeeded() throws IOException {
        if (headerWritten) return;
        writeIntLE(MAGIC);
        final byte[] desc = { (byte) FLG, (byte) BD };
        final XxHash32 h = new XxHash32(0);
        h.update(desc, 0, 2);
        out.write(desc);
        out.write((h.digest() >>> 8) & 0xFF);
        headerWritten = true;
    }

    private void flushBlock() throws IOException {
        contentHash.update(block, 0, blockLen);
        final int clen = compressBlock(block, blockLen, comp);
        if (clen < blockLen) {
            writeIntLE(clen);
            out.write(comp, 0, clen);
        } else {
            writeIntLE(blockLen | 0x80000000); // stored uncompressed
            out.write(block, 0, blockLen);
        }
        blockLen = 0;
    }

    private void writeIntLE(final int v) throws IOException {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    // ---- Block compressor -------------------------------------------------

    /** Compresses src[0..len) into dst as one LZ4 block and returns the compressed size. */
    private int compressBlock(final byte[] src, final int len, final byte[] dst) {
        int op = 0;
        int anchor = 0;
        if (len >= MF_LIMIT + 1) {
            java.util.Arrays.fill(table, -1);
            final int limit = len - MF_LIMIT;
            final int matchLimit = len - LAST_LITERALS;
            int ip = 0;
            while (ip < limit) {
                final int seq = readIntLE(src, ip);
                final int h = hash(seq);
                int ref = table[h];
                table[h] = ip;
                if (ref < 0 || ip - ref > MAX_OFFSET || readIntLE(src, ref) != seq) {
                    ip++;
                    continue;
                }
                int start = ip;
                while (start > anchor && ref > 0 && src[start - 1] == src[ref - 1]) { start--; ref--; }
                int mlen = MIN_MATCH + (ip - start);
                while (start + mlen < matchLimit && src[start + mlen] == src[ref + mlen]) mlen++;
                op = writeSequence(src, anchor, start - anchor, start - ref, mlen, dst, op);
                ip = start + mlen;
                anchor = ip;
                if (ip - 2 < limit) table[hash(readIntLE(src, ip - 2))] = ip - 2;
            }
        }
        return writeLastLiterals(src, anchor, len - anchor, dst, op);
    }

    private static int writeSequence(final byte[] src, final int litOff, final int litLen, final int offset, final int mlen, final byte[] dst, int op) {
        final int ml = mlen - MIN_MATCH;
        final int tokenPos = op++;
        dst[tokenPos] = (byte) ((Math.min(litLen, 15) << 4) | Math.min(ml, 15));
        op = writeLength(litLen, dst, op);
        System.arraycopy(src, litOff, dst, op, litLen);
        op += litLen;
        dst[op++] = (byte) offset;
        dst[op++] = (byte) (offset >>> 8);
        return writeLength(ml, dst, op);
    }

    private static int writeLastLiterals(final byte[] src, final int litOff, final int litLen, final byte[] dst, int op) {
        dst[op++] = (byte) (Math.min(litLen, 15) << 4);
        op = writeLength(litLen, dst, op);
        System.arraycopy(src, litOff, dst, op, litLen);
        return op + litLen;
    }

    /** Writes the extra length bytes (255, 255, ..., rest) when the 4-bit token field is saturated. */
    private static int writeLength(final int value, final byte[] dst, int op) {
        if (value < 15) return op;
        int rest = value - 15;
        while (rest >= 255) { dst[op++] = (byte) 255; rest -= 255; }
        dst[op++] = (byte) rest;
        return op;
    }

    private static int hash(final int seq) {
        return (seq * -1640531535) >>> (32 - HASH_LOG); // 2654435761 (Knuth multiplicative hash)
    }

    private static int readIntLE(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    // ---- xxHash32 (streaming) ---------------------------------------------

    /** Minimal streaming xxHash32, used for the frame header and content checksums. */
    static final class XxHash32 {
        private static final int P1 = 0x9E3779B1;
        private static final int P2 = 0x85EBCA77;
        private static final int P3 = 0xC2B2AE3D;
        private static final int P4 = 0x27D4EB2F;
        private static final int P5 = 0x165667B1;

        private final int seed;
        private int v1, v2, v3, v4;
        private final byte[] mem = new byte[16];
        private int memSize;
        private long total;

        XxHash32(final int seed) {
            this.seed = seed;
            v1 = seed + P1 + P2;
            v2 = seed + P2;
            v3 = seed;
            v4 = seed - P1;
        }

        void update(final byte[] b, int off, int len) {
            total += len;
            if (memSize + len < 16) {
                System.arraycopy(b, off, mem, memSize, len);
                memSize += len;
                return;
            }
            if (memSize > 0) {
                final int fill = 16 - memSize;
                System.arraycopy(b, off, mem, memSize, fill);
                round4(mem, 0);
                off += fill;
                len -= fill;
                memSize = 0;
            }
            while (len >= 16) {
                round4(b, off);
                off += 16;
                len -= 16;
            }
            System.arraycopy(b, off, mem, 0, len);
            memSize = len;
        }

        private void round4(final byte[] b, final int p) {
            v1 = round(v1, readIntLE(b, p));
            v2 = round(v2, readIntLE(b, p + 4));
            v3 = round(v3, readIntLE(b, p + 8));
            v4 = round(v4, readIntLE(b, p + 12));
        }

        private static int round(final int acc, final int input) {
            return Integer.rotateLeft(acc + input * P2, 13) * P1;
        }

        int digest() {
            int h;
            if (total >= 16) h = Integer.rotateLeft(v1, 1) + Integer.rotateLeft(v2, 7) + Integer.rotateLeft(v3, 12) + Integer.rotateLeft(v4, 18);
            else h = seed + P5;
            h += (int) total;
            int p = 0;
            while (p + 4 <= memSize) {
                h = Integer.rotateLeft(h + readIntLE(mem, p) * P3, 17) * P4;
                p += 4;
            }
            while (p < memSize) {
                h = Integer.rotateLeft(h + (mem[p] & 0xFF) * P5, 11) * P1;
                p++;
            }
            h ^= h >>> 15;
            h *= P2;
            h ^= h >>> 13;
            h *= P3;
            h ^= h >>> 16;
            return h;
        }
    }
}
