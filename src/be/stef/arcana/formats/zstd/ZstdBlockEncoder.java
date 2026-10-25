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

/**
 * Writes the content of a compressed block (RFC 8878, section 3.1.1.3): the
 * literals section (raw, RLE or Huffman, one or four streams) and the
 * sequences section (literal length, offset and match length codes, each
 * with the predefined distribution, a single symbol (RLE) or its own FSE
 * table, whichever is estimated smaller).
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdBlockEncoder {

    private static final short[] LL_DEFAULT = {4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1};
    private static final short[] ML_DEFAULT = {1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1};
    private static final short[] OF_DEFAULT = {1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};
    private static final int LL_DEFAULT_LOG = 6;
    private static final int ML_DEFAULT_LOG = 6;
    private static final int OF_DEFAULT_LOG = 5;

    private static final ZstdFseEncoder LL_DEFAULT_TABLE = new ZstdFseEncoder(LL_DEFAULT, LL_DEFAULT.length - 1, LL_DEFAULT_LOG);
    private static final ZstdFseEncoder ML_DEFAULT_TABLE = new ZstdFseEncoder(ML_DEFAULT, ML_DEFAULT.length - 1, ML_DEFAULT_LOG);
    private static final ZstdFseEncoder OF_DEFAULT_TABLE = new ZstdFseEncoder(OF_DEFAULT, OF_DEFAULT.length - 1, OF_DEFAULT_LOG);

    private static final int[] LL_BASE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000};
    private static final int[] ML_BASE = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003};

    /** Literal length code of the values below 64; the larger ones use the highest bit. */
    private static final byte[] LL_CODE = new byte[64];
    /** Match length code of (length - 3) below 128. */
    private static final byte[] ML_CODE = new byte[128];

    static {
        for (int v = 0; v < 64; v++) LL_CODE[v] = (byte) codeOf(LL_BASE, v);
        for (int v = 0; v < 128; v++) ML_CODE[v] = (byte) codeOf(ML_BASE, v + 3);
    }

    private final ZstdHuffmanEncoder huffman = new ZstdHuffmanEncoder();
    private final ZstdBitWriter bits = new ZstdBitWriter(Constants.MAX_BLOCK_SIZE + 1024);
    private final int[] counts = new int[256];
    private final byte[] llCodes = new byte[Constants.MAX_BLOCK_SIZE / 3 + 1];
    private final byte[] mlCodes = new byte[Constants.MAX_BLOCK_SIZE / 3 + 1];
    private final byte[] ofCodes = new byte[Constants.MAX_BLOCK_SIZE / 3 + 1];

    private static int codeOf(final int[] base, final int value) {
        int c = 0;
        while (c + 1 < base.length && base[c + 1] <= value) c++;
        return c;
    }

    static int literalLengthCode(final int ll) {
        return ll < 64 ? LL_CODE[ll] : Util.highestBit(ll) + 19;
    }

    static int matchLengthCode(final int ml) {
        final int v = ml - 3;
        return v < 128 ? ML_CODE[v] : Util.highestBit(v) + 36;
    }

    /**
     * Encodes the block in {@code dst} from {@code off}.
     *
     * @return the size written, or -1 if it does not fit in {@code limit} bytes
     */
    int encode(final ZstdSequenceStore store, final byte[] dst, final int off, final int limit) {
        int p = off;
        final int lit = encodeLiterals(store.literals, store.literalCount, dst, p, limit);
        if (lit < 0) return -1;
        p += lit;
        final int seq = encodeSequences(store, dst, p, off + limit - p);
        if (seq < 0) return -1;
        p += seq;
        return p - off;
    }

    // =========================================================================
    // Literals
    // =========================================================================

    private int encodeLiterals(final byte[] lit, final int n, final byte[] dst, final int off, final int limit) {
        if (n == 0) {
            if (limit < 1) return -1;
            dst[off] = 0; // raw, size 0
            return 1;
        }
        java.util.Arrays.fill(counts, 0);
        int distinct = 0;
        for (int i = 0; i < n; i++) {
            if (counts[lit[i] & 0xFF]++ == 0) distinct++;
        }
        if (distinct == 1) {
            final int h = rawHeader(1, n, dst, off);
            dst[off + h] = lit[0];
            return h + 1;
        }
        final int raw = rawSize(n);
        if (n >= 64 && huffman.build(counts)) {
            final int c = huffmanLiterals(lit, n, dst, off, Math.min(limit, raw - 1));
            if (c > 0) return c;
        }
        if (raw > limit) return -1;
        final int h = rawHeader(0, n, dst, off);
        System.arraycopy(lit, 0, dst, off + h, n);
        return h + n;
    }

    private static int rawSize(final int n) {
        return n + (n < 32 ? 1 : n < 4096 ? 2 : 3);
    }

    /** Header of raw (type 0) or RLE (type 1) literals; returns its size. */
    private static int rawHeader(final int type, final int n, final byte[] dst, final int off) {
        if (n < 32) {
            dst[off] = (byte) (type | (n << 3));
            return 1;
        }
        if (n < 4096) {
            final int v = type | (1 << 2) | (n << 4);
            dst[off] = (byte) v;
            dst[off + 1] = (byte) (v >>> 8);
            return 2;
        }
        final int v = type | (3 << 2) | (n << 4);
        dst[off] = (byte) v;
        dst[off + 1] = (byte) (v >>> 8);
        dst[off + 2] = (byte) (v >>> 16);
        return 3;
    }

    /** Huffman-compressed literals; returns the size, or -1 if not smaller than {@code limit}. */
    private int huffmanLiterals(final byte[] lit, final int n, final byte[] dst, final int off, final int limit) {
        final boolean single = n < 256;
        final int desc = huffman.descriptionSize();
        final long estimate = desc + (huffman.encodedBits(counts) >>> 3) + (single ? 1 : 10);
        if (estimate + 5 > limit) return -1;
        final int headerSize;
        int sizeFormat;
        // the sizes are known after encoding: reserve the largest header that may be needed
        if (single) {
            sizeFormat = 0;
            headerSize = 3;
        } else if (n < 1024) {
            sizeFormat = 1;
            headerSize = 3;
        } else if (n < 16384) {
            sizeFormat = 2;
            headerSize = 4;
        } else {
            sizeFormat = 3;
            headerSize = 5;
        }
        int p = off + headerSize;
        huffman.writeDescription(dst, p);
        p += desc;
        if (single) {
            final int s = huffman.encodeStream(lit, 0, n, bits);
            if (p + s > off + limit) return -1;
            System.arraycopy(bits.buffer(), 0, dst, p, s);
            p += s;
        } else {
            final int seg = (n + 3) / 4;
            final int jump = p;
            p += 6;
            for (int k = 0; k < 4; k++) {
                final int start = k * seg;
                final int len = k < 3 ? seg : n - 3 * seg;
                final int s = huffman.encodeStream(lit, start, len, bits);
                if (p + s > off + limit) return -1;
                if (k < 3) {
                    if (s > 0xFFFF) return -1;
                    dst[jump + 2 * k] = (byte) s;
                    dst[jump + 2 * k + 1] = (byte) (s >>> 8);
                }
                System.arraycopy(bits.buffer(), 0, dst, p, s);
                p += s;
            }
        }
        final int compressed = p - off - headerSize;
        final int sizeBits = sizeFormat <= 1 ? 10 : sizeFormat == 2 ? 14 : 18;
        if (compressed >= (1 << sizeBits)) return -1;
        final long h = 2 | (sizeFormat << 2) | ((long) n << 4) | ((long) compressed << (4 + sizeBits));
        for (int i = 0; i < headerSize; i++) dst[off + i] = (byte) (h >>> (8 * i));
        return p - off;
    }

    // =========================================================================
    // Sequences
    // =========================================================================

    private int encodeSequences(final ZstdSequenceStore store, final byte[] dst, final int off, final int limit) {
        final int n = store.count;
        int p = off;
        if (limit < 4) return -1;
        if (n < 128) {
            dst[p++] = (byte) n;
        } else if (n < Constants.LONG_NUMBER_OF_SEQUENCES) {
            dst[p++] = (byte) ((n >>> 8) + 128);
            dst[p++] = (byte) n;
        } else {
            dst[p++] = (byte) 255;
            final int v = n - Constants.LONG_NUMBER_OF_SEQUENCES;
            dst[p++] = (byte) v;
            dst[p++] = (byte) (v >>> 8);
        }
        if (n == 0) return p - off;
        for (int i = 0; i < n; i++) {
            llCodes[i] = (byte) literalLengthCode(store.literalLengths[i]);
            mlCodes[i] = (byte) matchLengthCode(store.matchLengths[i]);
            ofCodes[i] = (byte) Util.highestBit(store.offsetValues[i]);
        }
        final int modes = p++;
        final ZstdFseEncoder[] tables = new ZstdFseEncoder[3];
        final int[] modeOf = new int[3];
        final byte[][] codes = {llCodes, ofCodes, mlCodes};
        final short[][] defaults = {LL_DEFAULT, OF_DEFAULT, ML_DEFAULT};
        final int[] defaultLogs = {LL_DEFAULT_LOG, OF_DEFAULT_LOG, ML_DEFAULT_LOG};
        final ZstdFseEncoder[] defaultTables = {LL_DEFAULT_TABLE, OF_DEFAULT_TABLE, ML_DEFAULT_TABLE};
        final int[] maxLogs = {Constants.LITERAL_LENGTH_TABLE_LOG, Constants.OFFSET_TABLE_LOG, Constants.MATCH_LENGTH_TABLE_LOG};
        final int[] maxSymbols = {Constants.MAX_LITERALS_LENGTH_SYMBOL, Constants.DEFAULT_MAX_OFFSET_CODE_SYMBOL, Constants.MAX_MATCH_LENGTH_SYMBOL};
        for (int t = 0; t < 3; t++) {
            final int[] c = new int[64];
            int max = 0;
            for (int i = 0; i < n; i++) {
                final int s = codes[t][i];
                c[s]++;
                if (s > max) max = s;
            }
            if (max > maxSymbols[t]) return -1;
            if (c[max] == n) {
                // a single symbol: RLE (or the default table for very few sequences)
                if (p + 1 > off + limit) return -1;
                modeOf[t] = Constants.SEQUENCE_ENCODING_RLE;
                dst[p++] = (byte) max;
                tables[t] = null;
                continue;
            }
            final double defaultCost = ZstdFseEncoder.cost(c, max, defaults[t], defaults[t].length - 1, defaultLogs[t]);
            final int tableLog = FiniteStateEntropy.optimalTableLog(maxLogs[t], n, max);
            final short[] norm = new short[max + 1];
            FiniteStateEntropy.normalizeCounts(norm, tableLog, c, n, max);
            final byte[] header = new byte[160];
            final int headerSize = FiniteStateEntropy.writeNormalizedCounts(header, MemoryAccess.BASE, header.length, norm, max, tableLog);
            final double fseCost = ZstdFseEncoder.cost(c, max, norm, max, tableLog) + headerSize * 8;
            if (defaultCost >= 0 && defaultCost <= fseCost) {
                modeOf[t] = Constants.SEQUENCE_ENCODING_BASIC;
                tables[t] = defaultTables[t];
            } else {
                if (p + headerSize > off + limit) return -1;
                modeOf[t] = Constants.SEQUENCE_ENCODING_COMPRESSED;
                System.arraycopy(header, 0, dst, p, headerSize);
                p += headerSize;
                tables[t] = new ZstdFseEncoder(norm, max, tableLog);
            }
        }
        dst[modes] = (byte) ((modeOf[0] << 6) | (modeOf[1] << 4) | (modeOf[2] << 2));
        final ZstdFseEncoder llT = tables[0];
        final ZstdFseEncoder ofT = tables[1];
        final ZstdFseEncoder mlT = tables[2];
        final ZstdBitWriter w = bits;
        w.reset();
        final int last = n - 1;
        int mlState = mlT != null ? mlT.init(mlCodes[last]) : 0;
        int ofState = ofT != null ? ofT.init(ofCodes[last]) : 0;
        int llState = llT != null ? llT.init(llCodes[last]) : 0;
        w.addBits(store.literalLengths[last], Constants.LITERALS_LENGTH_BITS[llCodes[last]]);
        w.addBits(store.matchLengths[last] - 3, Constants.MATCH_LENGTH_BITS[mlCodes[last]]);
        w.addBits(store.offsetValues[last], ofCodes[last]);
        for (int i = n - 2; i >= 0; i--) {
            if (ofT != null) ofState = ofT.encode(w, ofState, ofCodes[i]);
            if (mlT != null) mlState = mlT.encode(w, mlState, mlCodes[i]);
            if (llT != null) llState = llT.encode(w, llState, llCodes[i]);
            w.addBits(store.literalLengths[i], Constants.LITERALS_LENGTH_BITS[llCodes[i]]);
            w.addBits(store.matchLengths[i] - 3, Constants.MATCH_LENGTH_BITS[mlCodes[i]]);
            w.addBits(store.offsetValues[i], ofCodes[i]);
        }
        if (mlT != null) mlT.flush(w, mlState);
        if (ofT != null) ofT.flush(w, ofState);
        if (llT != null) llT.flush(w, llState);
        final int size = w.close();
        if (p + size > off + limit) return -1;
        System.arraycopy(w.buffer(), 0, dst, p, size);
        p += size;
        return p - off;
    }
}
