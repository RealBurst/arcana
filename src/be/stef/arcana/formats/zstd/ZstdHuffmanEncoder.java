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
 * Huffman coding of the literals (RFC 8878, sections 3.1.1.3.1 and 4.2).
 *
 * <p>The code lengths come from a Huffman tree limited to 11 bits. The
 * description written in the block gives a weight per symbol
 * (weight = maxBits + 1 - length, 0 = absent) for every symbol but the last,
 * either as 4-bit values or compressed with FSE (two interleaved states).
 * The codes are assigned like the decoder fills its table: by weight, then by
 * symbol value. Literal streams are written backward: the last literal first,
 * so that the decoder, reading from the end, gets the first literal first.</p>
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdHuffmanEncoder {

    static final int MAX_BITS = 11;
    private static final int MAX_FSE_LOG = 6;

    private final int[] lengths = new int[256];
    private final int[] codes = new int[256];
    private final int[] weights = new int[256];
    private int maxBits;
    private int maxSymbol;

    /** Description of the table, as written in the block (header byte included). */
    private final byte[] description = new byte[256];
    private int descriptionSize;

    /**
     * Builds the code for {@code counts} (at least two symbols used).
     *
     * @return false when the table cannot be described (the caller writes raw literals)
     */
    boolean build(final int[] counts) {
        maxSymbol = 255;
        while (maxSymbol > 0 && counts[maxSymbol] == 0) maxSymbol--;
        final int[] c = Arrays.copyOf(counts, 256);
        while (true) {
            final int max = buildLengths(c, lengths);
            if (max <= MAX_BITS) {
                maxBits = max;
                break;
            }
            for (int s = 0; s < 256; s++) if (c[s] > 0) c[s] = (c[s] + 1) >>> 1;
        }
        for (int s = 0; s < 256; s++) weights[s] = lengths[s] > 0 ? maxBits + 1 - lengths[s] : 0;
        // codes: the decoder fills its table by increasing weight, then by symbol
        int next = 0;
        for (int w = 1; w <= maxBits; w++) {
            for (int s = 0; s <= maxSymbol; s++) {
                if (weights[s] != w) continue;
                codes[s] = next >>> (maxBits - lengths[s]);
                next += 1 << (w - 1);
            }
        }
        return describe();
    }

    /** Huffman code lengths for the used symbols; returns the longest. */
    private static int buildLengths(final int[] counts, final int[] lengths) {
        Arrays.fill(lengths, 0);
        int n = 0;
        final int[] sym = new int[256];
        for (int s = 0; s < 256; s++) if (counts[s] > 0) sym[n++] = s;
        // nodes 0..n-1 are leaves, then internal nodes; two queues (leaves sorted by count, internal nodes in creation order)
        final long[] key = new long[n];
        for (int i = 0; i < n; i++) key[i] = ((long) counts[sym[i]] << 9) | i;
        Arrays.sort(key);
        final int[] leaf = new int[n];
        final long[] weight = new long[2 * n];
        final int[] parent = new int[2 * n];
        for (int i = 0; i < n; i++) {
            leaf[i] = (int) (key[i] & 0x1FF);
            weight[i] = key[i] >>> 9;
        }
        // leaf node i (sorted) -> node index i; internal nodes from n
        int lq = 0;
        int iq = n;
        int next = n;
        for (int k = 0; k < n - 1; k++) {
            final int a;
            if (lq < n && (iq >= next || weight[lq] <= weight[iq])) a = lq++;
            else a = iq++;
            final int b;
            if (lq < n && (iq >= next || weight[lq] <= weight[iq])) b = lq++;
            else b = iq++;
            weight[next] = weight[a] + weight[b];
            parent[a] = next;
            parent[b] = next;
            next++;
        }
        final int root = next - 1;
        final int[] depth = new int[2 * n];
        int max = 0;
        for (int i = root - 1; i >= 0; i--) {
            depth[i] = depth[parent[i]] + 1;
        }
        for (int i = 0; i < n; i++) {
            final int d = depth[i];
            lengths[sym[leaf[i]]] = d;
            if (d > max) max = d;
        }
        return max;
    }

    /** Writes the weights of symbols 0 to maxSymbol - 1, the shorter of the two forms. */
    private boolean describe() {
        final int count = maxSymbol; // the weight of maxSymbol is implied
        int fseSize = -1;
        final byte[] fse = new byte[256];
        if (count >= 2) fseSize = fseWeights(count, fse);
        final int directSize = count <= 128 ? 1 + (count + 1) / 2 : -1;
        if (fseSize > 0 && (directSize < 0 || fseSize + 1 <= directSize)) {
            description[0] = (byte) fseSize;
            System.arraycopy(fse, 0, description, 1, fseSize);
            descriptionSize = fseSize + 1;
            return true;
        }
        if (directSize < 0) return false;
        description[0] = (byte) (127 + count);
        for (int i = 0; i < count; i += 2) {
            final int hi = weights[i];
            final int lo = i + 1 < count ? weights[i + 1] : 0;
            description[1 + i / 2] = (byte) ((hi << 4) | lo);
        }
        descriptionSize = directSize;
        return true;
    }

    /** FSE-compressed weights; returns the size (below 128) or -1. */
    private int fseWeights(final int count, final byte[] out) {
        final int[] wc = new int[MAX_BITS + 1];
        int maxW = 0;
        for (int i = 0; i < count; i++) {
            wc[weights[i]]++;
            if (weights[i] > maxW) maxW = weights[i];
        }
        for (int w = 0; w <= maxW; w++) if (wc[w] == count) return -1; // a single value: FSE cannot describe it
        final int tableLog = FiniteStateEntropy.optimalTableLog(MAX_FSE_LOG, count, maxW);
        final short[] norm = new short[MAX_BITS + 1];
        FiniteStateEntropy.normalizeCounts(norm, tableLog, wc, count, maxW);
        final byte[] header = new byte[64];
        final int headerSize = FiniteStateEntropy.writeNormalizedCounts(header, MemoryAccess.BASE, header.length, norm, maxW, tableLog);
        final ZstdFseEncoder fse = new ZstdFseEncoder(norm, maxW, tableLog);
        final ZstdBitWriter bw = new ZstdBitWriter(256);
        int i = count;
        int state1;
        int state2;
        if ((count & 1) != 0) {
            state1 = fse.init(weights[--i]);
            state2 = fse.init(weights[--i]);
            state1 = fse.encode(bw, state1, weights[--i]);
        } else {
            state2 = fse.init(weights[--i]);
            state1 = fse.init(weights[--i]);
        }
        while (i > 0) {
            state2 = fse.encode(bw, state2, weights[--i]);
            state1 = fse.encode(bw, state1, weights[--i]);
        }
        fse.flush(bw, state2);
        fse.flush(bw, state1);
        final int streamSize = bw.close();
        final int total = headerSize + streamSize;
        if (total >= 128) return -1;
        System.arraycopy(header, 0, out, 0, headerSize);
        System.arraycopy(bw.buffer(), 0, out, headerSize, streamSize);
        return total;
    }

    int descriptionSize() {
        return descriptionSize;
    }

    void writeDescription(final byte[] dst, final int off) {
        System.arraycopy(description, 0, dst, off, descriptionSize);
    }

    /** Size in bytes of {@code n} literals coded with this table, end marks excluded (estimate). */
    long encodedBits(final int[] counts) {
        long bits = 0;
        for (int s = 0; s <= maxSymbol; s++) bits += (long) counts[s] * lengths[s];
        return bits;
    }

    /** Encodes {@code len} literals as one stream; returns its size. */
    int encodeStream(final byte[] src, final int off, final int len, final ZstdBitWriter bw) {
        bw.reset();
        for (int i = off + len - 1; i >= off; i--) {
            final int s = src[i] & 0xFF;
            bw.addBits(codes[s], lengths[s]);
        }
        return bw.close();
    }
}
