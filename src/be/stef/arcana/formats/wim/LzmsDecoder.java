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
package be.stef.arcana.formats.wim;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;

/**
 * Decoder for Microsoft LZMS, the compression of most .esd files and of
 * "solid" WIM resources (one chunk = one independent LZMS block).
 *
 * <p>The format is not documented by Microsoft; this implementation follows
 * the public description of the format (bit streams, item types, adaptive
 * probabilities and Huffman codes, x86 post-filter) and was checked against
 * data written by an independent LZMS encoder.</p>
 *
 * <ul>
 *   <li>The block is read as 16-bit little-endian units from both ends: forwards
 *       for a binary range decoder (item types, 64-entry adaptive
 *       probabilities indexed by the last 4, 5 or 6 bits of their context),
 *       backwards for Huffman symbols and extra bits (most significant bit
 *       first).</li>
 *   <li>Items: literal; LZ match (explicit offset or one of 3 recent offsets);
 *       delta match (power and raw offset, explicit or one of 3 recent pairs).
 *       A newly used offset enters the recent queue one item later.</li>
 *   <li>Five Huffman codes (literals, LZ offsets, lengths, delta offsets, delta
 *       powers) start with all frequencies 1 and are rebuilt every 512 or 1024
 *       symbols, the frequencies being then halved.</li>
 *   <li>After decoding, x86 relative addresses that the encoder made absolute
 *       are converted back.</li>
 * </ul>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class LzmsDecoder {

    // ---- slot tables, built from (extra bits, number of slots) runs -----------
    private static final int[] OFFSET_RUNS = {0, 8, 2, 9, 3, 7, 4, 10, 5, 15, 6, 15, 7, 20, 8, 20, 9, 30, 10, 33, 11, 40, 12, 42, 13, 45, 14, 60, 15, 73, 16, 80, 17, 85, 18, 95, 19, 105, 20, 6, 30, 1};
    private static final int[] LENGTH_RUNS = {0, 26, 1, 4, 2, 6, 3, 4, 4, 5, 5, 2, 6, 1, 7, 1, 8, 1, 9, 1, 10, 1, 16, 1, 30, 1};
    private static final int[] OFFSET_EXTRA = extraBits(OFFSET_RUNS);
    private static final long[] OFFSET_BASE = bases(OFFSET_EXTRA);
    private static final int[] LENGTH_EXTRA = extraBits(LENGTH_RUNS);
    private static final long[] LENGTH_BASE = bases(LENGTH_EXTRA);

    private static final int MAX_CODE_LEN = 15;
    private static final int X86_MAX_TRANSLATION = 1023;
    private static final int X86_ID_WINDOW = 65535;

    private static int[] extraBits(final int[] runs) {
        int n = 0;
        for (int i = 1; i < runs.length; i += 2) n += runs[i];
        final int[] r = new int[n];
        int k = 0;
        for (int i = 0; i < runs.length; i += 2) {
            for (int j = 0; j < runs[i + 1]; j++) r[k++] = runs[i];
        }
        return r;
    }

    private static long[] bases(final int[] extra) {
        final long[] b = new long[extra.length + 1];
        b[0] = 1;
        for (int i = 0; i < extra.length; i++) b[i + 1] = b[i] + (1L << extra[i]);
        return b;
    }

    // ---- input -----------------------------------------------------------------
    private byte[] in;
    private int start;
    private int end;

    // range decoder (forward stream)
    private int range;
    private int code;
    private int fwd;

    // bit reader (backward stream)
    private long bits;
    private int bitCount;
    private int bwd;

    // ---- adaptive probabilities: zero count of the last 64 bits, and those bits ----
    private final int[] zeros = new int[16 + 32 + 64 + 64 + 2 * 64 + 2 * 64];
    private final long[] recent = new long[zeros.length];
    private static final int P_MAIN = 0;
    private static final int P_MATCH = 16;
    private static final int P_LZ = 48;
    private static final int P_DELTA = 112;
    private static final int P_LZ_REP = 176;
    private static final int P_DELTA_REP = 304;

    // ---- adaptive Huffman codes -------------------------------------------------
    private final Code literals = new Code(256, 1024, 10);
    private final Code lengths = new Code(54, 512, 9);
    private final Code deltaPowers = new Code(8, 512, 7);
    private Code lzOffsets;
    private Code deltaOffsets;
    private int offsetSlots = -1;

    private int[] lastTargetUse;

    /**
     * Decompresses one LZMS block.
     *
     * @param src    compressed data
     * @param off    offset of the block in src
     * @param len    length of the block (even, at least 4)
     * @param out    destination
     * @param outLen uncompressed size of the block
     */
    public void decompress(final byte[] src, final int off, final int len, final byte[] out, final int outLen) throws IOException {
        if ((len & 1) != 0 || len < 4) throw new ArcanaCorruptedException("Invalid LZMS block size " + len);
        in = src;
        start = off;
        end = off + len;
        range = 0xFFFFFFFF;
        code = u16(off) << 16 | u16(off + 2);
        fwd = off + 4;
        bits = 0;
        bitCount = 0;
        bwd = end;
        for (int i = 0; i < zeros.length; i++) {
            zeros[i] = 48;
            recent[i] = 0x0000000055555555L;
        }
        final int slots = outLen < 2 ? 0 : slotOf(OFFSET_BASE, outLen - 1) + 1;
        if (slots != offsetSlots) {
            lzOffsets = new Code(slots, 1024, 11);
            deltaOffsets = new Code(slots, 1024, 11);
            offsetSlots = slots;
        }
        literals.reset();
        lengths.reset();
        deltaPowers.reset();
        lzOffsets.reset();
        deltaOffsets.reset();
        decodeItems(out, outLen);
        undoX86(out, outLen);
    }

    private void decodeItems(final byte[] out, final int outLen) throws IOException {
        // recent LZ offsets and delta (power, raw offset) pairs; a used value is
        // "pending" and enters the front of its queue after the next item
        final long[] lzq = {1, 2, 3, 4};
        final long[] dq = {1, 2, 3, 4};
        long lzPending = -1;
        long dPending = -1;
        int sMain = 0;
        int sMatch = 0;
        int sLz = 0;
        int sDelta = 0;
        final int[] sLzRep = new int[2];
        final int[] sDeltaRep = new int[2];
        int pos = 0;
        while (pos < outLen) {
            long newLz = -1;
            long newDelta = -1;
            int bit = bit(P_MAIN + sMain);
            sMain = (sMain << 1 | bit) & 15;
            if (bit == 0) {
                out[pos++] = (byte) literals.decode();
            } else {
                bit = bit(P_MATCH + sMatch);
                sMatch = (sMatch << 1 | bit) & 31;
                if (bit == 0) {
                    // LZ match
                    long offset;
                    bit = bit(P_LZ + sLz);
                    sLz = (sLz << 1 | bit) & 63;
                    if (bit == 0) {
                        offset = readOffset(lzOffsets);
                    } else {
                        final int rep = repIndex(P_LZ_REP, sLzRep);
                        offset = take(lzq, rep);
                    }
                    newLz = offset;
                    final long length = readLength();
                    if (offset > pos || length > outLen - pos) throw new ArcanaCorruptedException("Invalid LZMS match");
                    int from = pos - (int) offset;
                    for (int n = (int) length; n > 0; n--) out[pos++] = out[from++];
                } else {
                    // delta match
                    long pair;
                    bit = bit(P_DELTA + sDelta);
                    sDelta = (sDelta << 1 | bit) & 63;
                    if (bit == 0) {
                        final int power = deltaPowers.decode();
                        final long raw = readOffset(deltaOffsets);
                        pair = (long) power << 32 | raw;
                    } else {
                        final int rep = repIndex(P_DELTA_REP, sDeltaRep);
                        pair = take(dq, rep);
                    }
                    newDelta = pair;
                    final long length = readLength();
                    final int power = (int) (pair >>> 32);
                    final long raw = pair & 0xFFFFFFFFL;
                    final long span = 1L << power;
                    final long offset = raw << power;
                    if (power > 7 || offset + span > pos || length > outLen - pos) throw new ArcanaCorruptedException("Invalid LZMS delta match");
                    int a = pos - (int) offset;
                    final int sp = (int) span;
                    for (int n = (int) length; n > 0; n--) {
                        out[pos] = (byte) (out[a] + out[pos - sp] - out[a - sp]);
                        pos++;
                        a++;
                    }
                }
            }
            if (lzPending >= 0) push(lzq, lzPending);
            if (dPending >= 0) push(dq, dPending);
            lzPending = newLz;
            dPending = newDelta;
        }
    }

    /** Index (0-2) of a recent offset: up to two range-coded decisions. */
    private int repIndex(final int base, final int[] states) {
        int b = bit(base + states[0]);
        states[0] = (states[0] << 1 | b) & 63;
        if (b == 0) return 0;
        b = bit(base + 64 + states[1]);
        states[1] = (states[1] << 1 | b) & 63;
        return b == 0 ? 1 : 2;
    }

    /** Removes entry i of a recent queue (the following entries move up) and returns it. */
    private static long take(final long[] q, final int i) {
        final long v = q[i];
        for (int k = i; k < q.length - 1; k++) q[k] = q[k + 1];
        return v;
    }

    /** Inserts at the front of a recent queue, dropping the last entry. */
    private static void push(final long[] q, final long v) {
        for (int k = q.length - 1; k > 0; k--) q[k] = q[k - 1];
        q[0] = v;
    }

    private long readOffset(final Code c) throws IOException {
        if (c.size == 0) throw new ArcanaCorruptedException("Invalid LZMS match");
        final int slot = c.decode();
        return OFFSET_BASE[slot] + readBits(OFFSET_EXTRA[slot]);
    }

    private long readLength() throws IOException {
        final int slot = lengths.decode();
        final int e = LENGTH_EXTRA[slot];
        return LENGTH_BASE[slot] + (e == 0 ? 0 : readBits(e));
    }

    private static int slotOf(final long[] base, final long v) {
        int lo = 0;
        int hi = base.length - 2;
        while (lo < hi) {
            final int mid = (lo + hi + 1) >>> 1;
            if (base[mid] <= v) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    // =========================================================================
    // Range decoder
    // =========================================================================

    private int bit(final int p) {
        int prob = zeros[p];
        if (prob == 0) prob = 1;
        else if (prob == 64) prob = 63;
        if ((range & 0xFFFF0000) == 0) {
            range <<= 16;
            code <<= 16;
            if (fwd < end) {
                code |= u16(fwd);
                fwd += 2;
            }
        }
        final int bound = (range >>> 6) * prob;
        final int b;
        if (Integer.compareUnsigned(code, bound) < 0) {
            range = bound;
            b = 0;
        } else {
            range -= bound;
            code -= bound;
            b = 1;
        }
        // the bit leaving the 64-bit history and the new bit update the zero count
        final long r = recent[p];
        if (r >= 0) zeros[p]--; // oldest bit was 0
        if (b == 0) zeros[p]++;
        recent[p] = r << 1 | b;
        return b;
    }

    // =========================================================================
    // Backward bit reader
    // =========================================================================

    private void need(final int n) {
        while (bitCount < n) {
            int w = 0;
            if (bwd - 2 >= start) {
                bwd -= 2;
                w = u16(bwd);
            }
            bits = bits << 16 | w;
            bitCount += 16;
        }
    }

    private long readBits(final int n) {
        if (n == 0) return 0;
        need(n);
        bitCount -= n;
        return (bits >>> bitCount) & ((1L << n) - 1);
    }

    private int u16(final int p) {
        return (in[p] & 0xff) | (in[p + 1] & 0xff) << 8;
    }

    // =========================================================================
    // Adaptive Huffman code
    // =========================================================================

    private final class Code {
        final int size;
        private final int rebuildEvery;
        private final int tableBits;
        private final int[] freq;
        private final int[] table;          // symbol << 4 | length, or -1 for longer codes
        private final int[] first = new int[MAX_CODE_LEN + 2];
        private final int[] count = new int[MAX_CODE_LEN + 1];
        private final int[] index = new int[MAX_CODE_LEN + 1];
        private final int[] sorted;         // symbols by (length, symbol)
        private final int[] lens;
        private int untilRebuild;

        Code(final int size, final int rebuildEvery, final int tableBits) {
            this.size = size;
            this.rebuildEvery = rebuildEvery;
            this.tableBits = tableBits;
            this.freq = new int[size];
            this.table = new int[1 << tableBits];
            this.sorted = new int[size];
            this.lens = new int[size];
        }

        void reset() {
            for (int i = 0; i < size; i++) freq[i] = 1;
            if (size > 0) build();
        }

        int decode() throws IOException {
            need(MAX_CODE_LEN);
            final int v = (int) (bits >>> (bitCount - MAX_CODE_LEN)) & 0x7FFF;
            int sym;
            int len;
            final int t = table[v >>> (MAX_CODE_LEN - tableBits)];
            if (t >= 0) {
                sym = t >>> 4;
                len = t & 15;
            } else {
                sym = -1;
                len = tableBits + 1;
                for (; len <= MAX_CODE_LEN; len++) {
                    final int c = v >>> (MAX_CODE_LEN - len);
                    final int k = c - first[len];
                    if (k >= 0 && k < count[len]) {
                        sym = sorted[index[len] + k];
                        break;
                    }
                }
                if (sym < 0) throw new ArcanaCorruptedException("Invalid LZMS Huffman code");
            }
            bitCount -= len;
            freq[sym]++;
            if (--untilRebuild == 0) {
                build();
                for (int i = 0; i < size; i++) freq[i] = (freq[i] >>> 1) + 1;
            }
            return sym;
        }

        /**
         * Canonical code from the frequencies: Huffman tree built from the
         * symbols sorted by (frequency, symbol), ties going to leaves; lengths
         * limited to 15 bits; longest codes to the first sorted symbols.
         */
        private void build() {
            untilRebuild = rebuildEvery;
            final int n = size;
            // sort symbols by frequency then symbol value
            final long[] keys = new long[n];
            for (int s = 0; s < n; s++) keys[s] = (long) freq[s] << 32 | s;
            java.util.Arrays.sort(keys);
            final int[] lenCount = new int[MAX_CODE_LEN + 2];
            if (n == 1) {
                lenCount[1] = 1;
            } else {
                // two-queue Huffman construction; only the parents of internal nodes are kept
                final long[] nodeFreq = new long[n - 1];
                final int[] parent = new int[n - 1];
                int leaf = 0;
                int nodeHead = 0;
                for (int e = 0; e < n - 1; e++) {
                    long f = 0;
                    for (int pick = 0; pick < 2; pick++) {
                        final boolean useLeaf = leaf < n && (nodeHead == e || (keys[leaf] >>> 32) <= nodeFreq[nodeHead]);
                        if (useLeaf) {
                            f += keys[leaf++] >>> 32;
                        } else {
                            f += nodeFreq[nodeHead];
                            parent[nodeHead++] = e;
                        }
                    }
                    nodeFreq[e] = f;
                }
                // depths of internal nodes from the root (last created) down; count leaves per length
                final int root = n - 2;
                final int[] depth = new int[n - 1];
                lenCount[1] = 2;
                for (int node = root - 1; node >= 0; node--) {
                    depth[node] = depth[parent[node]] + 1;
                    int l = depth[node];
                    if (l >= MAX_CODE_LEN) {
                        l = MAX_CODE_LEN;
                        do {
                            l--;
                        } while (lenCount[l] == 0);
                    }
                    lenCount[l]--;
                    lenCount[l + 1] += 2;
                }
            }
            // lengths: longest first, to the symbols in sorted order
            int k = 0;
            for (int l = MAX_CODE_LEN; l >= 1; l--) {
                for (int c = lenCount[l]; c > 0; c--) lens[(int) keys[k++]] = l;
            }
            // canonical codes
            int c = 0;
            int idx = 0;
            for (int l = 1; l <= MAX_CODE_LEN; l++) {
                count[l] = lenCount[l];
                first[l] = c;
                index[l] = idx;
                idx += count[l];
                c = (c + count[l]) << 1;
            }
            final int[] fill = new int[MAX_CODE_LEN + 1];
            for (int s = 0; s < n; s++) {
                final int l = lens[s];
                sorted[index[l] + fill[l]++] = s;
            }
            java.util.Arrays.fill(table, -1);
            for (int l = 1; l <= tableBits; l++) {
                for (int j = 0; j < count[l]; j++) {
                    final int s = sorted[index[l] + j];
                    final int cw = first[l] + j;
                    final int lo = cw << (tableBits - l);
                    final int hi = lo + (1 << (tableBits - l));
                    for (int t = lo; t < hi; t++) table[t] = s << 4 | l;
                }
            }
        }
    }

    // =========================================================================
    // x86 post-filter
    // =========================================================================

    /**
     * Converts back the relative addresses of CALL (E8), RIP-relative LEA/MOV
     * (48/4C 8D or 8B with ModR/M xx000101), "lock add" (F0 83 05) and "call
     * indirect" (FF 15) that the encoder made absolute, in the regions that
     * look like x86 code: two uses of the same 16-bit target within 64 KiB
     * mark a likely instruction, which enables conversions for the next 1023
     * bytes (511 for E8).
     */
    private void undoX86(final byte[] d, final int size) {
        if (size <= 17) return;
        if (lastTargetUse == null) lastTargetUse = new int[65536];
        java.util.Arrays.fill(lastTargetUse, -X86_ID_WINDOW - 1);
        int lastX86 = -X86_MAX_TRANSLATION - 1;
        final int limit = size - 16;
        int i = 1; // the first byte is never an opcode
        while (i < limit) {
            final int op = d[i] & 0xff;
            int opLen = 0;
            int maxTrans = X86_MAX_TRANSLATION;
            if (op == 0xE8) {
                opLen = 1;
                maxTrans >>= 1;
            } else if (op == 0xE9) {
                i += 5; // relative jumps are not converted
                continue;
            } else if (op == 0xFF) {
                if ((d[i + 1] & 0xff) == 0x15) opLen = 2;
            } else if (op == 0xF0) {
                if ((d[i + 1] & 0xff) == 0x83 && (d[i + 2] & 0xff) == 0x05) opLen = 3;
            } else if (op == 0x48 || op == 0x4C) {
                final int op2 = d[i + 1] & 0xff;
                final int modrm = d[i + 2] & 0xff;
                if ((modrm & 0x07) == 0x05 && (op2 == 0x8D || (op2 == 0x8B && (op & 0x04) == 0 && (modrm & 0xF0) == 0))) opLen = 3;
            }
            if (opLen == 0) {
                i++;
                continue;
            }
            final int p = i + opLen;
            if (i - lastX86 <= maxTrans) {
                final int v = le32(d, p) - i;
                d[p] = (byte) v;
                d[p + 1] = (byte) (v >> 8);
                d[p + 2] = (byte) (v >> 16);
                d[p + 3] = (byte) (v >> 24);
            }
            final int target = (i + ((d[p] & 0xff) | (d[p + 1] & 0xff) << 8)) & 0xFFFF;
            final int last = i + opLen + 3;
            if (last - lastTargetUse[target] <= X86_ID_WINDOW) lastX86 = last;
            lastTargetUse[target] = last;
            i = p + 4;
        }
    }

    private static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }
}
