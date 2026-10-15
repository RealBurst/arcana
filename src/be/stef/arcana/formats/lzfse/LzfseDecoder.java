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
package be.stef.arcana.formats.lzfse;

import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * LZFSE decoder (Apple's LZ77 + finite state entropy codec: ULFO disk images,
 * HFS+ / APFS transparent compression), written from the description of the
 * format given by Apple's reference implementation (github.com/lzfse/lzfse,
 * BSD-3-Clause, Copyright (c) 2015-2016 Apple Inc.; no code copied).
 *
 * <p>A stream is a list of blocks, each starting with a 4-byte little-endian
 * magic:</p>
 * <ul>
 * <li>"bvx-": uncompressed block (raw size, then the bytes);</li>
 * <li>"bvxn": LZVN block (raw size, payload size, then {@link LzvnDecoder} data);</li>
 * <li>"bvx1" / "bvx2": LZFSE block, with the frequency tables stored as plain
 *     16-bit values (v1) or packed with a variable-length code (v2);</li>
 * <li>"bvx$": end of stream.</li>
 * </ul>
 *
 * <p>An LZFSE block holds up to 40000 literals, coded with 4 interleaved FSE
 * states (1024 states, 256 symbols), then up to 10000 (L, M, D) triplets
 * (literal count, match length, match distance; 64, 64 and 256 states) coded
 * with FSE "value" tables: each symbol gives a base value and a number of
 * extra bits. Both payloads are bit streams read backwards from their end, the
 * first bits of the last 8 bytes being skipped as told by the header. D = 0
 * reuses the previous distance.</p>
 *
 * @author Stef
 * @since 1.5
 */
public final class LzfseDecoder {

    private static final int MAGIC_END = 0x24787662; // "bvx$"
    private static final int MAGIC_RAW = 0x2d787662; // "bvx-"
    private static final int MAGIC_V1 = 0x31787662; // "bvx1"
    private static final int MAGIC_V2 = 0x32787662; // "bvx2"
    private static final int MAGIC_LZVN = 0x6e787662; // "bvxn"

    private static final int L_SYMBOLS = 20;
    private static final int M_SYMBOLS = 20;
    private static final int D_SYMBOLS = 64;
    private static final int LITERAL_SYMBOLS = 256;
    private static final int L_STATES = 64;
    private static final int M_STATES = 64;
    private static final int D_STATES = 256;
    private static final int LITERAL_STATES = 1024;
    private static final int MATCHES_PER_BLOCK = 10000;
    private static final int LITERALS_PER_BLOCK = 4 * MATCHES_PER_BLOCK;
    private static final int V1_HEADER_SIZE = 772;

    private static final int[] L_EXTRA_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8};
    private static final int[] L_BASE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60};
    private static final int[] M_EXTRA_BITS = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11};
    private static final int[] M_BASE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312};
    private static final int[] D_EXTRA_BITS = new int[D_SYMBOLS];
    private static final int[] D_BASE = new int[D_SYMBOLS];

    static {
        // D symbols: 4 values per bit count (0, 0, 0, 0, 1, 1, 1, 1, ..., 15), base values in sequence
        int base = 0;
        for (int i = 0; i < D_SYMBOLS; i++) {
            D_EXTRA_BITS[i] = i / 4;
            D_BASE[i] = base;
            base += 1 << D_EXTRA_BITS[i];
        }
    }

    private LzfseDecoder() {
    }

    /**
     * Decodes the LZFSE stream src[srcOff, srcOff + srcLen) into
     * dst[dstOff, dstOff + dstLen).
     *
     * @return the number of bytes written
     * @throws ArcanaCorruptedException on invalid or truncated data, or an
     *         output larger than dstLen
     */
    public static int decode(final byte[] src, final int srcOff, final int srcLen, final byte[] dst, final int dstOff, final int dstLen) throws ArcanaCorruptedException {
        try {
            return run(src, srcOff, srcOff + srcLen, dst, dstOff, dstOff + dstLen);
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new ArcanaCorruptedException("Corrupted LZFSE data", e);
        }
    }

    private static int run(final byte[] src, final int srcOff, final int srcEnd, final byte[] dst, final int dstBegin, final int dstEnd) throws ArcanaCorruptedException {
        int sp = srcOff;
        int dp = dstBegin;
        Block block = null;
        while (true) {
            if (srcEnd - sp < 4) throw new ArcanaCorruptedException("LZFSE stream truncated (no end-of-stream block)");
            final int magic = le32(src, sp);
            if (magic == MAGIC_END) {
                return dp - dstBegin;
            } else if (magic == MAGIC_RAW) {
                if (srcEnd - sp < 8) throw new ArcanaCorruptedException("LZFSE stream truncated");
                final int n = le32(src, sp + 4);
                sp += 8;
                if (n < 0 || n > srcEnd - sp) throw new ArcanaCorruptedException("LZFSE raw block truncated");
                if (n > dstEnd - dp) throw new ArcanaCorruptedException("LZFSE output larger than expected");
                System.arraycopy(src, sp, dst, dp, n);
                sp += n;
                dp += n;
            } else if (magic == MAGIC_LZVN) {
                if (srcEnd - sp < 12) throw new ArcanaCorruptedException("LZFSE stream truncated");
                final int raw = le32(src, sp + 4);
                final int payload = le32(src, sp + 8);
                sp += 12;
                if (payload < 0 || payload > srcEnd - sp) throw new ArcanaCorruptedException("LZVN block truncated");
                if (raw < 0 || raw > dstEnd - dp) throw new ArcanaCorruptedException("LZFSE output larger than expected");
                final int end = LzvnDecoder.decode(src, sp, sp + payload, dst, dstBegin, dp, dp + raw);
                if (end != dp + raw) throw new ArcanaCorruptedException("LZVN block shorter than its size");
                dp = end;
                sp += payload;
            } else if (magic == MAGIC_V1 || magic == MAGIC_V2) {
                if (block == null) block = new Block();
                sp = block.header(src, sp, srcEnd, magic == MAGIC_V2);
                dp = block.decode(src, sp, dst, dstBegin, dp, dstEnd);
                sp += block.nLiteralPayload + block.nLmdPayload;
            } else {
                throw new ArcanaCorruptedException("Invalid LZFSE block magic 0x" + Integer.toHexString(magic));
            }
        }
    }

    /** State of one compressed block (tables reused from block to block). */
    private static final class Block {
        int nLiterals;
        int nMatches;
        int nLiteralPayload;
        int nLmdPayload;
        int literalBits;
        int lmdBits;
        final int[] literalState = new int[4];
        int lState;
        int mState;
        int dState;
        final int[] freq = new int[L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS];
        final int[] literalTable = new int[LITERAL_STATES];
        final ValueTable lTable = new ValueTable(L_STATES);
        final ValueTable mTable = new ValueTable(M_STATES);
        final ValueTable dTable = new ValueTable(D_STATES);
        final byte[] literals = new byte[LITERALS_PER_BLOCK + 64];

        /** Reads the block header at sp; returns the position of the literal payload. */
        int header(final byte[] src, final int sp, final int srcEnd, final boolean v2) throws ArcanaCorruptedException {
            int headerSize;
            if (v2) {
                if (srcEnd - sp < 32) throw new ArcanaCorruptedException("LZFSE block header truncated");
                final long v0 = le64(src, sp + 8);
                final long v1 = le64(src, sp + 16);
                final long w2 = le64(src, sp + 24);
                nLiterals = field(v0, 0, 20);
                nLiteralPayload = field(v0, 20, 20);
                nMatches = field(v0, 40, 20);
                literalBits = field(v0, 60, 3) - 7;
                literalState[0] = field(v1, 0, 10);
                literalState[1] = field(v1, 10, 10);
                literalState[2] = field(v1, 20, 10);
                literalState[3] = field(v1, 30, 10);
                nLmdPayload = field(v1, 40, 20);
                lmdBits = field(v1, 60, 3) - 7;
                headerSize = (int) w2;
                lState = field(w2, 32, 10);
                mState = field(w2, 42, 10);
                dState = field(w2, 52, 10);
                if (headerSize < 32 || headerSize > srcEnd - sp) throw new ArcanaCorruptedException("LZFSE block header truncated");
                readPackedFrequencies(src, sp + 32, sp + headerSize);
            } else {
                headerSize = V1_HEADER_SIZE;
                if (srcEnd - sp < headerSize) throw new ArcanaCorruptedException("LZFSE block header truncated");
                nLiterals = le32(src, sp + 12);
                nMatches = le32(src, sp + 16);
                nLiteralPayload = le32(src, sp + 20);
                nLmdPayload = le32(src, sp + 24);
                literalBits = le32(src, sp + 28);
                for (int i = 0; i < 4; i++) literalState[i] = le16(src, sp + 32 + 2 * i);
                lmdBits = le32(src, sp + 40);
                lState = le16(src, sp + 44);
                mState = le16(src, sp + 46);
                dState = le16(src, sp + 48);
                for (int i = 0; i < freq.length; i++) freq[i] = le16(src, sp + 50 + 2 * i);
            }
            if (nLiterals < 0 || nLiterals > LITERALS_PER_BLOCK || nMatches < 0 || nMatches > MATCHES_PER_BLOCK || (nLiterals & 3) != 0) throw new ArcanaCorruptedException("Invalid LZFSE block header");
            for (int i = 0; i < 4; i++) if (literalState[i] < 0 || literalState[i] >= LITERAL_STATES) throw new ArcanaCorruptedException("Invalid LZFSE block header");
            if (lState >= L_STATES || mState >= M_STATES || dState >= D_STATES || lState < 0 || mState < 0 || dState < 0) throw new ArcanaCorruptedException("Invalid LZFSE block header");
            final int start = sp + headerSize;
            if (nLiteralPayload < 0 || nLmdPayload < 0 || (long) nLiteralPayload + nLmdPayload > srcEnd - start) throw new ArcanaCorruptedException("LZFSE block truncated");
            int off = 0;
            initValueTable(lTable, L_STATES, off, L_SYMBOLS, L_EXTRA_BITS, L_BASE);
            off += L_SYMBOLS;
            initValueTable(mTable, M_STATES, off, M_SYMBOLS, M_EXTRA_BITS, M_BASE);
            off += M_SYMBOLS;
            initValueTable(dTable, D_STATES, off, D_SYMBOLS, D_EXTRA_BITS, D_BASE);
            off += D_SYMBOLS;
            initLiteralTable(off);
            return start;
        }

        /** v2 frequency tables: a prefix code read LSB first (2, 3, 5, 8 or 14 bits per value). */
        private void readPackedFrequencies(final byte[] src, int pos, final int end) throws ArcanaCorruptedException {
            if (pos == end) {
                java.util.Arrays.fill(freq, 0);
                return;
            }
            int accum = 0;
            int bits = 0;
            for (int i = 0; i < freq.length; i++) {
                while (pos < end && bits + 8 <= 32) {
                    accum |= (src[pos++] & 0xff) << bits;
                    bits += 8;
                }
                final int b = accum & 31;
                int n;
                int value;
                if ((b & 1) == 0) {
                    n = 2;
                    value = (b >>> 1) & 1; // xx0: 0 or 1
                } else if ((b & 3) == 1) {
                    n = 3;
                    value = 2 + ((b >>> 2) & 1); // x01: 2 or 3
                } else if ((b & 7) == 3) {
                    n = 5;
                    value = 4 + ((b >>> 3) & 3); // xx011: 4 to 7
                } else if ((b & 15) == 7) {
                    n = 8;
                    value = 8 + ((accum >>> 4) & 0xf); // 0111 + 4 bits: 8 to 23
                } else {
                    n = 14;
                    value = 24 + ((accum >>> 4) & 0x3ff); // 1111 + 10 bits: 24 to 1047
                }
                if (n > bits) throw new ArcanaCorruptedException("Invalid LZFSE frequency table");
                freq[i] = value;
                accum >>>= n;
                bits -= n;
            }
            if (bits >= 8 || pos != end) throw new ArcanaCorruptedException("Invalid LZFSE frequency table");
        }

        private void initLiteralTable(final int off) throws ArcanaCorruptedException {
            java.util.Arrays.fill(literalTable, 0);
            final int nClz = Integer.numberOfLeadingZeros(LITERAL_STATES);
            int sum = 0;
            int t = 0;
            for (int s = 0; s < LITERAL_SYMBOLS; s++) {
                final int f = freq[off + s];
                if (f == 0) continue;
                sum += f;
                if (sum > LITERAL_STATES) throw new ArcanaCorruptedException("Invalid LZFSE literal frequencies");
                final int k = Integer.numberOfLeadingZeros(f) - nClz;
                final int j0 = ((2 * LITERAL_STATES) >> k) - f;
                for (int j = 0; j < f; j++) {
                    final int bits;
                    final int delta;
                    if (j < j0) {
                        bits = k;
                        delta = ((f + j) << k) - LITERAL_STATES;
                    } else {
                        bits = k - 1;
                        delta = (j - j0) << (k - 1);
                    }
                    literalTable[t++] = bits | s << 8 | delta << 16;
                }
            }
        }

        private void initValueTable(final ValueTable vt, final int nStates, final int off, final int nSymbols, final int[] extraBits, final int[] base) throws ArcanaCorruptedException {
            vt.clear();
            final int nClz = Integer.numberOfLeadingZeros(nStates);
            int sum = 0;
            int t = 0;
            for (int s = 0; s < nSymbols; s++) {
                final int f = freq[off + s];
                if (f == 0) continue;
                sum += f;
                if (sum > nStates) throw new ArcanaCorruptedException("Invalid LZFSE L/M/D frequencies");
                final int k = Integer.numberOfLeadingZeros(f) - nClz;
                final int j0 = ((2 * nStates) >> k) - f;
                for (int j = 0; j < f; j++) {
                    if (j < j0) {
                        vt.totalBits[t] = k + extraBits[s];
                        vt.delta[t] = ((f + j) << k) - nStates;
                    } else {
                        vt.totalBits[t] = k - 1 + extraBits[s];
                        vt.delta[t] = (j - j0) << (k - 1);
                    }
                    vt.valueBits[t] = extraBits[s];
                    vt.base[t] = base[s];
                    t++;
                }
            }
        }

        /** Decodes the literals then executes the L, M, D triplets; returns the new output position. */
        int decode(final byte[] src, final int litStart, final byte[] dst, final int dstBegin, int dp, final int dstEnd) throws ArcanaCorruptedException {
            // literals: the reference decoder may refill from any byte before the payload end
            final BitReader lit = new BitReader(src, 0, litStart + nLiteralPayload, literalBits);
            int s0 = literalState[0];
            int s1 = literalState[1];
            int s2 = literalState[2];
            int s3 = literalState[3];
            for (int i = 0; i < nLiterals; i += 4) {
                lit.refill();
                int e = literalTable[s0];
                literals[i] = (byte) (e >>> 8);
                s0 = (e >> 16) + (int) lit.pull(e & 0xff);
                e = literalTable[s1];
                literals[i + 1] = (byte) (e >>> 8);
                s1 = (e >> 16) + (int) lit.pull(e & 0xff);
                e = literalTable[s2];
                literals[i + 2] = (byte) (e >>> 8);
                s2 = (e >> 16) + (int) lit.pull(e & 0xff);
                e = literalTable[s3];
                literals[i + 3] = (byte) (e >>> 8);
                s3 = (e >> 16) + (int) lit.pull(e & 0xff);
            }
            // L, M, D triplets
            final int lmdStart = litStart + nLiteralPayload;
            final BitReader in = new BitReader(src, lmdStart, lmdStart + nLmdPayload, lmdBits);
            int ls = lState;
            int ms = mState;
            int ds = dState;
            int d = -1;
            int litPos = 0;
            for (int n = 0; n < nMatches; n++) {
                in.refill();
                long bits = in.pull(lTable.totalBits[ls]);
                final int l = lTable.base[ls] + (int) (bits & ((1L << lTable.valueBits[ls]) - 1));
                ls = lTable.delta[ls] + (int) (bits >>> lTable.valueBits[ls]);
                bits = in.pull(mTable.totalBits[ms]);
                final int m = mTable.base[ms] + (int) (bits & ((1L << mTable.valueBits[ms]) - 1));
                ms = mTable.delta[ms] + (int) (bits >>> mTable.valueBits[ms]);
                bits = in.pull(dTable.totalBits[ds]);
                final int newD = dTable.base[ds] + (int) (bits & ((1L << dTable.valueBits[ds]) - 1));
                ds = dTable.delta[ds] + (int) (bits >>> dTable.valueBits[ds]);
                if (newD != 0) d = newD;
                if (l > nLiterals - litPos) throw new ArcanaCorruptedException("Invalid LZFSE literal count");
                if (l + m > dstEnd - dp) throw new ArcanaCorruptedException("LZFSE output larger than expected");
                if (d < 0 || (m > 0 && (d == 0 || d > dp + l - dstBegin))) throw new ArcanaCorruptedException("Invalid LZFSE match distance");
                System.arraycopy(literals, litPos, dst, dp, l);
                litPos += l;
                dp += l;
                for (int i = 0; i < m; i++) dst[dp + i] = dst[dp + i - d];
                dp += m;
            }
            return dp;
        }
    }

    /** Decoding table of a value (L, M or D) stream. */
    private static final class ValueTable {
        final int[] totalBits;
        final int[] valueBits;
        final int[] delta;
        final int[] base;

        ValueTable(final int n) {
            totalBits = new int[n];
            valueBits = new int[n];
            delta = new int[n];
            base = new int[n];
        }

        void clear() {
            java.util.Arrays.fill(totalBits, 0);
            java.util.Arrays.fill(valueBits, 0);
            java.util.Arrays.fill(delta, 0);
            java.util.Arrays.fill(base, 0);
        }
    }

    /**
     * Backward bit stream: bytes are taken from the end towards the start
     * (little-endian groups), bits are pulled from the most significant end of
     * a 64-bit accumulator.
     */
    private static final class BitReader {
        private final byte[] src;
        private final int start;
        private int pos;
        private long accum;
        private int count;

        BitReader(final byte[] src, final int start, final int end, final int extraBits) throws ArcanaCorruptedException {
            this.src = src;
            this.start = start;
            if (extraBits < -7 || extraBits > 0) throw new ArcanaCorruptedException("Invalid LZFSE bit stream header");
            final int n = extraBits != 0 ? 8 : 7;
            if (end - n < start) throw new ArcanaCorruptedException("LZFSE bit stream truncated");
            pos = end - n;
            accum = load(pos, n);
            count = extraBits != 0 ? 64 + extraBits : 56;
            if ((accum >>> count) != 0 && count < 64) throw new ArcanaCorruptedException("Invalid LZFSE bit stream");
        }

        private long load(final int at, final int n) {
            long v = 0;
            for (int i = n - 1; i >= 0; i--) v = v << 8 | (src[at + i] & 0xffL);
            return v;
        }

        /** Loads whole bytes until the accumulator holds at least 56 bits. */
        void refill() throws ArcanaCorruptedException {
            final int nBits = (63 - count) & -8;
            if (nBits == 0) return;
            final int n = nBits >>> 3;
            if (pos - n < start) throw new ArcanaCorruptedException("LZFSE bit stream truncated");
            pos -= n;
            accum = accum << nBits | load(pos, n);
            count += nBits;
        }

        long pull(final int n) throws ArcanaCorruptedException {
            if (n == 0) return 0;
            if (n > count) throw new ArcanaCorruptedException("LZFSE bit stream exhausted");
            count -= n;
            final long r = accum >>> count;
            accum &= (1L << count) - 1;
            return r;
        }
    }

    private static int field(final long v, final int offset, final int bits) {
        return (int) ((v >>> offset) & ((1L << bits) - 1));
    }

    private static int le16(final byte[] b, final int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8;
    }

    private static int le32(final byte[] b, final int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8 | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    private static long le64(final byte[] b, final int off) {
        return (le32(b, off) & 0xffffffffL) | (long) le32(b, off + 4) << 32;
    }
}
