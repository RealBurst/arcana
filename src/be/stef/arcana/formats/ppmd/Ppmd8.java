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
package be.stef.arcana.formats.ppmd;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * PPMd variant I revision 2 (PPMd8) model and decoder, as used by ZIP
 * (compression method 98).
 *
 * <p>Java port of Ppmd8.c and Ppmd8Dec.c by Igor Pavlov (public domain),
 * based on PPMd var.I (2002) by Dmitry Shkarin and on the carry-less range
 * coder (1999) by Dmitry Subbotin (both public domain). As in {@link Ppmd7},
 * the model lives in one {@code byte[]} heap with the same layout and the same
 * allocation decisions as the C code, so that the decoder rebuilds exactly the
 * model of the encoder.</p>
 *
 * <p>Heap records (little-endian):</p>
 * <ul>
 *   <li>State (6 bytes): Symbol(1) Freq(1) Successor(4)</li>
 *   <li>Context (12 bytes): NumStats(1, number of symbols - 1) Flags(1)
 *       SummFreq(2) Stats(4) Suffix(4); a context with one symbol stores its
 *       State inline at offset 2</li>
 *   <li>Free-list node (12 bytes): Stamp(4) Next(4) NU(4)</li>
 * </ul>
 *
 * <p>Restore methods: 0 (restart) and 1 (cut off). The "freeze" method (2) is
 * not supported, like in 7-Zip.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public final class Ppmd8 {

    public static final int MIN_ORDER = 2;
    public static final int MAX_ORDER = 16;
    public static final int RESTORE_RESTART = 0;
    public static final int RESTORE_CUT_OFF = 1;

    /** Value returned by {@link #decodeSymbol()} at the end mark. */
    public static final int SYM_END = -1;
    /** Value returned by {@link #decodeSymbol()} on corrupted data. */
    public static final int SYM_ERROR = -2;

    private static final int INT_BITS = 7;
    private static final int PERIOD_BITS = 7;
    private static final int BIN_SCALE = 1 << (INT_BITS + PERIOD_BITS);
    private static final int N1 = 4;
    private static final int N2 = 4;
    private static final int N3 = 4;
    private static final int N4 = (128 + 3 - 1 * N1 - 2 * N2 - 3 * N3) / 4;
    private static final int NUM_INDEXES = N1 + N2 + N3 + N4;
    private static final int MAX_FREQ = 124;
    private static final int UNIT_SIZE = 12;
    private static final int EMPTY_NODE = 0xFFFFFFFF;
    private static final int FLAG_RESCALED = 1 << 2;
    private static final int FLAG_PREV_HIGH = 1 << 4;
    private static final long TOP = 1L << 24;
    private static final long BOT = 1L << 15;

    private static final int[] EXP_ESCAPE = {25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2};
    private static final int[] INIT_BIN_ESC = {0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051};

    // ---- model state (offsets in mem) ----
    private int minContext;
    private int maxContext;
    private int foundState;
    private int orderFall;
    private int initEsc;
    private int prevSuccess;
    private int maxOrder;
    private int restoreMethod;
    private int runLength;
    private int initRL;
    private final int size;
    private int glueCount;
    private final int alignOffset;
    private final byte[] mem;
    private int loUnit;
    private int hiUnit;
    private int text;
    private int unitsStart;

    private final int[] indx2Units = new int[NUM_INDEXES];
    private final int[] units2Indx = new int[128];
    private final int[] freeList = new int[NUM_INDEXES];
    private final int[] stamps = new int[NUM_INDEXES];
    private final int[] ns2bsIndx = new int[256];
    private final int[] ns2Indx = new int[260];
    // SEE contexts: 24 x 32, then the dummy one
    private static final int DUMMY_SEE = 24 * 32;
    private final int[] seeSumm = new int[DUMMY_SEE + 1];
    private final int[] seeShift = new int[DUMMY_SEE + 1];
    private final int[] seeCount = new int[DUMMY_SEE + 1];
    private final int[][] binSumm = new int[25][64];
    private final boolean[] charMask = new boolean[256];

    // ---- range decoder (unsigned 32-bit values held in longs) ----
    private final InputStream in;
    private long range;
    private long code;
    private long low;

    /**
     * @param in            compressed data
     * @param order         model order (2 to 16)
     * @param memSize       model memory in bytes
     * @param restoreMethod 0 (restart) or 1 (cut off)
     */
    public Ppmd8(final InputStream in, final int order, final int memSize, final int restoreMethod) throws IOException {
        if (order < MIN_ORDER || order > MAX_ORDER) throw new IOException("PPMd: invalid order " + order);
        if (restoreMethod != RESTORE_RESTART && restoreMethod != RESTORE_CUT_OFF) throw new IOException("PPMd: unsupported restore method " + restoreMethod);
        if (memSize < (1 << 11) || memSize > Integer.MAX_VALUE - 64) throw new IOException("PPMd: invalid memory size " + memSize);
        this.in = in;
        int k = 0;
        for (int i = 0; i < NUM_INDEXES; i++) {
            int step = i >= 12 ? 4 : (i >> 2) + 1;
            do {
                units2Indx[k++] = i;
            } while (--step != 0);
            indx2Units[i] = k;
        }
        ns2bsIndx[0] = 0;
        ns2bsIndx[1] = 2;
        Arrays.fill(ns2bsIndx, 2, 11, 4);
        Arrays.fill(ns2bsIndx, 11, 256, 6);
        int i = 0;
        for (; i < 5; i++) ns2Indx[i] = i;
        for (int m = i, kk = 1; i < 260; i++) {
            ns2Indx[i] = m;
            if (--kk == 0) kk = (++m) - 4;
        }
        size = memSize;
        alignOffset = (4 - memSize) & 3;
        mem = new byte[alignOffset + memSize + UNIT_SIZE * 2];
        maxOrder = order;
        this.restoreMethod = restoreMethod;
        restartModel();
        // Ppmd8_Init_RangeDec
        code = 0;
        range = 0xFFFFFFFFL;
        low = 0;
        for (int j = 0; j < 4; j++) code = ((code << 8) | readByte()) & 0xFFFFFFFFL;
        if (code == 0xFFFFFFFFL) throw new IOException("PPMd: corrupted data");
    }

    private int readByte() throws IOException {
        final int b = in.read();
        return b < 0 ? 0 : b; // like 7-Zip: zeros after the end of the input
    }

    // =========================================================================
    // Heap access
    // =========================================================================

    private int u16(final int p) {
        return (mem[p] & 0xFF) | (mem[p + 1] & 0xFF) << 8;
    }

    private void u16(final int p, final int v) {
        mem[p] = (byte) v;
        mem[p + 1] = (byte) (v >>> 8);
    }

    private int u32(final int p) {
        return (mem[p] & 0xFF) | (mem[p + 1] & 0xFF) << 8 | (mem[p + 2] & 0xFF) << 16 | (mem[p + 3] & 0xFF) << 24;
    }

    private void u32(final int p, final int v) {
        mem[p] = (byte) v;
        mem[p + 1] = (byte) (v >>> 8);
        mem[p + 2] = (byte) (v >>> 16);
        mem[p + 3] = (byte) (v >>> 24);
    }

    // State: Symbol(0) Freq(1) Successor(2..5)
    private int sym(final int s) {
        return mem[s] & 0xFF;
    }

    private void sym(final int s, final int v) {
        mem[s] = (byte) v;
    }

    private int freq(final int s) {
        return mem[s + 1] & 0xFF;
    }

    private void freq(final int s, final int v) {
        mem[s + 1] = (byte) v;
    }

    private int successor(final int s) {
        return u32(s + 2);
    }

    private void successor(final int s, final int v) {
        u32(s + 2, v);
    }

    // Context: NumStats(0) Flags(1) SummFreq(2) Stats(4) Suffix(8); one state inline at 2
    private int numStats(final int c) {
        return mem[c] & 0xFF;
    }

    private void numStats(final int c, final int v) {
        mem[c] = (byte) v;
    }

    private int flags(final int c) {
        return mem[c + 1] & 0xFF;
    }

    private void flags(final int c, final int v) {
        mem[c + 1] = (byte) v;
    }

    private int summFreq(final int c) {
        return u16(c + 2);
    }

    private void summFreq(final int c, final int v) {
        u16(c + 2, v);
    }

    private int stats(final int c) {
        return u32(c + 4);
    }

    private void stats(final int c, final int v) {
        u32(c + 4, v);
    }

    private int suffix(final int c) {
        return u32(c + 8);
    }

    private void suffix(final int c, final int v) {
        u32(c + 8, v);
    }

    private static int oneState(final int c) {
        return c + 2;
    }

    // Node: Stamp(0) Next(4) NU(8)
    private int u2i(final int nu) {
        return units2Indx[nu - 1];
    }

    private int i2u(final int indx) {
        return indx2Units[indx];
    }

    private static int u2b(final int nu) {
        return nu * UNIT_SIZE;
    }

    private static int hiBitsFlag3(final int s) {
        return ((s + 0xC0) >> (8 - 3)) & (1 << 3);
    }

    private static int hiBitsFlag4(final int s) {
        return ((s + 0xC0) >> (8 - 4)) & (1 << 4);
    }

    private void copyState(final int dst, final int src) {
        System.arraycopy(mem, src, mem, dst, 6);
    }

    private void swapStates(final int a, final int b) {
        for (int i = 0; i < 6; i++) {
            final byte t = mem[a + i];
            mem[a + i] = mem[b + i];
            mem[b + i] = t;
        }
    }

    // =========================================================================
    // Memory allocator
    // =========================================================================

    private void insertNode(final int node, final int indx) {
        u32(node, EMPTY_NODE);
        u32(node + 4, freeList[indx]);
        u32(node + 8, i2u(indx));
        freeList[indx] = node;
        stamps[indx]++;
    }

    private int removeNode(final int indx) {
        final int node = freeList[indx];
        freeList[indx] = u32(node + 4);
        stamps[indx]--;
        return node;
    }

    private void splitBlock(int ptr, final int oldIndx, final int newIndx) {
        final int nu = i2u(oldIndx) - i2u(newIndx);
        ptr += u2b(i2u(newIndx));
        int i = u2i(nu);
        if (i2u(i) != nu) {
            final int k = i2u(--i);
            insertNode(ptr + u2b(k), nu - k - 1);
        }
        insertNode(ptr, i);
    }

    private void glueFreeBlocks() {
        glueCount = 1 << 13;
        Arrays.fill(stamps, 0);
        if (loUnit != hiUnit) u32(loUnit, 0); // guard
        // the chain of all free blocks: "prev" is the offset of the field holding the next reference (-1: local n)
        int n = 0;
        int prevField = -1;
        for (int i = 0; i < NUM_INDEXES; i++) {
            int next = freeList[i];
            freeList[i] = 0;
            while (next != 0) {
                final int node = next;
                int nu = u32(node + 8);
                if (prevField < 0) n = next;
                else u32(prevField, next);
                next = u32(node + 4);
                if (nu != 0) {
                    prevField = node + 4;
                    int node2;
                    while (u32(node2 = node + nu * UNIT_SIZE) == EMPTY_NODE) {
                        nu += u32(node2 + 8);
                        u32(node2 + 8, 0);
                        u32(node + 8, nu);
                    }
                }
            }
        }
        if (prevField < 0) n = 0;
        else u32(prevField, 0);

        while (n != 0) {
            int node = n;
            int nu = u32(node + 8);
            n = u32(node + 4);
            if (nu == 0) continue;
            for (; nu > 128; nu -= 128, node += 128 * UNIT_SIZE) insertNode(node, NUM_INDEXES - 1);
            int i = u2i(nu);
            if (i2u(i) != nu) {
                final int k = i2u(--i);
                insertNode(node + k * UNIT_SIZE, nu - k - 1);
            }
            insertNode(node, i);
        }
    }

    /** Returns 0 when there is no memory left. */
    private int allocUnitsRare(final int indx) {
        if (glueCount == 0) {
            glueFreeBlocks();
            if (freeList[indx] != 0) return removeNode(indx);
        }
        int i = indx;
        do {
            if (++i == NUM_INDEXES) {
                final int numBytes = u2b(i2u(indx));
                final int us = unitsStart;
                glueCount--;
                return (us - text) > numBytes ? (unitsStart = us - numBytes) : 0;
            }
        } while (freeList[i] == 0);
        final int block = removeNode(i);
        splitBlock(block, i, indx);
        return block;
    }

    private int allocUnits(final int indx) {
        if (freeList[indx] != 0) return removeNode(indx);
        final int numBytes = u2b(i2u(indx));
        final int lo = loUnit;
        if (hiUnit - lo >= numBytes) {
            loUnit = lo + numBytes;
            return lo;
        }
        return allocUnitsRare(indx);
    }

    private int shrinkUnits(final int oldPtr, final int oldNU, final int newNU) {
        final int i0 = u2i(oldNU);
        final int i1 = u2i(newNU);
        if (i0 == i1) return oldPtr;
        if (freeList[i1] != 0) {
            final int ptr = removeNode(i1);
            System.arraycopy(mem, oldPtr, mem, ptr, newNU * UNIT_SIZE);
            insertNode(oldPtr, i0);
            return ptr;
        }
        splitBlock(oldPtr, i0, i1);
        return oldPtr;
    }

    private void freeUnits(final int ptr, final int nu) {
        insertNode(ptr, u2i(nu));
    }

    private void specialFreeUnit(final int ptr) {
        if (ptr != unitsStart) insertNode(ptr, 0);
        else unitsStart += UNIT_SIZE;
    }

    private void expandTextArea() {
        final int[] count = new int[NUM_INDEXES];
        if (loUnit != hiUnit) u32(loUnit, 0);
        int node = unitsStart;
        while (u32(node) == EMPTY_NODE) {
            final int nu = u32(node + 8);
            u32(node, 0);
            count[u2i(nu)]++;
            node += nu * UNIT_SIZE;
        }
        unitsStart = node;
        for (int i = 0; i < NUM_INDEXES; i++) {
            int cnt = count[i];
            if (cnt == 0) continue;
            int prevField = -1; // -1: freeList[i]
            int n = freeList[i];
            stamps[i] -= cnt;
            for (;;) {
                final int nd = n;
                n = u32(nd + 4);
                if (u32(nd) != 0) {
                    prevField = nd + 4;
                    continue;
                }
                if (prevField < 0) freeList[i] = n;
                else u32(prevField, n);
                if (--cnt == 0) break;
            }
        }
    }

    // =========================================================================
    // Model
    // =========================================================================

    private void restartModel() {
        Arrays.fill(freeList, 0);
        Arrays.fill(stamps, 0);
        text = alignOffset;
        hiUnit = text + size;
        loUnit = unitsStart = hiUnit - size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        glueCount = 0;
        orderFall = maxOrder;
        runLength = initRL = -(maxOrder < 12 ? maxOrder : 12) - 1;
        prevSuccess = 0;

        hiUnit -= UNIT_SIZE;
        final int mc = hiUnit;
        int s = loUnit;
        loUnit += u2b(256 / 2);
        maxContext = minContext = mc;
        foundState = s;
        flags(mc, 0);
        numStats(mc, 256 - 1);
        summFreq(mc, 256 + 1);
        stats(mc, s);
        suffix(mc, 0);
        for (int i = 0; i < 256; i++, s += 6) {
            sym(s, i);
            freq(s, 1);
            successor(s, 0);
        }

        for (int i = 0, m = 0; m < 25; m++) {
            while (ns2Indx[i] == m) i++;
            for (int k = 0; k < 8; k++) {
                final int val = BIN_SCALE - INIT_BIN_ESC[k] / (i + 1);
                for (int r = 0; r < 64; r += 8) binSumm[m][k + r] = val;
            }
        }
        for (int i = 0, m = 0; m < 24; m++) {
            while (ns2Indx[i + 3] == m + 3) i++;
            final int summ = (2 * i + 5) << (PERIOD_BITS - 4);
            for (int k = 0; k < 32; k++) {
                seeSumm[m * 32 + k] = summ;
                seeShift[m * 32 + k] = PERIOD_BITS - 4;
                seeCount[m * 32 + k] = 7;
            }
        }
        seeSumm[DUMMY_SEE] = 0;
        seeShift[DUMMY_SEE] = PERIOD_BITS;
        seeCount[DUMMY_SEE] = 64;
    }

    private void refresh(final int ctx, final int oldNU, int scale) {
        int i = numStats(ctx);
        int s = shrinkUnits(stats(ctx), oldNU, (i + 2) >> 1);
        stats(ctx, s);
        scale |= summFreq(ctx) >= (1 << 15) ? 1 : 0;
        int fl = sym(s) + 0xC0;
        int f = freq(s);
        int escFreq = summFreq(ctx) - f;
        f = (f + scale) >> scale;
        int sumFreq = f;
        freq(s, f);
        do {
            s += 6;
            f = freq(s);
            escFreq -= f;
            f = (f + scale) >> scale;
            sumFreq += f;
            freq(s, f);
            fl |= sym(s) + 0xC0;
        } while (--i != 0);
        summFreq(ctx, sumFreq + ((escFreq + scale) >> scale));
        flags(ctx, (flags(ctx) & (FLAG_PREV_HIGH + FLAG_RESCALED * scale)) + ((fl >> (8 - 3)) & (1 << 3)));
    }

    private int cutOff(final int ctx, final int order) {
        int ns = numStats(ctx);
        if (ns == 0) {
            final int s = oneState(ctx);
            int succ = successor(s);
            if (succ >= unitsStart) {
                if (order < maxOrder) succ = cutOff(succ, order + 1);
                else succ = 0;
                successor(s, succ);
                if (succ != 0 || order <= 9) return ctx;
            }
            specialFreeUnit(ctx);
            return 0;
        }
        final int nu = (ns + 2) >> 1;
        int st;
        {
            final int indx = u2i(nu);
            st = stats(ctx);
            if (st - unitsStart <= (1 << 14) && st - unitsStart >= 0 && Integer.compareUnsigned(stats(ctx), freeList[indx]) <= 0) {
                final int ptr = removeNode(indx);
                stats(ctx, ptr);
                System.arraycopy(mem, st, mem, ptr, nu * UNIT_SIZE);
                if (st != unitsStart) insertNode(st, indx);
                else unitsStart += u2b(i2u(indx));
                st = ptr;
            }
        }
        int s = st + ns * 6;
        do {
            final int succ = successor(s);
            if (succ < unitsStart) {
                final int s2 = st + (ns--) * 6;
                if (order != 0) {
                    if (s != s2) copyState(s, s2);
                } else {
                    swapStates(s, s2);
                    successor(s2, 0);
                }
            } else {
                if (order < maxOrder) successor(s, cutOff(succ, order + 1));
                else successor(s, 0);
            }
            s -= 6;
        } while (s >= st);

        if (ns != numStats(ctx) && order != 0) {
            if (ns < 0) {
                freeUnits(st, nu);
                specialFreeUnit(ctx);
                return 0;
            }
            numStats(ctx, ns);
            if (ns == 0) {
                final int symbol = sym(st);
                flags(ctx, (flags(ctx) & FLAG_PREV_HIGH) + hiBitsFlag3(symbol));
                mem[ctx + 2] = (byte) symbol;
                mem[ctx + 3] = (byte) ((freq(st) + 11) >> 3);
                u32(ctx + 4, successor(st));
                freeUnits(st, nu);
            } else {
                refresh(ctx, nu, summFreq(ctx) > 16 * ns ? 1 : 0);
            }
        }
        return ctx;
    }

    private int getUsedMemory() {
        long v = 0;
        for (int i = 0; i < NUM_INDEXES; i++) v += (long) stamps[i] * i2u(i);
        return (int) (size - (hiUnit - loUnit) - (unitsStart - text) - v * UNIT_SIZE);
    }

    private void restoreModel(final int ctxError) {
        text = alignOffset;
        int c;
        for (c = maxContext; c != ctxError; c = suffix(c)) {
            final int ns = numStats(c) - 1;
            numStats(c, ns);
            if (ns == 0) {
                final int s = stats(c);
                flags(c, (flags(c) & FLAG_PREV_HIGH) + hiBitsFlag3(sym(s)));
                mem[c + 2] = (byte) sym(s);
                mem[c + 3] = (byte) ((freq(s) + 11) >> 3);
                u32(c + 4, successor(s));
                specialFreeUnit(s);
            } else {
                refresh(c, (numStats(c) + 3) >> 1, 0);
            }
        }
        for (; c != minContext; c = suffix(c)) {
            if (numStats(c) == 0) {
                mem[c + 3] = (byte) ((freq(oneState(c)) + 1) >> 1);
            } else {
                final int sf = (summFreq(c) + 4) & 0xFFFF;
                summFreq(c, sf);
                if (sf > 128 + 4 * numStats(c)) refresh(c, (numStats(c) + 2) >> 1, 1);
            }
        }
        if (restoreMethod == RESTORE_RESTART || getUsedMemory() < (size >>> 1)) {
            restartModel();
        } else {
            while (suffix(maxContext) != 0) maxContext = suffix(maxContext);
            do {
                cutOff(maxContext, 0);
                expandTextArea();
            } while (getUsedMemory() > 3 * (size >>> 2));
            glueCount = 0;
            orderFall = maxOrder;
        }
        minContext = maxContext;
    }

    /** Returns 0 when there is no memory left. */
    private int createSuccessors(final boolean skip, int s1, int c) {
        int upBranch = successor(foundState);
        final int[] ps = new int[MAX_ORDER + 1];
        int numPs = 0;
        if (!skip) ps[numPs++] = foundState;
        while (suffix(c) != 0) {
            int s;
            c = suffix(c);
            if (s1 != 0) {
                s = s1;
                s1 = 0;
            } else if (numStats(c) != 0) {
                final int symbol = sym(foundState);
                for (s = stats(c); sym(s) != symbol; s += 6) {
                    // search
                }
                if (freq(s) < MAX_FREQ - 9) {
                    freq(s, freq(s) + 1);
                    summFreq(c, summFreq(c) + 1);
                }
            } else {
                final int temp = numStats(suffix(c)) == 0 ? 1 : 0;
                s = oneState(c);
                freq(s, freq(s) + (temp & (freq(s) < 24 ? 1 : 0)));
            }
            final int succ = successor(s);
            if (succ != upBranch) {
                c = succ;
                if (numPs == 0) return c;
                break;
            }
            ps[numPs++] = s;
        }
        final int newSym = mem[upBranch] & 0xFF;
        upBranch++;
        final int fl = hiBitsFlag4(sym(foundState)) + hiBitsFlag3(newSym);
        int newFreq;
        if (numStats(c) == 0) {
            newFreq = mem[c + 3] & 0xFF;
        } else {
            int s;
            for (s = stats(c); sym(s) != newSym; s += 6) {
                // search
            }
            final long cf = freq(s) - 1L;
            final long s0 = (long) summFreq(c) - numStats(c) - cf;
            newFreq = (int) (1 + ((2 * cf <= s0) ? (5 * cf > s0 ? 1 : 0) : ((cf + 2 * s0 - 3) / s0)));
        }
        do {
            int c1;
            if (hiUnit != loUnit) {
                hiUnit -= UNIT_SIZE;
                c1 = hiUnit;
            } else if (freeList[0] != 0) {
                c1 = removeNode(0);
            } else {
                c1 = allocUnitsRare(0);
                if (c1 == 0) return 0;
            }
            flags(c1, fl);
            numStats(c1, 0);
            mem[c1 + 2] = (byte) newSym;
            mem[c1 + 3] = (byte) newFreq;
            successor(oneState(c1), upBranch);
            suffix(c1, c);
            successor(ps[--numPs], c1);
            c = c1;
        } while (numPs != 0);
        return c;
    }

    /** Returns 0 for a NULL context. */
    private int reduceOrder(int s1, int c) {
        int s = 0;
        final int c1 = c;
        final int upBranch = text;
        successor(foundState, upBranch);
        orderFall++;
        for (;;) {
            if (s1 != 0) {
                c = suffix(c);
                s = s1;
                s1 = 0;
            } else {
                if (suffix(c) == 0) return c;
                c = suffix(c);
                if (numStats(c) != 0) {
                    s = stats(c);
                    if (sym(s) != sym(foundState)) {
                        do {
                            s += 6;
                        } while (sym(s) != sym(foundState));
                    }
                    if (freq(s) < MAX_FREQ - 9) {
                        freq(s, freq(s) + 2);
                        summFreq(c, summFreq(c) + 2);
                    }
                } else {
                    s = oneState(c);
                    freq(s, freq(s) + (freq(s) < 32 ? 1 : 0));
                }
            }
            if (successor(s) != 0) break;
            successor(s, upBranch);
            orderFall++;
        }
        if (Integer.compareUnsigned(successor(s), upBranch) <= 0) {
            final int s2 = foundState;
            foundState = s;
            final int succ = createSuccessors(false, 0, c);
            successor(s, succ);
            foundState = s2;
        }
        final int succ = successor(s);
        if (orderFall == 1 && c1 == maxContext) {
            successor(foundState, succ);
            text--;
        }
        return succ;
    }

    private void updateModel() {
        int minSuccessor = successor(foundState);
        int maxSuccessor;
        int c;
        final int fFreq = freq(foundState);
        final int fSymbol = sym(foundState);
        int s = 0;
        if (fFreq < MAX_FREQ / 4 && suffix(minContext) != 0) {
            c = suffix(minContext);
            if (numStats(c) == 0) {
                s = oneState(c);
                if (freq(s) < 32) freq(s, freq(s) + 1);
            } else {
                s = stats(c);
                if (sym(s) != fSymbol) {
                    do {
                        s += 6;
                    } while (sym(s) != fSymbol);
                    if (freq(s) >= freq(s - 6)) {
                        swapStates(s, s - 6);
                        s -= 6;
                    }
                }
                if (freq(s) < MAX_FREQ - 9) {
                    freq(s, freq(s) + 2);
                    summFreq(c, summFreq(c) + 2);
                }
            }
        }
        c = maxContext;
        if (orderFall == 0 && minSuccessor != 0) {
            final int cs = createSuccessors(true, s, minContext);
            if (cs == 0) {
                successor(foundState, 0);
                restoreModel(c);
                return;
            }
            successor(foundState, cs);
            minContext = maxContext = cs;
            return;
        }
        {
            mem[text] = (byte) sym(foundState);
            text++;
            if (text >= unitsStart) {
                restoreModel(c);
                return;
            }
            maxSuccessor = text;
        }
        if (minSuccessor == 0) {
            final int cs = reduceOrder(s, minContext);
            if (cs == 0) {
                restoreModel(c);
                return;
            }
            minSuccessor = cs;
        } else if (minSuccessor < unitsStart) {
            final int cs = createSuccessors(false, s, minContext);
            if (cs == 0) {
                restoreModel(c);
                return;
            }
            minSuccessor = cs;
        }
        if (--orderFall == 0) {
            maxSuccessor = minSuccessor;
            text -= maxContext != minContext ? 1 : 0;
        }

        final int flag = hiBitsFlag3(fSymbol);
        final int ns = numStats(minContext);
        final long s0 = (long) summFreq(minContext) - ns - fFreq;

        for (; c != minContext; c = suffix(c)) {
            final int ns1 = numStats(c);
            long sum;
            if (ns1 != 0) {
                if ((ns1 & 1) != 0) {
                    final int oldNU = (ns1 + 1) >> 1;
                    final int i = u2i(oldNU);
                    if (i != u2i(oldNU + 1)) {
                        final int ptr = allocUnits(i + 1);
                        if (ptr == 0) {
                            restoreModel(c);
                            return;
                        }
                        final int oldPtr = stats(c);
                        System.arraycopy(mem, oldPtr, mem, ptr, oldNU * UNIT_SIZE);
                        insertNode(oldPtr, i);
                        stats(c, ptr);
                    }
                }
                sum = summFreq(c);
                sum += (3 * ns1 + 1 < ns) ? 1 : 0;
            } else {
                final int st = allocUnits(0);
                if (st == 0) {
                    restoreModel(c);
                    return;
                }
                int f = mem[c + 3] & 0xFF;
                mem[st] = mem[c + 2];
                u32(st + 2, u32(c + 4));
                stats(c, st);
                if (f < MAX_FREQ / 4 - 1) f <<= 1;
                else f = MAX_FREQ - 4;
                freq(st, f);
                sum = f + initEsc + (ns > 2 ? 1 : 0);
            }
            final int st = stats(c) + (ns1 + 1) * 6;
            long cf = 2 * (sum + 6) * fFreq;
            final long sf = s0 + sum;
            sym(st, fSymbol);
            numStats(c, ns1 + 1);
            successor(st, maxSuccessor);
            flags(c, flags(c) | flag);
            if (cf < 6 * sf) {
                cf = 1 + (cf > sf ? 1 : 0) + (cf >= 4 * sf ? 1 : 0);
                sum += 4;
            } else {
                cf = 4 + (cf > 9 * sf ? 1 : 0) + (cf > 12 * sf ? 1 : 0) + (cf > 15 * sf ? 1 : 0);
                sum += cf;
            }
            summFreq(c, (int) sum);
            freq(st, (int) cf);
        }
        maxContext = minContext = minSuccessor;
    }

    private void rescale() {
        final int st = stats(minContext);
        int s = foundState;
        if (s != st) {
            final byte[] tmp = new byte[6];
            System.arraycopy(mem, s, tmp, 0, 6);
            do {
                copyState(s, s - 6);
                s -= 6;
            } while (s != st);
            System.arraycopy(tmp, 0, mem, s, 6);
        }
        int sumFreq = freq(s);
        int escFreq = summFreq(minContext) - sumFreq;
        final int adder = orderFall != 0 ? 1 : 0;
        sumFreq = (sumFreq + 4 + adder) >> 1;
        int i = numStats(minContext);
        freq(s, sumFreq);
        do {
            s += 6;
            int f = freq(s);
            escFreq -= f;
            f = (f + adder) >> 1;
            sumFreq += f;
            freq(s, f);
            if (f > freq(s - 6)) {
                final byte[] tmp = new byte[6];
                System.arraycopy(mem, s, tmp, 0, 6);
                int s1 = s;
                do {
                    copyState(s1, s1 - 6);
                    s1 -= 6;
                } while (s1 != st && f > freq(s1 - 6));
                System.arraycopy(tmp, 0, mem, s1, 6);
            }
        } while (--i != 0);

        if (freq(s) == 0) {
            i = 0;
            do {
                i++;
                s -= 6;
            } while (freq(s) == 0);
            escFreq += i;
            final int mc = minContext;
            final int numSt = numStats(mc);
            final int numStatsNew = numSt - i;
            numStats(mc, numStatsNew);
            final int n0 = (numSt + 2) >> 1;
            if (numStatsNew == 0) {
                int f = (2 * freq(st) + escFreq - 1) / escFreq;
                if (f > MAX_FREQ / 3) f = MAX_FREQ / 3;
                flags(mc, (flags(mc) & FLAG_PREV_HIGH) + hiBitsFlag3(sym(st)));
                final int one = oneState(mc);
                copyState(one, st);
                freq(one, f);
                foundState = one;
                insertNode(st, u2i(n0));
                return;
            }
            final int n1 = (numStatsNew + 2) >> 1;
            if (n0 != n1) stats(mc, shrinkUnits(st, n0, n1));
        }
        final int mc = minContext;
        summFreq(mc, sumFreq + escFreq - (escFreq >> 1));
        flags(mc, flags(mc) | FLAG_RESCALED);
        foundState = stats(mc);
    }

    /** Returns the SEE context index and stores the escape frequency in seeEscFreq. */
    private int makeEscFreq(final int numMasked1) {
        final int mc = minContext;
        final int ns = numStats(mc);
        if (ns != 0xFF) {
            final int see = (ns2Indx[ns + 2] - 3) * 32
                    + (summFreq(mc) > 11 * (ns + 1) ? 1 : 0)
                    + 2 * (2 * ns < numStats(suffix(mc)) + numMasked1 ? 1 : 0)
                    + flags(mc);
            final int summ = seeSumm[see] & 0xFFFF;
            final int r = summ >>> seeShift[see];
            seeSumm[see] = (summ - r) & 0xFFFF;
            seeEscFreq = r + (r == 0 ? 1 : 0);
            return see;
        }
        seeEscFreq = 1;
        return DUMMY_SEE;
    }

    private int seeEscFreq;

    private void seeUpdate(final int see) {
        if (seeShift[see] < PERIOD_BITS && --seeCount[see] == 0) {
            seeSumm[see] = (seeSumm[see] << 1) & 0xFFFF;
            seeCount[see] = (3 << seeShift[see]++) & 0xFF;
        }
    }

    private void nextContext() {
        final int c = successor(foundState);
        if (orderFall == 0 && c >= unitsStart) maxContext = minContext = c;
        else updateModel();
    }

    private void update1() {
        int s = foundState;
        final int f = freq(s) + 4;
        summFreq(minContext, summFreq(minContext) + 4);
        freq(s, f);
        if (f > freq(s - 6)) {
            swapStates(s, s - 6);
            foundState = s -= 6;
            if (f > MAX_FREQ) rescale();
        }
        nextContext();
    }

    private void update1First() {
        final int s = foundState;
        final int mc = minContext;
        int f = freq(s);
        final int sf = summFreq(mc);
        prevSuccess = 2 * f >= sf ? 1 : 0;
        runLength += prevSuccess;
        summFreq(mc, sf + 4);
        f += 4;
        freq(s, f);
        if (f > MAX_FREQ) rescale();
        nextContext();
    }

    private void update2() {
        final int s = foundState;
        final int f = freq(s) + 4;
        runLength = initRL;
        summFreq(minContext, summFreq(minContext) + 4);
        freq(s, f);
        if (f > MAX_FREQ) rescale();
        updateModel();
    }

    // =========================================================================
    // Range decoder
    // =========================================================================

    private void normalize() throws IOException {
        for (;;) {
            if (((low ^ (low + range)) & 0xFFFFFFFFL) < TOP) {
                // top bytes equal
            } else if (range < BOT) {
                range = (0 - low) & (BOT - 1);
            } else {
                return;
            }
            code = ((code << 8) | readByte()) & 0xFFFFFFFFL;
            range = (range << 8) & 0xFFFFFFFFL;
            low = (low << 8) & 0xFFFFFFFFL;
        }
    }

    private void rcDecode(final long start, final long sz) {
        final long st = (start * range) & 0xFFFFFFFFL;
        low = (low + st) & 0xFFFFFFFFL;
        code = (code - st) & 0xFFFFFFFFL;
        range = (range * sz) & 0xFFFFFFFFL;
    }

    private long getThreshold(final long total) {
        range = range / total;
        return code / range;
    }

    // =========================================================================
    // Symbol decoding
    // =========================================================================

    /** Decodes one byte: 0-255, {@link #SYM_END} or {@link #SYM_ERROR}. */
    public int decodeSymbol() throws IOException {
        if (numStats(minContext) != 0) {
            int s = stats(minContext);
            long summ = summFreq(minContext);
            if (summ > range) summ = range;
            long count = getThreshold(summ);
            long hiCnt = count;
            count -= freq(s);
            if (count < 0) {
                rcDecode(0, freq(s));
                normalize();
                foundState = s;
                final int symbol = sym(s);
                update1First();
                return symbol;
            }
            prevSuccess = 0;
            int i = numStats(minContext);
            do {
                s += 6;
                count -= freq(s);
                if (count < 0) {
                    rcDecode((hiCnt - count) - freq(s), freq(s));
                    normalize();
                    foundState = s;
                    final int symbol = sym(s);
                    update1();
                    return symbol;
                }
            } while (--i != 0);
            if (hiCnt >= summ) return SYM_ERROR;
            hiCnt -= count;
            rcDecode(hiCnt, summ - hiCnt);
            Arrays.fill(charMask, true);
            for (int s2 = stats(minContext); s2 <= s; s2 += 6) charMask[sym(s2)] = false;
        } else {
            final int s = oneState(minContext);
            final int[] row = binSumm[ns2Indx[freq(s) - 1]];
            final int col = prevSuccess + ((runLength >> 26) & 0x20) + ns2bsIndx[numStats(suffix(minContext))] + flags(minContext);
            int pr = row[col];
            final long size0 = (range >>> 14) * pr;
            pr = pr - ((pr + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS);
            if (code < size0) {
                row[col] = pr + (1 << INT_BITS);
                range = size0;
                normalize();
                final int f = freq(s);
                final int c = successor(s);
                final int symbol = sym(s);
                foundState = s;
                prevSuccess = 1;
                runLength++;
                freq(s, f + (f < 196 ? 1 : 0));
                if (orderFall == 0 && c >= unitsStart) maxContext = minContext = c;
                else updateModel();
                return symbol;
            }
            row[col] = pr;
            initEsc = EXP_ESCAPE[pr >>> 10];
            low = (low + size0) & 0xFFFFFFFFL;
            code = (code - size0) & 0xFFFFFFFFL;
            range = ((range & ~((long) BIN_SCALE - 1)) - size0) & 0xFFFFFFFFL;
            Arrays.fill(charMask, true);
            charMask[sym(s)] = false;
            prevSuccess = 0;
        }
        for (;;) {
            normalize();
            int mc = minContext;
            final int numMasked = numStats(mc);
            do {
                orderFall++;
                if (suffix(mc) == 0) return SYM_END;
                mc = suffix(mc);
            } while (numStats(mc) == numMasked);
            int s = stats(mc);
            long hiCnt = 0;
            final int num = numStats(mc) + 1;
            for (int k = 0; k < num; k++) {
                if (charMask[sym(s + 6 * k)]) hiCnt += freq(s + 6 * k);
            }
            minContext = mc;
            final int see = makeEscFreq(numMasked);
            long freqSum = seeEscFreq + hiCnt;
            long freqSum2 = freqSum;
            if (freqSum2 > range) freqSum2 = range;
            long count = getThreshold(freqSum2);
            if (count < hiCnt) {
                s = stats(minContext);
                hiCnt = count;
                for (;;) {
                    if (charMask[sym(s)]) count -= freq(s);
                    s += 6;
                    if (count < 0) break;
                }
                s -= 6;
                rcDecode((hiCnt - count) - freq(s), freq(s));
                normalize();
                seeUpdate(see);
                foundState = s;
                final int symbol = sym(s);
                update2();
                return symbol;
            }
            if (count >= freqSum2) return SYM_ERROR;
            rcDecode(hiCnt, freqSum2 - hiCnt);
            seeSumm[see] = (int) ((seeSumm[see] + freqSum) & 0xFFFF);
            s = stats(minContext);
            for (int k = 0; k < num; k++) charMask[sym(s + 6 * k)] = false;
        }
    }
}
