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
import java.util.Arrays;

/**
 * PPMd variant H model (PPMd7), as used by 7-Zip and RAR 3.x/4.x.
 *
 * <p>Java port of Ppmd7.c by Igor Pavlov (public domain), itself based on
 * PPMd var.H (2001) by Dmitry Shkarin (public domain). The model lives in one
 * {@code byte[]} heap exactly like the C code (12-byte units, 32-bit offsets),
 * so the memory layout and every allocation decision are identical to the
 * reference - a requirement, since the decoder must rebuild the very same model
 * as the encoder.</p>
 *
 * <p>Heap records (little-endian):</p>
 * <ul>
 *   <li>State (6 bytes): Symbol(1) Freq(1) Successor(4)</li>
 *   <li>Context (12 bytes): NumStats(2) SummFreq(2) Stats(4) Suffix(4);
 *       when NumStats == 1 the single State is stored inline at offset 2</li>
 *   <li>Free-list node (12 bytes): Stamp(2) NU(2) Next(4) Prev(4)</li>
 * </ul>
 *
 * <p>This class holds the model, its update rules and the symbol decoding
 * ({@link #decodeSymbol(Ppmd7RangeDecoder)}); the arithmetic coder is supplied by the
 * caller: {@link Ppmd7Decoder} for 7z, {@link RarRangeDecoder} for RAR 3.x/4.x.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class Ppmd7 {

    public static final int MIN_ORDER = 2;
    public static final int MAX_ORDER = 64;
    public static final int MIN_MEM_SIZE = 1 << 11;
    public static final int MAX_MEM_SIZE = Integer.MAX_VALUE - 64; // Java array limit (C allows 0xFFFFFFFF - 36)

    static final int INT_BITS = 7;
    static final int PERIOD_BITS = 7;
    static final int BIN_SCALE = 1 << (INT_BITS + PERIOD_BITS);

    private static final int N1 = 4, N2 = 4, N3 = 4;
    private static final int N4 = (128 + 3 - 1 * N1 - 2 * N2 - 3 * N3) / 4;
    static final int NUM_INDEXES = N1 + N2 + N3 + N4;

    static final int MAX_FREQ = 124;
    static final int UNIT_SIZE = 12;

    static final int[] EXP_ESCAPE = { 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
    private static final int[] INIT_BIN_ESC = { 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };

    /** Index of the dummy SEE context in the see arrays (after the 25 x 16 real ones). */
    static final int DUMMY_SEE = 25 * 16;

    // ---- model state (offsets into mem) ----
    int minContext, maxContext, foundState;
    int orderFall, initEsc, prevSuccess, maxOrder, hiBitsFlag;
    int runLength, initRL;

    private int size;
    private int glueCount;
    byte[] mem;
    private int loUnit, hiUnit, text, unitsStart;
    private int alignOffset;

    private final int[] indx2Units = new int[NUM_INDEXES];
    private final int[] units2Indx = new int[128];
    private final int[] freeList = new int[NUM_INDEXES];
    final int[] ns2Indx = new int[256];
    final int[] ns2bsIndx = new int[256];
    final int[] hb2Flag = new int[256];
    final int[] seeSumm = new int[DUMMY_SEE + 1];
    final int[] seeShift = new int[DUMMY_SEE + 1];
    final int[] seeCount = new int[DUMMY_SEE + 1];
    final int[][] binSumm = new int[128][64];

    /** Escape frequency computed by {@link #makeEscFreq(int)}. */
    int escFreq;

    /** Ppmd7_Construct + Ppmd7_Alloc. */
    public Ppmd7(final int memSize) {
        if (memSize < MIN_MEM_SIZE || memSize > MAX_MEM_SIZE) throw new IllegalArgumentException("PPMd memory size out of range: " + memSize);
        int k = 0;
        for (int i = 0; i < NUM_INDEXES; i++) {
            int step = i >= 12 ? 4 : (i >> 2) + 1;
            do { units2Indx[k++] = i; } while (--step != 0);
            indx2Units[i] = k;
        }
        ns2bsIndx[0] = 0 << 1;
        ns2bsIndx[1] = 1 << 1;
        Arrays.fill(ns2bsIndx, 2, 11, 2 << 1);
        Arrays.fill(ns2bsIndx, 11, 256, 3 << 1);
        int i = 0;
        for (; i < 3; i++) ns2Indx[i] = i;
        for (int m = i, kk = 1; i < 256; i++) {
            ns2Indx[i] = m;
            if (--kk == 0) kk = (++m) - 2;
        }
        Arrays.fill(hb2Flag, 0, 0x40, 0);
        Arrays.fill(hb2Flag, 0x40, 0x100, 8);

        size = memSize;
        alignOffset = 4 - (memSize & 3);
        mem = new byte[alignOffset + memSize + UNIT_SIZE];
    }

    /** Ppmd7_Init. */
    public void init(final int order) {
        maxOrder = order;
        restartModel();
        seeShift[DUMMY_SEE] = PERIOD_BITS;
        seeSumm[DUMMY_SEE] = 0;
        seeCount[DUMMY_SEE] = 64;
    }

    // ---- heap accessors ----

    final int u16(final int p) { return (mem[p] & 0xFF) | ((mem[p + 1] & 0xFF) << 8); }
    final void u16(final int p, final int v) { mem[p] = (byte) v; mem[p + 1] = (byte) (v >>> 8); }
    final int u32(final int p) { return (mem[p] & 0xFF) | ((mem[p + 1] & 0xFF) << 8) | ((mem[p + 2] & 0xFF) << 16) | ((mem[p + 3] & 0xFF) << 24); }
    final void u32(final int p, final int v) { mem[p] = (byte) v; mem[p + 1] = (byte) (v >>> 8); mem[p + 2] = (byte) (v >>> 16); mem[p + 3] = (byte) (v >>> 24); }

    // State
    final int sym(final int s) { return mem[s] & 0xFF; }
    final int freq(final int s) { return mem[s + 1] & 0xFF; }
    final void freq(final int s, final int v) { mem[s + 1] = (byte) v; }
    final int successor(final int s) { return u32(s + 2); }
    final void successor(final int s, final int v) { u32(s + 2, v); }

    // Context
    final int numStats(final int c) { return u16(c); }
    final void numStats(final int c, final int v) { u16(c, v); }
    final int summFreq(final int c) { return u16(c + 2); }
    final void summFreq(final int c, final int v) { u16(c + 2, v); }
    final int stats(final int c) { return u32(c + 4); }
    final void stats(final int c, final int v) { u32(c + 4, v); }
    final int suffix(final int c) { return u32(c + 8); }
    final void suffix(final int c, final int v) { u32(c + 8, v); }
    static int oneState(final int c) { return c + 2; }

    private void copyState(final int dst, final int src) { System.arraycopy(mem, src, mem, dst, 6); }

    private void swapStates(final int a, final int b) {
        for (int i = 0; i < 6; i++) { final byte t = mem[a + i]; mem[a + i] = mem[b + i]; mem[b + i] = t; }
    }

    // ---- sub-allocator ----

    private int u2i(final int nu) { return units2Indx[nu - 1]; }
    private int i2u(final int indx) { return indx2Units[indx]; }
    private static int u2b(final int nu) { return nu * UNIT_SIZE; }

    private void insertNode(final int node, final int indx) {
        u32(node, freeList[indx]);
        freeList[indx] = node;
    }

    private int removeNode(final int indx) {
        final int node = freeList[indx];
        freeList[indx] = u32(node);
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
        final int head = alignOffset + size;
        int n = head;
        glueCount = 255;

        // doubly-linked list of all free blocks
        for (int i = 0; i < NUM_INDEXES; i++) {
            final int nu = i2u(i);
            int next = freeList[i];
            freeList[i] = 0;
            while (next != 0) {
                final int node = next;
                u32(node + 4, n);          // node->Next = n
                u32(n + 8, next);          // NODE(n)->Prev = next
                n = next;
                next = u32(node);          // free-list link stored at offset 0
                u16(node, 0);              // Stamp
                u16(node + 2, nu);         // NU
            }
        }
        u16(head, 1);
        u32(head + 4, n);
        u32(n + 8, head);
        if (loUnit != hiUnit) u16(loUnit, 1);

        // glue adjacent free blocks
        while (n != head) {
            final int node = n;
            int nu = u16(node + 2);
            for (;;) {
                final int node2 = node + nu * UNIT_SIZE;
                nu += u16(node2 + 2);
                if (u16(node2) != 0 || nu >= 0x10000) break;
                u32(u32(node2 + 8) + 4, u32(node2 + 4)); // NODE(node2->Prev)->Next = node2->Next
                u32(u32(node2 + 4) + 8, u32(node2 + 8)); // NODE(node2->Next)->Prev = node2->Prev
                u16(node + 2, nu);
            }
            n = u32(node + 4);
        }

        // refill the free lists
        for (n = u32(head + 4); n != head;) {
            int node = n;
            final int next = u32(node + 4);
            int nu = u16(node + 2);
            for (; nu > 128; nu -= 128, node += 128 * UNIT_SIZE) insertNode(node, NUM_INDEXES - 1);
            int i = u2i(nu);
            if (i2u(i) != nu) {
                final int k = i2u(--i);
                insertNode(node + k * UNIT_SIZE, nu - k - 1);
            }
            insertNode(node, i);
            n = next;
        }
    }

    private int allocUnitsRare(final int indx) {
        if (glueCount == 0) {
            glueFreeBlocks();
            if (freeList[indx] != 0) return removeNode(indx);
        }
        int i = indx;
        do {
            if (++i == NUM_INDEXES) {
                final int numBytes = u2b(i2u(indx));
                glueCount--;
                if (unitsStart - text > numBytes) {
                    unitsStart -= numBytes;
                    return unitsStart;
                }
                return 0;
            }
        } while (freeList[i] == 0);
        final int retVal = removeNode(i);
        splitBlock(retVal, i, indx);
        return retVal;
    }

    private int allocUnits(final int indx) {
        if (freeList[indx] != 0) return removeNode(indx);
        final int numBytes = u2b(i2u(indx));
        if (numBytes <= hiUnit - loUnit) {
            final int retVal = loUnit;
            loUnit += numBytes;
            return retVal;
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

    // ---- model ----

    private void restartModel() {
        Arrays.fill(freeList, 0);
        text = alignOffset;
        hiUnit = text + size;
        loUnit = unitsStart = hiUnit - size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        glueCount = 0;

        orderFall = maxOrder;
        runLength = initRL = -(maxOrder < 12 ? maxOrder : 12) - 1;
        prevSuccess = 0;

        hiUnit -= UNIT_SIZE;
        minContext = maxContext = hiUnit;
        suffix(minContext, 0);
        numStats(minContext, 256);
        summFreq(minContext, 256 + 1);
        foundState = loUnit;
        loUnit += u2b(256 / 2);
        stats(minContext, foundState);
        for (int i = 0; i < 256; i++) {
            final int s = foundState + i * 6;
            mem[s] = (byte) i;
            mem[s + 1] = 1;
            successor(s, 0);
        }

        for (int i = 0; i < 128; i++) {
            for (int k = 0; k < 8; k++) {
                final int val = BIN_SCALE - INIT_BIN_ESC[k] / (i + 2);
                for (int m = 0; m < 64; m += 8) binSumm[i][k + m] = val & 0xFFFF;
            }
        }
        for (int i = 0; i < 25; i++) {
            for (int k = 0; k < 16; k++) {
                final int idx = i * 16 + k;
                seeShift[idx] = PERIOD_BITS - 4;
                seeSumm[idx] = ((5 * i + 10) << seeShift[idx]) & 0xFFFF;
                seeCount[idx] = 4;
            }
        }
    }

    private final int[] ps = new int[MAX_ORDER];

    private int createSuccessors(final boolean skip) {
        int c = minContext;
        final int upBranch = successor(foundState);
        final int fsSymbol = sym(foundState);
        int numPs = 0;
        if (!skip) ps[numPs++] = foundState;

        while (suffix(c) != 0) {
            int s;
            c = suffix(c);
            if (numStats(c) != 1) {
                s = stats(c);
                while (sym(s) != fsSymbol) s += 6;
            } else {
                s = oneState(c);
            }
            final int succ = successor(s);
            if (succ != upBranch) {
                c = succ;
                if (numPs == 0) return c;
                break;
            }
            ps[numPs++] = s;
        }

        final int upSymbol = mem[upBranch] & 0xFF;
        final int upSuccessor = upBranch + 1;
        final int upFreq;
        if (numStats(c) == 1) {
            upFreq = freq(oneState(c));
        } else {
            int s = stats(c);
            while (sym(s) != upSymbol) s += 6;
            final int cf = freq(s) - 1;
            final int s0 = summFreq(c) - numStats(c) - cf;
            upFreq = 1 + ((2 * cf <= s0) ? (5 * cf > s0 ? 1 : 0) : ((2 * cf + 3 * s0 - 1) / (2 * s0)));
        }

        do {
            final int c1;
            if (hiUnit != loUnit) {
                hiUnit -= UNIT_SIZE;
                c1 = hiUnit;
            } else if (freeList[0] != 0) {
                c1 = removeNode(0);
            } else {
                c1 = allocUnitsRare(0);
                if (c1 == 0) return 0;
            }
            numStats(c1, 1);
            final int os = oneState(c1);
            mem[os] = (byte) upSymbol;
            mem[os + 1] = (byte) upFreq;
            successor(os, upSuccessor);
            suffix(c1, c);
            successor(ps[--numPs], c1);
            c = c1;
        } while (numPs != 0);
        return c;
    }

    private void updateModel() {
        int fSuccessor = successor(foundState);
        final int fsSymbol = sym(foundState);

        if (freq(foundState) < MAX_FREQ / 4 && suffix(minContext) != 0) {
            final int c = suffix(minContext);
            if (numStats(c) == 1) {
                final int s = oneState(c);
                if (freq(s) < 32) freq(s, freq(s) + 1);
            } else {
                int s = stats(c);
                if (sym(s) != fsSymbol) {
                    do { s += 6; } while (sym(s) != fsSymbol);
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

        if (orderFall == 0) {
            minContext = maxContext = createSuccessors(true);
            if (minContext == 0) {
                restartModel();
                return;
            }
            successor(foundState, minContext);
            return;
        }

        mem[text++] = (byte) fsSymbol;
        int successor = text;
        if (text >= unitsStart) {
            restartModel();
            return;
        }

        if (fSuccessor != 0) {
            if (fSuccessor <= successor) {
                final int cs = createSuccessors(false);
                if (cs == 0) {
                    restartModel();
                    return;
                }
                fSuccessor = cs;
            }
            if (--orderFall == 0) {
                successor = fSuccessor;
                if (maxContext != minContext) text--;
            }
        } else {
            successor(foundState, successor);
            fSuccessor = minContext;
        }

        final int ns = numStats(minContext);
        final int s0 = summFreq(minContext) - ns - (freq(foundState) - 1);
        final int fsFreq = freq(foundState);

        for (int c = maxContext; c != minContext; c = suffix(c)) {
            final int ns1 = numStats(c);
            if (ns1 != 1) {
                if ((ns1 & 1) == 0) {
                    // expand for one unit
                    final int oldNU = ns1 >>> 1;
                    final int i = u2i(oldNU);
                    if (i != u2i(oldNU + 1)) {
                        final int ptr = allocUnits(i + 1);
                        if (ptr == 0) {
                            restartModel();
                            return;
                        }
                        final int oldPtr = stats(c);
                        System.arraycopy(mem, oldPtr, mem, ptr, oldNU * UNIT_SIZE);
                        insertNode(oldPtr, i);
                        stats(c, ptr);
                    }
                }
                final int sf = summFreq(c);
                summFreq(c, sf + (2 * ns1 < ns ? 1 : 0) + 2 * ((4 * ns1 <= ns ? 1 : 0) & (sf <= 8 * ns1 ? 1 : 0)));
            } else {
                final int s = allocUnits(0);
                if (s == 0) {
                    restartModel();
                    return;
                }
                copyState(s, oneState(c));
                stats(c, s);
                if (freq(s) < MAX_FREQ / 4 - 1) freq(s, freq(s) << 1);
                else freq(s, MAX_FREQ - 4);
                summFreq(c, freq(s) + initEsc + (ns > 3 ? 1 : 0));
            }
            long cf = 2L * fsFreq * (summFreq(c) + 6);
            final long sf = (long) s0 + summFreq(c);
            if (cf < 6 * sf) {
                cf = 1 + (cf > sf ? 1 : 0) + (cf >= 4 * sf ? 1 : 0);
                summFreq(c, summFreq(c) + 3);
            } else {
                cf = 4 + (cf >= 9 * sf ? 1 : 0) + (cf >= 12 * sf ? 1 : 0) + (cf >= 15 * sf ? 1 : 0);
                summFreq(c, summFreq(c) + (int) cf);
            }
            final int s = stats(c) + ns1 * 6;
            successor(s, successor);
            mem[s] = (byte) fsSymbol;
            mem[s + 1] = (byte) cf;
            numStats(c, ns1 + 1);
        }
        maxContext = minContext = fSuccessor;
    }

    private void rescale() {
        final int stats = stats(minContext);
        int s = foundState;
        {
            final byte tSym = mem[s], tFreq = mem[s + 1];
            final int tSucc = successor(s);
            for (; s != stats; s -= 6) copyState(s, s - 6);
            mem[s] = tSym;
            mem[s + 1] = tFreq;
            successor(s, tSucc);
        }
        int escFreq = summFreq(minContext) - freq(s);
        freq(s, freq(s) + 4);
        final int adder = orderFall != 0 ? 1 : 0;
        freq(s, (freq(s) + adder) >>> 1);
        int sumFreq = freq(s);

        int i = numStats(minContext) - 1;
        do {
            s += 6;
            escFreq -= freq(s);
            freq(s, (freq(s) + adder) >>> 1);
            sumFreq += freq(s);
            if (freq(s) > freq(s - 6)) {
                int s1 = s;
                final byte tSym = mem[s1], tFreq = mem[s1 + 1];
                final int tSucc = successor(s1);
                final int tf = tFreq & 0xFF;
                do {
                    copyState(s1, s1 - 6);
                    s1 -= 6;
                } while (s1 != stats && tf > freq(s1 - 6));
                mem[s1] = tSym;
                mem[s1 + 1] = tFreq;
                successor(s1, tSucc);
            }
        } while (--i != 0);

        if (freq(s) == 0) {
            final int numStats = numStats(minContext);
            do { i++; s -= 6; } while (freq(s) == 0);
            escFreq += i;
            numStats(minContext, numStats(minContext) - i);
            if (numStats(minContext) == 1) {
                final byte tSym = mem[stats];
                int tFreq = mem[stats + 1] & 0xFF;
                final int tSucc = successor(stats);
                do {
                    tFreq = (tFreq - (tFreq >>> 1)) & 0xFF;
                    escFreq >>>= 1;
                } while (escFreq > 1);
                insertNode(stats, u2i((numStats + 1) >>> 1));
                foundState = oneState(minContext);
                mem[foundState] = tSym;
                mem[foundState + 1] = (byte) tFreq;
                successor(foundState, tSucc);
                return;
            }
            final int n0 = (numStats + 1) >>> 1;
            final int n1 = (numStats(minContext) + 1) >>> 1;
            if (n0 != n1) stats(minContext, shrinkUnits(stats, n0, n1));
        }
        summFreq(minContext, sumFreq + escFreq - (escFreq >>> 1));
        foundState = stats(minContext);
    }

    /** Ppmd7_MakeEscFreq: returns the SEE index and stores the escape frequency in {@link #escFreq}. */
    int makeEscFreq(final int numMasked) {
        final int mcNumStats = numStats(minContext);
        final int nonMasked = mcNumStats - numMasked;
        if (mcNumStats != 256) {
            final long diff = ((long) numStats(suffix(minContext)) - mcNumStats) & 0xFFFFFFFFL; // unsigned in C
            final int see = ns2Indx[nonMasked - 1] * 16
                    + (nonMasked < diff ? 1 : 0)
                    + 2 * (summFreq(minContext) < 11 * mcNumStats ? 1 : 0)
                    + 4 * (numMasked > nonMasked ? 1 : 0)
                    + hiBitsFlag;
            final int r = seeSumm[see] >>> seeShift[see];
            seeSumm[see] = (seeSumm[see] - r) & 0xFFFF;
            escFreq = r + (r == 0 ? 1 : 0);
            return see;
        }
        escFreq = 1;
        return DUMMY_SEE;
    }

    /** Ppmd_See_Update. */
    void seeUpdate(final int see) {
        if (seeShift[see] < PERIOD_BITS && --seeCount[see] == 0) {
            seeSumm[see] = (seeSumm[see] << 1) & 0xFFFF;
            seeCount[see] = (3 << seeShift[see]++) & 0xFF;
        }
    }

    private void nextContext() {
        final int c = successor(foundState);
        if (orderFall == 0 && c > text) minContext = maxContext = c;
        else updateModel();
    }

    void update1() {
        int s = foundState;
        freq(s, freq(s) + 4);
        summFreq(minContext, summFreq(minContext) + 4);
        if (freq(s) > freq(s - 6)) {
            swapStates(s, s - 6);
            foundState = s -= 6;
            if (freq(s) > MAX_FREQ) rescale();
        }
        nextContext();
    }

    void update1_0() {
        prevSuccess = 2 * freq(foundState) > summFreq(minContext) ? 1 : 0;
        runLength += prevSuccess;
        summFreq(minContext, summFreq(minContext) + 4);
        freq(foundState, freq(foundState) + 4);
        if (freq(foundState) > MAX_FREQ) rescale();
        nextContext();
    }

    void updateBin() {
        freq(foundState, freq(foundState) + (freq(foundState) < 128 ? 1 : 0));
        prevSuccess = 1;
        runLength++;
        nextContext();
    }

    void update2() {
        summFreq(minContext, summFreq(minContext) + 4);
        freq(foundState, freq(foundState) + 4);
        if (freq(foundState) > MAX_FREQ) rescale();
        runLength = initRL;
        updateModel();
    }

    /** Ppmd7_GetBinSumm: returns {row, col} packed as row * 64 + col (also sets hiBitsFlag, like the C macro). */
    int binSummIndex() {
        final int os = oneState(minContext);
        hiBitsFlag = hb2Flag[sym(foundState)];
        final int row = freq(os) - 1;
        final int col = prevSuccess + ns2bsIndx[numStats(suffix(minContext)) - 1] + hiBitsFlag + 2 * hb2Flag[sym(os)] + ((runLength >> 26) & 0x20);
        return row * 64 + col;
    }

    // ---- Ppmd7_DecodeSymbol (generic over the range coder) ----

    private final byte[] charMask = new byte[256];
    private final int[] psEsc = new int[256];

    /**
     * Decodes one symbol.
     *
     * @return the byte value, -1 for an escape at the root context (end marker), -2 for corrupted data
     */
    public int decodeSymbol(final Ppmd7RangeDecoder rc) throws IOException {
        final Ppmd7 p = this;
        if (p.numStats(p.minContext) != 1) {
            int s = p.stats(p.minContext);
            final int summFreq = p.summFreq(p.minContext);
            final long count = rc.getThreshold(summFreq);
            long hiCnt = p.freq(s);
            if (count < hiCnt) {
                rc.decode(0, p.freq(s));
                p.foundState = s;
                final int symbol = p.sym(s);
                p.update1_0();
                return symbol;
            }
            p.prevSuccess = 0;
            int i = p.numStats(p.minContext) - 1;
            do {
                s += 6;
                if ((hiCnt += p.freq(s)) > count) {
                    rc.decode(hiCnt - p.freq(s), p.freq(s));
                    p.foundState = s;
                    final int symbol = p.sym(s);
                    p.update1();
                    return symbol;
                }
            } while (--i != 0);
            if (count >= summFreq) return -2;
            p.hiBitsFlag = p.hb2Flag[p.sym(p.foundState)];
            rc.decode(hiCnt, summFreq - hiCnt);
            Arrays.fill(charMask, (byte) -1);
            charMask[p.sym(s)] = 0;
            i = p.numStats(p.minContext) - 1;
            do { s -= 6; charMask[p.sym(s)] = 0; } while (--i != 0);
        } else {
            final int idx = p.binSummIndex();
            final int row = idx >>> 6, col = idx & 63;
            final int prob = p.binSumm[row][col];
            if (rc.decodeBit(prob) == 0) {
                p.binSumm[row][col] = (prob + (1 << INT_BITS) - getMean(prob)) & 0xFFFF;
                p.foundState = oneState(p.minContext);
                final int symbol = p.sym(p.foundState);
                p.updateBin();
                return symbol;
            }
            final int np = (prob - getMean(prob)) & 0xFFFF;
            p.binSumm[row][col] = np;
            p.initEsc = EXP_ESCAPE[np >>> 10];
            Arrays.fill(charMask, (byte) -1);
            charMask[p.sym(oneState(p.minContext))] = 0;
            p.prevSuccess = 0;
        }
        for (;;) {
            final int numMasked = p.numStats(p.minContext);
            do {
                p.orderFall++;
                if (p.suffix(p.minContext) == 0) return -1;
                p.minContext = p.suffix(p.minContext);
            } while (p.numStats(p.minContext) == numMasked);
            long hiCnt = 0;
            int s = p.stats(p.minContext);
            int i = 0;
            final int num = p.numStats(p.minContext) - numMasked;
            do {
                final int k = charMask[p.sym(s)]; // -1 = not masked, 0 = masked
                hiCnt += p.freq(s) & k;
                psEsc[i] = s;
                s += 6;
                i -= k;
            } while (i != num);

            final int see = p.makeEscFreq(numMasked);
            final long freqSum = p.escFreq + hiCnt;
            final long count = rc.getThreshold(freqSum);

            if (count < hiCnt) {
                int k = 0;
                hiCnt = 0;
                while ((hiCnt += p.freq(psEsc[k])) <= count) k++;
                s = psEsc[k];
                rc.decode(hiCnt - p.freq(s), p.freq(s));
                p.seeUpdate(see);
                p.foundState = s;
                final int symbol = p.sym(s);
                p.update2();
                return symbol;
            }
            if (count >= freqSum) return -2;
            rc.decode(hiCnt, freqSum - hiCnt);
            p.seeSumm[see] = (int) ((p.seeSumm[see] + freqSum) & 0xFFFF);
            do { charMask[p.sym(psEsc[--i])] = 0; } while (i != 0);
        }
    }

    private static int getMean(final int prob) {
        return (prob + (1 << (PERIOD_BITS - 2))) >>> PERIOD_BITS;
    }
}
