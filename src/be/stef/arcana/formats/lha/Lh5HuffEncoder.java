/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.IOException;

/**
 * Builds canonical Huffman codes from frequency tables and serialises the
 * resulting Huffman trees in the LHA static-Huffman block format.
 *
 * <p>LHA uses three Huffman tables per block:</p>
 * <ol>
 *   <li><em>Command decoding tree</em> (a.k.a. "T" tree) - a meta-tree (up to 19 symbols) whose
 *       codes encode the code-lengths used to describe the command tree.</li>
 *   <li><em>Command tree</em> ("C" tree) - encodes literals (0-255) and
 *       match-length codes (256 to {@code NUMBER_OF_LITERALS + MAX_MATCH - MIN_MATCH}).</li>
 *   <li><em>Distance tree</em> ("P" tree) - encodes the distance "exponent" for back-references.</li>
 * </ol>
 *
 * <p>All trees use canonical Huffman codes with a maximum depth of 16. A tree
 * is always <b>complete</b> (Kraft sum = 1), as required by LHA decoders.</p>
 *
 * <p><b>Single-symbol trees.</b> When a table uses 0 or 1 distinct symbol, LHA does
 * not store code lengths: it writes {@code n = 0} followed by the symbol value, and
 * that symbol is then emitted with <b>zero</b> bits. {@link #singleSymbol(int[], int)}
 * detects this case; all writers take the resulting {@code single} value
 * ({@code -1} = normal tree).</p>
 *
 * @author Stef
 * @since 1.3
 */
final class Lh5HuffEncoder {

    static final int MAX_CODE_LEN  = 16;
    static final int MAX_SYMBOLS   = 510; // NUMBER_OF_LITERALS + MAX_MATCH - MIN_MATCH + 1

    private static final int CMD_DECODING_LEN_BITS = 5;  // TBIT
    private static final int CMD_TREE_LEN_BITS     = 9;  // CBIT
    private static final int CODE_LENGTH_BITS      = 3;

    // ---- Single-symbol detection -----------------------------------------

    /**
     * Returns the symbol to store when the table is degenerate, or -1 for a normal tree.
     *
     * @return -1 if 2 or more symbols are used; the only used symbol if exactly one; 0 if none
     */
    static int singleSymbol(final int[] freq, final int n) {
        int found = -1;
        for (int i = 0; i < n; i++) {
            if (freq[i] > 0) {
                if (found >= 0) return -1;
                found = i;
            }
        }
        return found < 0 ? 0 : found;
    }

    // ---- Length-limited Huffman construction -----------------------------

    /**
     * Builds code lengths for {@code n} symbols given their frequencies.
     * Symbols with frequency 0 get length 0. If fewer than 2 symbols are used,
     * all lengths are 0 (single-symbol case, see {@link #singleSymbol(int[], int)}).
     *
     * <p>If the optimal tree is deeper than {@link #MAX_CODE_LEN}, the frequencies
     * are halved (keeping every used symbol at >= 1) and the tree is rebuilt. This
     * always converges and always yields a complete prefix code.</p>
     */
    static int[] buildCodeLengths(final int[] freq, final int n) {
        final int[] lens = new int[n];
        int used = 0;
        for (int i = 0; i < n; i++) if (freq[i] > 0) used++;
        if (used < 2) return lens;

        final long[] f = new long[n];
        for (int i = 0; i < n; i++) f[i] = freq[i];
        while (true) {
            huffmanDepths(f, n, lens);
            int max = 0;
            for (int i = 0; i < n; i++) if (lens[i] > max) max = lens[i];
            if (max <= MAX_CODE_LEN) return lens;
            for (int i = 0; i < n; i++) if (f[i] > 0) f[i] = Math.max(1L, f[i] >>> 1);
        }
    }

    /** Plain Huffman: fills lens[i] with the depth of leaf i (0 for unused symbols). */
    private static void huffmanDepths(final long[] f, final int n, final int[] lens) {
        final int maxNodes = 2 * n;
        final long[] weight = new long[maxNodes];
        final int[]  parent = new int[maxNodes];
        final int[]  heap   = new int[n];
        int size = 0;
        for (int i = 0; i < n; i++) {
            lens[i] = 0;
            if (f[i] > 0) { weight[i] = f[i]; heap[size++] = i; }
        }
        for (int i = size / 2 - 1; i >= 0; i--) siftDown(heap, weight, i, size);

        int next = n;
        while (size > 1) {
            final int a = heap[0];
            heap[0] = heap[--size];
            siftDown(heap, weight, 0, size);
            final int b = heap[0];
            weight[next] = weight[a] + weight[b];
            parent[a] = next;
            parent[b] = next;
            heap[0] = next;               // replace b by the new internal node
            siftDown(heap, weight, 0, size);
            next++;
        }
        final int root = heap[0];
        for (int i = 0; i < n; i++) {
            if (f[i] <= 0) continue;
            int d = 0;
            for (int node = i; node != root; node = parent[node]) d++;
            lens[i] = d;
        }
    }

    private static void siftDown(final int[] heap, final long[] weight, final int start, final int size) {
        int pos = start;
        while (true) {
            int smallest = pos;
            final int l = 2 * pos + 1, r = l + 1;
            if (l < size && less(heap[l], heap[smallest], weight)) smallest = l;
            if (r < size && less(heap[r], heap[smallest], weight)) smallest = r;
            if (smallest == pos) return;
            final int tmp = heap[pos]; heap[pos] = heap[smallest]; heap[smallest] = tmp;
            pos = smallest;
        }
    }

    /** Weight order with node index as tie-breaker (deterministic output). */
    private static boolean less(final int a, final int b, final long[] weight) {
        return weight[a] < weight[b] || (weight[a] == weight[b] && a < b);
    }

    // ---- Canonical code assignment ---------------------------------------

    /**
     * Assigns canonical bit codes from the code lengths (shorter codes first,
     * then by symbol index), which is the ordering LHA decoders expect.
     */
    static int[] assignCodes(final int[] lens, final int n) {
        final int[] count = new int[MAX_CODE_LEN + 1];
        for (int i = 0; i < n; i++) if (lens[i] > 0) count[lens[i]]++;
        final int[] next = new int[MAX_CODE_LEN + 1];
        int code = 0;
        for (int len = 1; len <= MAX_CODE_LEN; len++) {
            next[len] = code;
            code = (code + count[len]) << 1;
        }
        final int[] codes = new int[n];
        for (int i = 0; i < n; i++) if (lens[i] > 0) codes[i] = next[lens[i]]++;
        return codes;
    }

    // ---- Command tree run-length scheme (shared by frequency count and writer) ----

    /** Number of meaningful entries in a code-length table (trailing zeros trimmed). */
    static int effectiveLength(final int[] lens, final int n) {
        int e = n;
        while (e > 0 && lens[e - 1] == 0) e--;
        return e;
    }

    /**
     * Counts the command-decoding-tree symbol frequencies needed to describe
     * {@code cmdLens}: 0 = one zero, 1 = 3..18 zeros, 2 = 20+ zeros, k+2 = length k.
     */
    static int[] countCommandDecodingFreq(final int[] cmdLens, final int n, final int cdSymbols) {
        final int[] freq = new int[cdSymbols];
        final int e = effectiveLength(cmdLens, n);
        int i = 0;
        while (i < e) {
            final int k = cmdLens[i++];
            if (k == 0) {
                int run = 1;
                while (i < e && cmdLens[i] == 0) { i++; run++; }
                if (run <= 2)       freq[0] += run;
                else if (run <= 18) freq[1]++;
                else if (run == 19) { freq[0]++; freq[1]++; }
                else                freq[2]++;
            } else {
                freq[k + 2]++;
            }
        }
        return freq;
    }

    // ---- Tree serialisation ----------------------------------------------

    /**
     * Writes the command-decoding tree. Its entries 0..2 are followed by a 2-bit
     * count of extra zero entries (always 0 here: every entry is written explicitly).
     */
    static void writeCommandDecodingTree(final LhaBitOutputStream out, final int[] cdLens, final int cdSingle) throws IOException {
        if (cdSingle >= 0) {
            out.writeBits(0, CMD_DECODING_LEN_BITS);
            out.writeBits(cdSingle, CMD_DECODING_LEN_BITS);
            return;
        }
        final int e = Math.max(3, effectiveLength(cdLens, cdLens.length));
        out.writeBits(e, CMD_DECODING_LEN_BITS);
        for (int i = 0; i < e; i++) {
            writeCodeLength(out, cdLens[i]);
            if (i == 2) out.writeBits(0, 2);
        }
    }

    /** Writes the command tree, run-length coded through the command-decoding tree. */
    static void writeCommandTree(final LhaBitOutputStream out, final int[] cmdLens, final int maxCmds, final int cmdSingle, final int[] cdCodes, final int[] cdLens, final int cdSingle) throws IOException {
        if (cmdSingle >= 0) {
            out.writeBits(0, CMD_TREE_LEN_BITS);
            out.writeBits(cmdSingle, CMD_TREE_LEN_BITS);
            return;
        }
        final int e = effectiveLength(cmdLens, maxCmds);
        out.writeBits(e, CMD_TREE_LEN_BITS);
        int i = 0;
        while (i < e) {
            final int k = cmdLens[i++];
            if (k == 0) {
                int run = 1;
                while (i < e && cmdLens[i] == 0) { i++; run++; }
                if (run <= 2) {
                    for (int r = 0; r < run; r++) writeCode(out, 0, cdCodes, cdLens, cdSingle);
                } else if (run <= 18) {
                    writeCode(out, 1, cdCodes, cdLens, cdSingle);
                    out.writeBits(run - 3, 4);
                } else if (run == 19) {
                    writeCode(out, 0, cdCodes, cdLens, cdSingle);
                    writeCode(out, 1, cdCodes, cdLens, cdSingle);
                    out.writeBits(15, 4);
                } else {
                    writeCode(out, 2, cdCodes, cdLens, cdSingle);
                    out.writeBits(run - 20, CMD_TREE_LEN_BITS);
                }
            } else {
                writeCode(out, k + 2, cdCodes, cdLens, cdSingle);
            }
        }
    }

    /** Writes the distance tree (code lengths for distance codes). */
    static void writeDistanceTree(final LhaBitOutputStream out, final int[] distLens, final int distSingle, final int distanceBits) throws IOException {
        if (distSingle >= 0) {
            out.writeBits(0, distanceBits);
            out.writeBits(distSingle, distanceBits);
            return;
        }
        final int e = effectiveLength(distLens, distLens.length);
        out.writeBits(e, distanceBits);
        for (int i = 0; i < e; i++) writeCodeLength(out, distLens[i]);
    }

    /** Writes a code length using the 3-bit extended format (7+ = 7 then unary 1s, 0-terminated). */
    static void writeCodeLength(final LhaBitOutputStream out, final int len) throws IOException {
        if (len < 7) {
            out.writeBits(len, CODE_LENGTH_BITS);
        } else {
            out.writeBits(7, CODE_LENGTH_BITS);
            for (int x = len - 7; x > 0; x--) out.writeBit(1);
            out.writeBit(0);
        }
    }

    /**
     * Writes one symbol. For a single-symbol tree ({@code single >= 0}) nothing is
     * written: the decoder returns that symbol without reading any bit.
     */
    static void writeCode(final LhaBitOutputStream out, final int symbol, final int[] codes, final int[] lens, final int single) throws IOException {
        if (single >= 0) {
            if (symbol != single) throw new IOException("LHA encode: symbol " + symbol + " not in single-symbol tree (" + single + ")");
            return;
        }
        if (lens[symbol] == 0) throw new IOException("LHA encode: symbol " + symbol + " has no code (length 0)");
        out.writeBits(codes[symbol], lens[symbol]);
    }

    private Lh5HuffEncoder() {}
}
