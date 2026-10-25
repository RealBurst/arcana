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
 * FSE (tANS) encoding table built from normalized counts, the mirror of the
 * decoding table of RFC 8878 section 4.1.1: the symbols are spread over the
 * table with the same step, the "less than 1" symbols at the end, and each
 * state is the decoding state that leads back to it.
 *
 * <p>A state is a value in [tableSize, 2 * tableSize). Encoding a symbol
 * writes the low bits of the state (the bits the decoder reads to come back to
 * the previous state) and moves to the state of that symbol. The symbols are
 * encoded in reverse order; {@link #flush} writes the final state, which the
 * decoder reads first as its initial state.</p>
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdFseEncoder {

    final int tableLog;
    private final int[] stateTable;
    private final int[] deltaNbBits;
    private final int[] deltaFindState;

    /**
     * @param norm      normalized counts (-1 = "less than 1"), summing to 1 &lt;&lt; tableLog
     * @param maxSymbol largest symbol of {@code norm}
     * @param tableLog  accuracy log
     */
    ZstdFseEncoder(final short[] norm, final int maxSymbol, final int tableLog) {
        this.tableLog = tableLog;
        final int tableSize = 1 << tableLog;
        final int mask = tableSize - 1;
        final int step = (tableSize >>> 1) + (tableSize >>> 3) + 3;
        int highThreshold = tableSize - 1;
        final int[] cumul = new int[maxSymbol + 2];
        final int[] tableSymbol = new int[tableSize];
        for (int s = 0; s <= maxSymbol; s++) {
            if (norm[s] == -1) {
                cumul[s + 1] = cumul[s] + 1;
                tableSymbol[highThreshold--] = s;
            } else {
                cumul[s + 1] = cumul[s] + norm[s];
            }
        }
        int position = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            for (int i = 0; i < norm[s]; i++) {
                tableSymbol[position] = s;
                do {
                    position = (position + step) & mask;
                } while (position > highThreshold);
            }
        }
        if (position != 0) throw new IllegalStateException("FSE: normalized counts do not fill the table");
        stateTable = new int[tableSize];
        for (int u = 0; u < tableSize; u++) {
            final int s = tableSymbol[u];
            stateTable[cumul[s]++] = tableSize + u;
        }
        deltaNbBits = new int[maxSymbol + 1];
        deltaFindState = new int[maxSymbol + 1];
        int total = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            final int n = norm[s];
            if (n == 0) {
                deltaNbBits[s] = ((tableLog + 1) << 16) - tableSize;
            } else if (n == -1 || n == 1) {
                deltaNbBits[s] = (tableLog << 16) - tableSize;
                deltaFindState[s] = total - 1;
                total++;
            } else {
                final int maxBitsOut = tableLog - Util.highestBit(n - 1);
                final int minStatePlus = n << maxBitsOut;
                deltaNbBits[s] = (maxBitsOut << 16) - minStatePlus;
                deltaFindState[s] = total - n;
                total += n;
            }
        }
    }

    /** First state, for the last symbol of the sequence (no bits written). */
    int init(final int symbol) {
        final int nbBitsOut = (deltaNbBits[symbol] + (1 << 15)) >>> 16;
        final int value = (nbBitsOut << 16) - deltaNbBits[symbol];
        return stateTable[(value >> nbBitsOut) + deltaFindState[symbol]];
    }

    /** Encodes {@code symbol} from {@code state}; returns the new state. */
    int encode(final ZstdBitWriter out, final int state, final int symbol) {
        final int nbBitsOut = (state + deltaNbBits[symbol]) >>> 16;
        out.addBits(state, nbBitsOut);
        return stateTable[(state >> nbBitsOut) + deltaFindState[symbol]];
    }

    /** Writes the final state (the decoder's initial state). */
    void flush(final ZstdBitWriter out, final int state) {
        out.addBits(state, tableLog);
    }

    /**
     * Estimated cost in bits of {@code counts} coded with {@code norm}
     * (accuracy {@code tableLog}); -1 if a used symbol has no probability.
     */
    static double cost(final int[] counts, final int maxSymbol, final short[] norm, final int normMax, final int tableLog) {
        double bits = 0;
        for (int s = 0; s <= maxSymbol; s++) {
            if (counts[s] == 0) continue;
            if (s > normMax || norm[s] == 0) return -1;
            final int p = norm[s] == -1 ? 1 : norm[s];
            bits += counts[s] * (tableLog - Math.log(p) / Math.log(2));
        }
        return bits;
    }
}
