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
package be.stef.arcana.formats.rar.rar4.decompress;

import java.io.IOException;
import java.util.Arrays;

/**
 * Canonical Huffman decoder for RAR4 compressed streams.
 *
 * <p>RAR4 Huffman tables are stored as arrays of code lengths (one per symbol).
 * This decoder builds internal threshold and symbol-mapping arrays from those
 * lengths, then decodes symbols by comparing the current bit window against
 * per-length thresholds.</p>
 *
 * <p>Four tables are used during LZ decompression:</p>
 * <ul>
 *   <li>Main table  : 299 symbols (literals 0-255, LZ control codes 256-298)</li>
 *   <li>Distance    : 60 symbols</li>
 *   <li>Low distance: 17 symbols</li>
 *   <li>Length      : 28 symbols</li>
 * </ul>
 * A 20-symbol pre-table is used to encode the code lengths themselves.
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4HuffmanDecoder {
    public static final int MAIN_TABLE_SIZE     = 299;
    public static final int DIST_TABLE_SIZE     = 60;
    public static final int LOW_DIST_TABLE_SIZE = 17;
    public static final int LEN_TABLE_SIZE      = 28;
    public static final int PRE_TABLE_SIZE      = 20;

    /** Maximum supported code length. */
    private static final int MAX_CODE_LEN = 15;

    /**
     * Upper bound of the 16-bit code range for each code length.
     * A symbol has {@code k} bits if {@code bitWindow < lenLimit[k]}.
     */
    private final int[] lenLimit  = new int[MAX_CODE_LEN + 1];

    /**
     * Starting index into {@link #symbolMap} for symbols of each code length.
     */
    private final int[] groupStart = new int[MAX_CODE_LEN + 1];

    /**
     * Flat array of symbols ordered by (length, canonical index).
     * Populated during {@link #build}.
     */
    private int[] symbolMap;

    /** Number of symbols in this table. */
    private int symbolCount;

    /** True after a successful {@link #build} call. */
    private boolean ready;

    // -------------------------------------------------------------------------
    // Table construction
    // -------------------------------------------------------------------------

    /**
     * Builds the decoding table from an array of code lengths.
     *
     * <p>The algorithm mirrors the canonical Huffman construction used by
     * the RAR4 format: for each bit length {@code k}, all symbols with that
     * length are assigned consecutive canonical codes starting from a base
     * value derived from the counts of shorter codes.</p>
     *
     * @param codeLengths array of per-symbol code lengths (values 0-15)
     * @param offset      starting index within {@code codeLengths}
     * @param count       number of symbols to process
     */
    public void build(int[] codeLengths, int offset, int count) {
        ready       = false;
        symbolCount = count;

        if (symbolMap == null || symbolMap.length < count) {
            symbolMap = new int[count];
        }
        Arrays.fill(symbolMap, 0);

        // Count how many symbols have each code length
        int[] freq = new int[MAX_CODE_LEN + 1];
        for (int i = 0; i < count; i++) {
            freq[codeLengths[offset + i] & 0xF]++;
        }
        freq[0] = 0; // length-0 means "unused"

        // Compute cumulative positions and threshold values
        // lenLimit[k] is the exclusive upper bound of the 16-bit window
        // for a k-bit code.
        long accumulated = 0;
        groupStart[0]    = 0;
        lenLimit[0]      = 0;

        int[] fillPos = new int[MAX_CODE_LEN + 1];
        fillPos[0]    = 0;

        for (int k = 1; k <= MAX_CODE_LEN; k++) {
            accumulated    = 2 * (accumulated + freq[k]);
            long threshold = accumulated << (15 - k);
            lenLimit[k]    = (int) Math.min(threshold, 0xFFFF);
            groupStart[k]  = groupStart[k - 1] + freq[k - 1];
            fillPos[k]     = groupStart[k];
        }

        // Populate symbolMap in canonical order (symbol index order within each length)
        for (int sym = 0; sym < count; sym++) {
            int len = codeLengths[offset + sym] & 0xF;
            if (len != 0) {
                symbolMap[fillPos[len]++] = sym;
            }
        }

        ready = true;
    }

    /** Convenience overload without offset. */
    public void build(int[] codeLengths, int count) {
        build(codeLengths, 0, count);
    }

    // -------------------------------------------------------------------------
    // Symbol decoding
    // -------------------------------------------------------------------------

    /**
     * Decodes one symbol from the bit stream.
     *
     * <p>The current 16-bit window is compared against {@link #lenLimit}
     * thresholds to determine the code length, then the symbol index is
     * computed from the canonical position within that length group.</p>
     *
     * @param reader the bit decoder positioned at the start of the next code
     * @return the decoded symbol index
     * @throws IOException if the bit stream is malformed
     */
    public int decode(Rar4BitDecoder reader) throws IOException {
        if (!ready) throw new IOException("RAR4: Huffman table used before initialization");

        // Read 16-bit window (MSB-first) masking the LSB per RAR4 spec
        int window = reader.peek16() & 0xFFFE;
        int codeLen;

        // Binary search through lenLimit thresholds to find code length
        if (window < lenLimit[8]) {
            if (window < lenLimit[4]) {
                if      (window < lenLimit[2]) { codeLen = window < lenLimit[1] ? 1 : 2; }
                else                           { codeLen = window < lenLimit[3] ? 3 : 4; }
            } else {
                if      (window < lenLimit[6]) { codeLen = window < lenLimit[5] ? 5 : 6; }
                else                           { codeLen = window < lenLimit[7] ? 7 : 8; }
            }
        } else {
            if (window < lenLimit[12]) {
                if      (window < lenLimit[10]) { codeLen = window < lenLimit[9]  ?  9 : 10; }
                else                            { codeLen = window < lenLimit[11] ? 11 : 12; }
            } else {
                if      (window < lenLimit[14]) { codeLen = window < lenLimit[13] ? 13 : 14; }
                else                            { codeLen = 15; }
            }
        }

        reader.skip(codeLen);

        // Compute canonical index within this length group
        int canonicalIndex = groupStart[codeLen]
                + ((window - lenLimit[codeLen - 1]) >>> (16 - codeLen));

        if (canonicalIndex >= symbolCount) canonicalIndex = 0;
        return symbolMap[canonicalIndex];
    }

    public boolean isReady() { return ready; }

    // -------------------------------------------------------------------------
    // Code length table reading
    // -------------------------------------------------------------------------

    /**
     * Reads Huffman code lengths for one table from the bit stream.
     *
     * <p>The RAR4 format encodes code lengths using a 20-symbol pre-table
     * (itself stored as raw 4-bit values, with a special run-length extension
     * for the value 15). The pre-table symbols encode lengths and runs:</p>
     * <ul>
     *   <li>0-15 : delta value added to the previous table's length at this position</li>
     *   <li>16   : repeat previous symbol's length for 3 + (3-bit count) times</li>
     *   <li>17   : zero run of 3 + (3-bit count)</li>
     *   <li>18   : zero run of 11 + (7-bit count)</li>
     *   <li>19   : zero run of 3 + (1-bit count)</li>
     * </ul>
     *
     * @param reader     the bit decoder
     * @param prevTable  previous table's lengths (for delta decoding); modified in place
     * @param target     output array receiving the decoded lengths
     * @param symbolCount number of symbols to decode
     * @throws IOException on stream error or malformed data
     */
    public static void readLengthTable(Rar4BitDecoder reader, int[] prevTable, int[] target, int symbolCount) throws IOException {
       int[] preLengths = new int[PRE_TABLE_SIZE];
       for (int i = 0; i < PRE_TABLE_SIZE; i++) {
          int raw = reader.peek16() >>> 12 & 0xFF;
          reader.skip(4);
          if (raw == 15) {
             int zeroRun = reader.peek16() >>> 12 & 0xFF;
             reader.skip(4);
             if (zeroRun == 0) {
                preLengths[i] = 15;
             } else {
                zeroRun += 2;
                while (zeroRun-- > 0 && i < PRE_TABLE_SIZE)
                   preLengths[i++] = 0;
                i--;
             }
          } else {
             preLengths[i] = raw;
          }
       }

       Rar4HuffmanDecoder preTable = new Rar4HuffmanDecoder();
       preTable.build(preLengths, PRE_TABLE_SIZE);

       int pos = 0;
       while (pos < symbolCount) {
          int sym = preTable.decode(reader);
          if (sym < 16) {
             target[pos] = (sym + prevTable[pos]) & 0xF;
             pos++;
          } else if (sym == 16) {
             int count = (reader.peek16() >>> 13) + 3;
             reader.skip(3);
             count = Math.min(count, symbolCount - pos);
             int rep = (pos > 0) ? target[pos - 1] : 0;
             while (count-- > 0)
                target[pos++] = rep;
          } else if (sym == 17) {
             int count = (reader.peek16() >>> 9) + 11;
             reader.skip(7);
             count = Math.min(count, symbolCount - pos);
             int rep = (pos > 0) ? target[pos - 1] : 0;
             while (count-- > 0)
                target[pos++] = rep;
          } else if (sym == 18) {
             int count = (reader.peek16() >>> 13) + 3;
             reader.skip(3);
             count = Math.min(count, symbolCount - pos);
             while (count-- > 0)
                target[pos++] = 0;
          } else {
             int count = (reader.peek16() >>> 9) + 11;
             reader.skip(7);
             count = Math.min(count, symbolCount - pos);
             while (count-- > 0)
                target[pos++] = 0;
          }
       }
    }
   
}