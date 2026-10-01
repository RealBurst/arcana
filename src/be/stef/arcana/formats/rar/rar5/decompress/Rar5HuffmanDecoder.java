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
package be.stef.arcana.formats.rar.rar5.decompress;

import java.util.Arrays;

/**
 * Byte-based Huffman decoder for RAR5.
 * 
 * <p>This decoder supports up to 15-bit codes (RAR5 standard) and uses a
 * two-level decoding strategy:</p>
 * <ul>
 *   <li><b>Fast path:</b> Short codes (<= fastLookupBits) use direct table lookup - O(1)</li>
 *   <li><b>Slow path:</b> Long codes use threshold search to find code length</li>
 * </ul>
 * 
 * <p>The decoder must be built with {@link #build(byte[], int)} before use.
 * It can be reset and rebuilt for each new Huffman table in the stream.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5HuffmanDecoder {
   public static final int HUFFMAN_BUILD_MODE_PARTIAL = 0;         // Build mode: partial tree allowed (some codes may be unused)
   public static final int HUFFMAN_BUILD_MODE_FULL = 1;            // Build mode: full tree required (all code space must be used)
   public static final int HUFFMAN_BUILD_MODE_FULL_OR_EMPTY = 2;   // Build mode: full tree or completely empty tree
   private final int maxCodeLength;      // Maximum code length in bits (15 for RAR5)
   private final int alphabetSize;       // Number of symbols in the alphabet
   private final int fastLookupBits;     // Number of bits used for fast lookup table
   private int[] lengthThresholds;       // Thresholds for determining code length (long codes only)
   private int[] symbolOffsets;          // Symbol offsets for each code length (long codes only)
   private byte[] codeLengths;           // Code lengths for fast lookup table entries
   private int[] symbols;                // Decoded symbols table
   private boolean isReady;              // Flag indicating whether the decoder is ready to use
   
   
    /**
     * Creates a new Huffman decoder.
     * 
     * @param maxCodeLength maximum code length in bits (15 for RAR5)
     * @param alphabetSize number of symbols in the alphabet
     * @param fastLookupBits bits for fast lookup table (trades memory for speed)
     */
    public Rar5HuffmanDecoder(int maxCodeLength, int alphabetSize, int fastLookupBits) {
        this.maxCodeLength = maxCodeLength;
        this.alphabetSize = alphabetSize;
        this.fastLookupBits = fastLookupBits;
        this.lengthThresholds = new int[maxCodeLength + 2 - fastLookupBits];
        this.symbolOffsets = new int[maxCodeLength - fastLookupBits];
        this.codeLengths = new byte[1 << fastLookupBits];
        this.symbols = new int[(1 << fastLookupBits) + alphabetSize - (fastLookupBits + 1)];
        this.isReady = false;
        reset();
    }

    /**
     * Builds the Huffman tree from code lengths.
     * 
     * @param lengths array of code lengths for each symbol
     * @param buildMode build mode constant (HUFFMAN_BUILD_MODE_*)
     * @return true if build succeeded, false if the code lengths are invalid
     */
    public boolean build(byte[] lengths, int buildMode) {
        return build(lengths, 0, buildMode);
    }

    /**
     * Builds the Huffman tree from code lengths with offset.
     * 
     * <p>This method constructs both the fast lookup table for short codes
     * and the threshold/offset tables for long codes.</p>
     * 
     * @param lengths array of code lengths
     * @param offset starting offset in lengths array
     * @param buildMode build mode constant (HUFFMAN_BUILD_MODE_*)
     * @return true if build succeeded, false if the code lengths are invalid
     */
    public boolean build(byte[] lengths, int offset, int buildMode) {
        // Count symbols by code length
        int[] countsByLength = new int[maxCodeLength + 1];
        Arrays.fill(countsByLength, 0);

        for (int symbolIndex = 0; symbolIndex < alphabetSize; symbolIndex++) {
            int codeLength = lengths[offset + symbolIndex] & 0xFF;
            if (codeLength > maxCodeLength) {
                return false;
            }
            countsByLength[codeLength]++;
        }

        // Calculate sum for short codes (fast lookup table)
        int shortCodeSum = 0;
        for (int bitCount = 1; bitCount <= fastLookupBits; bitCount++) {
            shortCodeSum <<= 1;
            shortCodeSum += countsByLength[bitCount];
        }

        // Build thresholds and offsets for long codes
        int codePosition = shortCodeSum;
        lengthThresholds[0] = codePosition;

        for (int bitCount = fastLookupBits + 1; bitCount <= maxCodeLength; bitCount++) {
            codePosition <<= 1;
            symbolOffsets[bitCount - (fastLookupBits + 1)] = codePosition - shortCodeSum;

            int symbolCount = countsByLength[bitCount];
            countsByLength[bitCount] = shortCodeSum;
            shortCodeSum += symbolCount;
            codePosition += symbolCount;

            lengthThresholds[bitCount - fastLookupBits] = codePosition << (maxCodeLength - bitCount);
        }

        // Final sentinel value
        lengthThresholds[maxCodeLength + 1 - fastLookupBits] = 1 << maxCodeLength;

        // Verify tree completeness based on build mode
        if (buildMode == HUFFMAN_BUILD_MODE_PARTIAL) {
            if (codePosition > (1 << maxCodeLength)) {
                return false;
            }
        } else {
            if (buildMode != HUFFMAN_BUILD_MODE_FULL && codePosition == 0) {
                isReady = true;
                return true;
            }
            if (codePosition != (1 << maxCodeLength)) {
                return false;
            }
        }

        // Build fast lookup table for short codes
        int tablePosition = 0;
        for (int bitCount = 1; bitCount <= fastLookupBits; bitCount++) {
            int entryCount = countsByLength[bitCount] << (fastLookupBits - bitCount);
            countsByLength[bitCount] = tablePosition >> (fastLookupBits - bitCount);
            Arrays.fill(this.codeLengths, tablePosition, tablePosition + entryCount, (byte) bitCount);
            tablePosition += entryCount;
        }

        // Fill symbols table
        for (int symbolIndex = 0; symbolIndex < alphabetSize; symbolIndex++) {
            int codeLength = lengths[offset + symbolIndex] & 0xFF;
            if (codeLength == 0) {
                continue;
            }

            int symbolPosition = countsByLength[codeLength];
            countsByLength[codeLength] = symbolPosition + 1;

            if (codeLength <= fastLookupBits) {
                // Short code: fill lookup table with duplicates
                int fillStart = symbolPosition << (fastLookupBits - codeLength);
                int fillEnd = fillStart + (1 << (fastLookupBits - codeLength));

                for (int fillIndex = fillStart; fillIndex < fillEnd; fillIndex++) {
                    symbols[fillIndex] = symbolIndex;
                }
            } else {
                // Long code: store symbol directly
                symbols[symbolPosition] = symbolIndex;
            }
        }

        isReady = true;
        return true;
    }

    /**
     * Decodes a symbol from the bit stream.
     * 
     * <p>Uses fast table lookup for short codes (<= fastLookupBits) and
     * threshold-based search for longer codes.</p>
     * 
     * @param bitStream the bit stream to read from
     * @return the decoded symbol
     */
    public int decode(Rar5BitDecoder bitStream) {
        // Read maxCodeLength bits without advancing
        int bitValue = bitStream.getValueFast15();

        // Extract high bits for fast lookup table
        int lookupIndex = bitValue >>> (maxCodeLength - fastLookupBits);

        // Fast path: short code
        if (lookupIndex < lengthThresholds[0]) {
            int codeLength = codeLengths[lookupIndex] & 0xFF;
            int symbol = symbols[lookupIndex];
            bitStream.movePos(codeLength);
            return symbol;
        }

        // Slow path: long code - find code length via threshold search
        int codeLength = fastLookupBits + 1;

        if (bitValue >= lengthThresholds[1]) {
            do {
                codeLength++;
            } while (bitValue >= lengthThresholds[codeLength - fastLookupBits]);
        }

        // Calculate symbol position
        int shift = maxCodeLength - codeLength;
        int symbolPosition = (bitValue >>> shift) - symbolOffsets[codeLength - (fastLookupBits + 1)];

        bitStream.movePos(codeLength);
        return symbols[symbolPosition];
    }

    /**
     * Checks if the decoder has been built and is ready to decode.
     * 
     * @return true if the decoder is ready
     */
    public boolean isReady() {
        return isReady;
    }

    /**
     * Resets the decoder state.
     * 
     * <p>Clears all tables and marks the decoder as not ready.
     * Must call {@link #build(byte[], int)} again before decoding.</p>
     */
    public void reset() {
        if (lengthThresholds != null) Arrays.fill(lengthThresholds, 0);
        if (symbolOffsets != null) Arrays.fill(symbolOffsets, 0);
        if (codeLengths != null) Arrays.fill(codeLengths, (byte) 0);
        if (symbols != null) Arrays.fill(symbols, 0);
        isReady = false;
    }
}
