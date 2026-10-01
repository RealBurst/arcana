/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.cab;

import java.io.IOException;
import java.util.Arrays;

/**
 * Decompresses data in Microsoft's LZX format as used in Cabinet files.
 *
 * <p>LZ77 sliding window (2^windowBits), Huffman-coded symbols, three block types
 * (VERBATIM, ALIGNED, UNCOMPRESSED), delta-encoded Huffman trees, R0/R1/R2 distance cache.</p>
 *
 * <p>Window and decoder state persist across CFDATA blocks within the same CFFOLDER.</p>
 *
 * @author Stef
 * @since 1.3
 */
final class LzxDecoder {

    private static final int BLOCK_VERBATIM     = 1;
    private static final int BLOCK_ALIGNED      = 2;
    private static final int BLOCK_UNCOMPRESSED = 3;

    private static final int NUM_PRETREE_SYMBOLS  = 20;
    private static final int NUM_ALIGNED_SYMBOLS  = 8;
    private static final int NUM_LENGTH_SYMBOLS   = 249;
    private static final int NUM_CHARS            = 256;
    private static final int PRETREE_BITS         = 4;
    private static final int ALIGNED_BITS         = 3;
    private static final int MIN_MATCH            = 2;

    // position slot tables (MS-LZX spec Table 2)
    private static final int[] SLOT_BASE;
    private static final int[] SLOT_FOOTER_BITS;
    static {
        SLOT_BASE        = new int[50];
        SLOT_FOOTER_BITS = new int[50];
        SLOT_BASE[0] = 0; SLOT_FOOTER_BITS[0] = 0;
        SLOT_BASE[1] = 1; SLOT_FOOTER_BITS[1] = 0;
        int base = 2, bits = 0;
        for (int i = 2; i < 50; i++) {
            SLOT_BASE[i]        = base;
            SLOT_FOOTER_BITS[i] = bits;
            base += (1 << bits);
            if ((i % 2) == 0) bits++;
        }
    }

    private final int windowSize;
    private final int windowMask;
    private final int numPositionSlots;
    private final int numMainSymbols;

    private final byte[] window;
    private int windowPos = 0;

    private int r0 = 1, r1 = 1, r2 = 1;

    private final int[] pretreeLens  = new int[NUM_PRETREE_SYMBOLS];
    private final int[] mainLens;
    private final int[] lengthLens   = new int[NUM_LENGTH_SYMBOLS];
    private final int[] alignedLens  = new int[NUM_ALIGNED_SYMBOLS];

    private int blockType       = 0;
    private int blockRemaining  = 0;

    // bit stream
    private byte[] input;
    private int    inputPos;
    private int    inputEnd;
    private long   bitBuf   = 0;
    private int    bitsLeft = 0;

    // output
    private byte[] output;
    private int    outputPos;
    private int    outputEnd;

    LzxDecoder(int windowBits) throws IOException {
        if (windowBits < 15 || windowBits > 21) throw new IOException("CAB: LZX invalid window bits: " + windowBits);
        windowSize       = 1 << windowBits;
        windowMask       = windowSize - 1;
        numPositionSlots = numSlotsForWindow(windowBits);
        numMainSymbols   = NUM_CHARS + numPositionSlots * 8;
        window           = new byte[windowSize];
        mainLens         = new int[numMainSymbols];
        reset();
    }

    void reset() {
        r0 = r1 = r2 = 1;
        windowPos      = 0;
        blockRemaining = 0;
        blockType      = 0;
        Arrays.fill(mainLens,   0);
        Arrays.fill(lengthLens, 0);
    }

    void decompress(byte[] compressed, int compressedLen, byte[] uncompressed, int uncompressedLen) throws IOException {
        input     = compressed;
        inputPos  = 0;
        inputEnd  = compressedLen;
        output    = uncompressed;
        outputPos = 0;
        outputEnd = uncompressedLen;
        initBits();
        while (outputPos < outputEnd) {
            if (blockRemaining == 0) readBlockHeader();
            decodeBlock();
        }
    }

    // =========================================================================
    // Block header
    // =========================================================================

    private void readBlockHeader() throws IOException {
        blockType      = (int) readBits(3);
        long hi        = readBits(16);
        long lo        = readBits(8);
        blockRemaining = (int)((hi << 8) | lo);

        if (blockType == BLOCK_ALIGNED) {
            for (int i = 0; i < NUM_ALIGNED_SYMBOLS; i++) alignedLens[i] = (int) readBits(ALIGNED_BITS);
        }
        if (blockType == BLOCK_VERBATIM || blockType == BLOCK_ALIGNED) {
            readLens(mainLens, 0, 256);
            readLens(mainLens, 256, numMainSymbols);
            readLens(lengthLens, 0, NUM_LENGTH_SYMBOLS);
        } else if (blockType == BLOCK_UNCOMPRESSED) {
            alignBits16();
            r0 = readInt32LE();
            r1 = readInt32LE();
            r2 = readInt32LE();
        } else {
            throw new IOException("CAB: LZX unknown block type: " + blockType);
        }
    }

    // =========================================================================
    // Decode one block
    // =========================================================================

    private void decodeBlock() throws IOException {
        if (blockType == BLOCK_UNCOMPRESSED) {
            while (outputPos < outputEnd && blockRemaining > 0) {
                byte b = (byte) readRawByte();
                output[outputPos++] = b;
                window[windowPos]   = b;
                windowPos = (windowPos + 1) & windowMask;
                blockRemaining--;
            }
            return;
        }

        // Build decode tables once per block (build inline to avoid per-symbol overhead)
        int[] mainDec   = buildTable(mainLens,   numMainSymbols, 12);
        int[] lenDec    = buildTable(lengthLens,  NUM_LENGTH_SYMBOLS, 12);
        int[] alignDec  = (blockType == BLOCK_ALIGNED) ? buildTable(alignedLens, NUM_ALIGNED_SYMBOLS, 7) : null;

        while (outputPos < outputEnd && blockRemaining > 0) {
            int symbol = decode(mainDec, mainLens, numMainSymbols);
            if (symbol < NUM_CHARS) {
                byte b = (byte) symbol;
                window[windowPos]   = b;
                output[outputPos++] = b;
                windowPos = (windowPos + 1) & windowMask;
            } else {
                int matchSym  = symbol - NUM_CHARS;
                int posSlot   = matchSym >> 3;
                int lenHeader = matchSym & 7;

                int matchLen;
                if (lenHeader == 7) matchLen = 7 + MIN_MATCH + decode(lenDec, lengthLens, NUM_LENGTH_SYMBOLS);
                else                matchLen = lenHeader + MIN_MATCH;

                int matchDist;
                if (posSlot == 0) {
                    matchDist = r0;
                } else if (posSlot == 1) {
                    matchDist = r1; r1 = r0; r0 = matchDist;
                } else if (posSlot == 2) {
                    matchDist = r2; r2 = r0; r0 = matchDist;
                } else {
                    int footerBits = SLOT_FOOTER_BITS[posSlot];
                    int base       = SLOT_BASE[posSlot];
                    int footer;
                    if (blockType == BLOCK_ALIGNED && footerBits >= 3) {
                        footer  = (int) readBits(footerBits - 3) << 3;
                        footer |= decode(alignDec, alignedLens, NUM_ALIGNED_SYMBOLS);
                    } else {
                        footer = (int) readBits(footerBits);
                    }
                    matchDist = base + footer;
                    r2 = r1; r1 = r0; r0 = matchDist;
                }
                copyMatch(matchDist, matchLen);
            }
            blockRemaining--;
        }
    }

    private void copyMatch(int dist, int len) throws IOException {
        if (dist > windowSize) throw new IOException("CAB: LZX match distance " + dist + " > window " + windowSize);
        int src = (windowPos - dist + windowSize) & windowMask;
        for (int i = 0; i < len && outputPos < outputEnd; i++) {
            byte b = window[src];
            window[windowPos]   = b;
            output[outputPos++] = b;
            src       = (src + 1) & windowMask;
            windowPos = (windowPos + 1) & windowMask;
        }
    }

    // =========================================================================
    // Huffman tree delta-decode
    // =========================================================================

    private void readLens(int[] lens, int start, int end) throws IOException {
        // Read pretree (20 symbols x 4 bits)
        for (int i = 0; i < NUM_PRETREE_SYMBOLS; i++) pretreeLens[i] = (int) readBits(PRETREE_BITS);
        int[] preDec = buildTable(pretreeLens, NUM_PRETREE_SYMBOLS, 10);

        int i = start;
        while (i < end) {
            int sym = decode(preDec, pretreeLens, NUM_PRETREE_SYMBOLS);
            if (sym < 17) {
                lens[i] = (lens[i] - sym + 17) % 17;
                i++;
            } else if (sym == 17) {
                int zeros = (int) readBits(4) + 4;
                for (int j = 0; j < zeros && i < end; j++) lens[i++] = 0;
            } else if (sym == 18) {
                int zeros = (int) readBits(5) + 20;
                for (int j = 0; j < zeros && i < end; j++) lens[i++] = 0;
            } else if (sym == 19) {
                int same = (int) readBits(1) + 4;
                int next = decode(preDec, pretreeLens, NUM_PRETREE_SYMBOLS);
                int val  = (lens[i] - next + 17) % 17;
                for (int j = 0; j < same && i < end; j++) lens[i++] = val;
            }
        }
    }

    // =========================================================================
    // Huffman table (canonical, up to maxBits wide, 10-bit direct lookup)
    // =========================================================================

    private static int[] buildTable(int[] lens, int nSyms, int maxBits) throws IOException {
        int tBits  = Math.min(maxBits, 10);
        int tSize  = 1 << tBits;
        int[] tbl  = new int[tSize];
        Arrays.fill(tbl, -1);

        int[] count    = new int[maxBits + 1];
        for (int i = 0; i < nSyms; i++) if (lens[i] > 0) count[lens[i]]++;

        int[] nextCode = new int[maxBits + 1];
        int code = 0;
        for (int len = 1; len <= maxBits; len++) {
            nextCode[len] = code;
            code += count[len];
            if (len < maxBits) code <<= 1;
        }

        for (int sym = 0; sym < nSyms; sym++) {
            int len = lens[sym];
            if (len == 0) continue;
            int c = nextCode[len]++;
            if (len <= tBits) {
                int shift = tBits - len;
                int from  = c << shift;
                int to    = from + (1 << shift);
                int entry = sym | (len << 16);
                for (int j = from; j < to && j < tSize; j++) tbl[j] = entry;
            }
            // codes longer than tBits: fall back to bit-by-bit in decode()
        }
        return tbl;
    }

    private int decode(int[] tbl, int[] lens, int nSyms) throws IOException {
        int peek  = (int) peekBits(Math.min(10, bitsLeft > 0 ? bitsLeft : 10));
        if (peek < tbl.length && tbl[peek] >= 0) {
            int entry = tbl[peek];
            readBitsNoCheck(entry >>> 16);
            return entry & 0xFFFF;
        }
        // Slow bit-by-bit path for codes > 10 bits or table miss
        return decodeSlow(lens, nSyms);
    }

    private int decodeSlow(int[] lens, int nSyms) throws IOException {
        // Rebuild a full canonical mapping and decode bit by bit
        int[] nextCode = new int[17];
        int[] count    = new int[17];
        for (int i = 0; i < nSyms; i++) if (lens[i] > 0) count[lens[i]]++;
        int c = 0;
        for (int len = 1; len <= 16; len++) { nextCode[len] = c; c += count[len]; if (len < 16) c <<= 1; }

        int code = 0;
        for (int len = 1; len <= 16; len++) {
            code = (code << 1) | (int) readBits(1);
            int base = nextCode[len];
            if (code - base < count[len]) {
                // find the symbol
                int idx = code - base;
                for (int sym = 0; sym < nSyms; sym++) {
                    if (lens[sym] == len) {
                        if (idx == 0) return sym;
                        idx--;
                    }
                }
            }
        }
        throw new IOException("CAB: LZX Huffman decode failed");
    }

    // =========================================================================
    // Bit stream (16-bit LE words)
    // =========================================================================

    private void initBits() throws IOException { bitBuf = 0; bitsLeft = 0; refill(); }

    private void refill() throws IOException {
        while (bitsLeft <= 48 && inputPos + 1 < inputEnd) {
            int lo = input[inputPos++] & 0xFF;
            int hi = input[inputPos++] & 0xFF;
            bitBuf   = (bitBuf << 16) | (hi << 8) | lo;
            bitsLeft += 16;
        }
    }

    private long readBits(int count) throws IOException {
        refill();
        if (bitsLeft < count) throw new IOException("CAB: LZX unexpected end of bit stream");
        bitsLeft -= count;
        return (bitBuf >>> bitsLeft) & ((1L << count) - 1);
    }

    private void readBitsNoCheck(int count) { bitsLeft -= count; }

    private long peekBits(int count) throws IOException {
        refill();
        if (bitsLeft < count) return (bitBuf << (count - bitsLeft)) & ((1L << count) - 1);
        return (bitBuf >>> (bitsLeft - count)) & ((1L << count) - 1);
    }

    private void alignBits16() {
        int excess = bitsLeft % 16;
        if (excess > 0) bitsLeft -= excess;
    }

    private int readRawByte() throws IOException {
        if (inputPos >= inputEnd) throw new IOException("CAB: LZX unexpected end of stream");
        return input[inputPos++] & 0xFF;
    }

    private int readInt32LE() throws IOException {
        return readRawByte() | (readRawByte() << 8) | (readRawByte() << 16) | (readRawByte() << 24);
    }

    private static int numSlotsForWindow(int bits) {
        switch (bits) {
            case 15: return 30; case 16: return 32; case 17: return 34;
            case 18: return 36; case 19: return 38; case 20: return 42;
            case 21: return 50; default:  return 30;
        }
    }
}
