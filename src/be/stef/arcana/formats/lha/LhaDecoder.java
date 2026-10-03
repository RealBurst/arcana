/*
 * Copyright 2025 Stephane Bury - Derived from Apache Commons Compress
 * (LhStaticHuffmanCompressorInputStream.java, Apache License 2.0).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Decompresses LZH data for the LHA compression methods -lh4-, -lh5-, -lh6- and -lh7-.
 *
 * <p>All four methods use the same "static Huffman + LZ77 sliding window" algorithm
 * with different dictionary and distance-code parameters:</p>
 *
 * <table>
 *   <tr><th>Method</th><th>dictBits</th><th>distanceBits</th><th>maxDistCodes</th></tr>
 *   <tr><td>-lh4-</td><td>12</td><td>4</td><td>14</td></tr>
 *   <tr><td>-lh5-</td><td>13</td><td>4</td><td>14</td></tr>
 *   <tr><td>-lh6-</td><td>15</td><td>5</td><td>16</td></tr>
 *   <tr><td>-lh7-</td><td>16</td><td>5</td><td>17</td></tr>
 * </table>
 *
 * <p>Derived from {@code org.apache.commons.compress.archivers.lha
 * .LhStaticHuffmanCompressorInputStream} (Apache License 2.0).
 * Main changes: uses Arcana's {@link LhaBitInputStream}, {@link LhaBinaryTree} and
 * {@link LhaCircularBuffer}; replaces {@code CompressorException} with
 * {@code IOException}.</p>
 */
public final class LhaDecoder extends FilterInputStream {

    // ---- Constants shared by all methods -----------------------------------
    private static final int COMMAND_DECODING_LENGTH_BITS          = 5;
    private static final int MAX_COMMAND_DECODING_CODE_LENGTHS      = 19;
    private static final int COMMAND_TREE_LENGTH_BITS               = 9;
    private static final int NUMBER_OF_LITERALS                     = 0x100; // 256 literal byte values
    private static final int CODE_LENGTH_BITS                       = 3;
    private static final int MAX_CODE_LENGTH                        = 16;
    private static final int MAX_MATCH_LENGTH                       = 256;
    private static final int COPY_THRESHOLD                         = 3;    // minimum match length

    // ---- Per-method parameters -----------------------------------------------
    private final int dictionaryBits;
    private final int distanceBits;
    private final int maxDistanceCodes;

    // ---- Runtime state -------------------------------------------------------
    private LhaBitInputStream   bin;
    private LhaCircularBuffer   buffer;
    private int                  blockSize;  // commands remaining in the current block; 0 = start next block; -1 = EOS
    private LhaBinaryTree        commandTree;
    private LhaBinaryTree        distanceTree;

    // ---- Factory methods ------------------------------------------------------

    /** Creates a decoder for LHA -lh4- (dict 4KB, 4-bit distance). */
    static LhaDecoder lh4(final InputStream in) throws IOException { return new LhaDecoder(in, 12, 4, 14); }
    /** Creates a decoder for LHA -lh5- (dict 8KB, 4-bit distance). */
    static LhaDecoder lh5(final InputStream in) throws IOException { return new LhaDecoder(in, 13, 4, 14); }
    /** Creates a decoder for LHA -lh6- (dict 32KB, 5-bit distance). */
    static LhaDecoder lh6(final InputStream in) throws IOException { return new LhaDecoder(in, 15, 5, 16); }
    /** Creates a decoder for LHA -lh7- (dict 64KB, 5-bit distance). */
    static LhaDecoder lh7(final InputStream in) throws IOException { return new LhaDecoder(in, 16, 5, 17); }
    /**
     * Creates a decoder for ARJ methods 1 to 3 (same coding as -lh7-, 26 KiB window).
     * The stream does not end by itself: the caller stops at the original size.
     *
     * @since 1.0.4
     */
    public static LhaDecoder arj(final InputStream in) throws IOException { return new LhaDecoder(in, 16, 5, 17); }

    // ---- Constructor ---------------------------------------------------------

    private LhaDecoder(final InputStream in, final int dictionaryBits, final int distanceBits, final int maxDistanceCodes) throws IOException {
        super(in);
        this.dictionaryBits  = dictionaryBits;
        this.distanceBits    = distanceBits;
        this.maxDistanceCodes = maxDistanceCodes;
        this.bin             = new LhaBitInputStream(in);
        // Buffer must hold the full dictionary plus the maximum match length
        this.buffer          = new LhaCircularBuffer((1 << dictionaryBits) + MAX_MATCH_LENGTH);
        this.blockSize       = 0; // trigger read of first block header
    }

    // ---- InputStream ---------------------------------------------------------

    @Override
    public int read() throws IOException {
        if (!buffer.available()) {
            fillBuffer();
        }
        return buffer.get();
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        int count = 0;
        while (count < len) {
            if (!buffer.available()) {
                fillBuffer();
                if (!buffer.available()) break; // EOS
            }
            b[off + count++] = (byte) buffer.get();
        }
        return count == 0 ? -1 : count;
    }

    @Override
    public void close() throws IOException {
        bin    = null;
        buffer = null;
        blockSize = -1;
    }

    // ---- Private decode logic ------------------------------------------------

    /**
     * Fills the circular buffer with one decompressed token (literal byte or
     * back-reference copy).
     */
    private void fillBuffer() throws IOException {
        if (blockSize == -1) return; // already at EOS

        if (blockSize == 0) {
            // Start reading the next compressed block
            final long bs = bin.readBits(16);
            if (bs < 0) { blockSize = -1; return; }
            blockSize = (int) bs;
            if (blockSize == 0) { blockSize = -1; return; }
            final LhaBinaryTree cmdDecTree = readCommandDecodingTree();
            commandTree  = readCommandTree(cmdDecTree);
            distanceTree = readDistanceTree();
        }

        blockSize--;
        final int command = commandTree.read(bin);
        if (command < 0) throw new IOException("LHA: unexpected end of stream in command tree");

        if (command < NUMBER_OF_LITERALS) {
            buffer.put(command);
        } else {
            final int distance = readDistance();
            final int length   = command - NUMBER_OF_LITERALS + COPY_THRESHOLD;
            try {
                buffer.copy(distance + 1, length);
            } catch (final IllegalArgumentException e) {
                throw new IOException("LHA: bad back-reference (distance=" + distance + ", length=" + length + "): " + e.getMessage(), e);
            }
        }
    }

    // ---- Huffman tree reading -------------------------------------------------

    private int readBits(final int count) throws IOException {
        final long v = bin.readBits(count);
        if (v < 0) throw new IOException("LHA: unexpected end of stream");
        return (int) v;
    }

    /**
     * Reads a single code length.  Lengths 0-6 are stored as 3 bits.
     * Length 7 is extended: count the following consecutive 1-bits.
     */
    private int readCodeLength() throws IOException {
        int len = readBits(CODE_LENGTH_BITS);
        if (len == 7) {
            int bit = bin.readBit();
            while (bit == 1) {
                if (++len > MAX_CODE_LENGTH) throw new IOException("LHA: code length overflow");
                bit = bin.readBit();
            }
            if (bit < 0) throw new IOException("LHA: unexpected end of stream");
        }
        return len;
    }

    /**
     * Reads the "command decoding tree" (meta-tree that encodes the command-tree lengths).
     */
    private LhaBinaryTree readCommandDecodingTree() throws IOException {
        final int n = readBits(COMMAND_DECODING_LENGTH_BITS);
        if (n > MAX_COMMAND_DECODING_CODE_LENGTHS) throw new IOException("LHA: command decoding tree too large (" + n + ")");
        if (n == 0) return new LhaBinaryTree(readBits(COMMAND_DECODING_LENGTH_BITS));
        final int[] lengths = new int[n];
        for (int i = 0; i < n; i++) {
            lengths[i] = readCodeLength();
            if (i == 2) {
                // Skip a range after the first three entries
                i += readBits(2);
            }
        }
        return new LhaBinaryTree(lengths);
    }

    /**
     * Reads the command tree (decodes literal bytes and match-length codes).
     */
    private LhaBinaryTree readCommandTree(final LhaBinaryTree decTree) throws IOException {
        final int maxCmds = NUMBER_OF_LITERALS + MAX_MATCH_LENGTH - COPY_THRESHOLD + 1;
        final int n       = readBits(COMMAND_TREE_LENGTH_BITS);
        if (n > maxCmds) throw new IOException("LHA: command tree too large (" + n + ")");
        if (n == 0) return new LhaBinaryTree(readBits(COMMAND_TREE_LENGTH_BITS));
        final int[] lengths = new int[n];
        int i = 0;
        while (i < n) {
            final int code = decTree.read(bin);
            if (code < 0) throw new IOException("LHA: unexpected EOS in command tree");
            switch (code) {
                case 0: i++;                           break; // zero length (skip)
                case 1: i += readBits(4)  + 3;        break;
                case 2: i += readBits(9)  + 20;       break;
                default: lengths[i++] = code - 2;     break;
            }
        }
        return new LhaBinaryTree(lengths);
    }

    /**
     * Reads the distance tree (encodes the number of bits for each distance value).
     */
    private LhaBinaryTree readDistanceTree() throws IOException {
        final int n = readBits(distanceBits);
        if (n > maxDistanceCodes) throw new IOException("LHA: distance tree too large (" + n + ")");
        if (n == 0) return new LhaBinaryTree(readBits(distanceBits));
        final int[] lengths = new int[n];
        for (int i = 0; i < n; i++) {
            lengths[i] = readCodeLength();
        }
        return new LhaBinaryTree(lengths);
    }

    /**
     * Reads an encoded distance value.  The distance-tree encodes the number of
     * raw bits to read; the actual distance is reconstructed by adding an
     * implicit leading 1-bit.
     */
    private int readDistance() throws IOException {
        final int bits = distanceTree.read(bin);
        if (bits < 0) throw new IOException("LHA: unexpected EOS in distance tree");
        if (bits <= 1) return bits;
        final int value = readBits(bits - 1);
        return value | (1 << (bits - 1));
    }
}
