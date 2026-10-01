/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Compresses data using the LHA -lh5-, -lh6- or -lh7- algorithm.
 *
 * <h3>Algorithm overview</h3>
 * <ol>
 *   <li><b>LZ77 pass</b>: scans the input with a sliding dictionary of 8 KB
 *       (-lh5-), 32 KB (-lh6-) or 64 KB (-lh7-) and emits tokens:
 *       <ul>
 *         <li>Literal - one uncompressed byte (0-255)</li>
 *         <li>Back-reference - (distance, length) pair where
 *             length is 3..256 and distance &lt; dictionary size</li>
 *       </ul>
 *       Matches are found with hash chains on 3-byte strings, and chosen with
 *       lazy evaluation (a match is postponed by one byte when the next position
 *       gives a longer one), like zlib's best levels.</li>
 *   <li><b>Block encoding</b>: every {@value #BLOCK_SIZE} tokens a block is
 *       written.  The command frequency table determines the Huffman tree for
 *       that block; similarly for distances.</li>
 *   <li><b>Static Huffman output</b>: the three trees (command-decoding,
 *       command, distance) are serialised before the block's token stream.</li>
 * </ol>
 *
 * <p>The input is streamed through a sliding window: memory use does not
 * depend on the input size.</p>
 *
 * <p>This class is used by {@link LhaWriter} to compress file data.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class Lh5Encoder {

    // ---- -lhN- parameters -----------------------------------------------
    /** Method of the default dictionary size (8 KB, the most compatible). */
    static final String METHOD       = "-lh5-";
    /** Dictionary size bits of -lh5-, -lh6- and -lh7-. */
    public static final int LH5 = 13, LH6 = 15, LH7 = 16;
    private static final int MAX_MATCH      = 256;
    private static final int MIN_MATCH      = 3;                        // COPY_THRESHOLD

    // Command codes: 0..255 = literals, 256..509 = (matchLen - MIN_MATCH + 256)
    private static final int NUM_LITERALS   = 256;
    private static final int MAX_COMMANDS   = NUM_LITERALS + MAX_MATCH - MIN_MATCH + 1; // 510

    // Block size: number of commands per block (16-bit field; larger blocks amortise the trees)
    private static final int BLOCK_SIZE     = 16384;

    // Command decoding tree symbols (meta-tree for encoding the command tree's code lengths)
    private static final int MAX_CD_SYMS    = 19;

    // ---- Match finder tuning (zlib level 9 values) --------------------------
    private static final int MAX_CHAIN   = 1024; // positions examined per search
    private static final int GOOD_LENGTH = 32;   // search less when the previous match is this long
    private static final int NICE_LENGTH = MAX_MATCH; // stop searching at this length
    private static final int TOO_FAR     = 4096; // a 3-byte match farther than this costs more than 3 literals

    private static final int HASH_BITS   = 16;
    private static final int HASH_SIZE   = 1 << HASH_BITS;
    private static final int NIL         = -1;
    private static final int MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1;

    // ---- Method parameters ------------------------------------------------
    private final int wsize;         // dictionary size
    private final int wmask;
    private final int maxDistCodes;  // dictBits + 1
    private final int distanceBits;  // bits of the distance tree size field (4 for lh5, 5 for lh6/lh7)

    // ---- LZ77 state (zlib-style sliding window) -------------------------------
    private final byte[]  window;    // 2 x wsize (+ lookahead margin)
    private final int[]   head = new int[HASH_SIZE]; // hash -> most recent position
    private final int[]   prev;      // position & wmask -> previous position with the same hash
    private int strstart;            // current position in window
    private int lookahead;           // bytes available from strstart
    private int matchStart;          // start of the match found by longestMatch
    private boolean eof;
    private InputStream src;

    // ---- Block accumulation -----------------------------------------------
    private final int[]   cmdBuf   = new int[BLOCK_SIZE]; // command values
    private final int[]   distBuf  = new int[BLOCK_SIZE]; // distance values (for match commands)
    private int           blockPos  = 0;                  // current position in cmdBuf/distBuf

    // ---- Frequency tables ------------------------------------------------
    private final int[]   cmdFreq  = new int[MAX_COMMANDS];
    private final int[]   distFreq;

    // ---- I/O -------------------------------------------------------
    private final LhaBitOutputStream bitOut;
    /** Counts compressed bytes written (used to compute compressed size). */
    private final CountingOutputStream counter;
    /** The original byte count of the underlying output. */
    private long startCount = 0;

    // ---- Constructor -----------------------------------------------------

    private Lh5Encoder(final OutputStream out, final int dictBits) {
        if (dictBits != LH5 && dictBits != LH6 && dictBits != LH7) throw new IllegalArgumentException("dictBits must be 13 (lh5), 15 (lh6) or 16 (lh7)");
        this.wsize        = 1 << dictBits;
        this.wmask        = wsize - 1;
        this.maxDistCodes = dictBits + 1;
        this.distanceBits = dictBits == LH5 ? 4 : 5;
        this.window       = new byte[2 * wsize + MIN_LOOKAHEAD];
        this.prev         = new int[wsize];
        this.distFreq     = new int[maxDistCodes];
        this.counter = new CountingOutputStream(out);
        this.bitOut  = new LhaBitOutputStream(counter);
        java.util.Arrays.fill(head, NIL);
        java.util.Arrays.fill(prev, NIL);
    }

    // ---- Public API ------------------------------------------------------

    /** LHA method name ("-lh5-", "-lh6-", "-lh7-") for a dictionary size. */
    public static String methodFor(final int dictBits) {
        switch (dictBits) {
            case LH5: return "-lh5-";
            case LH6: return "-lh6-";
            case LH7: return "-lh7-";
            default:  throw new IllegalArgumentException("dictBits must be 13 (lh5), 15 (lh6) or 16 (lh7)");
        }
    }

    /**
     * Compresses all bytes from {@code in} into the LHA -lh5- format and
     * writes the result to {@code out}.  Returns the number of compressed
     * bytes written.
     *
     * @param in  uncompressed data source
     * @param out compressed data destination
     * @return number of compressed bytes written to {@code out}
     * @throws IOException if an I/O error occurs
     */
    public static long compress(final InputStream in, final OutputStream out) throws IOException {
        return compress(in, out, LH5);
    }

    /**
     * Same as {@link #compress(InputStream, OutputStream)} with the dictionary
     * size of the method: {@link #LH5} (8 KB), {@link #LH6} (32 KB) or {@link #LH7} (64 KB).
     */
    public static long compress(final InputStream in, final OutputStream out, final int dictBits) throws IOException {
        final Lh5Encoder enc = new Lh5Encoder(out, dictBits);
        enc.startCount = enc.counter.getCount();
        enc.encode(in);
        enc.flush();
        return enc.counter.getCount() - enc.startCount;
    }

    // ---- Encoding --------------------------------------------------------

    /** Reads the input through the sliding window and emits the LZ77 tokens (lazy matching). */
    private void encode(final InputStream in) throws IOException {
        this.src = in;
        int hashCur = NIL;
        int matchLen = MIN_MATCH - 1;
        int matchPos = 0;
        boolean matchAvailable = false;

        while (true) {
            if (lookahead < MIN_LOOKAHEAD) {
                matchPos -= fillWindow(); // positions move down when the window slides
                if (lookahead == 0) break;
            }

            // Insert the string at strstart in the hash chains; hashCur = previous string with the same hash
            hashCur = lookahead >= MIN_MATCH ? insertString(strstart) : NIL;

            final int prevLen = matchLen;
            final int prevPos = matchPos;
            matchLen = MIN_MATCH - 1;

            if (hashCur != NIL && prevLen < MAX_MATCH && strstart - hashCur <= wsize) {
                matchLen = longestMatch(hashCur, prevLen);
                matchPos = matchStart;
                if (matchLen == MIN_MATCH && strstart - matchPos > TOO_FAR) matchLen = MIN_MATCH - 1;
            }

            if (prevLen >= MIN_MATCH && matchLen <= prevLen) {
                // The match found at the previous position is kept
                final int maxInsert = strstart + lookahead - MIN_MATCH;
                emitMatch(prevLen, (strstart - 1) - prevPos - 1);
                if (blockPos == BLOCK_SIZE) flushBlock();
                // strstart-1 and strstart are already inserted: insert the rest of the match
                lookahead -= prevLen - 1;
                int left = prevLen - 2;
                do {
                    if (++strstart <= maxInsert) insertString(strstart);
                } while (--left != 0);
                matchAvailable = false;
                matchLen = MIN_MATCH - 1;
                strstart++;
            } else if (matchAvailable) {
                // No better match: the previous byte goes out as a literal
                emitLiteral(window[strstart - 1] & 0xFF);
                if (blockPos == BLOCK_SIZE) flushBlock();
                strstart++;
                lookahead--;
            } else {
                // Wait for the next position to decide
                matchAvailable = true;
                strstart++;
                lookahead--;
            }
        }
        if (matchAvailable) {
            emitLiteral(window[strstart - 1] & 0xFF);
            if (blockPos == BLOCK_SIZE) flushBlock();
        }
    }

    /** Inserts the 3-byte string at {@code pos}; returns the previous head of its chain. */
    private int insertString(final int pos) {
        final int h = hash3(window, pos);
        final int old = head[h];
        prev[pos & wmask] = old;
        head[h] = pos;
        return old;
    }

    private static int hash3(final byte[] w, final int pos) {
        final int v = ((w[pos] & 0xFF) << 16) | ((w[pos + 1] & 0xFF) << 8) | (w[pos + 2] & 0xFF);
        return (v * 0x9E3779B1) >>> (32 - HASH_BITS);
    }

    /**
     * Longest match for the string at strstart, walking the hash chain from
     * {@code curMatch}. Sets {@link #matchStart} when a match longer than
     * {@code prevLen} is found and returns its length, otherwise returns prevLen.
     */
    private int longestMatch(int curMatch, final int prevLen) {
        final byte[] w = window;
        final int scan = strstart;
        final int maxLen = Math.min(MAX_MATCH, lookahead);
        int bestLen = prevLen;
        if (bestLen >= maxLen) return bestLen;
        int chain = prevLen >= GOOD_LENGTH ? MAX_CHAIN >> 2 : MAX_CHAIN;
        final int limit = strstart - wsize; // candidates must be closer than the dictionary size
        do {
            final int m = curMatch;
            // cheap rejection: the byte that would make the match longer, then the first two bytes
            if (w[m + bestLen] == w[scan + bestLen] && w[m] == w[scan] && w[m + 1] == w[scan + 1]) {
                int len = 2;
                while (len < maxLen && w[m + len] == w[scan + len]) len++;
                if (len > bestLen) {
                    matchStart = m;
                    bestLen = len;
                    if (len >= NICE_LENGTH || len >= maxLen) break;
                }
            }
            curMatch = prev[m & wmask];
        } while (curMatch > limit && curMatch >= 0 && --chain != 0);
        return bestLen;
    }

    /**
     * Refills the window. When strstart reaches the upper part, the second half
     * is moved down by wsize and every stored position is shifted (zlib technique).
     *
     * @return the shift applied to the positions (0 or wsize)
     */
    private int fillWindow() throws IOException {
        int shift = 0;
        if (strstart >= 2 * wsize - MIN_LOOKAHEAD) {
            System.arraycopy(window, wsize, window, 0, strstart + lookahead - wsize);
            matchStart -= wsize;
            strstart -= wsize;
            for (int i = 0; i < HASH_SIZE; i++) head[i] = head[i] >= wsize ? head[i] - wsize : NIL;
            for (int i = 0; i < wsize; i++) prev[i] = prev[i] >= wsize ? prev[i] - wsize : NIL;
            shift = wsize;
        }
        while (!eof && lookahead < MIN_LOOKAHEAD) {
            final int end = strstart + lookahead;
            final int n = src.read(window, end, window.length - end);
            if (n < 0) { eof = true; break; }
            lookahead += n;
        }
        return shift;
    }

    /**
     * Returns the distance code (0-16) for a given distance.
     * Code 0 -> distance 0 (1 byte back), code 1 -> distance 1,
     * code k (k>=2) -> distances [2^(k-1), 2^k - 1].
     */
    static int distanceBitsFor(final int dist) {
        if (dist <= 1) return dist;
        return 32 - Integer.numberOfLeadingZeros(dist);
    }

    // ---- Token emission --------------------------------------------------

    private void emitLiteral(final int byte0) {
        cmdBuf[blockPos]  = byte0;           // literal: command = byte value (0-255)
        distBuf[blockPos] = 0;               // no distance for literals
        cmdFreq[byte0]++;
        blockPos++;
    }

    private void emitMatch(final int length, final int distance) {
        final int cmd = NUM_LITERALS + length - MIN_MATCH; // 256 to 509
        cmdBuf[blockPos]  = cmd;
        distBuf[blockPos] = distance;
        cmdFreq[cmd]++;
        // Distance is encoded as a "distance code" (number of bits needed)
        final int distCode = distanceBitsFor(distance);
        distFreq[distCode]++;
        blockPos++;
    }

    // ---- Block output ----------------------------------------------------

    private void flushBlock() throws IOException {
        if (blockPos == 0) return;

        // Build Huffman trees from frequency tables (single = -1 for a normal tree,
        // otherwise the only symbol, stored as "n = 0 + value" and emitted with 0 bits)
        final int   cmdSingle  = Lh5HuffEncoder.singleSymbol(cmdFreq,  MAX_COMMANDS);
        final int   distSingle = Lh5HuffEncoder.singleSymbol(distFreq, maxDistCodes);
        final int[] cmdLens    = Lh5HuffEncoder.buildCodeLengths(cmdFreq,  MAX_COMMANDS);
        final int[] distLens   = Lh5HuffEncoder.buildCodeLengths(distFreq, maxDistCodes);
        final int[] cmdCodes   = Lh5HuffEncoder.assignCodes(cmdLens,  MAX_COMMANDS);
        final int[] distCodes  = Lh5HuffEncoder.assignCodes(distLens, maxDistCodes);

        // Command-decoding tree: describes the run-length coded command-tree lengths.
        // Not used at all when the command tree is single-symbol (LHA then writes 0 / 0).
        final int[] cdFreq   = cmdSingle >= 0 ? new int[MAX_CD_SYMS] : Lh5HuffEncoder.countCommandDecodingFreq(cmdLens, MAX_COMMANDS, MAX_CD_SYMS);
        final int   cdSingle = Lh5HuffEncoder.singleSymbol(cdFreq, MAX_CD_SYMS);
        final int[] cdLens   = Lh5HuffEncoder.buildCodeLengths(cdFreq, MAX_CD_SYMS);
        final int[] cdCodes  = Lh5HuffEncoder.assignCodes(cdLens, MAX_CD_SYMS);

        // Write block header
        bitOut.writeBits(blockPos, 16);
        Lh5HuffEncoder.writeCommandDecodingTree(bitOut, cdLens, cdSingle);
        Lh5HuffEncoder.writeCommandTree(bitOut, cmdLens, MAX_COMMANDS, cmdSingle, cdCodes, cdLens, cdSingle);
        Lh5HuffEncoder.writeDistanceTree(bitOut, distLens, distSingle, distanceBits);

        // Write tokens
        for (int i = 0; i < blockPos; i++) {
            final int cmd = cmdBuf[i];
            Lh5HuffEncoder.writeCode(bitOut, cmd, cmdCodes, cmdLens, cmdSingle);
            if (cmd >= NUM_LITERALS) {
                // Write distance
                final int dist     = distBuf[i];
                final int distCode = distanceBitsFor(dist);
                Lh5HuffEncoder.writeCode(bitOut, distCode, distCodes, distLens, distSingle);
                if (distCode >= 2) {
                    // Write (distCode-1) raw bits
                    bitOut.writeBits(dist & ((1 << (distCode - 1)) - 1), distCode - 1);
                }
            }
        }

        // Reset for next block
        blockPos = 0;
        java.util.Arrays.fill(cmdFreq,  0);
        java.util.Arrays.fill(distFreq, 0);
    }

    private void flush() throws IOException {
        flushBlock();
        bitOut.flush();
    }

    // ---- Counting OutputStream -------------------------------------------

    private static final class CountingOutputStream extends java.io.FilterOutputStream {
        private long count = 0;
        CountingOutputStream(final OutputStream out) { super(out); }
        @Override public void write(final int b) throws IOException { out.write(b); count++; }
        @Override public void write(final byte[] b, final int off, final int len) throws IOException { out.write(b, off, len); count += len; }
        long getCount() { return count; }
    }
}
