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
package be.stef.arcana.formats.deflate64;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * Pure-Java raw inflater for Deflate (RFC 1951) and Deflate64 ("Enhanced Deflate",
 * PKWARE method 9).
 *
 * <p>Deflate64 differs from Deflate in three points only:</p>
 * <ul>
 *   <li>64 KB window instead of 32 KB;</li>
 *   <li>length code 285 means "3 + 16 extra bits" (lengths 3..65538) instead of 258;</li>
 *   <li>distance codes 30 and 31 are used (distances up to 65536, 14 extra bits).</li>
 * </ul>
 *
 * <p>The stream is raw (no zlib/gzip header). Reading stops at the end of the final
 * block; bytes after it are left unread in the bit buffer (up to 8 bytes).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class Deflate64InputStream extends InputStream {

    private static final int WINDOW_SIZE = 1 << 16;
    private static final int WINDOW_MASK = WINDOW_SIZE - 1;
    private static final int TABLE_BITS  = 15;
    private static final int TABLE_SIZE  = 1 << TABLE_BITS;

    private static final int STATE_HEADER = 0;
    private static final int STATE_STORED = 1;
    private static final int STATE_HUFF   = 2;
    private static final int STATE_DONE   = 3;

    private static final int[] LEN_BASE  = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    private static final int[] LEN_EXTRA = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    private static final int[] DIST_BASE  = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153 };
    private static final int[] DIST_EXTRA = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14 };
    private static final int[] CL_ORDER  = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

    private static int[] fixedLit;
    private static int[] fixedDist;

    private final InputStream in;
    private final boolean deflate64;
    private final int maxDistCodes;
    private final byte[] window = new byte[WINDOW_SIZE];
    private final byte[] single = new byte[1];
    private int wpos;
    private long totalOut;

    private long bitBuf;
    private int bitCnt;

    private int state = STATE_HEADER;
    private boolean lastBlock;
    private int storedRemaining;
    private int[] litTable;
    private int[] distTable;
    private int copyLen;
    private int copyDist;

    /**
     * @param in        raw deflate data
     * @param deflate64 true for Deflate64 (method 9), false for plain Deflate (method 8)
     */
    public Deflate64InputStream(final InputStream in, final boolean deflate64) {
        this.in = in;
        this.deflate64 = deflate64;
        this.maxDistCodes = deflate64 ? 32 : 30;
    }

    @Override
    public int read() throws IOException {
        final int n = read(single, 0, 1);
        return n < 0 ? -1 : single[0] & 0xFF;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        int n = 0;
        while (n < len) {
            if (copyLen > 0) {
                final int k = Math.min(copyLen, len - n);
                int src = (wpos - copyDist) & WINDOW_MASK;
                for (int i = 0; i < k; i++) {
                    final byte v = window[src];
                    src = (src + 1) & WINDOW_MASK;
                    window[wpos] = v;
                    wpos = (wpos + 1) & WINDOW_MASK;
                    b[off + n++] = v;
                }
                copyLen -= k;
                totalOut += k;
                continue;
            }
            switch (state) {
                case STATE_HEADER:
                    if (lastBlock) { state = STATE_DONE; break; }
                    readBlockHeader();
                    break;
                case STATE_STORED:
                    if (storedRemaining == 0) { state = STATE_HEADER; break; }
                    final byte v = (byte) getBits(8);
                    window[wpos] = v;
                    wpos = (wpos + 1) & WINDOW_MASK;
                    b[off + n++] = v;
                    storedRemaining--;
                    totalOut++;
                    break;
                case STATE_HUFF:
                    final int sym = decode(litTable);
                    if (sym < 256) {
                        window[wpos] = (byte) sym;
                        wpos = (wpos + 1) & WINDOW_MASK;
                        b[off + n++] = (byte) sym;
                        totalOut++;
                    } else if (sym == 256) {
                        state = STATE_HEADER;
                    } else {
                        decodeMatch(sym);
                    }
                    break;
                default:
                    return n == 0 ? -1 : n;
            }
        }
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // ---- Blocks -----------------------------------------------------------

    private void readBlockHeader() throws IOException {
        lastBlock = getBits(1) == 1;
        final int type = getBits(2);
        if (type == 0) {
            final int drop = bitCnt & 7; // align to byte boundary
            bitBuf >>>= drop;
            bitCnt -= drop;
            final int len  = getBits(16);
            final int nlen = getBits(16);
            if ((len ^ 0xFFFF) != nlen) throw new ArcanaCorruptedException("Deflate: invalid stored block length");
            storedRemaining = len;
            state = STATE_STORED;
        } else if (type == 1) {
            buildFixedTables();
            litTable = fixedLit;
            distTable = fixedDist;
            state = STATE_HUFF;
        } else if (type == 2) {
            readDynamicTables();
            state = STATE_HUFF;
        } else {
            throw new ArcanaCorruptedException("Deflate: invalid block type 3");
        }
    }

    private void readDynamicTables() throws IOException {
        final int hlit  = getBits(5) + 257;
        final int hdist = getBits(5) + 1;
        final int hclen = getBits(4) + 4;
        final int[] clLens = new int[19];
        for (int i = 0; i < hclen; i++) clLens[CL_ORDER[i]] = getBits(3);
        final int[] clTable = buildTable(clLens, 19);

        final int[] lens = new int[hlit + hdist];
        int i = 0;
        while (i < lens.length) {
            final int sym = decode(clTable);
            if (sym < 16) {
                lens[i++] = sym;
            } else {
                int rep;
                int val = 0;
                if (sym == 16) {
                    if (i == 0) throw new ArcanaCorruptedException("Deflate: repeat with no previous length");
                    val = lens[i - 1];
                    rep = 3 + getBits(2);
                } else if (sym == 17) {
                    rep = 3 + getBits(3);
                } else {
                    rep = 11 + getBits(7);
                }
                if (i + rep > lens.length) throw new ArcanaCorruptedException("Deflate: code lengths overflow");
                while (rep-- > 0) lens[i++] = val;
            }
        }
        if (lens[256] == 0) throw new ArcanaCorruptedException("Deflate: missing end-of-block code");
        final int[] litLens = new int[hlit];
        final int[] distLens = new int[hdist];
        System.arraycopy(lens, 0, litLens, 0, hlit);
        System.arraycopy(lens, hlit, distLens, 0, hdist);
        litTable = buildTable(litLens, hlit);
        distTable = buildTable(distLens, hdist);
    }

    private void decodeMatch(final int sym) throws IOException {
        final int li = sym - 257;
        if (li >= 29) throw new ArcanaCorruptedException("Deflate: invalid length code " + sym);
        final int length;
        if (deflate64 && sym == 285) length = 3 + getBits(16);
        else length = LEN_BASE[li] + getBits(LEN_EXTRA[li]);
        final int dsym = decode(distTable);
        if (dsym >= maxDistCodes) throw new ArcanaCorruptedException("Deflate: invalid distance code " + dsym);
        final int dist = DIST_BASE[dsym] + getBits(DIST_EXTRA[dsym]);
        if (dist > WINDOW_SIZE || dist > totalOut) throw new ArcanaCorruptedException("Deflate: distance " + dist + " too far back");
        copyLen = length;
        copyDist = dist;
    }

    // ---- Huffman ----------------------------------------------------------

    /** Table entry = (symbol << 4) | codeLength, indexed by the next 15 bits (LSB first). 0 = invalid code. */
    private static int[] buildTable(final int[] lens, final int n) throws ArcanaCorruptedException {
        final int[] count = new int[16];
        for (int i = 0; i < n; i++) count[lens[i]]++;
        count[0] = 0;
        int left = 1;
        for (int len = 1; len <= 15; len++) {
            left = (left << 1) - count[len];
            if (left < 0) throw new ArcanaCorruptedException("Deflate: over-subscribed Huffman code");
        }
        final int[] next = new int[16];
        int code = 0;
        for (int len = 1; len <= 15; len++) {
            code = (code + count[len - 1]) << 1;
            next[len] = code;
        }
        final int[] table = new int[TABLE_SIZE];
        for (int sym = 0; sym < n; sym++) {
            final int len = lens[sym];
            if (len == 0) continue;
            final int rev = Integer.reverse(next[len]++) >>> (32 - len);
            final int entry = (sym << 4) | len;
            for (int i = rev; i < TABLE_SIZE; i += 1 << len) table[i] = entry;
        }
        return table;
    }

    private static synchronized void buildFixedTables() throws ArcanaCorruptedException {
        if (fixedLit != null) return;
        final int[] l = new int[288];
        for (int i = 0; i < 144; i++) l[i] = 8;
        for (int i = 144; i < 256; i++) l[i] = 9;
        for (int i = 256; i < 280; i++) l[i] = 7;
        for (int i = 280; i < 288; i++) l[i] = 8;
        final int[] d = new int[32];
        for (int i = 0; i < 32; i++) d[i] = 5;
        fixedDist = buildTable(d, 32);
        fixedLit = buildTable(l, 288);
    }

    private int decode(final int[] table) throws IOException {
        fillForPeek();
        final int entry = table[(int) (bitBuf & (TABLE_SIZE - 1))];
        final int len = entry & 15;
        if (len == 0) throw new ArcanaCorruptedException("Deflate: invalid Huffman code");
        if (len > bitCnt) throw new EOFException("Deflate: unexpected end of compressed data");
        bitBuf >>>= len;
        bitCnt -= len;
        return entry >>> 4;
    }

    // ---- Bits -------------------------------------------------------------

    /** Loads up to 15 bits; at end of input the missing bits read as 0 (checked by the caller). */
    private void fillForPeek() throws IOException {
        while (bitCnt < TABLE_BITS) {
            final int c = in.read();
            if (c < 0) return;
            bitBuf |= (long) c << bitCnt;
            bitCnt += 8;
        }
    }

    private int getBits(final int n) throws IOException {
        if (n == 0) return 0;
        while (bitCnt < n) {
            final int c = in.read();
            if (c < 0) throw new EOFException("Deflate: unexpected end of compressed data");
            bitBuf |= (long) c << bitCnt;
            bitCnt += 8;
        }
        final int v = (int) (bitBuf & ((1L << n) - 1));
        bitBuf >>>= n;
        bitCnt -= n;
        return v;
    }
}
