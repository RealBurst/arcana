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
package be.stef.arcana.formats.lzx;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;
import java.util.Arrays;

/**
 * LZX decompressor for Cabinet files and CHM help files, written from the
 * Microsoft LZX documentation ([MS-PATCH] LZX DELTA, Cabinet LZX format).
 *
 * <p>The output is produced in frames of 32 KiB, each one compressed in its
 * own byte range (a CFDATA block of a cabinet, a reset-table entry of a CHM);
 * the window, the recent offsets and the Huffman code lengths carry over from
 * one frame to the next until {@link #reset()}. The stream starts with one bit
 * (plus a 32-bit size when it is 1) enabling the x86 CALL translation, undone
 * on every frame. A block header is a 3-bit type and a 24-bit size; an
 * uncompressed block starts on a 16-bit boundary, after 1 to 16 bits of
 * padding, with the three recent offsets.</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class LzxDecoder {

    /** Size of an output frame. */
    public static final int FRAME_SIZE = 32768;

    private static final int VERBATIM = 1;
    private static final int ALIGNED = 2;
    private static final int UNCOMPRESSED = 3;
    private static final int NUM_CHARS = 256;
    private static final int NUM_LENGTHS = 249;
    private static final int NUM_PRETREE = 20;
    private static final int NUM_ALIGNED = 8;
    private static final int MAX_CODE = 16;

    private static final int[] FOOTER_BITS = new int[51];
    private static final int[] BASE = new int[51];

    static {
        for (int i = 0; i < 51; i++) FOOTER_BITS[i] = i < 4 ? 0 : Math.min((i >> 1) - 1, 17);
        for (int i = 1; i < 51; i++) BASE[i] = BASE[i - 1] + (1 << FOOTER_BITS[i - 1]);
    }

    private final int windowSize;
    private final int numMain;
    private final byte[] window;
    private final int[] mainLens;
    private final int[] lengthLens = new int[NUM_LENGTHS];
    private final int[] alignedLens = new int[NUM_ALIGNED];
    private final int[] preLens = new int[NUM_PRETREE];
    private final Huffman main;
    private final Huffman length = new Huffman(NUM_LENGTHS);
    private final Huffman aligned = new Huffman(NUM_ALIGNED);
    private final Huffman pre = new Huffman(NUM_PRETREE);

    // state carried between frames
    private int windowPos;
    private int r0;
    private int r1;
    private int r2;
    private boolean headerRead;
    private int e8Size;
    private long e8Pos;
    private int blockType;
    private int blockRemaining;
    private int blockLength;
    /** Bytes already decoded past the end of the previous frame (a match may overrun it). */
    private int overrun;

    // bit input of the current frame: 16-bit little-endian words, most significant bit first
    private byte[] src;
    private int pos;
    private int end;
    private int buf;
    private int bits;

    /** @param windowBits 15 to 21 (32 KiB to 2 MiB) */
    public LzxDecoder(final int windowBits) throws IOException {
        if (windowBits < 15 || windowBits > 21) throw new ArcanaCorruptedException("LZX invalid window size 2^" + windowBits);
        windowSize = 1 << windowBits;
        final int slots = windowBits == 21 ? 50 : windowBits == 20 ? 42 : 2 * windowBits;
        numMain = NUM_CHARS + 8 * slots;
        window = new byte[windowSize];
        mainLens = new int[numMain];
        main = new Huffman(numMain);
        reset();
    }

    /** Full reset: start of a cabinet folder or of a CHM content section. */
    public void reset() {
        resetState();
        windowPos = 0;
        e8Pos = 0;
        overrun = 0;
    }

    /** Reset of the coding state at a CHM reset interval: the window and the output position go on. */
    public void resetState() {
        r0 = r1 = r2 = 1;
        headerRead = false;
        e8Size = 0;
        blockType = 0;
        blockRemaining = 0;
        Arrays.fill(mainLens, 0);
        Arrays.fill(lengthLens, 0);
    }

    /**
     * Decodes one frame.
     *
     * @param in     compressed data of the frame: in[off, off + len)
     * @param out    receives the frame
     * @param outLen frame size: 32768, less for the last frame
     */
    public void decompress(final byte[] in, final int off, final int len, final byte[] out, final int outLen) throws IOException {
        if (outLen <= 0 || outLen > FRAME_SIZE) throw new ArcanaCorruptedException("Invalid LZX frame size " + outLen);
        src = in;
        pos = off;
        end = off + len;
        buf = 0;
        bits = 0;
        final int frameStart = windowPos - overrun;
        int produced = overrun;
        overrun = 0;
        try {
            if (!headerRead) {
                if (bit() == 1) e8Size = read(16) << 16 | read(16);
                headerRead = true;
            }
            while (produced < outLen) {
                if (blockRemaining == 0) readBlockHeader();
                final int run = Math.min(blockRemaining, outLen - produced);
                final int done = blockType == UNCOMPRESSED ? copyStored(run) : decodeSymbols(run);
                produced += done;
                blockRemaining -= done;
                if (blockRemaining < 0) throw new ArcanaCorruptedException("LZX match past the end of its block");
                // an odd-sized uncompressed block is followed by a padding byte
                if (blockRemaining == 0 && blockType == UNCOMPRESSED && (blockLength & 1) != 0) pos++;
            }
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new ArcanaCorruptedException("LZX stream corrupted", e);
        }
        overrun = produced - outLen;
        // the frame, with the x86 CALL translation undone
        int p = frameStart & (windowSize - 1);
        for (int i = 0; i < outLen; i++) {
            out[i] = window[p];
            p = (p + 1) & (windowSize - 1);
        }
        if (e8Size != 0 && outLen > 10 && e8Pos < 32768L * FRAME_SIZE) undoE8(out, outLen);
        e8Pos += outLen;
    }

    private void readBlockHeader() throws IOException {
        blockType = read(3);
        blockLength = read(16) << 8 | read(8);
        blockRemaining = blockLength;
        if (blockLength == 0) throw new ArcanaCorruptedException("Empty LZX block");
        switch (blockType) {
            case ALIGNED:
                for (int i = 0; i < NUM_ALIGNED; i++) alignedLens[i] = read(3);
                aligned.build(alignedLens);
                // fall through: the rest is a verbatim header
            case VERBATIM:
                readLengths(mainLens, 0, NUM_CHARS);
                readLengths(mainLens, NUM_CHARS, numMain);
                main.build(mainLens);
                readLengths(lengthLens, 0, NUM_LENGTHS);
                length.build(lengthLens);
                break;
            case UNCOMPRESSED:
                // 1 to 16 bits of padding up to a 16-bit boundary
                if (bits == 0) pos += 2;
                else if (bits > 16) pos -= 2;
                buf = 0;
                bits = 0;
                r0 = le32();
                r1 = le32();
                r2 = le32();
                break;
            default:
                throw new ArcanaCorruptedException("Invalid LZX block type " + blockType);
        }
    }

    private int copyStored(final int run) throws IOException {
        if (pos + run > end) throw new ArcanaCorruptedException("LZX uncompressed block truncated");
        for (int i = 0; i < run; i++) {
            window[windowPos] = src[pos++];
            windowPos = (windowPos + 1) & (windowSize - 1);
        }
        return run;
    }

    /** Decodes symbols until at least {@code run} bytes are produced; returns the bytes produced (a match may go beyond). */
    private int decodeSymbols(final int run) throws IOException {
        int done = 0;
        final int mask = windowSize - 1;
        while (done < run) {
            final int sym = decode(main);
            if (sym < NUM_CHARS) {
                window[windowPos] = (byte) sym;
                windowPos = (windowPos + 1) & mask;
                done++;
                continue;
            }
            final int s = sym - NUM_CHARS;
            final int slot = s >> 3;
            int matchLen = s & 7;
            if (matchLen == 7) matchLen += decode(length);
            matchLen += 2;
            int offset;
            if (slot == 0) {
                offset = r0;
            } else if (slot == 1) {
                offset = r1;
                r1 = r0;
                r0 = offset;
            } else if (slot == 2) {
                offset = r2;
                r2 = r0;
                r0 = offset;
            } else {
                final int footer = FOOTER_BITS[slot];
                int extra;
                if (blockType == ALIGNED && footer >= 3) {
                    extra = read(footer - 3) << 3;
                    extra += decode(aligned);
                } else {
                    extra = read(footer);
                }
                offset = BASE[slot] + extra - 2;
                r2 = r1;
                r1 = r0;
                r0 = offset;
            }
            if (offset <= 0 || offset > windowSize) throw new ArcanaCorruptedException("Invalid LZX match offset " + offset);
            int from = (windowPos - offset) & mask;
            for (int i = 0; i < matchLen; i++) {
                window[windowPos] = window[from];
                windowPos = (windowPos + 1) & mask;
                from = (from + 1) & mask;
            }
            done += matchLen;
        }
        return done;
    }

    private void undoE8(final byte[] b, final int n) {
        int cur = (int) e8Pos;
        for (int i = 0; i < n - 10; i++, cur++) {
            if (b[i] != (byte) 0xE8) continue;
            final int abs = (b[i + 1] & 0xff) | (b[i + 2] & 0xff) << 8 | (b[i + 3] & 0xff) << 16 | (b[i + 4] & 0xff) << 24;
            if (abs >= -cur && abs < e8Size) {
                final int rel = abs >= 0 ? abs - cur : abs + e8Size;
                b[i + 1] = (byte) rel;
                b[i + 2] = (byte) (rel >> 8);
                b[i + 3] = (byte) (rel >> 16);
                b[i + 4] = (byte) (rel >> 24);
            }
            i += 4;
            cur += 4;
        }
    }

    /** Code lengths sent as differences with the previous ones, through the pretree. */
    private void readLengths(final int[] lens, final int from, final int to) throws IOException {
        for (int i = 0; i < NUM_PRETREE; i++) preLens[i] = read(4);
        pre.build(preLens);
        int i = from;
        while (i < to) {
            final int x = decode(pre);
            if (x <= 16) {
                lens[i] = (lens[i] - x + 17) % 17;
                i++;
            } else if (x == 17) {
                int n = 4 + read(4);
                while (n-- > 0 && i < to) lens[i++] = 0;
            } else if (x == 18) {
                int n = 20 + read(5);
                while (n-- > 0 && i < to) lens[i++] = 0;
            } else {
                // run of 4 or 5 equal lengths, derived from the first previous length
                int n = 4 + read(1);
                final int y = decode(pre);
                if (y > 16) throw new ArcanaCorruptedException("Invalid LZX pretree code");
                final int value = (lens[i] - y + 17) % 17;
                while (n-- > 0 && i < to) lens[i++] = value;
            }
        }
    }

    // =========================================================================
    // Bits
    // =========================================================================

    private void need(final int n) {
        while (bits < n) {
            final int w = pos + 1 < end ? (src[pos] & 0xff) | (src[pos + 1] & 0xff) << 8 : 0;
            pos += 2;
            buf |= w << (16 - bits);
            bits += 16;
        }
    }

    private int read(final int n) {
        if (n == 0) return 0;
        need(n);
        final int v = buf >>> (32 - n);
        buf <<= n;
        bits -= n;
        return v;
    }

    private int bit() {
        return read(1);
    }

    private int le32() throws IOException {
        if (pos + 4 > end) throw new ArcanaCorruptedException("LZX stream truncated");
        final int v = (src[pos] & 0xff) | (src[pos + 1] & 0xff) << 8 | (src[pos + 2] & 0xff) << 16 | (src[pos + 3] & 0xff) << 24;
        pos += 4;
        return v;
    }

    private int decode(final Huffman h) throws IOException {
        need(MAX_CODE);
        final int peek = buf >>> 16;
        final int e = h.table[peek >>> (16 - Huffman.BITS)];
        int sym;
        int len;
        if ((e & 0xFF) != 0) {
            sym = e >>> 8;
            len = e & 0xFF;
        } else {
            int code = 0;
            int first = 0;
            int index = 0;
            sym = -1;
            len = 0;
            for (int l = 1; l <= MAX_CODE; l++) {
                code |= (peek >>> (16 - l)) & 1;
                final int c = h.counts[l];
                if (code - first < c) {
                    sym = h.sorted[index + code - first];
                    len = l;
                    break;
                }
                index += c;
                first = (first + c) << 1;
                code <<= 1;
            }
            if (sym < 0) throw new ArcanaCorruptedException("Invalid LZX Huffman code");
        }
        buf <<= len;
        bits -= len;
        return sym;
    }

    /** Canonical Huffman code (lengths 0-16, most significant bit first). */
    private static final class Huffman {
        static final int BITS = 10;
        final int[] table = new int[1 << BITS];
        final int[] counts = new int[MAX_CODE + 1];
        final int[] sorted;

        Huffman(final int n) {
            sorted = new int[n];
        }

        void build(final int[] lens) throws IOException {
            Arrays.fill(counts, 0);
            Arrays.fill(table, 0);
            for (final int l : lens) counts[l]++;
            counts[0] = 0;
            final int[] offs = new int[MAX_CODE + 2];
            for (int l = 1; l <= MAX_CODE; l++) offs[l + 1] = offs[l] + counts[l];
            for (int s = 0; s < lens.length; s++) if (lens[s] != 0) sorted[offs[lens[s]]++] = s;
            int code = 0;
            int k = 0;
            for (int l = 1; l <= MAX_CODE; l++) {
                for (int j = 0; j < counts[l]; j++, k++) {
                    if (l <= BITS) {
                        final int start = code << (BITS - l);
                        final int span = 1 << (BITS - l);
                        if (start + span > table.length) throw new ArcanaCorruptedException("Invalid LZX Huffman lengths");
                        Arrays.fill(table, start, start + span, sorted[k] << 8 | l);
                    }
                    code++;
                }
                code <<= 1;
            }
        }
    }
}
