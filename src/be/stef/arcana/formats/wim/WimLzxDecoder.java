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
package be.stef.arcana.formats.wim;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;
import java.util.Arrays;

/**
 * LZX decompressor for WIM chunks, written from the LZX format description
 * ([MS-PATCH] LZX DELTA, and the Cabinet LZX documentation).
 *
 * <p>WIM specifics: every chunk is an independent LZX stream whose window is
 * the chunk size (32 KiB by default); there is no E8 header bit, the E8 call
 * translation is always applied with a translation size of 12000000; a block
 * header is a 3-bit type followed by "1" for the default size of 32768, or by
 * the size on 16 bits (plus 8 more bits for windows of 64 KiB and more).</p>
 *
 * @author Stef
 * @since 1.0.3
 */
final class WimLzxDecoder {

    private static final int VERBATIM = 1;
    private static final int ALIGNED = 2;
    private static final int UNCOMPRESSED = 3;
    private static final int NUM_CHARS = 256;
    private static final int NUM_LENGTHS = 249;
    private static final int NUM_PRETREE = 20;
    private static final int NUM_ALIGNED = 8;
    private static final int MAX_CODE = 16;
    private static final int E8_SIZE = 12000000;

    private static final int[] FOOTER_BITS = new int[51];
    private static final int[] BASE = new int[51];

    static {
        for (int i = 0; i < 51; i++) FOOTER_BITS[i] = i < 4 ? 0 : Math.min((i >> 1) - 1, 17);
        for (int i = 1; i < 51; i++) BASE[i] = BASE[i - 1] + (1 << FOOTER_BITS[i - 1]);
    }

    private final int windowOrder;
    private final int numMain;
    private final int[] mainLens;
    private final int[] lengthLens = new int[NUM_LENGTHS];
    private final int[] alignedLens = new int[NUM_ALIGNED];
    private final int[] preLens = new int[NUM_PRETREE];
    private final Huffman main;
    private final Huffman length = new Huffman(NUM_LENGTHS);
    private final Huffman aligned = new Huffman(NUM_ALIGNED);
    private final Huffman pre = new Huffman(NUM_PRETREE);

    // bit input: 16-bit little-endian words, most significant bit first
    private byte[] src;
    private int pos;
    private int end;
    private long buf;
    private int count;

    /** @param chunkSize uncompressed chunk size (power of two, 32 KiB to 2 MiB) */
    WimLzxDecoder(final int chunkSize) throws IOException {
        int order = 15;
        while ((1 << order) < chunkSize) order++;
        if (order > 21) throw new ArcanaCorruptedException("LZX window too large: " + chunkSize);
        windowOrder = order;
        final int slots = order == 21 ? 50 : order == 20 ? 42 : 2 * order;
        numMain = NUM_CHARS + 8 * slots;
        mainLens = new int[numMain];
        main = new Huffman(numMain);
    }

    /** Decompresses one chunk: src[off, off + len) to dst[0, outLen). */
    void decompress(final byte[] in, final int off, final int len, final byte[] dst, final int outLen) throws IOException {
        src = in;
        pos = off;
        end = off + len;
        buf = 0;
        count = 0;
        Arrays.fill(mainLens, 0);
        Arrays.fill(lengthLens, 0);
        int r0 = 1;
        int r1 = 1;
        int r2 = 1;
        int out = 0;
        try {
            while (out < outLen) {
                final int type = bits(3);
                int size;
                if (bits(1) == 1) {
                    size = 32768;
                } else {
                    size = bits(16);
                    if (windowOrder >= 16) size = size << 8 | bits(8);
                }
                if (size <= 0 || size > outLen - out) size = outLen - out;
                if (type == UNCOMPRESSED) {
                    // align to a 16-bit boundary, then 3 recent offsets and the raw bytes
                    if (count >= 16) pos -= 2 * (count / 16);
                    buf = 0;
                    count = 0;
                    r0 = le32();
                    r1 = le32();
                    r2 = le32();
                    if (pos + size > end) throw new ArcanaCorruptedException("LZX uncompressed block truncated");
                    System.arraycopy(src, pos, dst, out, size);
                    pos += size;
                    out += size;
                    if ((size & 1) != 0) pos++;
                    continue;
                }
                if (type != VERBATIM && type != ALIGNED) throw new ArcanaCorruptedException("Invalid LZX block type " + type);
                if (type == ALIGNED) {
                    for (int i = 0; i < NUM_ALIGNED; i++) alignedLens[i] = bits(3);
                    aligned.build(alignedLens);
                }
                readLengths(mainLens, 0, NUM_CHARS);
                readLengths(mainLens, NUM_CHARS, numMain);
                main.build(mainLens);
                readLengths(lengthLens, 0, NUM_LENGTHS);
                length.build(lengthLens);
                final int blockEnd = out + size;
                while (out < blockEnd) {
                    final int sym = decode(main);
                    if (sym < NUM_CHARS) {
                        dst[out++] = (byte) sym;
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
                        if (type == ALIGNED && footer >= 3) {
                            extra = bits(footer - 3) << 3;
                            extra += decode(aligned);
                        } else {
                            extra = footer == 0 ? 0 : bits(footer);
                        }
                        offset = BASE[slot] + extra - 2;
                        r2 = r1;
                        r1 = r0;
                        r0 = offset;
                    }
                    if (offset <= 0 || offset > out) throw new ArcanaCorruptedException("LZX match before the start of the output");
                    if (out + matchLen > outLen) throw new ArcanaCorruptedException("LZX match past the end of the chunk");
                    for (int i = 0; i < matchLen; i++, out++) dst[out] = dst[out - offset];
                }
            }
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new ArcanaCorruptedException("LZX stream corrupted", e);
        }
        undoE8(dst, outLen);
    }

    /** Reverses the x86 CALL translation (absolute targets back to relative). */
    private static void undoE8(final byte[] b, final int n) {
        for (int i = 0; i < n - 10; i++) {
            if (b[i] != (byte) 0xE8) continue;
            final int abs = (b[i + 1] & 0xff) | (b[i + 2] & 0xff) << 8 | (b[i + 3] & 0xff) << 16 | (b[i + 4] & 0xff) << 24;
            if (abs >= -i && abs < E8_SIZE) {
                final int rel = abs >= 0 ? abs - i : abs + E8_SIZE;
                b[i + 1] = (byte) rel;
                b[i + 2] = (byte) (rel >> 8);
                b[i + 3] = (byte) (rel >> 16);
                b[i + 4] = (byte) (rel >> 24);
            }
            i += 4;
        }
    }

    /** Code lengths sent as differences with the previous ones, through the pretree. */
    private void readLengths(final int[] lens, final int from, final int to) throws IOException {
        for (int i = 0; i < NUM_PRETREE; i++) preLens[i] = bits(4);
        pre.build(preLens);
        int i = from;
        while (i < to) {
            final int x = decode(pre);
            if (x <= 16) {
                lens[i] = (lens[i] - x + 17) % 17;
                i++;
            } else if (x == 17) {
                int n = 4 + bits(4);
                while (n-- > 0 && i < to) lens[i++] = 0;
            } else if (x == 18) {
                int n = 20 + bits(5);
                while (n-- > 0 && i < to) lens[i++] = 0;
            } else {
                // run of 4 or 5 equal lengths, all derived from the first previous length
                int n = 4 + bits(1);
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

    private void fill() {
        while (count <= 32) {
            final int w = pos + 1 < end ? (src[pos] & 0xff) | (src[pos + 1] & 0xff) << 8 : 0;
            pos += 2;
            buf |= (long) w << (48 - count);
            count += 16;
        }
    }

    private int bits(final int n) {
        if (n == 0) return 0;
        if (count < n) fill();
        final int v = (int) (buf >>> (64 - n));
        buf <<= n;
        count -= n;
        return v;
    }

    private int peek16() {
        if (count < MAX_CODE) fill();
        return (int) (buf >>> 48);
    }

    private int le32() throws IOException {
        if (pos + 4 > end) throw new ArcanaCorruptedException("LZX stream truncated");
        final int v = (src[pos] & 0xff) | (src[pos + 1] & 0xff) << 8 | (src[pos + 2] & 0xff) << 16 | (src[pos + 3] & 0xff) << 24;
        pos += 4;
        return v;
    }

    private int decode(final Huffman h) throws IOException {
        final int peek = peek16();
        final int e = h.table[peek >>> (16 - Huffman.BITS)];
        int sym;
        int len;
        if ((e & 0xFF) != 0) {
            sym = e >>> 8;
            len = e & 0xFF;
        } else {
            // longer code: canonical search
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
        count -= len;
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
