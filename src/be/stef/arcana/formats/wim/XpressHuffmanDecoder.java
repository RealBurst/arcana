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

/**
 * "LZ77 + Huffman" (XPRESS Huffman) decompressor, written from the Microsoft
 * specification [MS-XCA] section 2.2 (Compression Algorithm Extensions).
 *
 * <p>Each 64 KiB of output starts with a 256-byte table of 512 code lengths
 * (4 bits each, low nibble first), followed by a stream of 16-bit
 * little-endian words read most significant bit first. Symbols 0-255 are
 * literals; symbols 256-511 encode a match: low nibble = length - 3 (15:
 * extended by one byte, then 255: by a 16-bit word), high nibble = number of
 * offset bits. The extra length bytes are read from the byte stream between
 * the words.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
final class XpressHuffmanDecoder {

    private static final int TABLE_BITS = 15;

    private final int[] table = new int[1 << TABLE_BITS];
    private final int[] lengths = new int[512];

    /** Decompresses src[off, off + len) into dst[0, outLen). */
    void decompress(final byte[] src, final int off, final int len, final byte[] dst, final int outLen) throws IOException {
        final int end = off + len;
        int in = off;
        int out = 0;
        try {
            while (out < outLen) {
                // a new Huffman table every 65536 output bytes
                if (in + 256 > end) throw new ArcanaCorruptedException("XPRESS stream truncated");
                for (int i = 0; i < 256; i++) {
                    final int b = src[in + i] & 0xff;
                    lengths[2 * i] = b & 15;
                    lengths[2 * i + 1] = b >> 4;
                }
                buildTable();
                in += 256;
                long bits = (long) le16(src, in, end) << 16 | le16(src, in + 2, end);
                in += 4;
                int extra = 16;
                final int blockEnd = Math.min(outLen, out + 65536);
                while (out < blockEnd) {
                    final int entry = table[(int) (bits >>> (32 - TABLE_BITS)) & 0x7FFF];
                    final int sym = entry >>> 4;
                    final int n = entry & 15;
                    if (n == 0) throw new ArcanaCorruptedException("Invalid XPRESS Huffman code");
                    bits = (bits << n) & 0xFFFFFFFFL;
                    extra -= n;
                    if (extra < 0) {
                        bits |= (long) le16(src, in, end) << -extra;
                        extra += 16;
                        in += 2;
                    }
                    if (sym < 256) {
                        dst[out++] = (byte) sym;
                        continue;
                    }
                    int length = sym & 15;
                    final int offsetBits = (sym >> 4) & 15;
                    if (length == 15) {
                        if (in >= end) throw new ArcanaCorruptedException("XPRESS stream truncated");
                        length = src[in++] & 0xff;
                        if (length == 255) {
                            length = le16(src, in, end);
                            in += 2;
                            if (length < 15) throw new ArcanaCorruptedException("Invalid XPRESS match length");
                            length -= 15;
                        }
                        length += 15;
                    }
                    length += 3;
                    int offset = offsetBits == 0 ? 0 : (int) (bits >>> (32 - offsetBits));
                    offset += 1 << offsetBits;
                    bits = (bits << offsetBits) & 0xFFFFFFFFL;
                    extra -= offsetBits;
                    if (extra < 0) {
                        bits |= (long) le16(src, in, end) << -extra;
                        extra += 16;
                        in += 2;
                    }
                    if (offset > out) throw new ArcanaCorruptedException("XPRESS match before the start of the output");
                    final int stop = Math.min(outLen, out + length);
                    while (out < stop) {
                        dst[out] = dst[out - offset];
                        out++;
                    }
                }
                // the next block starts after the words consumed so far (the last word may be partly used)
            }
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new ArcanaCorruptedException("XPRESS stream corrupted", e);
        }
    }

    /** Words past the end read as 0: the encoder pads the last bits. */
    private static int le16(final byte[] b, final int p, final int end) {
        if (p + 1 >= end) return p < end ? b[p] & 0xff : 0;
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8;
    }

    /** Canonical Huffman decoding table indexed by the next 15 bits: (symbol << 4) | length. */
    private void buildTable() throws IOException {
        java.util.Arrays.fill(table, 0);
        int code = 0;
        for (int len = 1; len <= 15; len++) {
            for (int sym = 0; sym < 512; sym++) {
                if (lengths[sym] != len) continue;
                final int span = 1 << (TABLE_BITS - len);
                final int start = code << (TABLE_BITS - len);
                if (start + span > table.length) throw new ArcanaCorruptedException("Invalid XPRESS Huffman table");
                java.util.Arrays.fill(table, start, start + span, sym << 4 | len);
                code++;
            }
            code <<= 1;
        }
    }
}
