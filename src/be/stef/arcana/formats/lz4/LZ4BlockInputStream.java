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
/* Algorithm ported from the LZ4 specification (https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)
 * and validated against the Python lz4.block module. Public domain algorithm (Yann Collet). */
package be.stef.arcana.formats.lz4;

import java.io.IOException;
import java.io.InputStream;

/**
 * Decompresses a single raw LZ4 block (no framing, no checksum).
 *
 * <p>This class decompresses a fully-buffered LZ4 block from its raw
 * compressed form. It is used internally by {@link LZ4InputStream} to
 * decompress individual blocks inside an LZ4 frame, and may also be used
 * directly when the block size is known in advance (e.g. from metadata).</p>
 *
 * <p>The LZ4 block format consists of a sequence of sequences, each made of:
 * a token byte (high nibble = literal length, low nibble = match length - 4),
 * followed by optional extra literal-length bytes (if high nibble == 15),
 * followed by literal bytes, followed by a 2-byte little-endian match offset,
 * followed by optional extra match-length bytes (if low nibble == 15).
 * The last sequence has no match part.</p>
 *
 * @author Stef
 * @since 1.1
 */
public final class LZ4BlockInputStream extends InputStream {

    private final byte[] decompressed;
    private int pos;

    /**
     * Decompresses {@code compressedLen} bytes from {@code compressed} starting
     * at {@code compressedOff} into a new buffer of {@code outputSize} bytes.
     *
     * @param compressed    source bytes (raw LZ4 block, no framing)
     * @param compressedOff offset in {@code compressed} where the block starts
     * @param compressedLen number of compressed bytes to consume
     * @param outputSize    exact number of output bytes to produce; pass -1 if unknown
     *                      (the output buffer will grow dynamically)
     * @throws IOException if the block data is malformed
     */
    public LZ4BlockInputStream(final byte[] compressed, final int compressedOff, final int compressedLen, final int outputSize) throws IOException {
        this.decompressed = decompress(compressed, compressedOff, compressedLen, outputSize);
        this.pos = 0;
    }

    /**
     * Decompresses a complete raw LZ4 block from {@code compressed[0..length-1]}.
     *
     * @param compressed raw LZ4 block bytes
     * @param outputSize exact output size, or -1 if unknown
     * @throws IOException if the block is malformed
     */
    public LZ4BlockInputStream(final byte[] compressed, final int outputSize) throws IOException {
        this(compressed, 0, compressed.length, outputSize);
    }

    // =========================================================================
    // InputStream
    // =========================================================================

    @Override
    public int read() throws IOException {
        if (pos >= decompressed.length) return -1;
        return decompressed[pos++] & 0xFF;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (pos >= decompressed.length) return -1;
        final int n = Math.min(len, decompressed.length - pos);
        System.arraycopy(decompressed, pos, buf, off, n);
        pos += n;
        return n;
    }

    @Override
    public int available() {
        return decompressed.length - pos;
    }

    // =========================================================================
    // Static decompression helper
    // =========================================================================

    /**
     * Decompresses a raw LZ4 block and returns the output as a byte array.
     * Also callable statically (e.g. by {@link LZ4InputStream}).
     *
     * @param src        compressed data
     * @param srcOff     offset in src
     * @param srcLen     number of compressed bytes
     * @param outputSize expected output size (-1 = unknown, grows dynamically)
     * @return decompressed bytes
     * @throws IOException on malformed data
     */
    static byte[] decompress(final byte[] src, final int srcOff, final int srcLen, final int outputSize) throws IOException {
        return decompress(src, srcOff, srcLen, outputSize, null);
    }

    /**
     * Decompresses a raw LZ4 block whose matches may reach back into {@code prefix}
     * (the previous output of a frame using linked blocks, at most 64 KB).
     *
     * @param prefix history preceding this block, or null for an independent block
     * @return the decompressed bytes of THIS block only (prefix excluded)
     * @throws IOException on malformed data
     */
    static byte[] decompress(final byte[] src, final int srcOff, final int srcLen, final int outputSize, final byte[] prefix) throws IOException {
        final int base = prefix == null ? 0 : prefix.length;
        byte[] out = new byte[base + (outputSize >= 0 ? outputSize : Math.max(64, Math.min(srcLen * 4, 1 << 20)))];
        if (base > 0) System.arraycopy(prefix, 0, out, 0, base);
        int sPos = srcOff;
        final int sEnd = srcOff + srcLen;
        int dPos = base;

        while (sPos < sEnd) {
            final int token = src[sPos++] & 0xFF;
            // Literal length
            int litLen = token >>> 4;
            if (litLen == 15) {
                int extra;
                do {
                    if (sPos >= sEnd) throw new IOException("LZ4 block truncated: literal length");
                    extra = src[sPos++] & 0xFF;
                    litLen += extra;
                } while (extra == 255);
            }
            if (sPos + litLen > sEnd) throw new IOException("LZ4 block truncated: literals");
            if (dPos + litLen > out.length) out = grow(out, dPos + litLen);
            System.arraycopy(src, sPos, out, dPos, litLen);
            sPos += litLen;
            dPos += litLen;
            if (sPos >= sEnd) break; // last sequence has literals only
            // Match offset (little-endian 16-bit)
            if (sPos + 1 >= sEnd) throw new IOException("LZ4 block truncated: missing match offset");
            final int offset = (src[sPos] & 0xFF) | ((src[sPos + 1] & 0xFF) << 8);
            sPos += 2;
            if (offset == 0) throw new IOException("LZ4 block malformed: match offset 0");
            // Match length
            int matchLen = (token & 0xF) + 4;
            if ((token & 0xF) == 15) {
                int extra;
                do {
                    if (sPos >= sEnd) throw new IOException("LZ4 block truncated: match length");
                    extra = src[sPos++] & 0xFF;
                    matchLen += extra;
                } while (extra == 255);
            }
            final int matchPos = dPos - offset;
            if (matchPos < 0) throw new IOException("LZ4 block malformed: match goes before start of output");
            if (dPos + matchLen > out.length) out = grow(out, dPos + matchLen);
            for (int k = 0; k < matchLen; k++) out[dPos + k] = out[matchPos + k]; // byte by byte: overlap allowed
            dPos += matchLen;
        }
        final int produced = dPos - base;
        if (outputSize >= 0 && produced != outputSize) throw new IOException("LZ4 block decompressed to " + produced + " bytes, expected " + outputSize);
        return (base == 0 && dPos == out.length) ? out : java.util.Arrays.copyOfRange(out, base, dPos);
    }

    private static byte[] grow(final byte[] out, final int needed) {
        return java.util.Arrays.copyOf(out, Math.max(out.length * 2, needed));
    }
}
