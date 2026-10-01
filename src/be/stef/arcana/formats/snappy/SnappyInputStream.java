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
/* Snappy format specification: https://github.com/google/snappy/blob/main/framing_format.txt
 * Snappy block format: https://github.com/google/snappy/blob/main/format_description.txt
 * Public domain algorithm (Google / Jyrki Alakuijala et al.). Validated against python-snappy. */
package be.stef.arcana.formats.snappy;

import java.io.IOException;
import java.io.InputStream;

/**
 * Decompresses a Snappy stream (.snappy files, framing format).
 *
 * <p>Supports the Snappy framing format (stream magic
 * {@code FF 06 00 00 73 4E 61 50 70 59}), which is the standard file format
 * for {@code .snappy} files. Both compressed chunks (type {@code 0x00}) and
 * uncompressed chunks (type {@code 0x01}) are handled; other chunk types are
 * silently skipped per the specification.</p>
 *
 * <p>The masked CRC-32C of every chunk is verified (pure-Java table implementation,
 * {@code java.util.zip.CRC32C} only exists since Java 9).</p>
 *
 * <p>Also accepts raw Snappy blocks (no framing, starts with a varint
 * uncompressed-size header) when the stream does not begin with the standard
 * framing magic. This covers the "naked" Snappy block format sometimes used
 * by Hadoop/Parquet tooling.</p>
 *
 * @author Stef
 * @since 1.1
 */
public final class SnappyInputStream extends InputStream {

    /** Snappy framing magic: FF 06 00 00 73 4E 61 50 70 59. */
    private static final byte[] FRAMING_MAGIC = {(byte) 0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59};

    private static final int CHUNK_COMPRESSED   = 0x00;
    private static final int CHUNK_UNCOMPRESSED = 0x01;

    private final InputStream in;
    private final boolean framing; // true = framing format, false = raw block

    private byte[] currentChunk;
    private int chunkPos;
    private boolean eof;

    public SnappyInputStream(final InputStream in) throws IOException {
        this.in = in;
        // Peek at first 10 bytes to detect framing vs raw
        final byte[] peek = new byte[10];
        final int n = readFully(peek, 0, 10, false);
        if (n == 10 && matchesMagic(peek)) {
            this.framing = true;
            // magic consumed, ready to read chunks
        } else {
            this.framing = false;
            // The n bytes we read are the start of the raw block - decompress them
            // together with the rest of the stream by buffering all input first.
            this.currentChunk = decompressRawBlock(peek, n);
            this.chunkPos = 0;
        }
    }

    // =========================================================================
    // InputStream
    // =========================================================================

    @Override
    public int read() throws IOException {
        final byte[] buf = new byte[1];
        final int n = read(buf, 0, 1);
        return n < 0 ? -1 : buf[0] & 0xFF;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (eof) return -1;
        while (currentChunk == null || chunkPos >= currentChunk.length) {
            if (!framing) { eof = true; return -1; }
            if (!readNextFramingChunk()) return -1;
        }
        final int n = Math.min(len, currentChunk.length - chunkPos);
        System.arraycopy(currentChunk, chunkPos, buf, off, n);
        chunkPos += n;
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Framing format
    // =========================================================================

    private boolean readNextFramingChunk() throws IOException {
        final int type = in.read();
        if (type < 0) { eof = true; return false; }
        final byte[] lenBytes = new byte[3];
        if (readFully(lenBytes, 0, 3, false) < 3) throw new IOException("Snappy: truncated chunk header");
        final int chunkLen = (lenBytes[0] & 0xFF) | ((lenBytes[1] & 0xFF) << 8) | ((lenBytes[2] & 0xFF) << 16);
        final byte[] chunkData = new byte[chunkLen];
        readFully(chunkData, 0, chunkLen, true);

        if (type == CHUNK_COMPRESSED || type == CHUNK_UNCOMPRESSED) {
            if (chunkLen < 4) throw new IOException("Snappy: chunk too short");
            // 4-byte masked CRC32C of the uncompressed data, then the data
            currentChunk = type == CHUNK_COMPRESSED ? decompressBlock(chunkData, 4, chunkLen - 4) : java.util.Arrays.copyOfRange(chunkData, 4, chunkLen);
            final int stored = (chunkData[0] & 0xFF) | ((chunkData[1] & 0xFF) << 8) | ((chunkData[2] & 0xFF) << 16) | ((chunkData[3] & 0xFF) << 24);
            if (stored != maskedCrc32c(currentChunk)) throw new IOException("Snappy: chunk checksum error");
        } else if (type >= 0x02 && type <= 0x7F) {
            throw new IOException("Snappy: reserved unskippable chunk type 0x" + Integer.toHexString(type));
        } else {
            // padding (0xFE), repeated stream identifier (0xFF) or skippable chunk: skip, recurse
            return readNextFramingChunk();
        }
        chunkPos = 0;
        return true;
    }

    // =========================================================================
    // Raw block decompression (no framing, varint size prefix)
    // =========================================================================

    private byte[] decompressRawBlock(final byte[] prefix, final int prefixLen) throws IOException {
        // Read the rest of the stream and prepend the already-consumed prefix
        final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        baos.write(prefix, 0, prefixLen);
        final byte[] tmp = new byte[65536];
        int n;
        while ((n = in.read(tmp)) >= 0) baos.write(tmp, 0, n);
        return decompressBlock(baos.toByteArray(), 0, baos.size());
    }

    // =========================================================================
    // Snappy block decompressor (varint size prefix + tag sequences)
    // =========================================================================

    /**
     * Decompresses a raw Snappy block.
     *
     * @param data   source bytes
     * @param srcOff offset into data (may skip a checksum before the block)
     * @param srcLen number of bytes to consume from srcOff
     * @return decompressed bytes
     */
    static byte[] decompressBlock(final byte[] data, final int srcOff, final int srcLen) throws IOException {
        int pos = srcOff;
        final int end = srcOff + srcLen;

        // Read varint uncompressed size
        int outSize = 0;
        int shift = 0;
        while (true) {
            if (pos >= end) throw new IOException("Snappy block: truncated varint");
            final int b = data[pos++] & 0xFF;
            outSize |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift >= 32) throw new IOException("Snappy block: varint overflow");
        }

        final byte[] out = new byte[outSize];
        int d = 0;

        while (pos < end && d < outSize) {
            final int b = data[pos++] & 0xFF;
            final int tagType = b & 3;
            if (tagType == 0) {
                // Literal
                final int lenBits = (b >> 2) & 0x3F;
                final int litLen;
                if (lenBits < 60) {
                    litLen = lenBits + 1;
                } else {
                    final int extra = lenBits - 59;
                    int v = 0;
                    for (int i = 0; i < extra; i++) v |= (data[pos++] & 0xFF) << (8 * i);
                    litLen = v + 1;
                }
                System.arraycopy(data, pos, out, d, litLen);
                pos += litLen;
                d += litLen;
            } else if (tagType == 1) {
                // Copy with 1-byte offset
                final int copyLen = ((b >> 2) & 0x7) + 4;
                final int offset = ((b & 0xE0) << 3) | (data[pos++] & 0xFF);
                if (offset == 0 || offset > d) throw new IOException("Snappy invalid copy offset");
                final int matchPos = d - offset;
                for (int i = 0; i < copyLen; i++) out[d + i] = out[matchPos + i];
                d += copyLen;
            } else if (tagType == 2) {
                // Copy with 2-byte offset
                final int copyLen = (b >> 2) + 1;
                final int offset = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
                pos += 2;
                if (offset == 0 || offset > d) throw new IOException("Snappy invalid copy offset");
                final int matchPos = d - offset;
                for (int i = 0; i < copyLen; i++) out[d + i] = out[matchPos + i];
                d += copyLen;
            } else {
                // Copy with 4-byte offset
                final int copyLen = (b >> 2) + 1;
                final int offset = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8) | ((data[pos + 2] & 0xFF) << 16) | ((data[pos + 3] & 0xFF) << 24);
                pos += 4;
                if (offset == 0 || offset > d) throw new IOException("Snappy invalid copy offset");
                final int matchPos = d - offset;
                for (int i = 0; i < copyLen; i++) out[d + i] = out[matchPos + i];
                d += copyLen;
            }
        }

        if (d != outSize) throw new IOException("Snappy block decompressed to " + d + " bytes, expected " + outSize);
        return out;
    }

    // =========================================================================
    // I/O helpers
    // =========================================================================

    private static boolean matchesMagic(final byte[] buf) {
        for (int i = 0; i < FRAMING_MAGIC.length; i++) {
            if (buf[i] != FRAMING_MAGIC[i]) return false;
        }
        return true;
    }

    private int readFully(final byte[] buf, final int off, final int len, final boolean required) throws IOException {
        int remaining = len;
        int pos = off;
        while (remaining > 0) {
            final int n = in.read(buf, pos, remaining);
            if (n < 0) {
                if (required) throw new IOException("Unexpected end of Snappy stream");
                return len - remaining;
            }
            pos += n;
            remaining -= n;
        }
        return len;
    }

    // =========================================================================
    // CRC-32C (Castagnoli), masked as in the Snappy framing format
    // =========================================================================

    private static final int[] CRC32C_TABLE = new int[256];

    static {
        for (int n = 0; n < 256; n++) {
            int c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? (c >>> 1) ^ 0x82F63B78 : c >>> 1;
            CRC32C_TABLE[n] = c;
        }
    }

    static int maskedCrc32c(final byte[] data) {
        int crc = 0xFFFFFFFF;
        for (final byte b : data) crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ b) & 0xFF];
        crc = ~crc;
        return ((crc >>> 15) | (crc << 17)) + 0xA282EAD8;
    }
}
