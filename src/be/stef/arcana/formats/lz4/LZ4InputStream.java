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
/* LZ4 Frame format specification: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
 * Public domain algorithm (Yann Collet). Validated against the Python lz4.frame module. */
package be.stef.arcana.formats.lz4;

import java.io.IOException;
import java.io.InputStream;

/**
 * Decompresses an LZ4 Frame stream (.lz4 files).
 *
 * <p>Supports the standard LZ4 Frame format (magic 0x184D2204), including
 * optional content size, optional block checksums, and optional content
 * checksum fields. Both independent-blocks and linked-blocks modes are
 * handled correctly.</p>
 *
 * <p>Checksums (xxHash32) are read and skipped without verification - this
 * keeps the implementation dependency-free while still consuming the stream
 * correctly. Skippable frames (magic 0x184D2A5x) are silently skipped.</p>
 *
 * @author Stef
 * @since 1.1
 */
public final class LZ4InputStream extends InputStream {

    /** Magic number for a standard LZ4 Frame. Little-endian 0x184D2204. */
    private static final int LZ4_MAGIC = 0x184D2204;
    /** Magic mask for skippable frames (0x184D2A50 to 0x184D2A5F). */
    private static final int LZ4_SKIPPABLE_MAGIC_MASK = 0xFFFFFFF0;
    private static final int LZ4_SKIPPABLE_MAGIC_BASE = 0x184D2A50;
    /** Legacy frame format (lz4 -l, old Linux kernels): blocks of up to 8 MB, no checksum, no end mark. */
    private static final int LZ4_LEGACY_MAGIC = 0x184C2102;
    private static final int LEGACY_BLOCK_SIZE = 8 << 20;

    private final java.io.PushbackInputStream in;
    private boolean legacy;
    /** Content checksum of the current frame (null when the frame has none). */
    private LZ4OutputStream.XxHash32 contentHash;
    private byte[] currentBlock;
    private int blockPos;
    private boolean eof;

    // Frame flags
    private boolean bIndep;       // true if blocks are independent (most common)
    private boolean bChecksum;    // true if each block has a 4-byte xxHash checksum
    private boolean cChecksum;    // true if stream ends with a 4-byte content checksum
    private boolean hasCSize;     // true if frame header contains content size
    /** Linked blocks (bIndep = false): the last 64 KB of output, which the next block may reference. */
    private byte[]  history;
    private static final int LINKED_HISTORY = 64 * 1024;

    public LZ4InputStream(final InputStream in) throws IOException {
        this.in = new java.io.PushbackInputStream(in, 4);
        readFrameHeader(readInt32LE());
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
        while (currentBlock == null || blockPos >= currentBlock.length) {
            if (!readNextBlock()) return -1;
        }
        final int n = Math.min(len, currentBlock.length - blockPos);
        System.arraycopy(currentBlock, blockPos, buf, off, n);
        blockPos += n;
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Frame header / block reading
    // =========================================================================

    private void readFrameHeader(final int magic) throws IOException {
        if ((magic & LZ4_SKIPPABLE_MAGIC_MASK) == LZ4_SKIPPABLE_MAGIC_BASE) {
            final int skipSize = readInt32LE();
            skipFully(skipSize);
            readFrameHeader(readInt32LE());
            return;
        }
        if (magic == LZ4_LEGACY_MAGIC) {
            legacy = true;
            bIndep = true;
            return;
        }
        legacy = false;
        if (magic != LZ4_MAGIC) throw new IOException("Not an LZ4 frame (magic 0x" + Integer.toHexString(magic) + ")");

        final int flg = readByte();
        final int bd = readByte();
        final LZ4OutputStream.XxHash32 hc = new LZ4OutputStream.XxHash32(0);
        hc.update(new byte[] { (byte) flg, (byte) bd }, 0, 2);
        final int version = (flg >>> 6) & 0x3;
        if (version != 1) throw new IOException("Unsupported LZ4 FLG version: " + version);
        bIndep    = ((flg >>> 5) & 1) != 0;
        bChecksum = ((flg >>> 4) & 1) != 0;
        hasCSize  = ((flg >>> 3) & 1) != 0;
        cChecksum = ((flg >>> 2) & 1) != 0;

        final boolean hasDictId = (flg & 1) != 0;
        if (hasCSize) { final byte[] b = new byte[8]; readFully(b, 0, 8); hc.update(b, 0, 8); }   // content size
        if (hasDictId) { final byte[] b = new byte[4]; readFully(b, 0, 4); hc.update(b, 0, 4); }  // dictionary ID (external dictionaries are not supported)
        final int headerChecksum = readByte();
        if (headerChecksum != ((hc.digest() >>> 8) & 0xFF)) throw new IOException("LZ4: frame header checksum error");
        // bd byte: max block size - not needed for decompression
        contentHash = cChecksum ? new LZ4OutputStream.XxHash32(0) : null;
        history = null;
    }

    /** Next magic number after an end mark, or null at the real end of the input (concatenated frames). */
    private Integer readNextMagic() throws IOException {
        final byte[] b = new byte[4];
        int n = 0;
        while (n < 4) {
            final int r = in.read(b, n, 4 - n);
            if (r < 0) break;
            n += r;
        }
        if (n == 0) return null;
        if (n < 4) throw new IOException("LZ4: trailing garbage after the last frame");
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    /** Reads the next block from the stream. Returns false at end-of-frames. */
    private boolean readNextBlock() throws IOException {
        if (legacy) return readLegacyBlock();
        final int rawSize = readInt32LE();
        if (rawSize == 0) {
            // End mark, then the content checksum
            if (cChecksum && readInt32LE() != contentHash.digest()) throw new IOException("LZ4: content checksum error");
            final Integer next = readNextMagic();
            final boolean known = next != null && (next == LZ4_MAGIC || next == LZ4_LEGACY_MAGIC || (next & LZ4_SKIPPABLE_MAGIC_MASK) == LZ4_SKIPPABLE_MAGIC_BASE);
            if (!known) {
                // real end, or trailing data that is not a frame (ignored, like the lz4 tool and libarchive):
                // the frame just read has been fully verified by its checksums
                eof = true;
                return false;
            }
            readFrameHeader(next); // concatenated frame (lz4 CLI appends frames)
            return readNextBlock();
        }
        final boolean uncompressed = (rawSize & 0x80000000) != 0;
        final int blockSize = rawSize & 0x7FFFFFFF;
        final byte[] blockData = new byte[blockSize];
        readFully(blockData, 0, blockSize);
        if (bChecksum) {
            final LZ4OutputStream.XxHash32 bh = new LZ4OutputStream.XxHash32(0);
            bh.update(blockData, 0, blockSize);
            if (readInt32LE() != bh.digest()) throw new IOException("LZ4: block checksum error");
        }

        if (uncompressed) {
            currentBlock = blockData;
        } else {
            currentBlock = LZ4BlockInputStream.decompress(blockData, 0, blockSize, -1, bIndep ? null : history);
        }
        if (contentHash != null) contentHash.update(currentBlock, 0, currentBlock.length);
        if (!bIndep) history = lastBytes(history, currentBlock, LINKED_HISTORY);
        blockPos = 0;
        return true;
    }

    /** Legacy format: 4-byte compressed size then an independent block; ends at EOF (or a new legacy magic). */
    private boolean readLegacyBlock() throws IOException {
        Integer size = readNextMagic();
        while (size != null && size == LZ4_LEGACY_MAGIC) size = readNextMagic();
        if (size == null) {
            eof = true;
            return false;
        }
        if (size < 0 || size > LEGACY_BLOCK_SIZE + LEGACY_BLOCK_SIZE / 255 + 16) {
            // not a legacy block size: a new standard frame may follow
            readFrameHeader(size);
            return readNextBlock();
        }
        final byte[] blockData = new byte[size];
        readFully(blockData, 0, size);
        currentBlock = LZ4BlockInputStream.decompress(blockData, 0, size, -1, null);
        blockPos = 0;
        return true;
    }

    /** Returns the last {@code max} bytes of (prev + cur). */
    private static byte[] lastBytes(final byte[] prev, final byte[] cur, final int max) {
        if (cur.length >= max) return java.util.Arrays.copyOfRange(cur, cur.length - max, cur.length);
        final int keepPrev = prev == null ? 0 : Math.min(prev.length, max - cur.length);
        final byte[] h = new byte[keepPrev + cur.length];
        if (keepPrev > 0) System.arraycopy(prev, prev.length - keepPrev, h, 0, keepPrev);
        System.arraycopy(cur, 0, h, keepPrev, cur.length);
        return h;
    }

    // =========================================================================
    // Low-level I/O helpers
    // =========================================================================

    private int readInt32LE() throws IOException {
        final byte[] b = new byte[4];
        readFully(b, 0, 4);
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    private int readByte() throws IOException {
        final int b = in.read();
        if (b < 0) throw new IOException("Unexpected end of LZ4 stream");
        return b;
    }

    private void readFully(final byte[] buf, final int off, final int len) throws IOException {
        int remaining = len;
        int pos = off;
        while (remaining > 0) {
            final int n = in.read(buf, pos, remaining);
            if (n < 0) throw new IOException("Unexpected end of LZ4 stream");
            pos += n;
            remaining -= n;
        }
    }

    private void skipFully(final int n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            final long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() < 0) throw new IOException("Unexpected end of LZ4 stream while skipping");
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }
}
