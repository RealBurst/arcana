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
package be.stef.arcana.formats.zstd;
import static be.stef.arcana.formats.zstd.MemoryAccess.BASE;

import java.io.IOException;
import java.io.InputStream;


/**
 * Streaming Zstandard decompressor.
 *
 * <p>Reads a Zstd stream block by block: each block (at most 128 KB compressed)
 * is read from the underlying stream, decoded by {@link ZstdFrameDecompressor}
 * into a history buffer, and then consumed. The history buffer keeps the last
 * window-size bytes of the frame (matches can reach that far back) and slides
 * when it is full, so memory is bounded by the window size of the frame (at
 * most 128 MB, window log 27, like the zstd tool's default decoding limit),
 * not by the content size. Frames without a content size (written by zstd
 * when it reads from a pipe) are handled the same way.</p>
 *
 * <p>Zstd skippable frames (magic 0x184D2A5x) are silently consumed and
 * skipped wherever they appear. Multi-frame streams (concatenated Zstd frames)
 * are handled correctly -- each frame is decompressed independently, and the
 * decompressed output is the concatenation of all frame outputs.</p>
 *
 * @author Stef
 * @since 1.1
 */
public final class ZstdInputStream extends InputStream {

    private static final int ZSTD_MAGIC         = 0xFD2FB528;
    private static final int ZSTD_V07_MAGIC     = 0xFD2FB527;
    private static final int SKIPPABLE_MAGIC_MIN = 0x184D2A50;
    private static final int SKIPPABLE_MAGIC_MAX = 0x184D2A5F;
    private static final int SIZE_OF_BLOCK_HEADER = 3;
    private static final int SIZE_OF_INT = 4;
    /** Largest frame header after the magic: descriptor, window, dictionary ID (4), content size (8). */
    private static final int MAX_FRAME_HEADER = 1 + 1 + 4 + 8;
    /** Extra room in the block buffer so that the decoder may read a few bytes past the block. */
    private static final int BLOCK_PADDING = 16;

    private final InputStream in;
    private final ZstdFrameDecompressor decompressor = new ZstdFrameDecompressor();
    private final byte[] block = new byte[Constants.MAX_BLOCK_SIZE + BLOCK_PADDING];

    /** History buffer of the current frame: decoded bytes [0, winPos), of which [outPos, winPos) are not yet consumed. */
    private byte[] window = new byte[0];
    private int winPos;
    private int outPos;
    private boolean eof;

    // Current frame state
    private boolean inFrame;
    private boolean lastBlock;
    private int historySize;
    private int capacity;
    private long contentSize;
    private long produced;
    private XxHash64 hasher;

    public ZstdInputStream(final InputStream in) {
        this.in = in;
    }

    // =========================================================================
    // InputStream
    // =========================================================================

    @Override
    public int read() throws IOException {
        final byte[] buf = new byte[1];
        final int n = read(buf, 0, 1);
        return n < 0 ? -1 : (buf[0] & 0xFF);
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        if (eof) return -1;
        while (outPos >= winPos) {
            if (!decodeNextBlock()) { eof = true; return -1; }
        }
        final int n = Math.min(len, winPos - outPos);
        System.arraycopy(window, outPos, buf, off, n);
        outPos += n;
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Frame and block reading
    // =========================================================================

    /**
     * Decodes the next block of the stream, starting a new frame when needed.
     * Returns false on end of stream.
     */
    private boolean decodeNextBlock() throws IOException {
        while (!inFrame || lastBlock) {
            if (inFrame) endFrame();
            if (!startFrame()) return false;
        }

        readFully(block, 0, SIZE_OF_BLOCK_HEADER, true);
        final int header24 = (block[0] & 0xFF) | ((block[1] & 0xFF) << 8) | ((block[2] & 0xFF) << 16);
        lastBlock = (header24 & 1) != 0;
        final int blockType = (header24 >>> 1) & 0x03;
        final int blockSize = (header24 >>> 3) & 0x1FFFFF;
        if (blockType == 3) throw new IOException("Zstd reserved block type encountered");
        if (blockSize > Constants.MAX_BLOCK_SIZE) throw new IOException("Zstd block too large: " + blockSize);

        final int rawBytes = (blockType == Constants.RLE_BLOCK) ? 1 : blockSize;
        readFully(block, 0, rawBytes, true);
        java.util.Arrays.fill(block, rawBytes, rawBytes + BLOCK_PADDING, (byte) 0);

        final int decodedMax = (blockType == Constants.COMPRESSED_BLOCK) ? Constants.MAX_BLOCK_SIZE : blockSize;
        makeRoom(decodedMax);

        final long output = BASE + winPos;
        final long outputLimit = BASE + window.length;
        final int decoded;
        switch (blockType) {
            case Constants.RAW_BLOCK:
                decoded = ZstdFrameDecompressor.decodeRawBlock(block, BASE, blockSize, window, output, outputLimit);
                break;
            case Constants.RLE_BLOCK:
                decoded = ZstdFrameDecompressor.decodeRleBlock(blockSize, block, BASE, window, output, outputLimit);
                break;
            default:
                decoded = decompressor.decodeCompressedBlock(block, BASE, blockSize, window, output, outputLimit, historySize, BASE);
                break;
        }
        if (hasher != null && decoded > 0) hasher.update(window, winPos, decoded);
        winPos += decoded;
        produced += decoded;
        return true;
    }

    /**
     * Makes sure that {@code need} bytes can be decoded after {@code winPos}:
     * grows the history buffer up to the frame capacity, then slides it so
     * that only the last {@code historySize} bytes are kept. All the bytes
     * before {@code winPos} have been consumed when this is called.
     */
    private void makeRoom(final int need) {
        if ((long) winPos + need <= window.length) return;
        if (window.length < capacity) {
            final long wanted = Math.max(2L * window.length, (long) winPos + need);
            final byte[] grown = new byte[(int) Math.min(capacity, Math.max(wanted, 65536L))];
            System.arraycopy(window, 0, grown, 0, winPos);
            window = grown;
            return;
        }
        if (winPos > historySize) {
            final int keep = historySize;
            System.arraycopy(window, winPos - keep, window, 0, keep);
            winPos = keep;
            outPos = keep;
        }
        // Otherwise the block can only fit if it is smaller than announced; the decoder checks the limit.
    }

    /**
     * Reads the next frame header, skipping skippable frames.
     * Returns false on end of stream.
     */
    private boolean startFrame() throws IOException {
        while (true) {
            final byte[] magicBytes = new byte[4];
            final int n = readFully(magicBytes, 0, 4, false);
            if (n == 0) return false;
            if (n < 4) throw new IOException("Zstd stream truncated in magic number");

            final int magic = ((magicBytes[0] & 0xFF)) | ((magicBytes[1] & 0xFF) << 8) | ((magicBytes[2] & 0xFF) << 16) | ((magicBytes[3] & 0xFF) << 24);

            if (magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX) {
                // Skippable frame: read 4-byte size and skip content
                final byte[] szBuf = new byte[4];
                readFully(szBuf, 0, 4, true);
                final long skipSize = ((szBuf[0] & 0xFF) | ((szBuf[1] & 0xFF) << 8) | ((szBuf[2] & 0xFF) << 16) | ((szBuf[3] & 0xFF) << 24)) & 0xFFFFFFFFL;
                skipFully(skipSize);
                continue;
            }
            if (magic == ZSTD_V07_MAGIC) throw new IOException("Data encoded in unsupported ZSTD v0.7 format");
            if (magic != ZSTD_MAGIC) throw new IOException("Not a Zstd stream (magic 0x" + Integer.toHexString(magic) + ")");
            break;
        }

        // Frame header: descriptor, then window descriptor, dictionary ID and content size
        final byte[] hdr = new byte[MAX_FRAME_HEADER + 8];
        final int fhd = readRequired();
        hdr[0] = (byte) fhd;
        final boolean singleSegment = (fhd & 0x20) != 0;
        final int dictDesc = fhd & 0x03;
        final int csDesc = (fhd >>> 6) & 0x03;
        final int rest = (singleSegment ? 0 : 1) + ((dictDesc == 0) ? 0 : (1 << (dictDesc - 1))) + ((csDesc == 0) ? (singleSegment ? 1 : 0) : (1 << csDesc));
        readFully(hdr, 1, rest, true);
        final FrameHeader fh = ZstdFrameDecompressor.readFrameHeader(hdr, BASE, BASE + 1 + rest);

        contentSize = fh.contentSize;
        if (fh.windowSize >= 0) {
            historySize = fh.windowSize;
        } else {
            // Single segment: the window is the whole content
            if (contentSize < 0 || contentSize > ZstdFrameDecompressor.MAX_WINDOW_SIZE) throw new IOException("Zstd window size too large: " + contentSize + " bytes (maximum " + ZstdFrameDecompressor.MAX_WINDOW_SIZE + ")");
            historySize = (int) contentSize;
        }
        // Room for the history plus the new blocks: a larger margin means fewer slides
        final int margin = Math.max(4 * Constants.MAX_BLOCK_SIZE, historySize >= (1 << 24) ? historySize / 2 : historySize);
        long cap = (fh.windowSize >= 0) ? (long) historySize + margin : historySize;
        if (contentSize >= 0 && contentSize < cap) cap = contentSize;
        capacity = (int) cap;

        decompressor.reset();
        hasher = fh.hasChecksum ? new XxHash64() : null;
        if (window.length > capacity) window = new byte[0];
        winPos = 0;
        outPos = 0;
        produced = 0;
        lastBlock = false;
        inFrame = true;
        return true;
    }

    /** Checks the content size and the checksum of the frame that has just been decoded. */
    private void endFrame() throws IOException {
        inFrame = false;
        if (contentSize >= 0 && produced != contentSize) throw new IOException("Zstd frame content size mismatch: expected " + contentSize + " bytes, got " + produced);
        if (hasher != null) {
            final byte[] cs = new byte[SIZE_OF_INT];
            readFully(cs, 0, SIZE_OF_INT, true);
            final int checksum = (cs[0] & 0xFF) | ((cs[1] & 0xFF) << 8) | ((cs[2] & 0xFF) << 16) | ((cs[3] & 0xFF) << 24);
            final int hash = (int) hasher.hash();
            if (checksum != hash) throw new ZstdMalformedInputException(produced, "Bad checksum. Expected: " + Integer.toHexString(checksum) + ", actual: " + Integer.toHexString(hash));
            hasher = null;
        }
    }

    // =========================================================================
    // I/O helpers
    // =========================================================================

    private int readRequired() throws IOException {
        final int b = in.read();
        if (b < 0) throw new IOException("Unexpected end of Zstd stream");
        return b;
    }

    private int readFully(final byte[] buf, final int off, final int len, final boolean required) throws IOException {
        int pos = off;
        int remaining = len;
        while (remaining > 0) {
            final int n = in.read(buf, pos, remaining);
            if (n < 0) {
                if (required) throw new IOException("Unexpected end of Zstd stream");
                return len - remaining;
            }
            pos += n;
            remaining -= n;
        }
        return len;
    }

    private void skipFully(final long n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            final long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() < 0) throw new IOException("Unexpected end of Zstd stream while skipping");
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }
}
