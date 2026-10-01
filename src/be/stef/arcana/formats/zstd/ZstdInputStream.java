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
 * <p>Reads a Zstd stream frame by frame. Each frame is fully buffered in
 * memory (compressed form only), decompressed via {@link ZstdFrameDecompressor},
 * and then consumed byte by byte. Only one frame is held in memory at a time,
 * so archives of arbitrary size can be decompressed without exhausting the
 * heap as long as individual frames are of reasonable size (typically 1-128 MB
 * for files produced by standard tooling).</p>
 *
 * <p>Zstd skippable frames (magic 0x184D2A5x) are silently consumed and
 * skipped. Multi-frame streams (concatenated Zstd frames) are handled
 * correctly -- each frame is decompressed independently, and the decompressed
 * output is the concatenation of all frame outputs.</p>
 *
 * @author Stef
 * @since 1.1
 */
public final class ZstdInputStream extends InputStream {

    private static final int ZSTD_MAGIC         = 0xFD2FB528;
    private static final int SKIPPABLE_MAGIC_MIN = 0x184D2A50;
    private static final int SKIPPABLE_MAGIC_MAX = 0x184D2A5F;
    private static final int SIZE_OF_BLOCK_HEADER = 3;
    private static final int SIZE_OF_INT = 4;
    /** Initial frame read buffer size (grows if a single frame is larger). */
    private static final int INITIAL_FRAME_BUFFER = 4 * 1024 * 1024; // 4 MB

    private final InputStream in;
    private final ZstdFrameDecompressor decompressor = new ZstdFrameDecompressor();

    /** Decompressed bytes of the current frame, ready to be consumed. */
    private byte[] frameOut;
    private int frameOutPos;
    private int frameOutLen;
    private boolean eof;

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
        if (eof) return -1;
        while (frameOut == null || frameOutPos >= frameOutLen) {
            if (!readNextFrame()) return -1;
        }
        final int n = Math.min(len, frameOutLen - frameOutPos);
        System.arraycopy(frameOut, frameOutPos, buf, off, n);
        frameOutPos += n;
        return n;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Frame reading
    // =========================================================================

    /**
     * Reads, decompresses and stores the next Zstd frame.
     * Returns false on end of stream.
     */
    private boolean readNextFrame() throws IOException {
        // Read 4-byte magic
        final byte[] magicBytes = new byte[4];
        final int n = readFully(magicBytes, 0, 4, false);
        if (n == 0) { eof = true; return false; }
        if (n < 4) throw new IOException("Zstd stream truncated in magic number");

        final int magic = ((magicBytes[0] & 0xFF)) | ((magicBytes[1] & 0xFF) << 8) | ((magicBytes[2] & 0xFF) << 16) | ((magicBytes[3] & 0xFF) << 24);

        if (magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX) {
            // Skippable frame: read 4-byte size and skip content
            final byte[] szBuf = new byte[4];
            readFully(szBuf, 0, 4, true);
            final int skipSize = (szBuf[0] & 0xFF) | ((szBuf[1] & 0xFF) << 8) | ((szBuf[2] & 0xFF) << 16) | ((szBuf[3] & 0xFF) << 24);
            skipFully(skipSize);
            return readNextFrame(); // tail-recurse to get the real frame
        }

        if (magic != ZSTD_MAGIC) throw new IOException("Not a Zstd stream (magic 0x" + Integer.toHexString(magic) + ")");

        // Read the frame incrementally into a growing buffer
        // Strategy: read byte by byte to track block boundaries, then decompress in one call
        final java.io.ByteArrayOutputStream frameData = new java.io.ByteArrayOutputStream(INITIAL_FRAME_BUFFER);
        frameData.write(magicBytes); // include magic in the frame buffer

        // Read frame header descriptor to determine header size
        final int fhd = readRequired();
        frameData.write(fhd);
        final boolean singleSegment = (fhd & 0x20) != 0;
        final int dictDesc = fhd & 0x03;
        final int csDesc = (fhd >>> 6) & 0x03;
        final boolean hasChecksum = (fhd & 0x04) != 0;

        int windowSize = -1;
        if (!singleSegment) {
            final int wd = readRequired();
            frameData.write(wd);
            final int exp = (wd >>> 3) & 0x1F;
            final int mant = wd & 0x07;
            windowSize = (1 << (Constants.MIN_WINDOW_LOG + exp)) + ((1 << (Constants.MIN_WINDOW_LOG + exp)) / 8) * mant;
        }

        // Dictionary id
        final int dictBytes = (dictDesc == 0) ? 0 : (1 << (dictDesc - 1));
        readAndWrite(frameData, dictBytes);

        // Content size
        final int csBytes = (csDesc == 0) ? (singleSegment ? 1 : 0) : (1 << csDesc);
        final byte[] csField = new byte[csBytes];
        readFully(csField, 0, csBytes, true);
        frameData.write(csField, 0, csBytes);
        long contentSize = -1L;
        if (csBytes > 0) {
            contentSize = 0;
            for (int i = 0; i < csBytes; i++) contentSize |= (csField[i] & 0xFFL) << (8 * i);
            if (csDesc == 1) contentSize += 256; // spec
        }
        if (windowSize < 0 && contentSize >= 0) windowSize = (int) Math.min(contentSize, Integer.MAX_VALUE);
        if (windowSize < 0) windowSize = 1 << 17; // 128 KB safe default

        // Read blocks until LAST_BLOCK
        while (true) {
            final byte[] bh = new byte[SIZE_OF_BLOCK_HEADER];
            readFully(bh, 0, SIZE_OF_BLOCK_HEADER, true);
            frameData.write(bh);
            final int header24 = (bh[0] & 0xFF) | ((bh[1] & 0xFF) << 8) | ((bh[2] & 0xFF) << 16);
            final boolean lastBlock = (header24 & 1) != 0;
            final int blockType = (header24 >>> 1) & 0x03;
            final int blockSize = (header24 >>> 3) & 0x1FFFFF;
            if (blockType == 3) throw new IOException("Zstd reserved block type encountered");
            final int rawBytes = (blockType == 1) ? 1 : blockSize; // RLE_BLOCK has 1 byte payload
            readAndWrite(frameData, rawBytes);
            if (lastBlock) break;
        }

        // Optional content checksum
        if (hasChecksum) readAndWrite(frameData, SIZE_OF_INT);

        // Decompress the complete frame
        final byte[] compressed = frameData.toByteArray();
        final int outCapacity = contentSize >= 0 ? (int) contentSize : windowSize;
        final byte[] out = new byte[outCapacity > 0 ? outCapacity : windowSize];

        final int written = decompressor.decompress(
                compressed, BASE,
                BASE + compressed.length,
                out, BASE,
                BASE + out.length);

        frameOut = out;
        frameOutPos = 0;
        frameOutLen = written;
        return true;
    }

    // =========================================================================
    // I/O helpers
    // =========================================================================

    private int readRequired() throws IOException {
        final int b = in.read();
        if (b < 0) throw new IOException("Unexpected end of Zstd stream");
        return b;
    }

    private void readAndWrite(final java.io.ByteArrayOutputStream buf, final int len) throws IOException {
        if (len <= 0) return;
        final byte[] tmp = new byte[len];
        readFully(tmp, 0, len, true);
        buf.write(tmp, 0, len);
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
