/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * This package is based on the work done by Keiron Liddle, Aftex Software
 * <keiron@aftexsw.com> to whom the Ant project is very grateful for his
 * great code.
 */
/*
 * Ported from org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
 * (Apache Commons Compress 1.28.0) to package be.stef.arcana.formats.bzip2
 * by Stephane Bury (2025).
 * Changes:
 *   - Renamed to BZip2OutputStream.
 *   - Extends java.io.OutputStream directly instead of CompressorOutputStream.
 *   - Removed IOUtils dependency (inlined copy helper).
 *   - BZip2Constants used via direct values (same package).
 */
package be.stef.arcana.formats.bzip2;

import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.OrderedTaskQueue;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Compresses data to the BZip2 format.
 *
 * <p>The block size affects memory usage and compression ratio:
 * a larger block size produces better compression but uses more memory.
 * Valid values are 1 to 9 (where 9 is the maximum, i.e. 900 KB blocks).</p>
 *
 * <p><b>Multithreading:</b> bzip2 blocks are independent (only the stream CRC
 * combines them), so full blocks are sorted and Huffman-coded by worker threads
 * while the caller keeps writing; the coded blocks are appended in order, bit by
 * bit, to a single standard stream. The output is <b>identical</b> whatever the
 * number of threads (see {@link ArcanaConcurrency#threads}).</p>
 *
 * <p>Usage:</p>
 * <pre>
 *   try (BZip2OutputStream bos = new BZip2OutputStream(new FileOutputStream("out.bz2"))) {
 *       bos.write(data);
 *   }
 * </pre>
 *
 * @NotThreadSafe
 */
public class BZip2OutputStream extends OutputStream implements BZip2Constants {

    // =========================================================================
    // Constants
    // =========================================================================

    /** Maximum allowed block size (multiple of BASEBLOCKSIZE). */
    public static final int MAX_BLOCKSIZE = 9;
    /** Minimum allowed block size. */
    public static final int MIN_BLOCKSIZE = 1;

    private static final int GREATER_ICOST = 15;
    private static final int LESSER_ICOST  = 0;
    private static final int NUM_OVERSHOOT = BZip2Constants.NUM_OVERSHOOT_BYTES;

    /** Approximate memory of one block encoder, per 100k of block size (block, fmap, SA-IS arrays, output). */
    private static final long ENCODER_BYTES_PER_100K = 3_500_000L;

    // =========================================================================
    // Instance state
    // =========================================================================

    private final OutputStream out;
    private final int blockSize100k;

    private boolean finished = false; // true once finish() has written the EOS marker/CRC
    private boolean closed = false;   // true once the underlying stream has been closed

    // current block (filled by the caller thread: RLE1 + CRC)
    private int allowableBlockSize;
    private int last;          // index of last byte in block
    private int[] data_block;  // RLE1 output (blockSize100k * 100000)

    // Bit stream of the output
    private int    bsLive;
    private int    bsBuff;

    // CRC
    private final BZip2CRC crc = new BZip2CRC();
    private int combinedCRC;

    // RLE1 pre-BWT run-length encoder state (persists across write0() calls
    // within a single block; reset in initBlock())
    private int rleLast = -1;
    private int rleRun  = 0;

    // Block coding: sequential encoder, or worker queue when several threads are used
    private final BlockEncoder sequential;
    private final OrderedTaskQueue<EncodedBlock> queue;
    private final ConcurrentLinkedQueue<int[]> freeBlocks = new ConcurrentLinkedQueue<int[]>();
    private final ConcurrentLinkedQueue<BlockEncoder> freeEncoders = new ConcurrentLinkedQueue<BlockEncoder>();

    // =========================================================================
    // Constructors
    // =========================================================================

    /**
     * Creates a BZip2OutputStream with maximum block size (9).
     *
     * @param out underlying output stream
     */
    public BZip2OutputStream(OutputStream out) throws IOException {
        this(out, MAX_BLOCKSIZE);
    }

    /**
     * Creates a BZip2OutputStream with the given block size, using the default
     * number of threads ({@link ArcanaConcurrency#threads}, limited by the heap).
     *
     * @param out        underlying output stream
     * @param blockSize  block size in units of 100 KB (1..9)
     */
    public BZip2OutputStream(OutputStream out, int blockSize) throws IOException {
        this(out, blockSize, ArcanaConcurrency.workersFor(ENCODER_BYTES_PER_100K * blockSize));
    }

    /**
     * Creates a BZip2OutputStream with the given block size and number of threads.
     *
     * @param out        underlying output stream
     * @param blockSize  block size in units of 100 KB (1..9)
     * @param threads    worker threads coding blocks (1 = in the caller thread)
     */
    public BZip2OutputStream(OutputStream out, int blockSize, int threads) throws IOException {
        if (blockSize < MIN_BLOCKSIZE || blockSize > MAX_BLOCKSIZE) {
            throw new IllegalArgumentException("blockSize must be between " + MIN_BLOCKSIZE + " and " + MAX_BLOCKSIZE);
        }
        this.out = out;
        this.blockSize100k = blockSize;
        if (threads > 1) {
            this.sequential = null;
            this.queue = new OrderedTaskQueue<EncodedBlock>(threads, this::writeEncoded);
        } else {
            this.sequential = new BlockEncoder();
            this.queue = null;
        }
        bsSetStream();
        writeStreamHeader();
        initBlock();
    }

    // =========================================================================
    // OutputStream methods
    // =========================================================================

    @Override
    public void write(int b) throws IOException {
        if (finished) throw new IOException("Stream closed");
        write0(b);
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        if (finished) throw new IOException("Stream closed");
        if (buf == null) throw new NullPointerException();
        if (off < 0 || len < 0 || off + len > buf.length) throw new IndexOutOfBoundsException();
        for (int i = off, end = off + len; i < end; i++) {
            write0(buf[i] & 0xff);
        }
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            try {
                finish();
            } finally {
                if (queue != null) queue.close();
                out.close();
                closed = true;
            }
        }
    }

    /**
     * Returns whether the underlying stream has been closed by this stream.
     * A wrapper that called {@link #finish()} explicitly (to avoid closing
     * the wrapped stream at that point) can still safely rely on a later
     * try-with-resources {@link #close()} to flush and close the underlying
     * stream -- {@link #finish()} alone never closes it.
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Completes the BZip2 stream and flushes to the underlying stream
     * without closing it. Use this when wrapping another stream (e.g. TAR).
     */
    public void finish() throws IOException {
        if (!finished) {
            finished = true;
            try {
                flushPendingRun();
                endBlock();
                if (queue != null) queue.finish();
                endCompression();
            } finally {
                if (queue != null) queue.close();
            }
        }
    }

    /**
     * Flushes any RLE1 run still pending (4 or more repeats of the same byte
     * seen but not yet followed by a count byte) at true end-of-stream.
     */
    private void flushPendingRun() {
        if (rleRun >= 4) {
            emitToBlock(rleRun - 4);
            rleRun = 0;
        }
    }

    // =========================================================================
    // Core write path
    // =========================================================================

    private void write0(int b) throws IOException {
        if (last >= allowableBlockSize) {
            // A run of 4+ identical bytes may be pending: its count byte must be written
            // into THIS block, otherwise the block ends with 4 copies and no count and the
            // decoder fails (CRC error on blocks cut in the middle of a run).
            flushPendingRun();
            endBlock();
            initBlock();
        }
        // CRC is computed over the RAW (pre-RLE1) bytes belonging to this block.
        crc.update(b);
        // Mandatory bzip2 pre-BWT run-length encoding (RLE1): any run of 4-255
        // identical bytes becomes 4 literal copies followed by a count byte (0-251).
        rle1Put(b);
    }

    /**
     * Feeds one raw byte through the RLE1 state machine, appending 0, 1, or 2
     * bytes to the current block as a result.
     */
    private void rle1Put(int b) {
        if (rleRun > 0 && b == rleLast) {
            rleRun++;
            if (rleRun <= 4) {
                emitToBlock(b);
            }
            if (rleRun == 255) {
                emitToBlock(251);
                rleRun = 0;
                rleLast = -1;
            }
        } else {
            if (rleRun >= 4) {
                emitToBlock(rleRun - 4);
            }
            rleLast = b;
            rleRun = 1;
            emitToBlock(b);
        }
    }

    /** Appends one RLE1-output byte to the current block buffer. */
    private void emitToBlock(int b) {
        data_block[++last] = b;
    }

    // =========================================================================
    // Block initialisation / finalisation
    // =========================================================================

    private void initBlock() {
        final int n = blockSize100k * BASEBLOCKSIZE;
        if (data_block == null) {
            final int[] recycled = freeBlocks.poll();
            data_block = recycled != null ? recycled : new int[n + NUM_OVERSHOOT];
        }
        last = -1;
        allowableBlockSize = n - 20;
        crc.reset();
        rleLast = -1;
        rleRun = 0;
    }

    private void endBlock() throws IOException {
        if (last == -1) return; // empty block - no data, no CRC contribution
        final int blockCRC = crc.getValue();
        combinedCRC = (combinedCRC << 1) | (combinedCRC >>> 31);
        combinedCRC ^= blockCRC;
        final int n = last + 1;
        if (queue == null) {
            writeEncoded(sequential.encode(data_block, n, blockCRC));
            return;
        }
        // Parallel: the block buffer goes to a worker, a new one is taken for the next block
        final int[] block = data_block;
        data_block = null;
        queue.submit(() -> {
            BlockEncoder enc = freeEncoders.poll();
            if (enc == null) enc = new BlockEncoder();
            try {
                return enc.encode(block, n, blockCRC);
            } finally {
                freeBlocks.add(block);
                freeEncoders.add(enc);
            }
        });
    }

    /** Appends a coded block to the output bit stream (called in block order). */
    private void writeEncoded(final EncodedBlock b) throws IOException {
        final byte[] buf = b.bytes;
        for (int i = 0, n = b.fullBytes; i < n; i++) bsW(8, buf[i] & 0xff);
        if (b.tailBits > 0) bsW(b.tailBits, b.tail);
    }

    private void writeStreamHeader() throws IOException {
        // 'B' 'Z' 'h' blockSize+'0'
        bsPutUByte('B');
        bsPutUByte('Z');
        bsPutUByte('h');
        bsPutUByte('0' + blockSize100k);
    }

    private void endCompression() throws IOException {
        // write EOS block marker: 6 bytes = 0x177245385090
        bsPutUByte(0x17);
        bsPutUByte(0x72);
        bsPutUByte(0x45);
        bsPutUByte(0x38);
        bsPutUByte(0x50);
        bsPutUByte(0x90);
        bsPutInt(combinedCRC);
        bsFinishedWithStream();
    }

    // =========================================================================
    // Bit stream
    // =========================================================================

    private void bsSetStream() {
        bsLive = 0;
        bsBuff = 0;
    }

    private void bsFinishedWithStream() throws IOException {
        while (bsLive > 0) {
            int ch = bsBuff >> 24;
            out.write(ch);
            bsBuff <<= 8;
            bsLive -= 8;
        }
    }

    private void bsPutUByte(int c) throws IOException {
        bsW(8, c);
    }

    private void bsPutInt(int u) throws IOException {
        bsW(8, (u >> 24) & 0xff);
        bsW(8, (u >> 16) & 0xff);
        bsW(8, (u >>  8) & 0xff);
        bsW(8,  u        & 0xff);
    }

    private void bsW(int n, int v) throws IOException {
        while (bsLive >= 8) {
            out.write(bsBuff >> 24);
            bsBuff <<= 8;
            bsLive -= 8;
        }
        bsBuff |= v << (32 - bsLive - n);
        bsLive += n;
    }

    // =========================================================================
    // Coded block
    // =========================================================================

    /** One block coded as a bit string: {@code fullBytes} bytes then {@code tailBits} bits. */
    static final class EncodedBlock {
        final byte[] bytes;
        final int fullBytes;
        final int tailBits;
        final int tail;

        EncodedBlock(final byte[] bytes, final int fullBytes, final int tailBits, final int tail) {
            this.bytes = bytes;
            this.fullBytes = fullBytes;
            this.tailBits = tailBits;
            this.tail = tail;
        }
    }

    /** Bit writer into a growable byte array (MSB first, like the bzip2 stream). */
    static final class BitWriter {
        private byte[] buf = new byte[1 << 16];
        private int pos;
        private int live;
        private int buff;

        void reset() {
            pos = 0;
            live = 0;
            buff = 0;
        }

        void w(final int n, final int v) {
            while (live >= 8) {
                if (pos == buf.length) buf = java.util.Arrays.copyOf(buf, buf.length * 2);
                buf[pos++] = (byte) (buff >>> 24);
                buff <<= 8;
                live -= 8;
            }
            buff |= v << (32 - live - n);
            live += n;
        }

        void putByte(final int c) {
            w(8, c);
        }

        void putInt(final int u) {
            w(8, (u >> 24) & 0xff);
            w(8, (u >> 16) & 0xff);
            w(8, (u >>  8) & 0xff);
            w(8,  u        & 0xff);
        }

        EncodedBlock toBlock() {
            while (live >= 8) {
                if (pos == buf.length) buf = java.util.Arrays.copyOf(buf, buf.length * 2);
                buf[pos++] = (byte) (buff >>> 24);
                buff <<= 8;
                live -= 8;
            }
            return new EncodedBlock(java.util.Arrays.copyOf(buf, pos), pos, live, live == 0 ? 0 : buff >>> (32 - live));
        }
    }

    // =========================================================================
    // Block encoder (BWT + MTF/RLE2 + Huffman), one per worker thread
    // =========================================================================

    /** Codes one block; holds the working arrays so that they are reused between blocks. */
    static final class BlockEncoder {
        private final BZip2BlockSort blockSort = new BZip2BlockSort();
        private final BitWriter bw = new BitWriter();
        private int[] fmap = new int[0];
        private int[] mtfBuf = new int[0];
        private final int[][] len = new int[N_GROUPS][MAX_ALPHA_SIZE];
        private final int[][] code = new int[N_GROUPS][MAX_ALPHA_SIZE];
        private final int[][] rfreq = new int[N_GROUPS][MAX_ALPHA_SIZE];
        private final byte[] selector = new byte[MAX_SELECTORS];
        private final byte[] selectorMtf = new byte[MAX_SELECTORS];

        EncodedBlock encode(final int[] block, final int n, final int blockCRC) {
            if (fmap.length < n) fmap = new int[n];
            // Burrows-Wheeler transform: sorted rotation order in fmap, and origPtr
            final int origPtr = blockSort.sort(block, n, fmap);
            bw.reset();
            huffman(block, n, origPtr, blockCRC);
            return bw.toBlock();
        }

            private void huffman(final int[] block, final int n, final int origPtr, final int storedBlockCRC) {

            // Build symbol frequency table from BWT output (last column).
            // The last column value for sorted rotation i is the byte immediately
            // PRECEDING that rotation's start (circularly) -- block[(fmap[i]-1) mod n] --
            // not the byte at the rotation's start.
            final int[] freq = new int[MAX_ALPHA_SIZE];
            final boolean[] inUse = new boolean[256];
            final int[] fmap = this.fmap;
            for (int i = 0; i < n; i++) {
                final int f = fmap[i];
                int sym = block[f == 0 ? n - 1 : f - 1];
                inUse[sym] = true;
                freq[sym + 1]++;
            }
            freq[0]++; // EOB symbol

            // Build symbol map
            int nInUse = 0;
            final int[] symToSeq = new int[256];
            java.util.Arrays.fill(symToSeq, -1);
            final boolean[] inUse16 = new boolean[16];
            for (int i = 0; i < 256; i++) {
                if (inUse[i]) {
                    symToSeq[i] = nInUse++;
                    inUse16[i >> 4] = true;
                }
            }
            final int alphaSize = nInUse + 2; // +1 for RUNA/RUNB, +1 for EOB
            final int eob = alphaSize - 1;

            // Build RLE-encoded MTF sequence.
            // The initial MTF list must be the COMPACTED, ascending list of only
            // the bytes actually present in this block -- not the full 256-byte
            // identity table -- since that is the alphabet the header transmits
            // via the sparse symbol map and the alphaSize the decoder expects.
            final byte[] mtf = new byte[nInUse];
            {
                int p = 0;
                for (int b = 0; b < 256; b++) {
                    if (inUse[b]) mtf[p++] = (byte) b;
                }
            }
            final int[] mtfFreq = new int[alphaSize];
            int mtfCount = 0;
            if (mtfBuf.length < n + alphaSize) mtfBuf = new int[n + alphaSize]; // generous upper bound, kept between blocks
            int mtfIdx = 0;
            int runLen = 0;
            for (int i = 0; i < n; i++) {
                final int f = fmap[i];
                int sym = block[f == 0 ? n - 1 : f - 1];
                int seqNo = symToSeq[sym];
                // find seqNo in mtf list
                int mtfPos = 0;
                while ((mtf[mtfPos] & 0xff) != sym) mtfPos++;
                // emit run or symbol
                if (mtfPos == 0) {
                    runLen++;
                } else {
                    // flush run using bijective base-2 numerals (RUNA=1, RUNB=2 place
                    // value 2^i) -- this is the encoding bzip2's RLE2 actually requires,
                    // NOT a naive binary split.
                    while (runLen > 0) {
                        runLen--;
                        final int d = runLen % 2;
                        final int sym0 = (d == 0) ? 0 : 1;
                        mtfBuf[mtfIdx++] = sym0; mtfFreq[sym0]++;
                        runLen /= 2;
                    }
                    // move to front
                    System.arraycopy(mtf, 0, mtf, 1, mtfPos);
                    mtf[0] = (byte) sym;
                    mtfBuf[mtfIdx++] = mtfPos + 1; // +1 to skip RUNA/RUNB positions
                    mtfFreq[mtfPos + 1]++;
                }
            }
            // flush final run (same bijective base-2 numerals as above)
            while (runLen > 0) {
                runLen--;
                final int d = runLen % 2;
                final int sym0 = (d == 0) ? 0 : 1;
                mtfBuf[mtfIdx++] = sym0; mtfFreq[sym0]++;
                runLen /= 2;
            }
            mtfBuf[mtfIdx++] = eob; mtfFreq[eob]++;
            mtfCount = mtfIdx;

            // Determine number of groups
            int nGroups;
            if      (mtfCount < 200)  nGroups = 2;
            else if (mtfCount < 600)  nGroups = 3;
            else if (mtfCount < 1200) nGroups = 4;
            else if (mtfCount < 2400) nGroups = 5;
            else                      nGroups = 6;

            // Initialise length tables
            final int[][] len = this.len;
            for (int t = 0; t < nGroups; t++) {
                final int lo = (t * alphaSize) / nGroups;
                final int hi = ((t + 1) * alphaSize) / nGroups;
                for (int v = 0; v < alphaSize; v++) {
                    len[t][v] = (v >= lo && v < hi) ? LESSER_ICOST : GREATER_ICOST;
                }
            }

            // Iterate to find near-optimal codes (3 iterations like Commons Compress)
            final int nSelectors = (mtfCount + G_SIZE - 1) / G_SIZE;
            final byte[] selector = this.selector;
            final byte[] selectorMtf = this.selectorMtf;
            final int[][] rfreq = this.rfreq;

            for (int iter = 0; iter < N_ITERS; iter++) {
                // Zero frequency tables
                for (int t = 0; t < nGroups; t++) java.util.Arrays.fill(rfreq[t], 0, alphaSize, 0);
                // Assign groups to selectors (greedy: pick group with min cost)
                for (int gs = 0; gs < mtfCount; ) {
                    final int ge = Math.min(gs + G_SIZE - 1, mtfCount - 1);
                    int best = 0, bestCost = Integer.MAX_VALUE;
                    for (int t = 0; t < nGroups; t++) {
                        int cost = 0;
                        for (int v = gs; v <= ge; v++) cost += len[t][mtfBuf[v]];
                        if (cost < bestCost) { bestCost = cost; best = t; }
                    }
                    selector[gs / G_SIZE] = (byte) best;
                    for (int v = gs; v <= ge; v++) rfreq[best][mtfBuf[v]]++;
                    gs = ge + 1;
                }
                // Recompute codes
                for (int t = 0; t < nGroups; t++) hbMakeCodeLengths(len[t], rfreq[t], alphaSize, 17);
            }

            // Build Huffman codes from lengths
            final int[][] code = this.code;
            for (int t = 0; t < nGroups; t++) hbAssignCodes(code[t], len[t], alphaSize);

            // MTF-encode selectors
            final byte[] smtf = new byte[N_GROUPS];
            for (int i = 0; i < nGroups; i++) smtf[i] = (byte) i;
            for (int i = 0; i < nSelectors; i++) {
                int pos = 0;
                byte s = selector[i];
                while (smtf[pos] != s) pos++;
                System.arraycopy(smtf, 0, smtf, 1, pos);
                smtf[0] = s;
                selectorMtf[i] = (byte) pos;
            }

            // === Write block ===
            // Block header magic: 0x314159265359
            bw.putByte(0x31); bw.putByte(0x41); bw.putByte(0x59); bw.putByte(0x26); bw.putByte(0x53); bw.putByte(0x59);
            // Block CRC
            bw.putInt(storedBlockCRC);
            // Randomised flag (always 0 - we do not randomise)
            bw.w(1, 0);
            // origPtr
            bw.w(24, origPtr);
            // Symbol map
            for (int i = 0; i < 16; i++) bw.w(1, inUse16[i] ? 1 : 0);
            for (int i = 0; i < 16; i++) {
                if (inUse16[i]) {
                    for (int j = 0; j < 16; j++) bw.w(1, inUse[i * 16 + j] ? 1 : 0);
                }
            }
            // nGroups (3 bits)
            bw.w(3, nGroups);
            // nSelectors (15 bits)
            bw.w(15, nSelectors);
            // Selector MTF values
            for (int i = 0; i < nSelectors; i++) {
                for (int j = 0; j < (selectorMtf[i] & 0xff); j++) bw.w(1, 1);
                bw.w(1, 0);
            }
            // Huffman tables
            for (int t = 0; t < nGroups; t++) {
                int curr = len[t][0];
                bw.w(5, curr);
                for (int i = 0; i < alphaSize; i++) {
                    while (curr < len[t][i]) { bw.w(2, 2); curr++; }
                    while (curr > len[t][i]) { bw.w(2, 3); curr--; }
                    bw.w(1, 0);
                }
            }
            // Data
            for (int gs = 0, si = 0; gs < mtfCount; ) {
                final int ge = Math.min(gs + G_SIZE - 1, mtfCount - 1);
                final int t = selector[si++] & 0xff;
                for (int v = gs; v <= ge; v++) {
                    final int sym = mtfBuf[v];
                    bw.w(len[t][sym], code[t][sym]);
                }
                gs = ge + 1;
            }
        }

        // Huffman helpers

        /** Builds near-optimal code lengths using a heap-based algorithm. */
        static void hbMakeCodeLengths(int[] len, int[] freq, int alphaSize, int maxLen) {
            // Heap sort to find shortest code lengths (standard Huffman construction)
            final int[] heap = new int[alphaSize + 2];
            final int[] weight = new int[alphaSize * 2];
            final int[] parent = new int[alphaSize * 2];

            for (int i = 0; i < alphaSize; i++) weight[i + 1] = (freq[i] == 0 ? 1 : freq[i]) << 8;

            while (true) {
                int nNodes = alphaSize;
                int nHeap  = 0;
                heap[0] = 0;
                weight[0] = 0;
                parent[0] = -2;
                for (int i = 1; i <= alphaSize; i++) {
                    parent[i] = -1;
                    nHeap++;
                    heap[nHeap] = i;
                    int zz = nHeap;
                    int tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]]) {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }

                while (nHeap > 1) {
                    int n1 = heap[1];
                    heap[1] = heap[nHeap--];
                    int zz = 1, yy, tmp;
                    while (true) {
                        yy = zz << 1;
                        if (yy > nHeap) break;
                        if (yy < nHeap && weight[heap[yy + 1]] < weight[heap[yy]]) yy++;
                        if (weight[heap[zz]] < weight[heap[yy]]) break;
                        tmp = heap[zz]; heap[zz] = heap[yy]; heap[yy] = tmp;
                        zz = yy;
                    }
                    int n2 = heap[1];
                    heap[1] = heap[nHeap--];
                    zz = 1;
                    while (true) {
                        yy = zz << 1;
                        if (yy > nHeap) break;
                        if (yy < nHeap && weight[heap[yy + 1]] < weight[heap[yy]]) yy++;
                        if (weight[heap[zz]] < weight[heap[yy]]) break;
                        tmp = heap[zz]; heap[zz] = heap[yy]; heap[yy] = tmp;
                        zz = yy;
                    }
                    nNodes++;
                    parent[n1] = parent[n2] = nNodes;
                    weight[nNodes] = ((weight[n1] & 0xFFFFFF00) + (weight[n2] & 0xFFFFFF00)) | (1 + Math.max(weight[n1] & 0xFF, weight[n2] & 0xFF));
                    parent[nNodes] = -1;
                    nHeap++;
                    heap[nHeap] = nNodes;
                    zz = nHeap; tmp = heap[zz];
                    while (weight[tmp] < weight[heap[zz >> 1]]) {
                        heap[zz] = heap[zz >> 1];
                        zz >>= 1;
                    }
                    heap[zz] = tmp;
                }

                // Calculate depths
                boolean tooLong = false;
                for (int i = 1; i <= alphaSize; i++) {
                    int j = 0, k = i;
                    while (parent[k] >= 0) { k = parent[k]; j++; }
                    len[i - 1] = j;
                    if (j > maxLen) tooLong = true;
                }
                if (!tooLong) break;
                // Increase weights of frequent symbols and retry
                for (int i = 1; i <= alphaSize; i++) weight[i] = 1 + (weight[i] >> 1);
            }
        }

        /** Assigns canonical Huffman codes from code lengths. */
        static void hbAssignCodes(int[] code, int[] len, int alphaSize) {
            int vec = 0;
            for (int n = 1; n <= 20; n++) {
                for (int i = 0; i < alphaSize; i++) {
                    if (len[i] == n) { code[i] = vec; vec++; }
                }
                vec <<= 1;
            }
        }
    }
}
