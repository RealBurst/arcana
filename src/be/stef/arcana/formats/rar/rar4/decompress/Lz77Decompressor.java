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
package be.stef.arcana.formats.rar.rar4.decompress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import be.stef.arcana.formats.ppmd.Ppmd7;
import be.stef.arcana.formats.ppmd.RarRangeDecoder;
import be.stef.arcana.formats.rar.rar4.Rar4Constants;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;

/**
 * Decompressor for RAR4 archives (algorithm version 2.9 / 3.x): LZ77 blocks,
 * PPMd var.H blocks (the encoder can switch between both inside one file, and
 * PPMd is what "Best" compression picks for text), and the standard
 * post-processing filters (E8, E8E9, DELTA) via signature recognition -
 * bypassing full VM bytecode interpretation.
 *
 * @author Stef
 * @since 1.0
 */
public class Lz77Decompressor implements Rar4Decompressor {

    private static final int SYM_MAIN     = 299;
    private static final int SYM_DIST     = 60;
    private static final int SYM_LOWDIST  = 17;
    private static final int SYM_LEN      = 28;
    private static final int COMBINED_SIZE = SYM_MAIN + SYM_DIST + SYM_LOWDIST + SYM_LEN;

    private static final int WIN_SIZE = 0x400000;
    private static final int WIN_MASK = WIN_SIZE - 1;
    private static final int LOW_DIST_REP_LIMIT = 16;

    /** Trigger a flush when the free space ahead of the write position falls below this. */
    private static final int FLUSH_TRIGGER = 0x80000;

    // --- Standard filter type identifiers (RAR VM standard filters) ---
    private static final int FILTER_E8    = 1;
    private static final int FILTER_E8E9  = 2;
    private static final int FILTER_DELTA = 6;
    private static final int X86_FILE_SIZE = 0x1000000;

    private final byte[] window = new byte[WIN_SIZE];
    private int          writePos;   // next write position (decoded data)
    private int          flushPos;   // next position to flush to output

    private final Rar4HuffmanDecoder mainDecoder    = new Rar4HuffmanDecoder();
    private final Rar4HuffmanDecoder distDecoder    = new Rar4HuffmanDecoder();
    private final Rar4HuffmanDecoder lowDistDecoder = new Rar4HuffmanDecoder();
    private final Rar4HuffmanDecoder lenDecoder     = new Rar4HuffmanDecoder();

    private final Rar4BitDecoder reader = new Rar4BitDecoder();

    private final int[] carriedLengths = new int[COMBINED_SIZE];
    private final int[] currentLengths = new int[COMBINED_SIZE];
    /** TablesRead3 in unrar: a solid file continues with the current tables/mode unless false. */
    private boolean     tablesRead;
    private boolean     solid;
    /** True when the last file ended on an explicit end marker (LZ 256 / PPMd escape 2). */
    private boolean     fileEndSeen;

    // --- PPMd state (kept across files: a PPMd block without the reset flag reuses the model) ---
    private Ppmd7                 ppm;
    private int                   ppmMemSize;
    private final RarRangeDecoder ppmRc = new RarRangeDecoder(this::getChar);
    private boolean               ppmMode;
    private int                   ppmEscChar = 2;

    private final int[] oldDist = new int[4];
    private int         lastDist;
    private int         lastLength;
    private int         prevLowDist;
    private int         lowDistRepCount;

    // --- Filter state ---
    private final List<Integer> filterTypes      = new ArrayList<>();
    private final List<int[]>   oldFilterLengths = new ArrayList<>();
    private int                 lastFilter;
    /** Pending filters: each entry = {type, blockStart, blockLength, channels(R0), fileOffset(R6)}. */
    private final ArrayDeque<int[]> pendingFilters = new ArrayDeque<>();

    private OutputStream output;
    private long         unpackedSize;
    private long         produced;   // bytes decoded into the window
    private long         written;    // bytes flushed to output

    // -------------------------------------------------------------------------
    // Distance / length value tables
    // -------------------------------------------------------------------------

    private static final int[] LEN_BASE = {
        0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,
        32,40,48,56,64,80,96,112,128,160,192,224
    };
    private static final int[] LEN_BITS = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
        3,3,3,3,4,4,4,4,5,5,5,5
    };
    private static final int[] SHORT_DIST_BASE = {0,4,8,16,32,64,128,192};
    private static final int[] SHORT_DIST_BITS = {2,2,3,4,5,6,6,6};
    private static final int[] DIST_BASE = new int[SYM_DIST];
    private static final int[] DIST_BITS = new int[SYM_DIST];

    static {
        int[] counts = {4,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,14,0,12};
        int dist = 0, bitLen = 0, slot = 0;
        for (int i = 0; i < counts.length; i++, bitLen++) {
            for (int j = 0; j < counts[i]; j++, slot++, dist += (1 << bitLen)) {
                DIST_BASE[slot] = dist;
                DIST_BITS[slot] = bitLen;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Rar4Decompressor
    // -------------------------------------------------------------------------

    @Override
    public boolean canHandle(int method, int version) {
        return method >= Rar4Constants.COMPRESS_METHOD_FASTEST
            && method <= Rar4Constants.COMPRESS_METHOD_BEST
            && version >= Rar4Constants.COMPRESS_VERSION_29;
    }

    @Override
    public void resetState(boolean isSolid) {
        solid = isSolid;
        if (!isSolid) {
            tablesRead      = false;
            ppmMode         = false;
            ppmEscChar      = 2;
            writePos        = 0;
            flushPos        = 0;
            lastDist        = 0;
            lastLength      = 0;
            prevLowDist     = 0;
            lowDistRepCount = 0;
            lastFilter      = 0;
            Arrays.fill(oldDist, 0);
            Arrays.fill(carriedLengths, 0);
            filterTypes.clear();
            oldFilterLengths.clear();
            pendingFilters.clear();
        }
    }

    @Override
    public void decompress(InputStream input, OutputStream out, Rar4FileBlock file) throws IOException {
        this.output       = out;
        this.unpackedSize = file.getUnpackedSize();
        this.produced     = 0;
        this.written      = 0;

        reader.init(input);
        fileEndSeen = false;
        if (!solid || !tablesRead) {
            if (!readTables()) throw new IOException("RAR4: failed to read initial tables");
        }

        while (produced < unpackedSize) {
            if (reader.shouldRefill()) reader.refill();

            if (ppmMode) {
                if (!decodePpm()) break;
                if (((flushPos - writePos - 1) & WIN_MASK) < FLUSH_TRIGGER) flush(false);
                continue;
            }

            int number = mainDecoder.decode(reader);

            if (number < 256) {
                emitByte((byte) number);

            } else if (number >= 271) {
                int idx    = number - 271;
                int length = LEN_BASE[idx] + 3;
                int lbits  = LEN_BITS[idx];
                if (lbits > 0) length += reader.readBits(lbits);

                int distSym  = distDecoder.decode(reader);
                int distance = DIST_BASE[distSym] + 1;
                int dbits    = DIST_BITS[distSym];
                if (dbits > 0) {
                    if (distSym > 9) {
                        if (dbits > 4) distance += reader.readBits(dbits - 4) << 4;
                        if (lowDistRepCount > 0) {
                            lowDistRepCount--;
                            distance += prevLowDist;
                        } else {
                            int lowDist = lowDistDecoder.decode(reader);
                            if (lowDist == LOW_DIST_REP_LIMIT) {
                                lowDistRepCount = LOW_DIST_REP_LIMIT - 1;
                                distance += prevLowDist;
                            } else {
                                distance  += lowDist;
                                prevLowDist = lowDist;
                            }
                        }
                    } else {
                        distance += reader.readBits(dbits);
                    }
                }
                if (distance >= 0x2000) {
                    length++;
                    if (distance >= 0x40000) length++;
                }
                insertOldDist(distance);
                lastLength = length;
                lastDist   = distance;
                copyMatch(distance, length);

            } else if (number == 256) {
                if (!readEndOfBlock()) { fileEndSeen = true; break; }

            } else if (number == 257) {
                readVmCode();

            } else if (number == 258) {
                if (lastLength != 0) copyMatch(lastDist, lastLength);

            } else if (number < 263) {
                int distNum  = number - 259;
                int distance = oldDist[distNum];
                for (int i = distNum; i > 0; i--) oldDist[i] = oldDist[i - 1];
                oldDist[0] = distance;

                int lenSym = lenDecoder.decode(reader);
                int length = LEN_BASE[lenSym] + 2;
                int lbits  = LEN_BITS[lenSym];
                if (lbits > 0) length += reader.readBits(lbits);
                lastLength = length;
                lastDist   = distance;
                copyMatch(distance, length);

            } else {
                int idx      = number - 263;
                int distance = SHORT_DIST_BASE[idx] + 1;
                int sbits    = SHORT_DIST_BITS[idx];
                if (sbits > 0) distance += reader.readBits(sbits);
                insertOldDist(distance);
                lastLength = 2;
                lastDist   = distance;
                copyMatch(distance, 2);
            }

            if (((flushPos - writePos - 1) & WIN_MASK) < FLUSH_TRIGGER) flush(false);
        }
        if (!fileEndSeen && produced >= unpackedSize) consumeFileTerminator();
        flush(true);
    }

    /**
     * The size limit stops the loop before the encoder's end-of-file marker. It is
     * decoded here (nothing is emitted) because it drives the state of the next file
     * of a solid archive: PPMd model update, or the "new table" flag of an LZ block.
     */
    private void consumeFileTerminator() {
        try {
            if (ppmMode) {
                if (ppmDecodeChar() == ppmEscChar && ppmDecodeChar() == 0) readTables();
            } else {
                if (reader.shouldRefill()) reader.refill();
                if (mainDecoder.decode(reader) == 256) readEndOfBlock();
            }
        } catch (IOException | RuntimeException ignored) {
            // no terminator (or last file): nothing to carry over
        }
    }

    // -------------------------------------------------------------------------
    // PPMd blocks
    // -------------------------------------------------------------------------

    /** Byte-aligned read used by the PPMd header and range coder. */
    private int getChar() throws IOException {
        if (reader.shouldRefill()) reader.refill();
        int b = reader.peek16() >>> 8;
        reader.skip(8);
        return b;
    }

    /** ModelPPM::DecodeInit. The first byte still carries the PPMd flag (bit 7). */
    private boolean initPpm() throws IOException {
        int maxOrder = getChar();
        boolean reset = (maxOrder & 0x20) != 0;
        int maxMB = 0;
        if (reset) maxMB = getChar();
        else if (ppm == null) throw new IOException("RAR4: PPMd block without an initialized model");
        if ((maxOrder & 0x40) != 0) ppmEscChar = getChar();
        ppmRc.init();
        if (reset) {
            maxOrder = (maxOrder & 0x1F) + 1;
            if (maxOrder > 16) maxOrder = 16 + (maxOrder - 16) * 3;
            if (maxOrder == 1) {
                ppm = null;
                throw new IOException("RAR4: invalid PPMd model order");
            }
            int memSize = (maxMB + 1) << 20;
            if (ppm == null || ppmMemSize != memSize) {
                ppm = null; // release the old heap before allocating the new one
                ppm = new Ppmd7(memSize);
                ppmMemSize = memSize;
            }
            ppm.init(maxOrder);
        }
        ppmMode = true;
        return true;
    }

    /** One PPMd symbol, or -1 on corrupted data (RAR has no PPMd end marker). */
    private int ppmDecodeChar() throws IOException {
        try {
            int c = ppm.decodeSymbol(ppmRc);
            return c < 0 ? -1 : c;
        } catch (RuntimeException e) { // inconsistent model offsets = corrupted stream
            return -1;
        }
    }

    /**
     * Decodes one PPMd step (Unpack29, BLOCK_PPM branch).
     *
     * @return false when the file ends (end-of-file code or corrupted data)
     */
    private boolean decodePpm() throws IOException {
        int ch = ppmDecodeChar();
        if (ch < 0) throw new IOException("RAR4: corrupted PPMd data");
        if (ch == ppmEscChar) {
            int next = ppmDecodeChar();
            switch (next) {
                case 0:  // end of PPMd block: LZ tables (or a new PPMd block) follow
                    return readTables();
                case 2:  // end of file
                    fileEndSeen = true;
                    return false;
                case 3:  // VM filter code
                    readVmCodePpm();
                    return true;
                case 4: { // LZ match inside PPMd: 3 distance bytes + 1 length byte
                    int distance = 0, length = 0;
                    for (int i = 0; i < 4; i++) {
                        int c = ppmDecodeChar();
                        if (c < 0) throw new IOException("RAR4: corrupted PPMd data");
                        if (i == 3) length = c; else distance = (distance << 8) + c;
                    }
                    copyMatch(distance + 2, length + 32);
                    return true;
                }
                case 5: { // RLE: repeat the previous byte
                    int length = ppmDecodeChar();
                    if (length < 0) throw new IOException("RAR4: corrupted PPMd data");
                    copyMatch(1, length + 4);
                    return true;
                }
                case 1:  // literal escape character
                    break;
                default:
                    throw new IOException("RAR4: corrupted PPMd data (escape code " + next + ")");
            }
        }
        emitByte((byte) ch);
        return true;
    }

    private void readVmCodePpm() throws IOException {
        int firstByte = ppmDecodeChar();
        if (firstByte < 0) throw new IOException("RAR4: corrupted PPMd data");
        int length = (firstByte & 7) + 1;
        if (length == 7) {
            int b1 = ppmDecodeChar();
            if (b1 < 0) throw new IOException("RAR4: corrupted PPMd data");
            length = b1 + 7;
        } else if (length == 8) {
            int b1 = ppmDecodeChar();
            int b2 = ppmDecodeChar();
            if (b1 < 0 || b2 < 0) throw new IOException("RAR4: corrupted PPMd data");
            length = b1 * 256 + b2;
        }
        byte[] vmCode = new byte[length];
        for (int i = 0; i < length; i++) {
            int c = ppmDecodeChar();
            if (c < 0) throw new IOException("RAR4: corrupted PPMd data");
            vmCode[i] = (byte) c;
        }
        addVmCode(firstByte, vmCode);
    }

    // -------------------------------------------------------------------------
    // Window write
    // -------------------------------------------------------------------------

    private void emitByte(byte b) {
        window[writePos] = b;
        writePos = (writePos + 1) & WIN_MASK;
        produced++;
    }

    private void copyMatch(int distance, int length) {
        int n   = (int) Math.min(length, unpackedSize - produced);
        int src = (writePos - distance) & WIN_MASK;
        for (int i = 0; i < n; i++) {
            window[writePos] = window[src];
            src      = (src      + 1) & WIN_MASK;
            writePos = (writePos + 1) & WIN_MASK;
        }
        produced += n;
    }

    private void insertOldDist(int distance) {
        oldDist[3] = oldDist[2];
        oldDist[2] = oldDist[1];
        oldDist[1] = oldDist[0];
        oldDist[0] = distance;
    }

    // -------------------------------------------------------------------------
    // Block boundaries / tables
    // -------------------------------------------------------------------------

    private boolean readEndOfBlock() throws IOException {
        int field = reader.peek16();
        boolean newTable, newFile = false;
        if ((field & 0x8000) != 0) {
            newTable = true;
            reader.skip(1);
        } else {
            newFile  = true;
            newTable = (field & 0x4000) != 0;
            reader.skip(2);
        }
        tablesRead = !newTable;
        if (newFile) return false;
        if (newTable) return readTables();
        return true;
    }

    /** ReadTables30: a PPMd block (bit 7 of the aligned byte) or new Huffman tables. */
    private boolean readTables() throws IOException {
        reader.alignToByte();
        if (reader.shouldRefill()) reader.refill();
        int control = reader.peek16();
        if ((control & 0x8000) != 0) return initPpm();
        ppmMode = false;
        boolean resetLengths = (control & 0x4000) == 0;
        reader.skip(2);
        prevLowDist     = 0;
        lowDistRepCount = 0;
        if (resetLengths) Arrays.fill(carriedLengths, 0);

        Rar4HuffmanDecoder.readLengthTable(reader, carriedLengths, currentLengths, COMBINED_SIZE);

        int off = 0;
        mainDecoder   .build(currentLengths, off, SYM_MAIN);    off += SYM_MAIN;
        distDecoder   .build(currentLengths, off, SYM_DIST);    off += SYM_DIST;
        lowDistDecoder.build(currentLengths, off, SYM_LOWDIST); off += SYM_LOWDIST;
        lenDecoder    .build(currentLengths, off, SYM_LEN);

        System.arraycopy(currentLengths, 0, carriedLengths, 0, COMBINED_SIZE);
        tablesRead = true;
        return true;
    }

    // -------------------------------------------------------------------------
    // VM code reading (symbol 257) - standard filter recognition
    // -------------------------------------------------------------------------

    /** Bit reader operating on the VM code byte array (MSB-first). */
    private static final class VmBitInput {
        private final byte[] buf;
        private int addr, bit;
        VmBitInput(byte[] b) { buf = b; }
        int getbits() {
            int b0 = addr     < buf.length ? (buf[addr]     & 0xFF) : 0;
            int b1 = addr + 1 < buf.length ? (buf[addr + 1] & 0xFF) : 0;
            int b2 = addr + 2 < buf.length ? (buf[addr + 2] & 0xFF) : 0;
            return (((b0 << 16) | (b1 << 8) | b2) >>> (8 - bit)) & 0xFFFF;
        }
        void addbits(int n) { n += bit; addr += n >>> 3; bit = n & 7; }
        int readData() {
            int data = getbits();
            switch (data & 0xC000) {
                case 0:      addbits(6);  return (data >>> 10) & 0xF;
                case 0x4000:
                    if ((data & 0x3C00) == 0) { data = 0xFFFFFF00 | ((data >>> 2) & 0xFF); addbits(14); }
                    else                      { data = (data >>> 6) & 0xFF;                addbits(10); }
                    return data;
                case 0x8000: addbits(2); data = getbits(); addbits(16); return data;
                default:     addbits(2); data = getbits() << 16; addbits(16); data |= getbits(); addbits(16); return data;
            }
        }
    }

    /** Standard filter signatures: {codeLength, crc32, filterType}. */
    private static final int[][] STD_FILTER_SIGS = {
        {53,  0xad576887, FILTER_E8},
        {57,  0x3cd7e57e, FILTER_E8E9},
        {120, 0x3769893f, 3},          // ITANIUM (not applied)
        {29,  0x0e06077d, FILTER_DELTA},
        {149, 0x1c2c5dc8, 4},          // RGB (not applied)
        {216, 0xbc85e701, 5},          // AUDIO (not applied)
        {40,  0x46b9c560, 7}           // UPCASE (not applied)
    };

    private static int identifyStandardFilter(byte[] code) {
        CRC32 crc = new CRC32();
        crc.update(code);
        int value = (int) crc.getValue();
        for (int[] sig : STD_FILTER_SIGS) {
            if (sig[1] == value && sig[0] == code.length) return sig[2];
        }
        return 0; // inconnu
    }

    private void readVmCode() throws IOException {
        int firstByte = reader.peek16() >>> 8;
        reader.skip(8);
        int length = (firstByte & 7) + 1;
        if (length == 7) {
            length = (reader.peek16() >>> 8) + 7;
            reader.skip(8);
        } else if (length == 8) {
            length = reader.peek16();
            reader.skip(16);
        }
        byte[] vmCode = new byte[length];
        for (int i = 0; i < length; i++) {
            if (reader.shouldRefill()) reader.refill();
            vmCode[i] = (byte) (reader.peek16() >>> 8);
            reader.skip(8);
        }
        addVmCode(firstByte, vmCode);
    }

    private void addVmCode(int firstByte, byte[] vmCode) {
        VmBitInput inp = new VmBitInput(vmCode);

        int filtPos;
        if ((firstByte & 0x80) != 0) {
            filtPos = inp.readData();
            if (filtPos == 0) { filterTypes.clear(); oldFilterLengths.clear(); }
            else filtPos--;
        } else {
            filtPos = lastFilter;
        }
        lastFilter = filtPos;
        boolean newFilter = (filtPos == filterTypes.size());

        int blockStart = inp.readData();
        if ((firstByte & 0x40) != 0) blockStart += 258;
        blockStart = (blockStart + writePos) & WIN_MASK;

        int blockLength;
        if ((firstByte & 0x20) != 0) blockLength = inp.readData();
        else blockLength = (filtPos < oldFilterLengths.size()) ? oldFilterLengths.get(filtPos)[0] : 0;

        int[] initR = new int[7];
        initR[3] = 0x3C000;
        initR[4] = blockLength;
        if ((firstByte & 0x10) != 0) {
            int initMask = inp.getbits() >>> 9;
            inp.addbits(7);
            for (int i = 0; i < 7; i++) {
                if ((initMask & (1 << i)) != 0) initR[i] = inp.readData();
            }
        }

        int type;
        if (newFilter) {
            int vmCodeSize = inp.readData();
            byte[] prog = new byte[Math.max(0, vmCodeSize)];
            for (int i = 0; i < vmCodeSize; i++) {
                prog[i] = (byte) (inp.getbits() >>> 8);
                inp.addbits(8);
            }
            type = identifyStandardFilter(prog);
            filterTypes.add(type);
            oldFilterLengths.add(new int[]{blockLength});
        } else {
            type = filterTypes.get(filtPos);
            if (filtPos < oldFilterLengths.size()) oldFilterLengths.get(filtPos)[0] = blockLength;
        }

        pendingFilters.addLast(new int[]{type, blockStart, blockLength, initR[0], initR[6]});
    }

    // -------------------------------------------------------------------------
    // Flush + filter application
    // -------------------------------------------------------------------------

    private void flush(boolean finalFlush) throws IOException {
        while (flushPos != writePos && written < unpackedSize) {
            int[] f = pendingFilters.peekFirst();
            if (f != null) {
                int bs = f[1], bl = f[2];
                int distToFilter = (bs - flushPos) & WIN_MASK;
                int avail        = (writePos - flushPos) & WIN_MASK;
                if (distToFilter < avail) {
                    if (distToFilter > 0) {
                        writeRaw(flushPos, distToFilter);
                        flushPos = (flushPos + distToFilter) & WIN_MASK;
                        continue;
                    }
                    int availAtBlock = (writePos - bs) & WIN_MASK;
                    if (bl <= availAtBlock || finalFlush) {
                        applyStandardFilter(f[0], bs, bl, f[3], f[4]);
                        writeRaw(bs, bl);
                        flushPos = (bs + bl) & WIN_MASK;
                        pendingFilters.pollFirst();
                        continue;
                    } else {
                        break; // not enough decoded data for this filter yet
                    }
                }
            }
            int avail = (writePos - flushPos) & WIN_MASK;
            if (avail == 0) break;
            writeRaw(flushPos, avail);
            flushPos = (flushPos + avail) & WIN_MASK;
        }
    }

    private void writeRaw(int start, int length) throws IOException {
        // Cap the run by the number of bytes still expected, then emit it as
        // one or two bulk writes (the second only when the run wraps around
        // the end of the circular window). Output bytes and order are
        // identical to a byte-by-byte copy.
        int n = (int) Math.min(length, unpackedSize - written);
        if (n <= 0) return;
        int firstChunk = Math.min(n, WIN_SIZE - start);
        output.write(window, start, firstChunk);
        if (n > firstChunk) {
            output.write(window, 0, n - firstChunk);
        }
        written += n;
    }

    private void applyStandardFilter(int type, int bs, int bl, int channels, int fileOffsetR6) throws IOException {
        if (type == FILTER_E8 || type == FILTER_E8E9) {
            long fileOffset = fileOffsetR6 & 0xFFFFFFFFL;
            byte cmp2 = (byte) ((type == FILTER_E8E9) ? 0xE9 : 0xE8);
            for (int curPos = 0; curPos < bl - 4; ) {
                byte cur = window[(bs + curPos) & WIN_MASK];
                curPos++;
                if (cur == (byte) 0xE8 || cur == cmp2) {
                    long offset = curPos + fileOffset;
                    int p = (bs + curPos) & WIN_MASK;
                    int addr = (window[p] & 0xFF)
                             | ((window[(p + 1) & WIN_MASK] & 0xFF) << 8)
                             | ((window[(p + 2) & WIN_MASK] & 0xFF) << 16)
                             | ((window[(p + 3) & WIN_MASK] & 0xFF) << 24);
                    if ((addr & 0x80000000) != 0) {
                        if (((addr + offset) & 0x80000000L) == 0) put(p, (int) (addr + X86_FILE_SIZE));
                    } else {
                        if (((addr - X86_FILE_SIZE) & 0x80000000L) != 0) put(p, (int) (addr - offset));
                    }
                    curPos += 4;
                }
            }
        } else if (type == FILTER_DELTA) {
            byte[] tmp = new byte[bl];
            int srcPos = 0;
            for (int ch = 0; ch < channels; ch++) {
                byte prev = 0;
                for (int destPos = ch; destPos < bl; destPos += channels) {
                    prev = (byte) (prev - window[(bs + srcPos) & WIN_MASK]);
                    srcPos++;
                    tmp[destPos] = prev;
                }
            }
            for (int i = 0; i < bl; i++) window[(bs + i) & WIN_MASK] = tmp[i];

        } else if (type == 7) {
           // UPCASE: convert each byte to uppercase (subtract 0x20 from lowercase ASCII letters)
           for (int i = 0; i < bl; i++) {
               int idx = (bs + i) & WIN_MASK;
               byte b = window[idx];
               if (b >= 'a' && b <= 'z') window[idx] = (byte) (b - 0x20);
           }
        } else {
          // ITANIUM / RGB / AUDIO: not implemented (rare) - the output would be wrong, so fail loudly
          String name;
          switch (type) {
              case 3:  name = "ITANIUM"; break;
              case 4:  name = "RGB";     break;
              case 5:  name = "AUDIO";   break;
              default: name = "unknown VM code"; break;
          }
          throw new IOException("RAR4: " + name + " filter not supported");
       }
    }

    private void put(int p, int v) {
        window[p]                 = (byte) v;
        window[(p + 1) & WIN_MASK] = (byte) (v >> 8);
        window[(p + 2) & WIN_MASK] = (byte) (v >> 16);
        window[(p + 3) & WIN_MASK] = (byte) (v >> 24);
    }
}