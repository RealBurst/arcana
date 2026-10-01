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
package be.stef.arcana.formats.rar.rar5.decompress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import be.stef.arcana.exceptions.RarCorruptedDataException;
import be.stef.arcana.formats.rar.util.ByteBuffer;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;

/**
 * LZ (Lempel-Ziv) decoder for RAR5 archives.
 * 
 * <p>This is the core decompression engine that handles RAR5's LZ77-based
 * compression algorithm with support for:</p>
 * <ul>
 *   <li>Huffman-coded symbols for literals and match lengths</li>
 *   <li>Multiple distance repetition registers</li>
 *   <li>Post-processing filters (Delta, E8, E8E9, ARM)</li>
 *   <li>Solid and non-solid archive modes</li>
 *   <li>V6 and V7 algorithm variants</li>
 * </ul>
 * 
 * <p><b>WARNING:</b> This is the most critical component of the RAR5 decompressor.
 * The algorithms have been carefully coded and debugged. Do not modify the
 * decompression logic without extensive testing on a large archive corpus.</p>
 * 
 * <h3>Usage:</h3>
 * <pre>
 * Rar5LZDecoder decoder = new Rar5LZDecoder();
 * byte[] properties = Rar5PropertyEncoder.encodeWindowSize(windowSize, solid, v7);
 * decoder.setDecoderProperties(properties);
 * decoder.decode(inputStream, outputStream, null, unpackSize, null);
 * </pre>
 * 
 * <h3>Thread Safety:</h3>
 * <p>This class is <b>not thread-safe</b>. Each thread should use its own instance.
 * However, a single instance can be reused for multiple files in a solid archive.</p>
 * 
 * @author Stef
 * @since 1.0
 * @see RarCorruptedDataException
 */
public class Rar5LZDecoder {
    private static final int WRITE_STEP = 1 << 18;             //Write step size for output buffering (256 KB).
    private static final int SUCCESS = 0;                      //Return code indicating successful LZ2 decoding.
    private static final int ERROR_FILTER_REQUIRED = 1;        //Return code indicating a filter needs to be added.
    private static final int SOLID_RECOVER_LIMIT = 1 << 20;    //Maximum position gap for solid archive recovery (1 MB).
    private boolean isSolid;
    private boolean isV7;
    private boolean wasInitialized;
    private long dictionarySize;
    private byte[] window;
    private int windowPos;
    private int windowSize;
    private long dictSizeForCheck;
    private long lzSize;
    private long lzEnd;
    private long writtenFileSize;
    private Rar5Filter[] filters;
    private int windowSizeAllocated;
    private byte[] inputBuf;
    private long unpackedSize;
    private boolean isUnpackedSizeDefined;
    // progress reporting removed (was javax.swing.JProgressBar, incompatible with headless environments)
    private long progressPack;
    private long progressUnpack;
    private InputStream inputStream;
    private OutputStream outputStream;
    private boolean isWriteError;
    private boolean isUnsupportedFilter;
    private boolean isTableWasFilled;
    private boolean isLastBlock;
    private boolean isUseAlignBits;
    private int lastLen;
    private long[] repDistances;
    private int nbFilters;
    private int nbUnusedFilters;
    private long filterEnd;
    private long lzFileStart;
    private long lzWritten;
    private byte[] bufRes;
    private int bufPosRes;
    private int bitPosRes;
    private int curLimit;
    private byte[] lenPlusTable;
    private Rar5BitDecoder reusableBitStream;
    private Rar5HuffmanDecoder mainDecoder;
    private Rar5HuffmanDecoder distDecoder;
    private Rar5HuffmanDecoder lenDecoder;
    private Rar5HuffmanDecoder alignDecoder;
    private ByteBuffer filterSourceBuffer;
    private ByteBuffer filterDestBuffer;
    
    /**
     * Constructs a new RAR5 LZ decoder.
     * 
     * <p>Initializes all internal structures including Huffman decoders,
     * repetition distance registers, and filter buffers. The decoder is
     * ready to use after construction but requires properties to be set
     * via {@link #setDecoderProperties(byte[])} before decoding.</p>
     */
    public Rar5LZDecoder() {
        isSolid = false;
        isV7 = false;
        wasInitialized = false;
        dictionarySize = Rar5Constants.WIN_SIZE_MIN;
        window = null;
        windowPos = 0;
        windowSize = 0;
        dictSizeForCheck = 0;
        lzSize = 0;
        lzEnd = 0;
        writtenFileSize = 0;
        filters = null;
        windowSizeAllocated = 0;
        inputBuf = null;
        repDistances = new long[4];
        Arrays.fill(repDistances, 0xFFFFFFFFL);
        filterSourceBuffer = new ByteBuffer();
        filterDestBuffer = new ByteBuffer();
        reusableBitStream = new Rar5BitDecoder();
        
        lenPlusTable = new byte[Rar5Constants.DICT_SIZE_BITS_MAX];
        System.arraycopy(Rar5Constants.LEN_PLUS_TABLE, 0, lenPlusTable, 0, Rar5Constants.DICT_SIZE_BITS_MAX);
        
        mainDecoder = new Rar5HuffmanDecoder(
            Rar5Constants.NUM_HUFFMAN_BITS, 
            Rar5Constants.MAIN_TABLE_SIZE, 
            Rar5Constants.NUM_HUFFMAN_TABLE_BITS_MAIN
        );
        
        distDecoder = new Rar5HuffmanDecoder(
            Rar5Constants.NUM_HUFFMAN_BITS, 
            Rar5Constants.DIST_TABLE_SIZE_MAX, 
            Rar5Constants.NUM_HUFFMAN_TABLE_BITS_DIST
        );
        
        lenDecoder = new Rar5HuffmanDecoder(
            Rar5Constants.NUM_HUFFMAN_BITS, 
            Rar5Constants.LEN_TABLE_SIZE, 
            Rar5Constants.NUM_HUFFMAN_TABLE_BITS_LEN
        );
        
        alignDecoder = new Rar5HuffmanDecoder(
            Rar5Constants.NUM_HUFFMAN_BITS, 
            Rar5Constants.ALIGN_TABLE_SIZE, 
            Rar5Constants.NUM_HUFFMAN_TABLE_BITS_ALIGN
        );
        
        lastLen = 0;
        isTableWasFilled = false;
        wasInitialized = true;
        nbFilters = 0;
        nbUnusedFilters = 0;
        isUnsupportedFilter = false;
        isWriteError = false;
        isUseAlignBits = false;
        isLastBlock = false;
    }
    
    /**
     * Releases all allocated resources.
     * 
     * <p>Frees the sliding window buffer, input buffer, filter arrays,
     * and filter buffers. After calling this method, the decoder cannot
     * be used without re-initialization.</p>
     * 
     * <p>This method is normally useless (as the garbage collector will 
     * reclaim the memory) but it can be useful for immediate memory release
     * when processing large archives.</p>
     */
    public void releaseResources() {
        window = null;
        windowSizeAllocated = 0;
        inputBuf = null;
        filters = null;
        filterSourceBuffer.free();
        filterDestBuffer.free();
    }
    
    /**
     * Removes filters that have already been executed from the filter list.
     * 
     * <p>This compacts the filter array by shifting remaining filters to
     * the beginning and updating the filter count.</p>
     */
    private void removeUnusedFilters() {
        if (nbUnusedFilters != 0) {
            int n = nbFilters - nbUnusedFilters;
            if (n > 0) {
                System.arraycopy(filters, nbUnusedFilters, filters, 0, n);
            }
            nbFilters = n;
            nbUnusedFilters = 0;
        }
    }
    
    /**
     * Writes decompressed data to the output stream.
     * 
     * <p>Handles size limiting when the unpack size is defined, ensuring
     * no more than the expected number of bytes are written.</p>
     * 
     * @param data the data buffer to write from
     * @param size the number of bytes to write
     * @throws IOException if a write error occurs
     */
    private void writeToOutput(byte[] data, int size) throws IOException {
        if (!isUnpackedSizeDefined || writtenFileSize < unpackedSize) {
            int cur = size;
            if (isUnpackedSizeDefined) {
                long rem = unpackedSize - writtenFileSize;
                if (cur > rem) {
                    cur = (int) rem;
                }
            }
            
            try {
                outputStream.write(data, 0, cur);
            } catch (IOException e) {
                isWriteError = true;
                throw e;
            }
        }
        writtenFileSize += size;
    }
    
    /**
     * Writes decompressed data to the output stream from a specific offset.
     * 
     * <p>Handles size limiting when the unpack size is defined, ensuring
     * no more than the expected number of bytes are written.</p>
     * 
     * @param data the data buffer to write from
     * @param offset the starting offset in the buffer
     * @param size the number of bytes to write
     * @throws IOException if a write error occurs
     */
    private void writeToOutput(byte[] data, int offset, int size) throws IOException {
        if (!isUnpackedSizeDefined || writtenFileSize < unpackedSize) {
            int cur = size;
            if (isUnpackedSizeDefined) {
                long rem = unpackedSize - writtenFileSize;
                if (cur > rem) {
                    cur = (int) rem;
                }
            }
            try {
                outputStream.write(data, offset, cur);
            } catch (IOException e) {
                isWriteError = true;
                throw e;
            }
        }
        writtenFileSize += size;
    }
    
    /**
     * Apply a post-processing filter on decompressed data.
     * 
     * <p>RAR5 supports several filter types for improving compression of
     * specific data patterns:</p>
     * <ul>
     *   <li><b>DELTA</b>: Reverses delta encoding for audio/image data</li>
     *   <li><b>E8</b>: Reverses x86 CALL instruction address transformation</li>
     *   <li><b>E8E9</b>: Reverses x86 CALL/JMP instruction address transformation</li>
     *   <li><b>ARM</b>: Reverses ARM branch instruction address transformation</li>
     * </ul>
     * 
     * @param f the filter descriptor containing type, position, and size
     * @throws IOException if a write error occurs
     * @throws OutOfMemoryError if filter buffer allocation fails
     */
    private void applyFilter(Rar5Filter f) throws IOException {
        byte[] data = filterSourceBuffer.getBuffer();
        int dataSize = f.size;

        if (f.type == Rar5Constants.FILTER_DELTA) {
            filterDestBuffer.allocAtLeastMax(dataSize, Rar5Constants.FILTER_BLOCK_SIZE_MAX);
            if (!filterDestBuffer.isAllocated()) {
                throw new OutOfMemoryError("Failed to allocate filter destination buffer");
            }
           
            byte[] dest = filterDestBuffer.getBuffer();
            int numChannels = f.channels;
           
            int curChannel = 0;
            int srcIdx = 0;

            do {
                byte prevByte = 0;
                int destIdx = curChannel;
                while (destIdx < dataSize) {
                    prevByte = (byte)(prevByte - data[srcIdx++]);
                    dest[destIdx] = prevByte;
                    destIdx += numChannels;
                }
            } while (++curChannel != numChannels);
           
            data = dest;
        
        } else if (f.type < Rar5Constants.FILTER_ARM) {
            // FILTER_E8 or FILTER_E8E9
            if (dataSize > 4) {
                int fileOffset = (int) (f.startPos - lzFileStart);
                final int fileSize = 1 << 24;
                int dataIdx = 0;
                int dataEnd = dataSize - 4;
               
                while (dataIdx < dataEnd) {
                    byte curByte = data[dataIdx++];
                   
                    if (curByte != (byte)0xE8) {
                        if (f.type == Rar5Constants.FILTER_E8 || curByte != (byte)0xE9) {
                            continue;
                        }
                    }
                   
                    int offset = (dataIdx + fileOffset) & (fileSize - 1);  // masque 24 bits
                   
                    int addr = (data[dataIdx] & 0xFF) |
                              ((data[dataIdx + 1] & 0xFF) << 8) |
                              ((data[dataIdx + 2] & 0xFF) << 16) |
                              ((data[dataIdx + 3] & 0xFF) << 24);
                   
                    if (Integer.compareUnsigned(addr, fileSize) < 0) {
                        addr -= offset;
                    } else if (Integer.compareUnsigned(addr, -offset) >= 0) {
                        addr += fileSize;
                    } else {
                        dataIdx += 4;
                        continue;
                    }
                   
                    data[dataIdx] = (byte) addr;
                    data[dataIdx + 1] = (byte) (addr >> 8);
                    data[dataIdx + 2] = (byte) (addr >> 16);
                    data[dataIdx + 3] = (byte) (addr >> 24);
                   
                    dataIdx += 4;
                }
            }
       
        } else if (f.type == Rar5Constants.FILTER_ARM) {
            int pc = (int) (f.startPos - lzFileStart);
            dataSize &= ~3;
            if (dataSize > 0) {
                int dataIdx = 0;
                while (dataIdx < dataSize) {
                    if (dataIdx + 3 < dataSize && data[dataIdx + 3] == (byte)0xEB) {
                        int instruction = (data[dataIdx] & 0xFF) |
                                         ((data[dataIdx + 1] & 0xFF) << 8) |
                                         ((data[dataIdx + 2] & 0xFF) << 16) |
                                         ((data[dataIdx + 3] & 0xFF) << 24);
                        
                        int offset = (pc + dataIdx) >> 2;
                        instruction = (instruction & 0xFF000000) | ((instruction - offset) & 0x00FFFFFF);
                        
                        data[dataIdx] = (byte) instruction;
                        data[dataIdx + 1] = (byte) (instruction >> 8);
                        data[dataIdx + 2] = (byte) (instruction >> 16);
                        data[dataIdx + 3] = (byte) (instruction >> 24);
                    }
                    dataIdx += 4;
                }
            }
        } else {
            isUnsupportedFilter = true;
            Arrays.fill(data, 0, dataSize, (byte)0);
        }
        
        writeToOutput(data, dataSize);
    }

    /**
     * Writes buffered data to the output, executing pending filters as needed.
     * 
     * <p>This method handles the complex interaction between the sliding window
     * and filter regions, ensuring data is written in the correct order and
     * filters are applied at the right positions.</p>
     * 
     * @throws IOException if a write error occurs
     * @throws OutOfMemoryError if filter buffer allocation fails
     */
    private void writeBufferedData() throws IOException {
        removeUnusedFilters();
        long curLzSize = lzSize + windowPos;
        
        int overflow = windowPos > windowSize ? (windowPos - windowSize) : 0;
        
        for (int i = 0; i < nbFilters;) {
            long lzAvail = curLzSize - lzWritten;
            if (lzAvail == 0) break;
            
            Rar5Filter f = filters[i];

            long blockStart = f.startPos;
            if (blockStart > lzWritten) {
                long rem = blockStart - lzWritten;
                int size = (int) Math.min(lzAvail, rem);
                int srcPos = windowPos - (int)lzAvail;
                
                writeToOutput(window, srcPos, size);
                lzWritten += size;
                continue;
            }
            
            int blockSize = f.size;
            int offset = (int) (lzWritten - blockStart);
            
            if (offset == 0) {
                filterSourceBuffer.allocAtLeastMax(blockSize + Rar5Constants.FILTER_AFTERPAD_SIZE, Rar5Constants.FILTER_BLOCK_SIZE_MAX + Rar5Constants.FILTER_AFTERPAD_SIZE);
                if (!filterSourceBuffer.isAllocated()) {
                    throw new OutOfMemoryError("Failed to allocate filter source buffer");
                }
            }

            int blockRem = blockSize - offset;
            int size = (int) Math.min(lzAvail, blockRem);
            byte[] filterSrcBuf = filterSourceBuffer.getBuffer();

            int srcPos = windowPos - (int)lzAvail;

            System.arraycopy(window, srcPos, filterSrcBuf, offset, size);
            
            lzWritten += size;
            offset += size;
            
            if (offset != blockSize) {
                return;
            }
            
            nbUnusedFilters = ++i;
            applyFilter(f);
        }
        
        removeUnusedFilters();
        if (nbFilters > 0) {
            return;
        }
        
        long lzAvail = Math.min(lzSize + windowSize, curLzSize) - lzWritten;
        if (lzAvail > 0) {
            int srcPos = (int)(((lzWritten - lzSize) % windowSize + windowSize) % windowSize);
            
            writeToOutput(window, srcPos, (int)lzAvail);
            lzWritten += lzAvail;
        }
        
        if (overflow > 0 && lzWritten < curLzSize) {
            writeToOutput(window, windowSize, overflow);
            lzWritten += overflow;
        }
    }
    
    /**
     * Parses and adds a filter from the bit stream.
     * 
     * <p>Reads filter parameters (start position, size, type, and channels
     * for delta filters) from the compressed stream and registers the filter
     * for later execution.</p>
     * 
     * @param bitStream the bit stream to read filter data from
     * @throws IOException if a read or write error occurs
     */
    private void registerFilter(Rar5BitDecoder bitStream) throws IOException {
        removeUnusedFilters();
        
        if (nbFilters >= Rar5Constants.MAX_UNPACK_FILTERS) {
            writeBufferedData();
            removeUnusedFilters();
            if (nbFilters >= Rar5Constants.MAX_UNPACK_FILTERS) {
                isUnsupportedFilter = true;
                initFilters();
            }
        }
        
        bitStream.prepare();
        
        Rar5Filter f = new Rar5Filter();
        f.startPos = Rar5Utils.readUInt32(bitStream);
        f.size = Rar5Utils.readUInt32(bitStream);
        
        if (f.size > Rar5Constants.FILTER_BLOCK_SIZE_MAX) {
            isUnsupportedFilter = true;
            f.size = 0;
        }
        
        f.type = bitStream.readBits9Fix(3);
        f.channels = 0;
        if (f.type == Rar5Constants.FILTER_DELTA) {
            f.channels = bitStream.readBits9Fix(5) + 1;
        }
        f.startPos = lzSize + windowPos + f.startPos;
        
        if (f.startPos < filterEnd) {
            isUnsupportedFilter = true;
        } else {
            filterEnd = f.startPos + f.size;
            if (f.size != 0) {
                if (filters == null) {
                    filters = new Rar5Filter[Rar5Constants.MAX_UNPACK_FILTERS];
                }
                if (nbFilters < filters.length) {
                    filters[nbFilters++] = f;
                }
            }
        }
    }
    
    /**
     * Initializes or resets the filter subsystem.
     * 
     * <p>Clears all pending filters (7-Zip CDecoder::InitFilters). Called at the start
     * of each file and when filter overflow occurs.</p>
     *
     * <p>The Huffman tables are deliberately kept: in a solid archive the next file
     * may start with a block that reuses the previous tables ("table not present"
     * flag). They are reset in {@link #decode} only for a non-solid file.</p>
     */
    private void initFilters() {
        nbFilters = 0;
        nbUnusedFilters = 0;
        filterEnd = 0;
    }
   
    /**
     * Reads and builds Huffman tables from the compressed stream.
     * 
     * <p>RAR5 uses adaptive Huffman coding with tables that can change
     * between blocks. This method reads the table definitions and builds
     * the four Huffman decoders (main, distance, length, and align).</p>
     * 
     * @param bitStream the bit stream to read table data from
     * @throws IOException if a read error occurs
     * @throws RarCorruptedDataException if table data is malformed
     */
    private void readHuffmanTables(Rar5BitDecoder bitStream) throws IOException {
        bitStream.prepare();
        int flags = bitStream.readByteInAligned() & 0xFF;
        int checkSum = bitStream.readByteInAligned() & 0xFF;
        checkSum ^= flags;
        int num = (flags >> 3) & 3;
        if (num >= 3) {
            throw new RarCorruptedDataException("Invalid block header flags");
        }

        int blockSize = bitStream.readByteInAligned() & 0xFF;
        checkSum ^= blockSize;
        if (num != 0) {
            int b = bitStream.readByteInAligned() & 0xFF;
            checkSum ^= b;
            blockSize += b << 8;
            if (num > 1) {
                b = bitStream.readByteInAligned() & 0xFF;
                checkSum ^= b;
                blockSize += b << 16;
            }
        }

        if (checkSum != 0x5A) {
            throw new RarCorruptedDataException("Block header checksum mismatch");
        }

        int blockSizeBits7 = (flags & 7) + 1;
        blockSize += blockSizeBits7 >> 3;
        if (blockSize == 0) {
            bitStream.minorError = true;
            blockSizeBits7 = 0;
            blockSize = 1;
        }
        blockSize--;
        blockSizeBits7 &= 7;

        bitStream.blockEndBits7 = blockSizeBits7;
        bitStream.blockEnd = bitStream.getProcessedSizeRound() + blockSize;
        bitStream.setCheckForBlock();
        isLastBlock = ((flags & 0x40) != 0);

        if ((flags & 0x80) == 0) {
            if (!isTableWasFilled) {
                if (blockSize + blockSizeBits7 != 0) {
                    throw new RarCorruptedDataException("Invalid empty block");
                }
            }
            return;
        }

        isTableWasFilled = false;

        final int kLevelTableSize = 20;
        final int k_NumHufTableBits_Level = 6;
        Rar5HuffmanDecoder levelDecoder = new Rar5HuffmanDecoder(Rar5Constants.NUM_HUFFMAN_BITS, kLevelTableSize, k_NumHufTableBits_Level);

        byte[] lens = new byte[Rar5Constants.TABLES_SIZES_SUM_MAX];
        
        byte[] levelLens = new byte[kLevelTableSize];
        int i = 0;
        do {
            if (bitStream.bufPos >= bitStream.bufCheckBlockPos) {
                bitStream.prepare();
                if (bitStream.isBlockOverRead()) {
                    throw new RarCorruptedDataException("Block overread while reading level table");
                }
            }
            int len = bitStream.readBits9Fix(4);
            if (len == 15) {
                int numZeros = bitStream.readBits9Fix(4);
                if (numZeros != 0) {
                    numZeros += 2;
                    numZeros += i;
                    if (numZeros > kLevelTableSize) {
                        numZeros = kLevelTableSize;
                    }
                    while (i < numZeros) {
                        levelLens[i++] = 0;
                    }
                    continue;
                }
            }
            levelLens[i++] = (byte) len;
        } while (i < kLevelTableSize);

        if (bitStream.isBlockOverRead()) {
            throw new RarCorruptedDataException("Block overread after level table");
        }

        if (!levelDecoder.build(levelLens, Rar5HuffmanDecoder.HUFFMAN_BUILD_MODE_FULL_OR_EMPTY)) {
            throw new RarCorruptedDataException("Failed to build level Huffman decoder");
        }

        i = 0;
        int tableSize = isV7 ? Rar5Constants.TABLES_SIZES_SUM_MAX : Rar5Constants.TABLES_SIZES_SUM_MAX - Rar5Constants.EXTRA_DIST_SYMBOLS_V7;

        do {
            if (bitStream.bufPos >= bitStream.bufCheckBlockPos) {
                bitStream.prepare();
                if (bitStream.isBlockOverRead()) {
                    throw new RarCorruptedDataException("Block overread while reading main table");
                }
            }

            int sym = levelDecoder.decode(bitStream);
            if (sym < 16) {
                lens[i++] = (byte) sym;
            } else {
                num = ((sym - 16) & 1) * 4;
                num += num + 3 + bitStream.readBits9(num + 3);
                num += i;
                if (num > tableSize) {
                    num = tableSize;
                }
                int v = 0;
                if (sym < 16 + 2) {
                    if (i == 0) {
                        throw new RarCorruptedDataException("Invalid repeat symbol at table start");
                    }
                    v = lens[i - 1] & 0xFF;
                }
                while (i < num) {
                    lens[i++] = (byte) v;
                }
            }
        } while (i < tableSize);

        if (bitStream.isBlockOverRead()) {
            throw new RarCorruptedDataException("Block overread after main table");
        }
        if (bitStream.inputEofError()) {
            throw new RarCorruptedDataException("Unexpected end of input while reading tables");
        }

        int buildMode = Rar5HuffmanDecoder.HUFFMAN_BUILD_MODE_FULL_OR_EMPTY;

        if (!mainDecoder.build(lens, 0, buildMode)) {
            throw new RarCorruptedDataException("Failed to build main Huffman decoder");
        }

        if (!isV7) {
            System.arraycopy(lens, Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_V6,
                           lens, Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_V6 + Rar5Constants.EXTRA_DIST_SYMBOLS_V7,
                           Rar5Constants.ALIGN_TABLE_SIZE + Rar5Constants.LEN_TABLE_SIZE);
            Arrays.fill(lens, Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_V6, 
                       Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_V6 + Rar5Constants.EXTRA_DIST_SYMBOLS_V7, (byte)0);
        }

        if (!distDecoder.build(lens, Rar5Constants.MAIN_TABLE_SIZE, buildMode)) {
            throw new RarCorruptedDataException("Failed to build distance Huffman decoder");
        }
        
        if (!lenDecoder.build(lens, Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_MAX + Rar5Constants.ALIGN_TABLE_SIZE, buildMode)) {
            throw new RarCorruptedDataException("Failed to build length Huffman decoder");
        }

        isUseAlignBits = false;
        for (i = 0; i < Rar5Constants.ALIGN_TABLE_SIZE; i++) {
            if (lens[Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_MAX + i] != Rar5Constants.NUM_ALIGN_BITS) {
                if (!alignDecoder.build(lens, Rar5Constants.MAIN_TABLE_SIZE + Rar5Constants.DIST_TABLE_SIZE_MAX, buildMode)) {
                    throw new RarCorruptedDataException("Failed to build align Huffman decoder");
                }
                isUseAlignBits = true;
                break;
            }
        }

        isTableWasFilled = true;
    }


    /**
     * Inner LZ decoding loop optimized for performance.
     * 
     * <p>This is the core decompression routine that processes Huffman-coded
     * symbols and performs LZ77 match copying. It uses local variables for
     * frequently accessed state to minimize field access overhead.</p>
     * 
     * <p>The method returns a result code rather than throwing exceptions
     * for the filter case, as adding a filter is a normal part of the
     * decompression flow, not an error condition.</p>
     * 
     * @param bitStream the bit stream to decode from
     * @return {@link #SUCCESS} for normal completion,
     *         {@link #ERROR_FILTER_REQUIRED} when a filter symbol is encountered
     * @throws IOException if an I/O error occurs
     * @throws RarCorruptedDataException if invalid data is encountered
     */
    private int processSymbols(Rar5BitDecoder bitStream) throws IOException {
        Rar5BitDecoder localBitStream = reusableBitStream;
        localBitStream.copyFrom(bitStream);         
        
        int exitResult = SUCCESS;
        
        long rep0 = repDistances[0];
        byte[] win = window;
        int curWinPos = windowPos;
        int limit = curLimit;

        while (true) {
           
            if (isUnpackedSizeDefined) {
                long decodedSize = lzSize + curWinPos - windowPos;
                if (decodedSize >= unpackedSize) {
                    break;
                }
            }
           
            if (curWinPos >= limit) {
                break;
            }

            long totalUnpacked = lzSize + curWinPos;
            if (isUnpackedSizeDefined && totalUnpacked >= unpackedSize + windowPos) {
                break;
            }
           
            if (localBitStream.bufPos >= localBitStream.bufCheckBlockPos) {
                if (localBitStream.inputEofError()) {
                    break;
                }
                if (localBitStream.bufPos >= localBitStream.bufCheckPos) {
                    if (!localBitStream.wasFinished) {
                        break;
                    }
                }
                long processed = localBitStream.getProcessedSizeRound();
                if (processed >= localBitStream.blockEnd &&
                    (processed > localBitStream.blockEnd ||
                     localBitStream.getProcessedBits7() >= localBitStream.blockEndBits7)) {
                    break;
                }
                if (!isTableWasFilled) {
                    throw new RarCorruptedDataException("Huffman table not filled");
                }
            }
            
            int sym;
            try {
                sym = mainDecoder.decode(localBitStream);

                if (sym < 256) {
                } else if (sym >= Rar5Constants.SYMBOL_REP && sym < Rar5Constants.SYMBOL_REP + Rar5Constants.NUM_REPS) {
                } else if (sym > Rar5Constants.SYMBOL_REP + Rar5Constants.NUM_REPS) {
                } else if (sym == 256) {
                    exitResult = ERROR_FILTER_REQUIRED;
                    break;
                }
            } catch (Exception e) {
                throw new RarCorruptedDataException("Main symbol decoding error", e);
            }

            if (sym < 256) {
                win[curWinPos++] = (byte) sym;
                continue;
            }

            int len;

            if (sym < Rar5Constants.SYMBOL_REP + Rar5Constants.NUM_REPS) {
                if (sym >= Rar5Constants.SYMBOL_REP) {
                    if (sym != Rar5Constants.SYMBOL_REP) {
                        long dist = repDistances[1];
                        repDistances[1] = rep0;
                        rep0 = dist;
                        if (sym >= Rar5Constants.SYMBOL_REP + 2) {
                            rep0 = repDistances[sym - Rar5Constants.SYMBOL_REP];
                            repDistances[sym - Rar5Constants.SYMBOL_REP] = repDistances[2];
                            repDistances[2] = dist;
                        }
                    }

                    try {
                        len = lenDecoder.decode(localBitStream);
                    } catch (Exception e) {
                        throw new RarCorruptedDataException("Length decoding error", e);
                    }

                    if (len >= 8) {
                        len = Rar5Utils.slotToLen(localBitStream, len);
                    }
                    len += 2;
                    lastLen = len;
                } else if (sym != 256) {
                    len = lastLen;
                    if (len == 0) {
                        continue;
                    }
                } else {
                    exitResult = ERROR_FILTER_REQUIRED;
                    break;
                }
            } else {
                repDistances[3] = repDistances[2];
                repDistances[2] = repDistances[1];
                repDistances[1] = rep0;
                len = sym - (Rar5Constants.SYMBOL_REP + Rar5Constants.NUM_REPS);

                
                if (len >= 8) {
                    len = Rar5Utils.slotToLen(localBitStream, len);
                }
                len += 2;

                lastLen = len;

                try {
                    rep0 = distDecoder.decode(localBitStream);
                } catch (Exception e) {
                    throw new RarCorruptedDataException("Distance decoding error", e);
                }

                if (rep0 >= 4) {
                    int numBits = ((int)rep0 - 2) >> 1;
                    rep0 = (2 | ((int)rep0 & 1)) << numBits;

                    if (numBits < Rar5Constants.NUM_ALIGN_BITS) {
                        int additionalBits = localBitStream.readBitsBig25(numBits, localBitStream.getValueInHigh32bits());
                        rep0 += additionalBits;
                    } else {
                        int lenPlus = lenPlusTable[numBits] & 0xFF;
                        len += lenPlus;

                        if (isUseAlignBits) {
                            int highBits = localBitStream.readBitsBig(numBits - Rar5Constants.NUM_ALIGN_BITS, localBitStream.getValueInHigh32bits());
                            
                            int alignBits;
                            try {
                                alignBits = alignDecoder.decode(localBitStream);
                            } catch (Exception e) {
                                throw new RarCorruptedDataException("Align bits decoding error", e);
                            }
                            
                            rep0 += highBits << Rar5Constants.NUM_ALIGN_BITS;
                            rep0 += alignBits;
                        } else {
                            rep0 += localBitStream.readBitsBig(numBits, localBitStream.getValueInHigh32bits());
                        }

                        if (numBits >= 30) {
                            rep0 = 0xFFFFFFFFL - 1;
                        }
                    }
                }

                rep0++;                 
            }
            
            lastLen = len;
            
            int destPos = curWinPos;
            curWinPos += len;
            
            if (rep0 <= dictSizeForCheck) {
                int srcPos;
                int winPosTemp = destPos;

                if (rep0 > winPosTemp) {
                    if (lzSize == 0) {
                        throw new RarCorruptedDataException("Invalid distance reference at start of archive");
                    }
                    
                    int back = (int)(rep0 - winPosTemp);
                    srcPos = destPos + windowSize - (int)rep0;
                    
                    if (back < len) {
                        System.arraycopy(win, srcPos, win, destPos, back);
                        destPos += back;
                        len -= back;
                       
                        srcPos = 0;
                        curWinPos = destPos + len;
                        Rar5Utils.copyMatch((int)rep0, win, destPos, win, srcPos, curWinPos);
                        continue;
                    }
                    
                } else {
                    srcPos = destPos - (int)rep0;
                }
                
                Rar5Utils.copyMatch((int)rep0, win, destPos, win, srcPos, curWinPos);
                
            } else {
                throw new RarCorruptedDataException("Invalid distance: " + rep0 + " exceeds dictionary size: " + dictSizeForCheck);
            }
        }

        // Restore state
        repDistances[0] = rep0;
        windowPos = curWinPos;
        bufRes = localBitStream.buf;
        bufPosRes = localBitStream.bufPos;
        bitPosRes = localBitStream.bitPos;

        return exitResult;
    }

    /**
     * Main LZ decoding loop that manages blocks and output buffering.
     * 
     * <p>This method coordinates the overall decompression process:</p>
     * <ul>
     *   <li>Manages the sliding window and periodic output flushing</li>
     *   <li>Reads block headers and Huffman tables</li>
     *   <li>Delegates symbol decoding to {@link #processSymbols(Rar5BitDecoder)}</li>
     *   <li>Handles filter insertion when filter symbols are encountered</li>
     * </ul>
     * 
     * @return {@code true} if decompression completed successfully,
     *         {@code false} if the stream ended prematurely or with minor errors
     * @throws IOException if an I/O error occurs
     * @throws RarCorruptedDataException if invalid data is encountered
     */
    private boolean processBlocks() throws IOException {
        Rar5BitDecoder bitStream = new Rar5BitDecoder();
        bitStream.setStream(inputStream);

        int curWinPos = windowPos;
        byte[] win = window;
        int limit;
        {
            int rem = windowSize - curWinPos;
            if (rem > WRITE_STEP) {
                rem = WRITE_STEP;
            }
            limit = curWinPos + rem;
        }

        while (true) {
            if (curWinPos >= limit) {
                windowPos = curWinPos; 
                
                writeBufferedData();

                if (isUnpackedSizeDefined && writtenFileSize >= unpackedSize) {
                    break;
                }

                int wp = windowPos;
                int rem = windowSize - wp;

                if (rem <= 0) {
                   int overflow = -rem;
                   lzSize += windowSize;
                   curWinPos = overflow;
                   windowPos = overflow;

                   if (overflow > 0) {
                       System.arraycopy(win, windowSize, win, 0, overflow);
                   }

                   limit = windowSize;
                   if (limit >= WRITE_STEP) {
                       limit = WRITE_STEP;
                       continue;
                   }
                   rem = windowSize - curWinPos;
                }
                
                if (rem > WRITE_STEP) {
                    rem = WRITE_STEP;
                }
                limit = curWinPos + rem;
                continue;
            }

            if (bitStream.bufPos >= bitStream.bufCheckBlockPos) {
                windowPos = curWinPos;
                if (bitStream.inputEofError()) {
                    break;
                }
                bitStream.prepare();

                long processed = bitStream.getProcessedSizeRound();
                if (processed >= bitStream.blockEnd) {
                    if (processed > bitStream.blockEnd) {
                        break;
                    }
                    int bits7 = bitStream.getProcessedBits7();
                    if (bits7 >= bitStream.blockEndBits7) {
                        if (bits7 > bitStream.blockEndBits7) {
                            bitStream.minorError = true;
                        }
                        bitStream.alignToByte();
                        
                        if (isLastBlock) {
                           
                            if (bitStream.inputEofError()) {
                                break;
                            }
                            if (bitStream.minorError) {
                                return false;
                            }
                            if (bitStream.hres != null) {
                                throw bitStream.hres;
                            }
                            return true;
                        }
                        readHuffmanTables(bitStream);
                        continue;
                    }
                }

                if (!isTableWasFilled) {
                    break;
                }
            }

            curLimit = limit;
            windowPos = curWinPos;
            int res = processSymbols(bitStream);

            bitStream.buf = bufRes;
            bitStream.bufPos = bufPosRes;
            bitStream.bitPos = bitPosRes;

            curWinPos = windowPos;

            if (res == ERROR_FILTER_REQUIRED) {
                registerFilter(bitStream);
                continue;
            }
        }

        windowPos = curWinPos;

        if (bitStream.hres != null) {
            throw bitStream.hres;
        }

        return false;
    }

    /**
     * Performs the actual decompression after setup is complete.
     * 
     * <p>Initializes the filter subsystem, runs the LZ decoder, and
     * flushes any remaining buffered output. Also validates that the
     * output size matches the expected size when defined.</p>
     * 
     * @throws IOException if an I/O error occurs
     * @throws RarCorruptedDataException if decompression fails or size mismatches
     */
    private void processFile() throws IOException {
        isUnsupportedFilter = false;
        isWriteError = false;
        isLastBlock = false;

        initFilters();

        filterEnd = 0;
        writtenFileSize = 0;
        long curLzSize = lzSize + windowPos;
        lzFileStart = curLzSize;
        lzWritten = curLzSize;

        boolean success = processBlocks();

        if (!isWriteError) {
            writeBufferedData();
        }

        if (success && isUnpackedSizeDefined && writtenFileSize != unpackedSize) {
            throw new RarCorruptedDataException("Output size mismatch: expected " + unpackedSize + ", got " + writtenFileSize);
        }
    }

    /**
     * Decodes a RAR5 compressed stream.
     * 
     * <p>This is the main entry point for decompression. It handles:</p>
     * <ul>
     *   <li>Solid archive state management (preserving dictionary between files)</li>
     *   <li>Sliding window allocation and initialization</li>
     *   <li>Input/output stream setup</li>
     *   <li>Delegation to the internal decoding methods</li>
     * </ul>
     * 
     * <p>For solid archives, the same decoder instance should be used for all
     * files in sequence, and {@link #reset()} should NOT be called between files.
     * For non-solid archives or the first file, call {@link #reset()} before decoding.</p>
     * 
     * @param packedInputStream the compressed input stream
     * @param unpackedOutputStream the output stream for decompressed data
     * @param packedSize the compressed size (can be null if unknown, currently unused)
     * @param unpackedSizeParam the expected uncompressed size (can be null if unknown)
     * @param progressBar optional progress bar for UI feedback (can be null)
     * @throws IOException if an I/O error occurs during reading or writing
     * @throws RarCorruptedDataException if the archive data is corrupted or malformed
     * @throws UnsupportedOperationException if an unsupported filter type is encountered
     * @throws OutOfMemoryError if memory allocation fails for buffers
     */
    public void decode(InputStream packedInputStream, OutputStream unpackedOutputStream, Long packedSize, Long unpackedSizeParam, Object progressBar) throws IOException {
        long curLzSize = lzSize + windowPos;
        
        if (window == null || !isSolid || !wasInitialized || 
            (curLzSize < lzEnd && curLzSize + SOLID_RECOVER_LIMIT < lzEnd)) {
            lzSize = 0;
            windowPos = 0;
            Arrays.fill(repDistances, 0xFFFFFFFFL);
            lastLen = 0;
            isTableWasFilled = false;
            wasInitialized = true;
            
        } else {
            int ws = windowSize;
            if (windowPos >= ws) {
                windowPos -= ws;
                lzSize += ws;
                System.arraycopy(window, ws, window, 0, windowPos);
            }

            if (curLzSize < lzEnd) {
                long rem = lzEnd - curLzSize;
                if (rem >= ws) {
                    Arrays.fill(window, 0, ws, (byte)0);
                    lzSize = ws;
                    windowPos = 0;
                } else {
                    int cur = ws - windowPos;
                    if (cur <= rem) {
                        rem -= cur;
                        Arrays.fill(window, windowPos, windowPos + cur, (byte)0);
                        lzSize = ws;
                        windowPos = 0;
                    }
                    Arrays.fill(window, windowPos, windowPos + (int)rem, (byte)0);
                    windowPos += (int)rem;
                }
            }
        }

        if (lzSize >= Rar5Constants.DICT_SIZE_MAX) {
            lzSize = Rar5Constants.DICT_SIZE_MAX;
        }
        lzEnd = lzSize + windowPos;

        long newSize = dictionarySize;
        if (newSize < Rar5Constants.WIN_SIZE_MIN) {
            newSize = Rar5Constants.WIN_SIZE_MIN;
        }

        this.unpackedSize = 0;
        isUnpackedSizeDefined = (unpackedSizeParam != null);
        if (isUnpackedSizeDefined) {
            this.unpackedSize = unpackedSizeParam;
        }

        if (this.unpackedSize >= 0) {
            lzEnd += this.unpackedSize;
        } else {
            lzEnd = 0;
        }

        if (isSolid && window != null) {
            if (newSize > dictSizeForCheck) {
                throw new OutOfMemoryError("Solid archive requires larger dictionary than allocated");
            }
        } else {
            dictSizeForCheck = newSize;
            int newSize_small = (int)newSize;
            int k_Win_AlignSize = 1 << 18;
            int newSize_alloc = newSize_small + (1 << 7) + k_Win_AlignSize;
            newSize_alloc &= ~(k_Win_AlignSize - 1);
            if (newSize_alloc < newSize_small) {
                throw new OutOfMemoryError("Window size overflow");
            }

            int allocSize = newSize_alloc + Rar5Constants.MAX_MATCH_LEN + 64;
            if (allocSize < newSize_alloc) {
                throw new OutOfMemoryError("Allocation size overflow");
            }

            if (window == null || allocSize > windowSizeAllocated) {
                window = new byte[allocSize];
                Arrays.fill(window, (byte)0);
                windowSizeAllocated = allocSize;
            }
            windowSize = newSize_small;
        }

        if (inputBuf == null) {
            inputBuf = new byte[Rar5BitDecoder.BUFFER_SIZE]; 
        }

        inputStream = packedInputStream;
        outputStream = unpackedOutputStream;
        progressPack = 0;
        progressUnpack = 0;

        processFile();

        if (isUnsupportedFilter) {
            throw new UnsupportedOperationException("Unsupported RAR5 filter type");
        }
    }

    /**
     * Sets the decoder properties from a RAR5 property block.
     * 
     * <p>The property block is a 2-byte structure encoding:</p>
     * <ul>
     *   <li>Byte 0: Dictionary size power (bits 0-7)</li>
     *   <li>Byte 1, bits 3-7: Dictionary size fraction</li>
     *   <li>Byte 1, bit 0: Solid flag</li>
     *   <li>Byte 1, bit 1: V7 algorithm flag</li>
     * </ul>
     * 
     * <p>The dictionary size is calculated as: {@code (frac + 32) << (pow + 12)}</p>
     * 
     * @param data the property data (must be exactly 2 bytes)
     * @throws IllegalArgumentException if the property data is null or not exactly 2 bytes
     * @throws UnsupportedOperationException if the dictionary size exceeds 4GB
     */
    public void setDecoderProperties(byte[] data) {
        if (data == null || data.length != 2) {
            throw new IllegalArgumentException("Decoder properties must be exactly 2 bytes");
        }
        int pow = data[0] & 0xFF;
        int b1 = data[1] & 0xFF;
        int frac = b1 >> 3;

        if (pow + ((frac + 31) >> 5) > 31 - 17) {
            throw new UnsupportedOperationException("Dictionary size too large (max 4GB)");
        }

        dictionarySize = ((long)(frac + 32)) << (pow + 12);
        isSolid = (b1 & 1) != 0;
        isV7 = (b1 & 2) != 0;
    }

    /**
     * Resets the decoder state for processing a new archive or non-solid file.
     * 
     * <p>This method clears:</p>
     * <ul>
     *   <li>Window position and LZ state</li>
     *   <li>Repetition distance registers</li>
     *   <li>Huffman table state</li>
     *   <li>Written file size counter</li>
     * </ul>
     * 
     * <p><b>Important:</b> Do NOT call this method between files in a solid archive,
     * as the dictionary state must be preserved. Only call it:</p>
     * <ul>
     *   <li>Before processing a new (non-solid) archive</li>
     *   <li>Before the first file in a solid archive</li>
     *   <li>When a file in a solid archive is marked as non-solid</li>
     * </ul>
     */
    public void reset() {
        windowPos = 0;
        lzSize = 0;
        lzEnd = 0;
        writtenFileSize = 0;
        Arrays.fill(repDistances, 0xFFFFFFFFL);
        lastLen = 0;
        isTableWasFilled = false;
        wasInitialized = false;
    }
}
