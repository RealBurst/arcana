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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;


/**
 * Builds minimal RAR5 archives with Zstandard-compressed entries for testing.
 *
 * <p>This class produces syntactically valid RAR5 archives whose file entries
 * use compression method 6 (Zstandard / RAR7). The Zstd frame is built from
 * scratch following RFC 8878 (Zstandard Compressed Data Format), using only
 * RAW_BLOCK and RLE_BLOCK types - no entropy coding required, which keeps
 * the generator self-contained and dependency-free.</p>
 *
 * <h3>RAR5 binary layout produced</h3>
 * <pre>
 *   [8]  RAR5 signature
 *   [?]  Main Archive Header block
 *   [?]  File Header block  (type=2, method=6, algoVersion=1)
 *   [?]  Zstandard frame (data area)
 *   [?]  End-of-Archive block
 * </pre>
 *
 * <h3>Usage</h3>
 * <pre>
 *   // Compressible content (text) - exercises the RAW_BLOCK path
 *   Rar5ZstdTestArchiveBuilder.buildTextArchive("test_zstd_text.rar");
 *
 *   // Incompressible content (binary) - same RAW_BLOCK path, random-looking data
 *   Rar5ZstdTestArchiveBuilder.buildBinaryArchive("test_zstd_binary.rar");
 * </pre>
 *
 * @author Stef
 * @since 2.0
 */
public final class Rar5ZstdTestArchiveBuilder {

    // ---- RAR5 signature ----
    private static final byte[] RAR5_SIG = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};

    // ---- RAR5 block types ----
    private static final int BLOCK_MAIN    = 1;
    private static final int BLOCK_FILE    = 2;
    private static final int BLOCK_ENDARC  = 5;

    // ---- RAR5 block flags ----
    private static final int BHDR_FLAG_SKIP_IF_UNKNOWN = 0x0001;
    private static final int BHDR_FLAG_DATA_AREA       = 0x0002;

    // ---- RAR5 file flags ----
    private static final int FILE_FLAG_UNIX_TIME = 0x0002;
    private static final int FILE_FLAG_CRC32     = 0x0004;

    // ---- Compression info field ----
    // bits 0-5  : algo version (1 = RAR7)
    // bit  6    : solid (0)
    // bits 7-9  : method (6 = Zstd)  -> stored in bits 7-9 as value 6
    // bits 10-14: dict main (0 = 128KB, smallest valid)
    // bits 15-19: dict frac (0)
    // compressionInfo = algoVersion | (method << 7) | (dictMain << 10)
    // = 1 | (6 << 7) | (0 << 10) = 1 | 768 = 769 = 0x301
    private static final long COMPRESSION_INFO_ZSTD = 0x301L;

    // ---- Zstd constants (RFC 8878) ----
    private static final int ZSTD_MAGIC          = 0xFD2FB528;
    private static final int ZSTD_BLOCK_RAW      = 0;  // uncompressed block
    private static final int ZSTD_BLOCK_LAST_BIT = 1;
    private static final int ZSTD_MAX_BLOCK_SIZE = 128 * 1024;

    private Rar5ZstdTestArchiveBuilder() {}

    // =========================================================================
    // Public entry points
    // =========================================================================

    /**
     * Creates a RAR5+Zstd archive containing a compressible text file.
     *
     * @param outputPath path of the .rar file to create
     * @throws IOException on write error
     */
    public static void buildTextArchive(String outputPath) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append("Ligne de test numero ").append(i)
              .append(" - contenu repetitif pour valider la decompression Zstandard dans unrar5j.\r\n");
        }
        byte[] content = sb.toString().getBytes(StandardCharsets.UTF_8);
        build(outputPath, "test_zstd_text.txt", content);
        System.out.println("Archive texte creee : " + outputPath + " (" + content.length + " octets non compresses)");
    }

    /**
     * Creates a RAR5+Zstd archive containing an incompressible binary file.
     * The content is a deterministic pseudo-random sequence (no java.util.Random needed).
     *
     * @param outputPath path of the .rar file to create
     * @throws IOException on write error
     */
    public static void buildBinaryArchive(String outputPath) throws IOException {
        // Deterministic pseudo-random: XorShift32
        int state = 0xDEADBEEF;
        byte[] content = new byte[64 * 1024];
        for (int i = 0; i < content.length; i++) {
            state ^= (state << 13);
            state ^= (state >>> 17);
            state ^= (state << 5);
            content[i] = (byte) state;
        }
        build(outputPath, "test_zstd_binary.bin", content);
        System.out.println("Archive binaire creee : " + outputPath + " (" + content.length + " octets non compresses)");
    }

    // =========================================================================
    // Core builder
    // =========================================================================

    private static void build(String outputPath, String fileName, byte[] content) throws IOException {
        byte[] zstdFrame  = buildZstdFrame(content);
        long   crc32value = crc32(content);
        long   unixTime   = System.currentTimeMillis() / 1000L;

        ByteArrayOutputStream rar = new ByteArrayOutputStream();

        // 1. RAR5 signature
        rar.write(RAR5_SIG);

        // 2. Main Archive Header
        rar.write(buildMainArchiveBlock());

        // 3. File Header + data area
        rar.write(buildFileBlock(fileName, content.length, crc32value, unixTime, zstdFrame));

        // 4. End-of-Archive
        rar.write(buildEndOfArchiveBlock());

        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            fos.write(rar.toByteArray());
        }
    }

    // =========================================================================
    // RAR5 block builders
    // =========================================================================

    /**
     * Builds the Main Archive Header (block type 1, no flags, no data area).
     */
    private static byte[] buildMainArchiveBlock() {
        // Header data: archive flags (VInt = 0 = no flags)
        byte[] headerData = encodeVInt(0);

        return buildBlock(BLOCK_MAIN, BHDR_FLAG_SKIP_IF_UNKNOWN, headerData, null);
    }

    /**
     * Builds the End-of-Archive block (block type 5).
     */
    private static byte[] buildEndOfArchiveBlock() {
        // End-of-archive flags (VInt = 0)
        byte[] headerData = encodeVInt(0);
        return buildBlock(BLOCK_ENDARC, BHDR_FLAG_SKIP_IF_UNKNOWN, headerData, null);
    }

    /**
     * Builds a File Header block with method=6 (Zstd) and its data area.
     *
     * @param fileName    filename to store in the archive
     * @param unpackedSize original (uncompressed) size
     * @param crc32value  CRC32 of the original content
     * @param unixTime    Unix timestamp (seconds)
     * @param zstdFrame   the compressed Zstd frame (data area)
     */
    private static byte[] buildFileBlock(String fileName, long unpackedSize, long crc32value, long unixTime, byte[] zstdFrame) {
        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);

        // File flags: unix time present + CRC32 present
        long fileFlags = FILE_FLAG_UNIX_TIME | FILE_FLAG_CRC32;

        ByteArrayOutputStream hd = new ByteArrayOutputStream();
        writeVInt(hd, fileFlags);                    // fileFlags
        writeVInt(hd, unpackedSize);                 // unpackedSize
        writeVInt(hd, 0x20);                         // attributes (FILE = 0x20)
        writeUInt32LE(hd, (int) unixTime);           // Unix mtime (4 bytes)
        writeUInt32LE(hd, (int) crc32value);         // CRC32 (4 bytes)
        writeVInt(hd, COMPRESSION_INFO_ZSTD);        // compressionInfo (method=6, algoVersion=1)
        writeVInt(hd, 0);                            // hostOS (0 = Windows)
        writeVInt(hd, nameBytes.length);             // nameLength
        hd.write(nameBytes, 0, nameBytes.length);    // name

        return buildBlock(BLOCK_FILE, BHDR_FLAG_SKIP_IF_UNKNOWN | BHDR_FLAG_DATA_AREA, hd.toByteArray(), zstdFrame);
    }

    /**
     * Assembles a complete RAR5 block with its CRC32 header checksum.
     *
     * <p>RAR5 block layout:</p>
     * <pre>
     *   [4]  header CRC32 (CRC of everything after these 4 bytes, up to end of header data)
     *   [?]  header size (VInt, = size of everything after header size field)
     *   [?]  block type (VInt)
     *   [?]  block flags (VInt)
     *   [?]  (optional) data area size (VInt, present if BHDR_FLAG_DATA_AREA set)
     *   [?]  header-specific data
     *   [?]  data area (if BHDR_FLAG_DATA_AREA set)
     * </pre>
     *
     * @param blockType  RAR5 block type constant
     * @param flags      block header flags
     * @param headerData block-specific header content
     * @param dataArea   data area bytes, or null if none
     */
    private static byte[] buildBlock(int blockType, int flags, byte[] headerData, byte[] dataArea) {
        // Build the variable part: type + flags + [data size] + headerData
        ByteArrayOutputStream variable = new ByteArrayOutputStream();
        writeVInt(variable, blockType);
        writeVInt(variable, flags);
        if (dataArea != null) {
            writeVInt(variable, dataArea.length);
        }
        variable.write(headerData, 0, headerData.length);
        byte[] varBytes = variable.toByteArray();

        // headerSize VInt covers everything in varBytes
        byte[] headerSizeVInt = encodeVInt(varBytes.length);

        // CRC32 covers headerSizeVInt + varBytes
        CRC32 crc = new CRC32();
        crc.update(headerSizeVInt);
        crc.update(varBytes);
        int crcValue = (int) crc.getValue();

        // Assemble block
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        writeUInt32LE(block, crcValue);
        block.write(headerSizeVInt, 0, headerSizeVInt.length);
        block.write(varBytes, 0, varBytes.length);
        if (dataArea != null) {
            block.write(dataArea, 0, dataArea.length);
        }
        return block.toByteArray();
    }

    // =========================================================================
    // Zstandard frame builder (RFC 8878, RAW_BLOCK only)
    // =========================================================================

    /**
     * Builds a minimal, valid Zstandard frame containing the given data.
     *
     * <p>The frame uses only RAW_BLOCK (type 0) blocks - no entropy coding.
     * This is valid per RFC 8878 and exercises the full decompression path in
     * {@link ZstdFrameDecompressor}: frame header parsing, block dispatch,
     * content checksum verification.</p>
     *
     * <p>Frame layout:</p>
     * <pre>
     *   [4]  magic number 0xFD2FB528 (LE)
     *   [1]  Frame_Header_Descriptor (FHD)
     *   [?]  Window_Descriptor (present if FCS not set or FHD says so)
     *   [?]  Frame_Content_Size (1/2/4/8 bytes, encoded per FHD)
     *   [?]  one or more blocks:
     *          [3] block header: last(1) + type(2) + size(21) packed in 24 bits LE
     *          [?] block data (RAW: verbatim copy)
     *   [4]  Content_Checksum (xxHash64 lower 32 bits) - present if FHD bit 2 set
     * </pre>
     *
     * @param data original (uncompressed) content
     * @return complete Zstd frame bytes
     */
    private static byte[] buildZstdFrame(byte[] data) {
        ByteArrayOutputStream frame = new ByteArrayOutputStream();

        // -- Magic --
        writeUInt32LE(frame, ZSTD_MAGIC);

        // -- Frame Header Descriptor (FHD) --
        // bit 0   : dictID flag (0 = no dictID)
        // bit 1   : dictID flag2 (0)
        // bit 2   : content checksum flag (1 = present)
        // bit 3   : reserved (0)
        // bit 4   : reserved (0)
        // bit 5   : single segment flag (1 = no window descriptor, FCS is total size)
        // bits 6-7: frame content size flag:
        //   00 = 1 byte  (if single segment)
        //   01 = 2 bytes
        //   10 = 4 bytes
        //   11 = 8 bytes
        //
        // Strategy: use single-segment=1 + FCS sized for our content
        int fcsFlag;
        int fcsBytes;
        if (data.length <= 0xFF) {
            fcsFlag  = 0x00;  // FCS = 1 byte
            fcsBytes = 1;
        } else if (data.length <= 0xFFFF + 256) {
            fcsFlag  = 0x01;  // FCS = 2 bytes (value - 256 stored)
            fcsBytes = 2;
        } else if (data.length <= 0xFFFFFFFFL) {
            fcsFlag  = 0x02;  // FCS = 4 bytes
            fcsBytes = 4;
        } else {
            fcsFlag  = 0x03;  // FCS = 8 bytes
            fcsBytes = 8;
        }

        // single_segment=1 -> no window descriptor
        // content_checksum=1
        int fhd = (fcsFlag << 6) | (1 << 5) | (1 << 2);
        frame.write(fhd);

        // -- Frame Content Size --
        writeFCS(frame, data.length, fcsFlag, fcsBytes);

        // -- Blocks (RAW, split into ZSTD_MAX_BLOCK_SIZE chunks) --
        int remaining = data.length;
        int offset    = 0;
        while (remaining > 0) {
            int blockSize = Math.min(remaining, ZSTD_MAX_BLOCK_SIZE);
            boolean isLast = (remaining <= ZSTD_MAX_BLOCK_SIZE);

            // Block header: 3 bytes LE
            // bits  0    : Last_Block
            // bits  1-2  : Block_Type (00 = RAW)
            // bits  3-23 : Block_Size
            int blockHeader = (isLast ? ZSTD_BLOCK_LAST_BIT : 0)
                            | (ZSTD_BLOCK_RAW << 1)
                            | (blockSize << 3);
            frame.write(blockHeader & 0xFF);
            frame.write((blockHeader >> 8) & 0xFF);
            frame.write((blockHeader >> 16) & 0xFF);

            // Block data (verbatim for RAW blocks)
            frame.write(data, offset, blockSize);

            offset    += blockSize;
            remaining -= blockSize;
        }

        // -- Content Checksum (xxHash64 lower 32 bits, LE) --
        // XxHash64.hash uses Unsafe addressing: address = BASE + array_index
        long xxh = XxHash64.hash(0L, data, BASE, data.length);
        writeUInt32LE(frame, (int) xxh);

        return frame.toByteArray();
    }

    /**
     * Writes the Frame Content Size field according to the FCS flag.
     * When fcsFlag == 1 (2-byte FCS), the value stored is (size - 256).
     */
    private static void writeFCS(ByteArrayOutputStream out, long size, int fcsFlag, int fcsBytes) {
        long stored = (fcsFlag == 1) ? (size - 256) : size;
        for (int i = 0; i < fcsBytes; i++) {
            out.write((int) (stored & 0xFF));
            stored >>>= 8;
        }
    }

    // =========================================================================
    // Low-level encoding helpers
    // =========================================================================

    /** Encodes a value as a RAR5 VInt and returns the bytes. */
    private static byte[] encodeVInt(long value) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(5);
        writeVInt(buf, value);
        return buf.toByteArray();
    }

    /** Writes a RAR5 VInt to a stream. */
    private static void writeVInt(ByteArrayOutputStream out, long value) {
        do {
            long next = value >>> 7;
            int b = (int) (value & 0x7F);
            if (next != 0) b |= 0x80;  // continuation bit
            out.write(b);
            value = next;
        } while (value != 0);
    }

    /** Writes a 32-bit little-endian integer to a stream. */
    private static void writeUInt32LE(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 24) & 0xFF);
    }

    /** Computes CRC32 of the given data. */
    private static long crc32(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    // =========================================================================
    // main - run directly to generate both test archives
    // =========================================================================

    /**
     * Entry point: generates two test archives in the current directory.
     *
     * <pre>
     *   java -cp . be.stef.arcana.formats.zstd.Rar5ZstdTestArchiveBuilder
     * </pre>
     */
    public static void main(String[] args) throws IOException {
        String textOut   = (args.length > 0) ? args[0] : "test_zstd_text.rar";
        String binaryOut = (args.length > 1) ? args[1] : "test_zstd_binary.rar";
        buildTextArchive(textOut);
        buildBinaryArchive(binaryOut);
    }
}
