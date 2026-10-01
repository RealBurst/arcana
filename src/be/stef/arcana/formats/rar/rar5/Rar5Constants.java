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
package be.stef.arcana.formats.rar.rar5;

/**
 * Constants for the RAR5 archive format.
 * 
 * <p>This class defines all constants used in RAR5 archive parsing and extraction,
 * including block types, flags, encryption parameters, and filter types.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public final class Rar5Constants {
    public static final byte[] RAR5_SIGNATURE = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};  //RAR5 archive signature (8 bytes): "Rar!\x1A\x07\x01\x00"
    
    // ========== Block Types ==========
    public static final int BLOCK_TYPE_MAIN_ARCHIVE = 1;  // Main archive header block
    public static final int BLOCK_TYPE_FILE = 2;          // File header block
    public static final int BLOCK_TYPE_SERVICE = 3;       // Service block (comments, ACL, streams, etc.)
    public static final int BLOCK_TYPE_ARC_ENCRYPT = 4;   // Archive encryption header block
    public static final int BLOCK_TYPE_END_OF_ARC = 5;    // End of archive block
    
    // ========== Common Header Flags ==========
    public static final int HEADER_FLAG_EXTRA = 0x01;     // Header contains extra area
    public static final int HEADER_FLAG_DATA = 0x02;      // Header contains data area
    public static final int HEADER_FLAG_PREV_VOL = 0x08;  // Block continues from previous volume
    public static final int HEADER_FLAG_NEXT_VOL = 0x10;  // Block continues in next volume
    
    // ========== Archive Flags (Main Archive Header) ==========
    public static final int ARC_FLAG_VOLUME = 0x01;               // Archive is part of a multi-volume set
    public static final int ARC_FLAG_VOLUME_NUMBER = 0x02;        // Volume number is present
    public static final int ARC_FLAG_SOLID = 0x04;                // Archive uses solid compression
    public static final int ARC_FLAG_RECOVERY = 0x08;             // Archive contains recovery record
    public static final int ARC_FLAG_LOCKED = 0x10;               // Archive is locked (cannot be
    
    // ========== File Flags (File Header) ==========
    public static final int FILE_FLAG_IS_DIR = 0x01;              // Entry is a directory
    public static final int FILE_FLAG_UNIX_TIME = 0x02;           // Unix modification time is present
    public static final int FILE_FLAG_CRC32 = 0x04;               // CRC32 checksum is present
    public static final int FILE_FLAG_UNKNOWN_SIZE = 0x08;        // Unpacked size is unknown
    
    // ========== Compression Method Flags ==========
    public static final int METHOD_FLAG_SOLID = 0x40;             // File uses solid compression
    public static final int METHOD_FLAG_RAR5_COMPAT = 0x100000;   // RAR5 compatibility mode
    
    // ========== Extra Record IDs ==========
    public static final int EXTRA_ID_CRYPTO = 1;                  // Encryption information
    public static final int EXTRA_ID_HASH = 2;                    // File hash (BLAKE2sp)
    public static final int EXTRA_ID_TIME = 3;                    // Extended timestamps
    public static final int EXTRA_ID_VERSION = 4;                 // File version
    public static final int EXTRA_ID_LINK = 5;                    // Symbolic/hard link information
    public static final int EXTRA_ID_UNIX_OWNER = 6;              // Unix owner information
    public static final int EXTRA_ID_SUBDATA = 7;                 // Service data subtype
    
    // ========== Crypto Flags ==========
    public static final int CRYPTO_FLAG_PASSWORD_CHECK = 0x01;    // Password verification data is present
    public static final int CRYPTO_FLAG_USE_MAC = 0x02;           // Use MAC for authentication          
    
    // ========== Encryption Parameters ==========
    public static final int SALT_SIZE = 16;                       // Salt size for PBKDF2 (bytes)
    public static final int AES_BLOCK_SIZE = 16;                  // AES block size (bytes)
    public static final int CHECK_VALUE_SIZE = 12;                // Password verification value size (bytes)
    
    // ========== Hash Types ==========
    public static final int HASH_TYPE_BLAKE2SP = 0;               // BLAKE2sp hash algorithm    

    // ========== Time Record Flags ==========
    public static final int TIME_FLAG_UNIX_TIME = 0x01;           // Times are in Unix format
    public static final int TIME_FLAG_MTIME = 0x02;               // Modification time is present
    public static final int TIME_FLAG_CTIME = 0x04;               // Creation time is present
    public static final int TIME_FLAG_ATIME = 0x08;               // Access time is present
    public static final int TIME_FLAG_UNIX_NS = 0x10;             // Nanosecond precision is present
    
    // ========== Link Types ==========
    public static final int LINK_TYPE_UNIX_SYMLINK = 1;           // Unix symbolic link
    public static final int LINK_TYPE_WIN_SYMLINK = 2;            // Windows symbolic link
    public static final int LINK_TYPE_WIN_JUNCTION = 3;           // Windows junction point
    public static final int LINK_TYPE_HARD_LINK = 4;              // Hard link
    public static final int LINK_TYPE_FILE_COPY = 5;              // File copy reference
    
    // ========== Link Flags ==========
    public static final int LINK_FLAG_TARGET_IS_DIR = 0x01;       // Link target is a directory
    
    // ========== Main Archive Extra Record Types ==========
    public static final int ARC_EXTRA_LOCATOR = 1;                // Quick open locator
    public static final int ARC_EXTRA_METADATA = 2;               // Archive metadata
    
    // ========== Locator Flags ==========
    public static final int LOCATOR_FLAG_QUICK_OPEN = 0x01;       // Quick open record offset is present
    public static final int LOCATOR_FLAG_RECOVERY = 0x02;         // Recovery record offset is present    

    // ========== Metadata Flags ==========
    public static final int METADATA_FLAG_ARC_NAME = 0x01;        // Archive name is present
    public static final int METADATA_FLAG_CREATION_TIME = 0x02;   // Creation time is present
    public static final int METADATA_FLAG_UNIX_TIME = 0x04;       // Times are in Unix format
    public static final int METADATA_FLAG_NANOSECOND = 0x08;      // Nanosecond precision is present
    
    // ========== End of Archive Flags ==========
    public static final int END_FLAG_MORE_VOLS = 0x01;            // More volumes follow
    
    // ========== Compression Methods ==========
    public static final int COMPRESS_METHOD_STORE = 0;            // Store (no compression)
    public static final int COMPRESS_METHOD_FASTEST = 1;          // Fastest compression
    public static final int COMPRESS_METHOD_FAST = 2;             // Fast compression
    public static final int COMPRESS_METHOD_NORMAL = 3;           // Normal compression
    public static final int COMPRESS_METHOD_GOOD = 4;             // Good compression
    public static final int COMPRESS_METHOD_BEST = 5;             // Best compression
    
    // ========== Dictionary Constants ==========
    public static final int DICT_SIZE_BITS_MAX = 40;              // Maximum dictionary size in bits (40 = 1TB)
    public static final long DICT_SIZE_MAX = 1L << DICT_SIZE_BITS_MAX; // Maximum dictionary size in bytes
    public static final int FILTER_BLOCK_SIZE_MAX = 1 << 22;      // Maximum filter block size
    public static final int FILTER_AFTERPAD_SIZE = 64;            // Padding after filter data
    public static final int WIN_SIZE_MIN = 1 << 18;               // Minimum window size
    public static final int MAX_UNPACK_FILTERS = 8192;            // Maximum number of filters
    public static final int SYMBOL_REP = 258;                     // Symbol value for repeat
    public static final int MAX_MATCH_LEN = 0x1001 + 3;           // Maximum match length
    
    // ========== Huffman Constants ==========
    public static final int NUM_HUFFMAN_BITS = 15;                // Number of bits for Huffman codes
    public static final int NUM_REPS = 4;                         // Number of distance repetitions
    public static final int LEN_TABLE_SIZE = 11 * 4;              // Length table size
    public static final int MAIN_TABLE_SIZE = 256 + 1 + 1 + NUM_REPS + LEN_TABLE_SIZE; // Main Huffman table size: 256 literals + 1 + 1 + 4 reps + length table
    public static final int EXTRA_DIST_SYMBOLS_V7 = 16;              // Extra distance symbols for v7 format
    public static final int DIST_TABLE_SIZE_V6 = 64;                 // Distance table size for v6 format
    public static final int DIST_TABLE_SIZE_MAX = 64 + EXTRA_DIST_SYMBOLS_V7; // Maximum distance table size
    public static final int NUM_ALIGN_BITS = 4;                      // Number of alignment bits
    public static final int ALIGN_TABLE_SIZE = 1 << NUM_ALIGN_BITS;  // Alignment table size
    public static final int TABLES_SIZES_SUM_MAX = MAIN_TABLE_SIZE + DIST_TABLE_SIZE_MAX + ALIGN_TABLE_SIZE + LEN_TABLE_SIZE; // Sum of all table sizes
    
    // ========== Huffman Table Bits for Fast Lookup ==========
    public static final int NUM_HUFFMAN_TABLE_BITS_MAIN = 10;     // Table bits for main decoder
    public static final int NUM_HUFFMAN_TABLE_BITS_DIST = 7;      // Table bits for distance decoder
    public static final int NUM_HUFFMAN_TABLE_BITS_LEN = 7;       // Table bits for length decoder
    public static final int NUM_HUFFMAN_TABLE_BITS_ALIGN = 6;     // Table bits for alignment decoder
    
    // ========== Filter Types ==========
    public static final int FILTER_DELTA = 0;                     // Delta filter for audio data
    public static final int FILTER_E8 = 1;                        // E8 filter for x86 executables (CALL instructions)
    public static final int FILTER_E8E9 = 2;                      // E8/E9 filter for x86 executables (CALL/JMP instructions)
    public static final int FILTER_ARM = 3;                       // ARM filter for ARM executables
    
    // ========== Length Plus Table ==========
    public static final byte[] LEN_PLUS_TABLE = {                 // Length plus table for distance decoding. Must have DICT_SIZE_BITS_MAX (40) elements.
        0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
        1, 1, 2, 2, 2, 2, 2, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3
    };
    

    
    private Rar5Constants() {
        // Constants class - no instantiation
    }
    

}
