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
package be.stef.arcana.formats.rar.rar4;

/**
 * Constants for RAR4 archive format.
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4Constants {

    private Rar4Constants() {}

    // --- Signature ---
    public static final byte[] RAR4_SIGNATURE = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
    public static final int SIGNATURE_LENGTH  = 7;

    // --- Block types ---
    public static final int BLOCK_TYPE_MARKER          = 0x72; // Archive marker (signature block)
    public static final int BLOCK_TYPE_ARCHIVE         = 0x73; // Main archive header
    public static final int BLOCK_TYPE_FILE            = 0x74; // File or directory entry
    public static final int BLOCK_TYPE_COMMENT         = 0x75; // Archive comment (old format)
    public static final int BLOCK_TYPE_EXTRA_INFO      = 0x76; // Extra archive info (old)
    public static final int BLOCK_TYPE_SUBBLOCK        = 0x77; // Subblock (old format)
    public static final int BLOCK_TYPE_RECOVERY        = 0x78; // Recovery record
    public static final int BLOCK_TYPE_AUTH            = 0x79; // Authenticity info (old)
    public static final int BLOCK_TYPE_NEWSUBBLOCK     = 0x7A; // New-format subblock (NTFS streams, etc.)
    public static final int BLOCK_TYPE_END_OF_ARC      = 0x7B; // End of archive

    // --- Common block flags (applicable to all block types) ---
    public static final int FLAG_HAS_ADD_SIZE          = 0x8000; // Block has additional data size field
    public static final int FLAG_SKIP_UNKNOWN          = 0x4000; // Skip block if unknown type

    // --- Archive header flags (BLOCK_TYPE_ARCHIVE) ---
    public static final int ARC_FLAG_VOLUME            = 0x0001; // Multi-volume archive
    public static final int ARC_FLAG_HAS_COMMENT       = 0x0002; // Archive has comment
    public static final int ARC_FLAG_LOCKED            = 0x0004; // Archive is locked
    public static final int ARC_FLAG_SOLID             = 0x0008; // Solid archive
    public static final int ARC_FLAG_NEW_NAMING        = 0x0010; // New volume naming scheme (volname.partN.rar)
    public static final int ARC_FLAG_AUTH_INFO         = 0x0020; // Authenticity info present
    public static final int ARC_FLAG_RECOVERY          = 0x0040; // Recovery record present
    public static final int ARC_FLAG_ENCRYPTED_HEADERS = 0x0080; // Headers are encrypted
    public static final int ARC_FLAG_FIRST_VOLUME      = 0x0100; // First volume of a set

    // --- File block flags (BLOCK_TYPE_FILE) ---
    public static final int FILE_FLAG_CONTINUED_FROM_PREV = 0x0001; // File continued from previous volume
    public static final int FILE_FLAG_CONTINUED_TO_NEXT   = 0x0002; // File continued to next volume
    public static final int FILE_FLAG_ENCRYPTED            = 0x0004; // File is encrypted
    public static final int FILE_FLAG_HAS_COMMENT          = 0x0008; // File has comment (old)
    public static final int FILE_FLAG_SOLID                = 0x0010; // Solid flag (depends on previous files)
    public static final int FILE_FLAG_DICT_MASK            = 0x00E0; // Dictionary size mask (bits 5-7)
    public static final int FILE_FLAG_DICT_SHIFT           = 5;      // Shift to extract dict index
    public static final int FILE_FLAG_HIGH_SIZE            = 0x0100; // High parts of pack/unpack size present
    public static final int FILE_FLAG_UNICODE_NAME         = 0x0200; // Filename is Unicode-encoded
    public static final int FILE_FLAG_SALT                 = 0x0400; // Salt present (AES encryption)
    public static final int FILE_FLAG_VERSION              = 0x0800; // File version (old)
    public static final int FILE_FLAG_EXT_TIME             = 0x1000; // Extended time info present
    public static final int FILE_FLAG_LARGE_FILE           = 0x8000; // Large file (pack/unpack > 4GB, requires HIGH_SIZE)

    // --- Compression methods ---
    public static final int COMPRESS_METHOD_STORE          = 0x30; // No compression
    public static final int COMPRESS_METHOD_FASTEST        = 0x31; // Fastest compression
    public static final int COMPRESS_METHOD_FAST           = 0x32; // Fast compression
    public static final int COMPRESS_METHOD_NORMAL         = 0x33; // Normal compression
    public static final int COMPRESS_METHOD_GOOD           = 0x34; // Good compression
    public static final int COMPRESS_METHOD_BEST           = 0x35; // Best compression (PPMd)

    // --- Compression versions ---
    public static final int COMPRESS_VERSION_20            = 20;  // RAR 2.0 algorithm
    public static final int COMPRESS_VERSION_26            = 26;  // RAR 2.6 algorithm
    public static final int COMPRESS_VERSION_29            = 29;  // RAR 2.9 / 3.x algorithm (most common)

    // --- Dictionary sizes (index = (flags & FILE_FLAG_DICT_MASK) >> FILE_FLAG_DICT_SHIFT) ---
    public static final long[] DICT_SIZES = {
        64L * 1024,        // 0 => 64 KB
        128L * 1024,       // 1 => 128 KB
        256L * 1024,       // 2 => 256 KB
        512L * 1024,       // 3 => 512 KB
        1024L * 1024,      // 4 => 1 MB
        2048L * 1024,      // 5 => 2 MB
        4096L * 1024,      // 6 => 4 MB
        4096L * 1024       // 7 => directory entry
    };

    // --- OS identifiers ---
    public static final int OS_MSDOS   = 0;
    public static final int OS_OS2     = 1;
    public static final int OS_WIN32   = 2;
    public static final int OS_UNIX    = 3;
    public static final int OS_MACOS   = 4;
    public static final int OS_BEOS    = 5;
}