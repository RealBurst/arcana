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
package be.stef.arcana.formats.rar.rar4.blocks;

import be.stef.arcana.formats.rar.rar4.Rar4Constants;

/**
 * RAR4 file or directory entry block (type 0x74).
 *
 * <p>Structure after common header:</p>
 * <pre>
 *   4 bytes : packed size (low 32 bits)
 *   4 bytes : unpacked size (low 32 bits)
 *   1 byte  : OS / attributes
 *   4 bytes : file CRC32
 *   4 bytes : file time (MS-DOS format)
 *   1 byte  : RAR version needed to extract
 *   1 byte  : compression method (0x30-0x35)
 *   2 bytes : filename length
 *   4 bytes : file attributes
 *  [4 bytes]: packed size high  (if FILE_FLAG_HIGH_SIZE)
 *  [4 bytes]: unpacked size high (if FILE_FLAG_HIGH_SIZE)
 *   N bytes : filename (ASCII or Unicode)
 *  [16 bytes]: salt (if FILE_FLAG_SALT)
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4FileBlock extends Rar4Block {
    private long   packedSize;
    private long   unpackedSize;
    private int    osId;
    private long   crc32;
    private long   fileTime;
    private int    requiredVersion;
    private int    compressionMethod;
    private int    fileNameLength;
    private long   fileAttributes;
    private String fileName;
    private byte[] salt;            // present if FILE_FLAG_SALT (8 bytes for RAR4)
    private long   dictSize;


    @Override
    public boolean parseSpecificData(byte[] buf, int offset, int length) {
        // PACK_SIZE was already read as addSize in the common header
        // offset points to UNP_SIZE
        if (length - offset < 18) return false;

        int pos = offset;

        long unpackedLow  = readUInt32LE(buf, pos);     pos += 4;
        osId              = buf[pos++] & 0xFF;
        crc32             = readUInt32LE(buf, pos);      pos += 4;
        fileTime          = readUInt32LE(buf, pos);      pos += 4;
        requiredVersion   = buf[pos++] & 0xFF;
        compressionMethod = buf[pos++] & 0xFF;
        fileNameLength    = readUInt16LE(buf, pos);      pos += 2;
        fileAttributes    = readUInt32LE(buf, pos);      pos += 4;

        // High parts (if FILE_FLAG_HIGH_SIZE)
        long packedHigh   = 0;
        long unpackedHigh = 0;
        if ((flags & Rar4Constants.FILE_FLAG_HIGH_SIZE) != 0) {
            if (length - pos < 8) return false;
            packedHigh   = readUInt32LE(buf, pos);      pos += 4;
            unpackedHigh = readUInt32LE(buf, pos);      pos += 4;
        }

        // packedSize comes from addSize (already parsed in common header)
        packedSize   = (packedHigh << 32) | addSize;
        unpackedSize = (unpackedHigh << 32) | unpackedLow;

        // Filename
        if (length - pos < fileNameLength) return false;
        fileName = parseFileName(buf, pos, fileNameLength);
        pos += fileNameLength;

        // AES salt (8 bytes for RAR4)
        if ((flags & Rar4Constants.FILE_FLAG_SALT) != 0) {
           if (length - pos < 8) return false;
           salt = new byte[8];
           System.arraycopy(buf, pos, salt, 0, 8);
           pos += 8;
        }

        // Dictionary size
        int dictIndex = (flags & Rar4Constants.FILE_FLAG_DICT_MASK) >> Rar4Constants.FILE_FLAG_DICT_SHIFT;
        dictSize = Rar4Constants.DICT_SIZES[dictIndex];

        return true;
    }
    
    /**
     * Parses the filename - Unicode if FILE_FLAG_UNICODE_NAME, OEM/ASCII otherwise.
     */
    private String parseFileName(byte[] buf, int offset, int length) {
        byte[] nameBytes = new byte[length];
        System.arraycopy(buf, offset, nameBytes, 0, length);

        if ((flags & Rar4Constants.FILE_FLAG_UNICODE_NAME) != 0) {
            // Find the null separator between the ASCII part and the Unicode data
            int sep = 0;
            while (sep < nameBytes.length && nameBytes[sep] != 0) sep++;

            if (sep != nameBytes.length) {
                // Unicode data follows the null terminator
                return decodeUnicodeName(nameBytes, sep + 1);
            }
            // No Unicode data: plain ASCII part
            return new String(nameBytes, 0, sep, java.nio.charset.StandardCharsets.ISO_8859_1);
        }

        // Non-Unicode: OEM bytes
        return new String(nameBytes, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /**
     * Decodes the RAR4 custom Unicode filename encoding.
     *
     * <p>The encoding interleaves a 2-bit operation flag per output character:</p>
     * <ul>
     *   <li>0 : raw byte (low byte, high byte = 0)</li>
     *   <li>1 : raw byte combined with the common high byte</li>
     *   <li>2 : full 16-bit character (low + high)</li>
     *   <li>3 : run-length copy from the ASCII part, optionally corrected</li>
     * </ul>
     *
     * @param name   the full name byte array (ASCII part + null + Unicode data)
     * @param encPos start offset of the Unicode-encoded data (just after the null)
     * @return the decoded filename
     */
    private static String decodeUnicodeName(byte[] name, int encPos) {
        int decPos   = 0;   // index into the ASCII part (used by op 3)
        int flags    = 0;
        int flagBits = 0;
        int low, high;

        int highByte = name[encPos++] & 0xFF;
        StringBuilder sb = new StringBuilder();

        while (encPos < name.length) {
            if (flagBits == 0) {
                flags    = name[encPos++] & 0xFF;
                flagBits = 8;
            }
            switch (flags >>> 6) {
                case 0:
                    sb.append((char) (name[encPos++] & 0xFF));
                    decPos++;
                    break;
                case 1:
                    sb.append((char) ((name[encPos++] & 0xFF) + (highByte << 8)));
                    decPos++;
                    break;
                case 2:
                    low  = name[encPos]     & 0xFF;
                    high = name[encPos + 1] & 0xFF;
                    sb.append((char) ((high << 8) + low));
                    decPos++;
                    encPos += 2;
                    break;
                case 3:
                    int len = name[encPos++] & 0xFF;
                    if ((len & 0x80) != 0) {
                        int correction = name[encPos++] & 0xFF;
                        for (len = (len & 0x7F) + 2; len > 0 && decPos < name.length; len--, decPos++) {
                            low = ((name[decPos] & 0xFF) + correction) & 0xFF;
                            sb.append((char) ((highByte << 8) + low));
                        }
                    } else {
                        for (len += 2; len > 0 && decPos < name.length; len--, decPos++) {
                            sb.append((char) (name[decPos] & 0xFF));
                        }
                    }
                    break;
            }
            flags = (flags << 2) & 0xFF;
            flagBits -= 2;
        }
        return sb.toString();
    }
    
    
    // --- Getters ---

    public long   getPackedSize()         { return packedSize; }
    public long   getUnpackedSize()       { return unpackedSize; }
    public int    getOsId()               { return osId; }
    public long   getCrc32()              { return crc32; }
    public long   getFileTime()           { return fileTime; }
    public int    getRequiredVersion()    { return requiredVersion; }
    public int    getCompressionMethod()  { return compressionMethod; }
    public String getFileName()           { return fileName; }
    public byte[] getSalt()               { return salt; }
    public long   getDictSize()           { return dictSize; }

    public boolean isEncrypted()          { return (flags & Rar4Constants.FILE_FLAG_ENCRYPTED)            != 0; }
    public boolean isSolid()              { return (flags & Rar4Constants.FILE_FLAG_SOLID)                != 0; }
    public boolean isDirectory()          { return ((flags & Rar4Constants.FILE_FLAG_DICT_MASK) >> Rar4Constants.FILE_FLAG_DICT_SHIFT) == 7; }
    public boolean hasUnicodeName()       { return (flags & Rar4Constants.FILE_FLAG_UNICODE_NAME)         != 0; }
    public boolean hasSalt()              { return (flags & Rar4Constants.FILE_FLAG_SALT)                 != 0; }
    public boolean hasExtendedTime()      { return (flags & Rar4Constants.FILE_FLAG_EXT_TIME)             != 0; }
    public boolean isContinuedFromPrev()  { return (flags & Rar4Constants.FILE_FLAG_CONTINUED_FROM_PREV) != 0; }
    public boolean isContinuedToNext()    { return (flags & Rar4Constants.FILE_FLAG_CONTINUED_TO_NEXT)   != 0; }
    public boolean isLargeFile()          { return (flags & Rar4Constants.FILE_FLAG_LARGE_FILE)           != 0; }
}