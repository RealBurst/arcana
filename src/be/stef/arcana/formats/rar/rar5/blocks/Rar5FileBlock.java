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
package be.stef.arcana.formats.rar.rar5.blocks;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.Rar5Constants;
import be.stef.arcana.formats.rar.rar5.extra.*;

/**
 * File Header block for RAR5 archives.
 * 
 * <p>This block contains all metadata for a file entry including:</p>
 * <ul>
 *   <li>File name and attributes</li>
 *   <li>Compression method and parameters</li>
 *   <li>Timestamps and checksums</li>
 *   <li>Encryption information (in extra area)</li>
 * </ul>
 * 
 * <p>Structure:</p>
 * <ul>
 *   <li>FileFlags (VInt)</li>
 *   <li>UnpackedSize (VInt)</li>
 *   <li>Attributes (VInt)</li>
 *   <li>MTime (4 bytes, optional)</li>
 *   <li>CRC32 (4 bytes, optional)</li>
 *   <li>CompressionInfo (VInt)</li>
 *   <li>HostOS (VInt)</li>
 *   <li>NameLength (VInt)</li>
 *   <li>Name (bytes)</li>
 *   <li>Extra area (optional)</li>
 * </ul>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5FileBlock extends Rar5Block {
    private long fileFlags;
    private long unpackedSize;
    private long attributes;
    private long unixModificationTime;
    private long crc;
    private long compressionInfo;
    private long hostOS;
    private String fileName;
    private byte[] encryptedFileName;
    
    private Map<Integer, Object> extraRecords = new HashMap<>(); // Parsed extra records
    
    // ========== File Flags ==========
    
    /**
     * @return true if this entry is a directory
     */
    public boolean isDirectory() {
        return (fileFlags & Rar5Constants.FILE_FLAG_IS_DIR) != 0;
    }
    
    /**
     * @return true if Unix modification time is present
     */
    public boolean hasUnixTime() {
        return (fileFlags & Rar5Constants.FILE_FLAG_UNIX_TIME) != 0;
    }
    
    /**
     * @return true if CRC32 checksum is present
     */
    public boolean hasCRC() {
        return (fileFlags & Rar5Constants.FILE_FLAG_CRC32) != 0;
    }
    
    /**
     * @return true if unpacked size is unknown
     */
    public boolean isUnknownSize() {
        return (fileFlags & Rar5Constants.FILE_FLAG_UNKNOWN_SIZE) != 0;
    }
    
    // ========== Compression Info Decoding ==========
    
    /**
     * Returns the algorithm version from compression info.
     * 
     * @return algorithm version (0 or 1)
     */
    public int getAlgoVersion() {
        return (int) (compressionInfo & 0x3F);
    }
    
    /**
     * Returns the algorithm version adjusted for Huffman compatibility.
     * If version is 1 and RAR5_COMPAT flag is set, returns 0.
     * 
     * @return effective algorithm version for Huffman decoding
     */
    public int getAlgoVersionHuffRev() {
        int version = getAlgoVersion();
        if (version == 1 && isRar5Compat()) {
            return 0;
        }
        return version;
    }
    
    /**
     * @return true if this file uses V7 algorithm features
     */
    public boolean isV7() {
        return getAlgoVersionHuffRev() == 1;
    }
    
    /**
     * @return true if file uses solid compression
     */
    public boolean isSolid() {
        return (compressionInfo & Rar5Constants.METHOD_FLAG_SOLID) != 0;
    }
    
    /**
     * @return true if RAR5 compatibility mode is enabled
     */
    public boolean isRar5Compat() {
        return (compressionInfo & Rar5Constants.METHOD_FLAG_RAR5_COMPAT) != 0;
    }
    
    /**
     * Returns the compression method (0-5).
     * 
     * @return compression method (0=store, 1=fastest, ..., 5=best)
     */
    public int getCompressionMethod() {
        return (int) ((compressionInfo >> 7) & 0x7);
    }
    
    /**
     * Returns the main dictionary size component.
     * 
     * @return dictionary size main value
     */
    public int getDictSizeMain() {
        int version = getAlgoVersion();
        int mask = (version == 0) ? 0xF : 0x1F;
        return (int) ((compressionInfo >> 10) & mask);
    }
    
    /**
     * Returns the fractional dictionary size component.
     * Only used when algo version is 1.
     * 
     * @return dictionary size fraction (0 if version 0)
     */
    public int getDictSizeFrac() {
        if (getAlgoVersion() == 0) {
            return 0;
        }
        return (int) ((compressionInfo >> 15) & 0x1F);
    }
    
    /**
     * Calculates the actual window size in bytes.
     * 
     * @return window size in bytes
     */
    public long getWindowSize() {
        int algo = getAlgoVersion();
        if (algo > 1) {
            return 0;
        }
        
        long base = 32;
        if (algo == 1) {
            base += getDictSizeFrac();
        }
        return base << (12 + getDictSizeMain());
    }
    
    /**
     * Builds the 2-byte decoder properties array.
     * 
     * <p>Format:</p>
     * <ul>
     *   <li>props[0] = DictSizeMain</li>
     *   <li>props[1] = (DictSizeFrac &lt;&lt; 3) | (version &lt;&lt; 1) | (solid ? 1 : 0)</li>
     * </ul>
     * 
     * @return decoder properties array
     */
    public byte[] getDecoderProperties() {
        int version = getAlgoVersionHuffRev();
        byte[] props = new byte[2];
        props[0] = (byte) getDictSizeMain();
        props[1] = (byte) ((getDictSizeFrac() << 3) | (version << 1) | (isSolid() ? 1 : 0));
        return props;
    }
    
    @Override
    public boolean parseSpecificData(byte[] data, int offset, int endExclusive) {
        try {
            int pos = offset;
            
            // File flags (VInt)
            VInt fileFlagsVInt = VIntReader.read(data, pos, endExclusive);
            if (fileFlagsVInt == null) {
                return false;
            }
            fileFlags = fileFlagsVInt.value;
            pos += fileFlagsVInt.length;
            
            // Unpacked size (VInt)
            VInt sizeVInt = VIntReader.read(data, pos, endExclusive);
            if (sizeVInt == null) {
                return false;
            }
            unpackedSize = sizeVInt.value;
            pos += sizeVInt.length;
            
            // Attributes (VInt)
            VInt attrVInt = VIntReader.read(data, pos, endExclusive);
            if (attrVInt == null) {
                return false;
            }
            attributes = attrVInt.value;
            pos += attrVInt.length;
            
            // Unix modification time (4 bytes, optional)
            if (hasUnixTime()) {
                if (pos + 4 > endExclusive) {
                    return false;
                }
                unixModificationTime = Utils.readUInt32LE(data, pos);
                pos += 4;
            }
            
            // CRC32 (4 bytes, optional)
            if (hasCRC()) {
                if (pos + 4 > endExclusive) {
                    return false;
                }
                crc = Utils.readUInt32LE(data, pos);
                pos += 4;
            }
            
            // Compression info (VInt)
            VInt methodVInt = VIntReader.read(data, pos, endExclusive);
            if (methodVInt == null) {
                return false;
            }
            compressionInfo = methodVInt.value;
            pos += methodVInt.length;
            
            // Host OS (VInt)
            VInt hostVInt = VIntReader.read(data, pos, endExclusive);
            if (hostVInt == null) {
                return false;
            }
            hostOS = hostVInt.value;
            pos += hostVInt.length;
            
            // File name length (VInt)
            VInt nameLenVInt = VIntReader.read(data, pos, endExclusive);
            if (nameLenVInt == null) {
                return false;
            }
            int nameLen = (int) nameLenVInt.value;
            pos += nameLenVInt.length;
            
            // File name (bytes)
            if (pos + nameLen > endExclusive) {
                return false;
            }
            byte[] nameBytes = new byte[nameLen];
            System.arraycopy(data, pos, nameBytes, 0, nameLen);
            pos += nameLen;
            
            // If file is encrypted, name is also encrypted
            if (isEncrypted()) {
                encryptedFileName = nameBytes;
                fileName = "[ENCRYPTED]";
            } else {
                fileName = new String(nameBytes, StandardCharsets.UTF_8);
            }
            
            // Parse extra area if present
            if (hasExtra() && pos + extraSize <= endExclusive) {
                parseExtraArea(data, pos, (int) extraSize);
                pos += (int) extraSize;
            }
            
            return pos == endExclusive;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    protected boolean parseExtraArea(byte[] data, int offset, int size) {
        try {
            int pos = offset;
            int end = offset + size;
            
            while (pos < end) {
                // Record size (VInt)
                VInt sizeVInt = VIntReader.read(data, pos, end);
                if (sizeVInt == null) {
                    break;
                }
                int recordSize = (int) sizeVInt.value;
                pos += sizeVInt.length;
                
                // Record ID (VInt)
                VInt idVInt = VIntReader.read(data, pos, end);
                if (idVInt == null) {
                    break;
                }
                int id = (int) idVInt.value;
                pos += idVInt.length;
                
                // Record data size
                int dataSize = recordSize - idVInt.length;
                if (pos + dataSize > end) {
                    break;
                }
                
                // Parse based on record type
                switch (id) {
                    case Rar5Constants.EXTRA_ID_CRYPTO:
                        Rar5ExtraCrypto crypto = new Rar5ExtraCrypto();
                        if (crypto.parse(data, pos, dataSize)) {
                            extraRecords.put(id, crypto);
                        }
                        break;
                        
                    case Rar5Constants.EXTRA_ID_HASH:
                        Rar5ExtraHash hash = new Rar5ExtraHash();
                        if (hash.parse(data, pos, dataSize)) {
                            extraRecords.put(id, hash);
                        }
                        break;
                        
                    case Rar5Constants.EXTRA_ID_TIME:
                        Rar5ExtraTime time = new Rar5ExtraTime();
                        if (time.parse(data, pos, dataSize)) {
                            extraRecords.put(id, time);
                        }
                        break;
                        
                    case Rar5Constants.EXTRA_ID_VERSION:
                        Rar5ExtraVersion version = new Rar5ExtraVersion();
                        if (version.parse(data, pos, dataSize)) {
                            extraRecords.put(id, version);
                        }
                        break;
                        
                    case Rar5Constants.EXTRA_ID_LINK:
                        Rar5ExtraLink link = new Rar5ExtraLink();
                        if (link.parse(data, pos, dataSize)) {
                            extraRecords.put(id, link);
                        }
                        break;
                        
                    default:
                        // Unknown extra record - store raw bytes
                        byte[] rawData = new byte[dataSize];
                        System.arraycopy(data, pos, rawData, 0, dataSize);
                        extraRecords.put(id, rawData);
                        break;
                }
                
                pos += dataSize;
            }
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== Extra Record Helpers ==========
    
    /**
     * @return true if file is encrypted
     */
    public boolean isEncrypted() {
        return extraRecords.containsKey(Rar5Constants.EXTRA_ID_CRYPTO);
    }
    
    /**
     * @return encryption information, or null if not encrypted
     */
    public Rar5ExtraCrypto getCrypto() {
        return (Rar5ExtraCrypto) extraRecords.get(Rar5Constants.EXTRA_ID_CRYPTO);
    }
    
    /**
     * @return hash information, or null if not present
     */
    public Rar5ExtraHash getHash() {
        return (Rar5ExtraHash) extraRecords.get(Rar5Constants.EXTRA_ID_HASH);
    }
    
    /**
     * @return extended time information, or null if not present
     */
    public Rar5ExtraTime getTime() {
        return (Rar5ExtraTime) extraRecords.get(Rar5Constants.EXTRA_ID_TIME);
    }
    
    /**
     * @return version information, or null if not present
     */
    public Rar5ExtraVersion getVersion() {
        return (Rar5ExtraVersion) extraRecords.get(Rar5Constants.EXTRA_ID_VERSION);
    }
    
    /**
     * @return link information, or null if not present
     */
    public Rar5ExtraLink getLink() {
        return (Rar5ExtraLink) extraRecords.get(Rar5Constants.EXTRA_ID_LINK);
    }
    
    // ========== Getters ==========
    
    public long getFileFlags() {
        return fileFlags;
    }
    
    public long getUnpackedSize() {
        return unpackedSize;
    }
    
    public long getAttributes() {
        return attributes;
    }
    
    public long getUnixModificationTime() {
        return unixModificationTime;
    }
    
    // Legacy getter
    public long getUnixMTime() {
        return unixModificationTime;
    }
    
    public long getCRC() {
        return crc;
    }
    
    /**
     * Returns the raw compression info field (method field).
     */
    public long getMethod() {
        return compressionInfo;
    }
    
    public long getHostOS() {
        return hostOS;
    }
    
    public String getFileName() {
        // "Keep previous file versions" (WinRAR -ver): older copies carry a version record and
        // are extracted as name;N, like WinRAR / libarchive, instead of overwriting each other
        Rar5ExtraVersion v = getVersion();
        if (v != null && v.getVersion() > 0 && fileName != null) return fileName + ";" + v.getVersion();
        return fileName;
    }
    
    public byte[] getEncryptedFileName() {
        return encryptedFileName;
    }
    
    public Map<Integer, Object> getExtraRecords() {
        return extraRecords;
    }
    
    /**
     * Sets the decrypted file name (called after decryption).
     * 
     * @param name the decrypted file name
     */
    public void setDecryptedFileName(String name) {
        this.fileName = name;
    }
}
