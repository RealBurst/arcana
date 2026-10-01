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

import java.io.File;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.formats.rar.util.Utils;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5Block;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5EncryptionBlock;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5EndBlock;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5FileBlock;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5MainArchiveBlock;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5ServiceBlock;
import be.stef.arcana.formats.rar.rar5.crypto.Rar5Crypto;
import be.stef.arcana.formats.rar.rar5.extra.Rar5ExtraCrypto;

/**
 * Reader for RAR5 archive structure.
 * 
 * <p>This class parses RAR5 archives and provides access to all blocks,
 * file entries, and metadata. It supports both encrypted and non-encrypted
 * archives.</p>
 * 
 * <h3>Usage:</h3>
 * <pre>
 * Rar5Reader reader = new Rar5Reader();
 * reader.read(new File("archive.rar"));
 * 
 * for (Rar5FileBlock file : reader.getFileBlocks()) {
 *     System.out.println(file.getFileName());
 * }
 * </pre>
 * 
 * <h3>For encrypted archives:</h3>
 * <pre>
 * Rar5Reader reader = new Rar5Reader("password");
 * reader.read(new File("encrypted.rar"));
 * </pre>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5Reader {
    private final List<Rar5Block> blocks = new ArrayList<>();
    private final List<Rar5FileBlock> fileBlocks = new ArrayList<>();
    private final List<Rar5ServiceBlock> serviceBlocks = new ArrayList<>();
    /** Structural damage found by the last read (header CRC, truncation); empty for a sound archive. */
    private final List<String> problems = new ArrayList<>();
    private Rar5MainArchiveBlock mainArchive;
    private Rar5EncryptionBlock encryptionBlock;
    private final String password;

    
    /**
     * Creates a reader for non-encrypted archives.
     */
    public Rar5Reader() {
        this.password = null;
    }
    
    /**
     * Creates a reader with a password for encrypted archives.
     * 
     * @param password the archive password
     */
    public Rar5Reader(String password) {
        this.password = password;
    }
    
    /**
     * Reads and parses a RAR5 archive file.
     * 
     * @param rarFile the archive file to read
     * @return true if reading succeeded, false otherwise
     */
    public boolean read(File rarFile) {
       try (RandomAccessFile raf = new RandomAccessFile(rarFile, "r")) {
           return read(raf);
       } catch (Exception e) {
           return false;
       }
    }
    
    
    /**
     * Reads and parses RAR5 archive from a RandomAccessFile.
     * Memory-efficient: only headers are loaded, not file data.
     * 
     * @param raf the RandomAccessFile to read from
     * @return true if reading succeeded, false otherwise
     */
    public boolean read(RandomAccessFile raf) {
        try {
            // Clear previous state
            blocks.clear();
            fileBlocks.clear();
            serviceBlocks.clear();
            problems.clear();
            mainArchive = null;
            encryptionBlock = null;
            
            // Verify signature
            byte[] signature = new byte[Rar5Constants.RAR5_SIGNATURE.length];
            raf.seek(0);
            if (raf.read(signature) != signature.length || !verifySignature(signature)) {
                return false;
            }
            
            long pos = Rar5Constants.RAR5_SIGNATURE.length;
            long fileLength = raf.length();
            
            while (pos + 4 < fileLength) {
                Rar5Block block = readBlock(raf, pos);
                if (block == null) {
                    if (problems.isEmpty()) problems.add("Damaged or truncated header at offset " + pos);
                    break;
                }
                
                blocks.add(block);
                if (block.getDataEnd() > fileLength) {
                    problems.add("Truncated archive: data of " + (block instanceof Rar5FileBlock ? ((Rar5FileBlock) block).getFileName() : "block at offset " + pos) + " goes beyond the end of the file");
                }
                
                // Store by type
                if (block instanceof Rar5MainArchiveBlock) {
                    mainArchive = (Rar5MainArchiveBlock) block;
                } else if (block instanceof Rar5ServiceBlock) {
                    serviceBlocks.add((Rar5ServiceBlock) block);
                } else if (block instanceof Rar5FileBlock) {
                    fileBlocks.add((Rar5FileBlock) block);
                } else if (block instanceof Rar5EncryptionBlock) {
                    encryptionBlock = (Rar5EncryptionBlock) block;
                }
                
                // Advance position
                pos = block.getDataEnd();
                
                // Stop at End of Archive
                if (block.getType() == Rar5Constants.BLOCK_TYPE_END_OF_ARC) {
                    break;
                }
            }
            // RAR5 always ends with an end-of-archive header (the "-en" switch does not exist for RAR5)
            boolean hasEnd = !blocks.isEmpty() && blocks.get(blocks.size() - 1).getType() == Rar5Constants.BLOCK_TYPE_END_OF_ARC;
            if (!hasEnd && problems.isEmpty()) problems.add("Truncated archive: end-of-archive header missing");
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    
    /**
     * Reads and parses RAR5 archive data from a byte array.
     * 
     * @param data the archive data
     * @return true if reading succeeded, false otherwise
     */
    public boolean read(byte[] data) {
        try {
            // Clear previous state
            blocks.clear();
            fileBlocks.clear();
            serviceBlocks.clear();
            mainArchive = null;
            encryptionBlock = null;
            
            // Verify signature
            if (!verifySignature(data)) {
                return false;
            }
            
            int pos = Rar5Constants.RAR5_SIGNATURE.length;
            
            while (pos + 4 < data.length) {
                Rar5Block block = readBlock(data, pos);
                if (block == null) {
                    break;
                }
                
                blocks.add(block);
                
                // Store by type
                if (block instanceof Rar5MainArchiveBlock) {
                    mainArchive = (Rar5MainArchiveBlock) block;
                } else if (block instanceof Rar5ServiceBlock) {
                    serviceBlocks.add((Rar5ServiceBlock) block);
                } else if (block instanceof Rar5FileBlock) {
                    fileBlocks.add((Rar5FileBlock) block);
                } else if (block instanceof Rar5EncryptionBlock) {
                    encryptionBlock = (Rar5EncryptionBlock) block;
                }
                
                // Advance position
                pos = (int) block.getDataEnd();
                
                // Stop at End of Archive
                if (block.getType() == Rar5Constants.BLOCK_TYPE_END_OF_ARC) {
                    break;
                }
            }
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Verifies that data starts with the RAR5 signature.
     * 
     * @param data the data to check
     * @return true if signature is valid
     */
    public static boolean verifySignature(byte[] data) {
        if (data == null || data.length < Rar5Constants.RAR5_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < Rar5Constants.RAR5_SIGNATURE.length; i++) {
            if (data[i] != Rar5Constants.RAR5_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Reads a single block from the archive data.
     */
    private Rar5Block readBlock(byte[] data, int pos) {
        try {
            int blockStart = pos;
            
            // CRC32 (4 bytes)
            if (pos + 4 > data.length) {
                return null;
            }
            long crc32 = Utils.readUInt32LE(data, pos);
            pos += 4;
            
            // Header size (VInt)
            VInt headerSizeVInt = VIntReader.read(data, pos, data.length);
            if (headerSizeVInt == null) {
                return null;
            }
            long headerSize = headerSizeVInt.value;
            pos += headerSizeVInt.length;
            
            int headerDataStart = pos;
            int headerDataEnd = (int) Math.min(pos + headerSize, data.length);
            
            // Peek type to create appropriate block object
            VInt typeVInt = VIntReader.read(data, pos, headerDataEnd);
            if (typeVInt == null) {
                return null;
            }
            int type = (int) typeVInt.value;
            
            // Create block based on type
            Rar5Block block;
            switch (type) {
                case Rar5Constants.BLOCK_TYPE_MAIN_ARCHIVE:
                    block = new Rar5MainArchiveBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_FILE:
                    block = new Rar5FileBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_SERVICE:
                    block = new Rar5ServiceBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT:
                    block = new Rar5EncryptionBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_END_OF_ARC:
                    block = new Rar5EndBlock();
                    break;
                default:
                    return null;
            }
            
            // Parse common header
            int commonEnd = block.parseCommonHeader(data, headerDataStart, headerDataEnd);
            if (commonEnd < 0) {
                return null;
            }
            
            // Parse specific data
            if (!block.parseSpecificData(data, commonEnd, headerDataEnd)) {
                return null;
            }
            
            // Store positions using setters
            block.setBlockStartPosition(blockStart);
            block.setHeaderDataStart(headerDataStart);
            block.setDataStart(headerDataEnd);
            block.setDataEnd(headerDataEnd + block.getDataSize());
            block.setCrc32(crc32);
            block.setHeaderSize(headerSize);
            
            return block;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    
    /**
     * Reads a single block from the archive using RandomAccessFile.
     * Only reads header data, not the compressed file data.
     */
    private Rar5Block readBlock(RandomAccessFile raf, long pos) {
        try {
            long blockStart = pos;
            raf.seek(pos);
            
            // Read header into buffer (headers are small, 4KB is plenty)
            // First read just enough to get CRC + header size
            byte[] prefix = new byte[16];
            int prefixRead = raf.read(prefix);
            if (prefixRead < 7) {
                return null;
            }
            
            // CRC32 (4 bytes)
            long crc32 = Utils.readUInt32LE(prefix, 0);
            int offset = 4;
            
            // Header size (VInt)
            VInt headerSizeVInt = VIntReader.read(prefix, offset, prefixRead);
            if (headerSizeVInt == null) {
                return null;
            }
            long headerSize = headerSizeVInt.value;
            offset += headerSizeVInt.length;
            
            // Now read the full header data
            int headerDataLength = (int) headerSize;
            byte[] headerData = new byte[headerDataLength];
            
            raf.seek(pos + 4 + headerSizeVInt.length);
            int headerRead = raf.read(headerData);
            if (headerRead < headerDataLength) {
                problems.add("Truncated archive: incomplete header at offset " + pos);
                return null;
            }
            // Header CRC32 covers the header size field and the header data
            java.util.zip.CRC32 hcrc = new java.util.zip.CRC32();
            hcrc.update(prefix, 4, headerSizeVInt.length);
            hcrc.update(headerData, 0, headerDataLength);
            if (hcrc.getValue() != crc32) {
                problems.add("Header CRC error at offset " + pos + " (corrupted archive)");
                return null;
            }
            
            long headerDataStart = pos + 4 + headerSizeVInt.length;
            long headerDataEnd = headerDataStart + headerSize;
            
            // Peek type to create appropriate block object
            VInt typeVInt = VIntReader.read(headerData, 0, headerDataLength);
            if (typeVInt == null) {
                return null;
            }
            int type = (int) typeVInt.value;
            
            // Create block based on type
            Rar5Block block;
            switch (type) {
                case Rar5Constants.BLOCK_TYPE_MAIN_ARCHIVE:
                    block = new Rar5MainArchiveBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_FILE:
                    block = new Rar5FileBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_SERVICE:
                    block = new Rar5ServiceBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT:
                    block = new Rar5EncryptionBlock();
                    break;
                case Rar5Constants.BLOCK_TYPE_END_OF_ARC:
                    block = new Rar5EndBlock();
                    break;
                default:
                    return null;
            }
            
            // Parse common header (relative to headerData buffer)
            int commonEnd = block.parseCommonHeader(headerData, 0, headerDataLength);
            if (commonEnd < 0) {
                return null;
            }
            
            // Parse specific data
            if (!block.parseSpecificData(headerData, commonEnd, headerDataLength)) {
                return null;
            }
            
            // Store positions (absolute file positions)
            block.setBlockStartPosition(blockStart);
            block.setHeaderDataStart(headerDataStart);
            block.setDataStart(headerDataEnd);
            block.setDataEnd(headerDataEnd + block.getDataSize());
            block.setCrc32(crc32);
            block.setHeaderSize(headerSize);
            
            return block;
            
        } catch (Exception e) {
            return null;
        }
    }
    
    
    /**
     * Decrypts the compressed data of an encrypted file.
     * 
     * <p>Process:</p>
     * <ol>
     *   <li>Extract encryption parameters from the file's extra area</li>
     *   <li>Derive a file-specific key (each file has its own salt)</li>
     *   <li>Decrypt using AES-256-CBC with the file's IV</li>
     * </ol>
     * 
     * @param block the file block containing encryption info
     * @param encryptedData the encrypted compressed data
     * @return the decrypted compressed data, or null on error
     */
    public byte[] decryptFileData(Rar5FileBlock block, byte[] encryptedData) {
        try {
            // Get crypto record from file
            Rar5ExtraCrypto crypto = block.getCrypto();
            if (crypto == null) {
                // Not encrypted
                return encryptedData;
            }
            
            // Verify data alignment (required for CBC)
            if (encryptedData.length % 16 != 0) {
                return null;
            }
            
            // Derive file-specific key
            Rar5Crypto.DerivedKeys keys = Rar5Crypto.deriveKeys(password, crypto);
            byte[] fileKey = keys.getEncryptionKey();
            
            // Decrypt data (IV is used directly, not derived with file index)
            return Rar5Crypto.decryptFileData(
                encryptedData,
                fileKey,
                crypto.getInitVector()
            );
            
        } catch (Exception e) {
            return null;
        }
    }
    
    
    /**
     * @return all blocks in the archive
     */
    public List<Rar5Block> getBlocks() {
        return blocks;
    }
    
    /**
     * @return the main archive header block
     */
    public Rar5MainArchiveBlock getMainArchive() {
        return mainArchive;
    }
    
    /**
     * @return all file blocks (excluding service blocks)
     */
    /** Damage found by the last read (header CRC errors, truncated headers or data). */
    public List<String> getProblems() {
        return problems;
    }

    public List<Rar5FileBlock> getFileBlocks() {
        return fileBlocks;
    }
    
    /**
     * @return all service blocks
     */
    public List<Rar5ServiceBlock> getServiceBlocks() {
        return serviceBlocks;
    }
    
    /**
     * @return the encryption block, or null if not encrypted
     */
    public Rar5EncryptionBlock getEncryptionBlock() {
        return encryptionBlock;
    }
    
    /**
     * @return true if the archive has encrypted headers
     */
    public boolean hasEncryptedHeaders() {
        return encryptionBlock != null;
    }
    
    
    /**
     * Creates a decrypting InputStream for streaming decryption.
     * 
     * @param block the file block containing encryption info
     * @param encryptedInput the encrypted input stream
     * @return a CipherInputStream that decrypts on-the-fly, or null on error
    * @throws Exception 
     */
    public InputStream createDecryptingStream(Rar5FileBlock block, InputStream encryptedInput) throws Exception {
        Rar5ExtraCrypto crypto = block.getCrypto();
        if (crypto == null) {
            return encryptedInput; // Not encrypted
        }
        
        Rar5Crypto.DerivedKeys keys = Rar5Crypto.deriveKeys(password, crypto);
        return Rar5Crypto.createDecryptingStream(
            encryptedInput,
            keys.getEncryptionKey(),
            crypto.getInitVector()
        );
    }    
    
    /**
     * Prints archive information to stdout.
     */
    public void printInfo() {
        System.out.println("=== RAR5 Archive ===");
        
        if (mainArchive != null) {
            System.out.println("\nMain Archive:");
            System.out.println("  Volume: " + mainArchive.isVolume());
            System.out.println("  Solid: " + mainArchive.isSolid());
            if (mainArchive.hasVolumeNumber()) {
                System.out.println("  Volume#: " + mainArchive.getVolumeNumber());
            }
        }
        
        System.out.println("\nFiles: " + fileBlocks.size());
        for (int i = 0; i < fileBlocks.size(); i++) {
            Rar5FileBlock f = fileBlocks.get(i);
            System.out.println("\n[" + (i + 1) + "] " + f.getFileName());
            System.out.println("  Size: " + f.getUnpackedSize() + " bytes");
            System.out.println("  Compressed: " + f.getDataSize() + " bytes");
            System.out.println("  Method: " + f.getCompressionMethod());
            System.out.println("  V7: " + f.isV7());
            System.out.println("  Solid: " + f.isSolid());
            System.out.println("  Directory: " + f.isDirectory());
            System.out.println("  Encrypted: " + f.isEncrypted());
            if (f.hasCRC()) {
                System.out.printf("  CRC32: %08X%n", f.getCRC());
            }
            if (f.getHash() != null) {
                System.out.println("  Hash: " + f.getHash());
            }
            if (f.getLink() != null) {
                System.out.println("  Link: " + f.getLink());
            }
        }
    }
}
