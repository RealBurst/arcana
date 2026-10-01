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

import java.io.File;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4Block;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4EndBlock;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4MainBlock;
import be.stef.arcana.formats.rar.rar4.crypto.Rar4Crypto;

/**
 * Parser for RAR4 archive structure.
 *
 * <p>Reads and parses all blocks from a RAR4 archive file.
 * Only headers are loaded into memory - file data is not read.</p>
 *
 * <h3>Usage:</h3>
 * <pre>
 * Rar4HeaderParser parser = new Rar4HeaderParser();
 * if (parser.parse(new File("archive.rar"))) {
 *     for (Rar4FileBlock f : parser.getFileBlocks()) {
 *         System.out.println(f.getFileName());
 *     }
 * }
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4HeaderParser {
    private final List<Rar4Block>     blocks     = new ArrayList<>();
    private final List<Rar4FileBlock> fileBlocks = new ArrayList<>();
    /** Structural damage found while parsing (header CRC, truncation); empty for a sound archive. */
    private final List<String>        problems   = new ArrayList<>();
    private Rar4MainBlock mainBlock;
    private String password;

    // Maximum header size we'll try to read (sanity guard)
    private static final int MAX_HEADER_SIZE = 65535;

    /**
     * Parses a RAR4 archive file.
     *
     * @param rarFile the archive file
     * @return true if parsing succeeded
     */
    public boolean parse(File rarFile) {
       return parse(rarFile, null);
    }

    /**
     * Parses a RAR4 archive file.
     *
     * @param rarFile the archive file
     * @param password the password
     * @return true if parsing succeeded
     */
    public boolean parse(File rarFile, String password) {
       this.password = password;
       try (RandomAccessFile raf = new RandomAccessFile(rarFile, "r")) {
           return parse(raf);
       } catch (Exception e) {
           return false;
       }
    }
    
    /**
     * Parses a RAR4 archive from a RandomAccessFile.
     *
     * @param raf the RandomAccessFile
     * @return true if parsing succeeded
     */
    public boolean parse(RandomAccessFile raf) {
       try {
           blocks.clear();
           fileBlocks.clear();
           problems.clear();
           mainBlock = null;

           byte[] sig = new byte[Rar4Constants.SIGNATURE_LENGTH];
           raf.seek(0);
           if (raf.read(sig) != sig.length || !verifySignature(sig)) {
               return false;
           }

           long pos      = Rar4Constants.SIGNATURE_LENGTH;
           long fileSize = raf.length();
           boolean encryptedHeaders = false;

           while (pos + 7 <= fileSize) {
               Rar4Block block;
               if (encryptedHeaders) {
                   block = readEncryptedBlock(raf, pos, fileSize);
               } else {
                   block = readBlock(raf, pos, fileSize);
               }
               if (block == null) {
                   if (problems.isEmpty()) problems.add("Damaged or truncated header at offset " + pos);
                   break;
               }

               blocks.add(block);
               if (block.getDataEnd() > fileSize) {
                   String what = block instanceof Rar4FileBlock ? ((Rar4FileBlock) block).getFileName() : "block at offset " + pos;
                   problems.add("Truncated archive: data of " + what + " goes beyond the end of the file");
               }

               if (block instanceof Rar4MainBlock) {
                   mainBlock = (Rar4MainBlock) block;
                   // From the next block onward, headers are encrypted if applicable
                   if (mainBlock.hasEncryptedHeaders()) {
                       if (password == null || password.isEmpty()) {
                           System.err.println("Password required: encrypted headers");
                           return false;
                       }
                       encryptedHeaders = true;
                   }
               } else if (block instanceof Rar4FileBlock) {
                   fileBlocks.add((Rar4FileBlock) block);
               }

               pos = block.getDataEnd();

               if (block instanceof Rar4EndBlock) break;
           }

           return true;

       } catch (Exception e) {
           return false;
       }
    }
    
    
    /**
     * Reads and parses a single block at the given position.
     */
    private Rar4Block readBlock(RandomAccessFile raf, long pos, long fileSize) {
        try {
            // Read common header prefix (7 bytes minimum)
            int prefixLen = (int) Math.min(11, fileSize - pos); // 7 + 4 (addSize)
            if (prefixLen < 7) return null;

            byte[] prefix = new byte[prefixLen];
            raf.seek(pos);
            if (raf.read(prefix) < 7) return null;

            int  type      = prefix[2] & 0xFF;
            int  flags     = ((prefix[3] & 0xFF) | ((prefix[4] & 0xFF) << 8));
            int  headerSize = ((prefix[5] & 0xFF) | ((prefix[6] & 0xFF) << 8));

            if (headerSize < 7 || headerSize > MAX_HEADER_SIZE) return null;

            // Read full header
            byte[] headerBuf = new byte[headerSize];
            raf.seek(pos);
            int headerRead = raf.read(headerBuf);
            if (headerRead < headerSize) {
                problems.add("Truncated archive: incomplete header at offset " + pos);
                return null;
            }
            if (!checkHeaderCrc(headerBuf, type, headerSize)) {
                problems.add("Header CRC error at offset " + pos + " (corrupted archive)");
                return null;
            }

            // Additional data size
            long addSize = 0;
            if ((flags & 0x8000) != 0 && headerSize >= 11) {
                addSize = ((headerBuf[7]  & 0xFFL))
                        | ((headerBuf[8]  & 0xFFL) << 8)
                        | ((headerBuf[9]  & 0xFFL) << 16)
                        | ((headerBuf[10] & 0xFFL) << 24);
            }

            // Instantiate correct block type
            Rar4Block block = createBlock(type);
            if (block == null) {
                // Unknown block - skip it using headerSize + addSize
                Rar4Block skip = new Rar4Block() {
                    @Override
                    public boolean parseSpecificData(byte[] buf, int offset, int length) {
                        return true;
                    }
                };
                skip.parseCommonHeader(headerBuf, 0, headerRead);
                skip.setBlockStart(pos);
                skip.setDataStart(pos + headerSize);
                skip.setDataEnd(pos + headerSize + addSize);
                return skip;
            }

            // Parse common header
            int consumed = block.parseCommonHeader(headerBuf, 0, headerRead);
            if (consumed < 0) return null;

            // Parse specific data
            if (!block.parseSpecificData(headerBuf, consumed, headerRead)) return null;

            // Set positions
            block.setBlockStart(pos);
            block.setDataStart(pos + headerSize);
            block.setDataEnd(pos + headerSize + addSize);

            return block;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reads and decrypts an encrypted header block.
     *
     * <p>Layout: 8-byte salt, then the header encrypted with AES-128 CBC,
     * padded up to a multiple of 16 bytes.</p>
     */
    private Rar4Block readEncryptedBlock(RandomAccessFile raf, long pos, long fileSize) {
        try {
            if (pos + 8 + 16 > fileSize) return null;

            // Read the salt (8 bytes, plaintext)
            byte[] salt = new byte[8];
            raf.seek(pos);
            if (raf.read(salt) != 8) return null;

            Cipher cipher = Rar4Crypto.buildDecipher(password, salt);

            long encStart = pos + 8;

            // Decrypt the first 16-byte block to read the header size
            byte[] enc16 = new byte[16];
            raf.seek(encStart);
            if (raf.read(enc16) != 16) return null;
            byte[] first = cipher.update(enc16);

            int type       = first[2] & 0xFF;
            int flags      = (first[3] & 0xFF) | ((first[4] & 0xFF) << 8);
            int headerSize = (first[5] & 0xFF) | ((first[6] & 0xFF) << 8);
            if (headerSize < 7 || headerSize > MAX_HEADER_SIZE) return null;

            int padded = (headerSize + 15) & ~15;

            // Assemble the full decrypted header
            byte[] headerBuf = new byte[padded];
            System.arraycopy(first, 0, headerBuf, 0, 16);
            if (padded > 16) {
                byte[] encRest = new byte[padded - 16];
                raf.seek(encStart + 16);
                if (raf.read(encRest) != encRest.length) return null;
                byte[] rest = cipher.update(encRest);
                System.arraycopy(rest, 0, headerBuf, 16, rest.length);
            }

            // addSize (size of the file's encrypted data)
            long addSize = 0;
            if ((flags & 0x8000) != 0 && headerSize >= 11) {
                addSize = (headerBuf[7]  & 0xFFL)
                        | ((headerBuf[8]  & 0xFFL) << 8)
                        | ((headerBuf[9]  & 0xFFL) << 16)
                        | ((headerBuf[10] & 0xFFL) << 24);
            }

            Rar4Block block = createBlock(type);
            if (block == null) {
                // Unknown block: advance past salt + padded header + data
                Rar4Block skip = new Rar4Block() {
                    @Override public boolean parseSpecificData(byte[] buf, int offset, int length) { return true; }
                };
                skip.parseCommonHeader(headerBuf, 0, headerSize);
                skip.setBlockStart(pos);
                skip.setDataStart(pos + 8 + padded);
                skip.setDataEnd(pos + 8 + padded + addSize);
                return skip;
            }

            if (!checkHeaderCrc(headerBuf, type, headerSize)) {
                problems.add("Header CRC error at offset " + pos + " (corrupted archive or wrong password)");
                return null;
            }
            int consumed = block.parseCommonHeader(headerBuf, 0, headerSize);
            if (consumed < 0) return null;
            if (!block.parseSpecificData(headerBuf, consumed, headerSize)) return null;

            block.setBlockStart(pos);
            block.setDataStart(pos + 8 + padded);              // file's encrypted data
            block.setDataEnd(pos + 8 + padded + addSize);

            return block;

        } catch (Exception e) {
            return null;
        }
     }
    
    /**
     * HEAD_CRC = low 16 bits of the CRC32 of the header from HEAD_TYPE to its end.
     * Checked for main, file and service headers (the other types use other rules).
     */
    private static boolean checkHeaderCrc(byte[] header, int type, int headerSize) {
        if (type != Rar4Constants.BLOCK_TYPE_ARCHIVE && type != Rar4Constants.BLOCK_TYPE_FILE && type != Rar4Constants.BLOCK_TYPE_NEWSUBBLOCK) return true;
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(header, 2, headerSize - 2);
        int stored = (header[0] & 0xFF) | ((header[1] & 0xFF) << 8);
        return ((int) crc.getValue() & 0xFFFF) == stored;
    }

    /**
     * Instantiates the correct block class for a given type.
     * Returns null for unknown/unsupported types (caller will skip them).
     */
    private Rar4Block createBlock(int type) {
        switch (type) {
            case Rar4Constants.BLOCK_TYPE_ARCHIVE:    return new Rar4MainBlock();
            case Rar4Constants.BLOCK_TYPE_FILE:       return new Rar4FileBlock();
            case Rar4Constants.BLOCK_TYPE_END_OF_ARC: return new Rar4EndBlock();
            case Rar4Constants.BLOCK_TYPE_MARKER:     return null; // signature block, skip
            case Rar4Constants.BLOCK_TYPE_NEWSUBBLOCK:return null; // NTFS streams etc., skip
            case Rar4Constants.BLOCK_TYPE_RECOVERY:   return null; // skip
            default:                                  return null;
        }
    }

    /**
     * Verifies the RAR4 signature.
     */
    public static boolean verifySignature(byte[] data) {
        if (data == null || data.length < Rar4Constants.SIGNATURE_LENGTH) return false;
        for (int i = 0; i < Rar4Constants.SIGNATURE_LENGTH; i++) {
            if (data[i] != Rar4Constants.RAR4_SIGNATURE[i]) return false;
        }
        return true;
    }

    // --- Getters ---

    public List<Rar4Block>     getBlocks()     { return blocks; }
    public List<Rar4FileBlock> getFileBlocks() { return fileBlocks; }

    /** Damage found by the last parse (header CRC errors, truncated headers or data). */
    public List<String> getProblems() { return problems; }
    public Rar4MainBlock       getMainBlock()  { return mainBlock; }

    public boolean isSolid() {
        return mainBlock != null && mainBlock.isSolid();
    }

    public boolean isVolume() {
       return mainBlock != null && mainBlock.isVolume();
    }
    
    public boolean hasEncryptedHeaders() {
        return mainBlock != null && mainBlock.hasEncryptedHeaders();
    }
}