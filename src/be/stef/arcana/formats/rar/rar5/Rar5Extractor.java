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

import be.stef.arcana.util.ExtractionGuard;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.exceptions.RarCorruptedDataException;
import be.stef.arcana.exceptions.RarDecryptException;
import be.stef.arcana.formats.rar.ExtractionError;
import be.stef.arcana.formats.rar.ExtractionResult;
import be.stef.arcana.formats.rar.util.Blake2sp;
import be.stef.arcana.formats.rar.util.Blake2spOutputStream;
import be.stef.arcana.formats.rar.util.BoundedInputStream;
import be.stef.arcana.formats.rar.util.CrcOutputStream;
import be.stef.arcana.formats.rar.util.DecoderPipeline;
import be.stef.arcana.util.ProgressOutputStream;
import be.stef.arcana.formats.rar.util.SafePathBuilder;
import be.stef.arcana.formats.rar.util.VInt;
import be.stef.arcana.formats.rar.util.VIntReader;
import be.stef.arcana.formats.rar.rar5.ExtractionContext;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5FileBlock;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5MainArchiveBlock;
import be.stef.arcana.formats.rar.rar5.crypto.Rar5Crypto;
import be.stef.arcana.formats.rar.rar5.decompress.Rar5LZDecoder;
import be.stef.arcana.formats.rar.rar5.decompress.Rar5PropertyEncoder;
import be.stef.arcana.formats.rar.rar5.extra.Rar5ExtraCrypto;
import be.stef.arcana.util.NullOutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * High-level API for extracting RAR5 archives.
 * 
 * <p>This class provides a simple interface for extracting files from RAR5 archives,
 * handling both encrypted and non-encrypted archives transparently.</p>
 * 
 * <h3>Basic Usage:</h3>
 * <pre>
 * // Extract without password
 * ExtractionResult result = Rar5Extractor.extract("archive.rar", "output/", null);
 * 
 * // Extract with password
 * ExtractionResult result = Rar5Extractor.extract("encrypted.rar", "output/", "password");
 * 
 * // Check results
 * System.out.println("Success: " + result.successCount + "/" + result.totalFiles);
 * </pre>
 * 
 * <h3>Check if Password Required:</h3>
 * <pre>
 * if (Rar5Extractor.isEncrypted("archive.rar")) {
 *     System.out.println("Password required");
 * }
 * </pre>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5Extractor {
    public static boolean showProgress = true;    
    public static boolean isEncryptedArchive;
    public static SafePathBuilder pathBuilder;
    /** @deprecated ignored since 1.3: the declared size is not trusted any more, see {@link be.stef.arcana.util.ExtractionLimits}. */
    @Deprecated
    public static long maxCompressionRatio = 1000;
    
    /**
     * Checks if an archive requires a password (has encrypted headers).
     * 
     * @param archivePath path to the archive
     * @return true if password is required
     * @throws IOException if file cannot be read
     */
    public static boolean isEncrypted(String archivePath) throws IOException {
        byte[] header = readFileHeader(archivePath, 500);
        if (header == null || header.length < Rar5Constants.RAR5_SIGNATURE.length + 10) {
            return false;
        }
        
        // Verify RAR5 signature
        for (int i = 0; i < Rar5Constants.RAR5_SIGNATURE.length; i++) {
            if (header[i] != Rar5Constants.RAR5_SIGNATURE[i]) {
                return false;
            }
        }
        
        // Check first block type
        try {
            int offset = Rar5Constants.RAR5_SIGNATURE.length + 4;
            VInt headerSize = VIntReader.read(header, offset, header.length);
            if (headerSize == null) {
                return false;
            }
            offset += headerSize.length;
            
            VInt blockType = VIntReader.read(header, offset, header.length);
            return blockType != null && blockType.value == Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Extracts a RAR5 archive to the specified directory.
     * 
     * <p>Extraction process:</p>
     * <ol>
     *   <li>If headers are encrypted, decrypt them first</li>
     *   <li>Read archive structure</li>
     *   <li>For each file: decrypt (if needed), decompress, write to disk</li>
     *   <li>Verify CRC32 checksums</li>
     * </ol>
     * 
     * @param archivePath path to the archive file
     * @param outputDir directory to extract files to
     * @param password password for encrypted archives, or null
     * @return extraction result with success/error counts
     */
    
    public static ExtractionResult extract(String archivePath, String outputDir, String password) {
       return extract(archivePath, outputDir, password, null);
    }
    
    public static synchronized ExtractionResult extract(String archivePath, String outputDir, String password, String fileFilter) {
        ExtractionResult result = new ExtractionResult();
        File tempFile = null;
        isEncryptedArchive = false;
        
        result.archiveName = archivePath;
              
        try {
            File archiveFile = new File(archivePath);
            if (!archiveFile.exists()) {
                result.errors.add(new ExtractionError(archivePath, "Archive not found"));
                result.errorCount++;
                return result;
            }
            
            File outDir = new File(outputDir);
            if (!outDir.exists()) {
                outDir.mkdirs();
            }
            
            // Initialize SafePathBuilder for path traversal protection
            pathBuilder = new SafePathBuilder(outDir);
            
            // Step 1: Decrypt headers if needed
            if (isEncrypted(archivePath)) {
               isEncryptedArchive = true;
                // No password or wrong password: reported as an encrypted-block error (ArcanaEncryptedException for RarExtractor)
                try {
                    tempFile = decryptHeadersToTemp(archivePath, password);
                } catch (ArcanaEncryptedException e) {
                    if (password != null && !password.isEmpty()) result.passwordStatus = 2;
                    result.errors.add(new ExtractionError(archiveFile.getName(), -1, -1, false, false, true, e.getMessage(), e));
                    result.errorCount++;
                    return result;
                }
                result.passwordStatus = 1;
                archiveFile = tempFile;
            }
         
            // Step 2: Read archive headers (small, stays in memory)
            Rar5Reader reader = new Rar5Reader(password);
            if (!reader.read(archiveFile)) {
                result.errors.add(new ExtractionError(new File(archivePath).getName(), "Failed to read RAR5 headers (corrupted archive, or wrong password for encrypted headers)"));
                result.errorCount++;
                return result;
            }
            for (String pb : reader.getProblems()) {
                result.errors.add(new ExtractionError(new File(archivePath).getName(), pb));
                result.errorCount++;
            }

            // Multi-volume archive: delegate to the dedicated path.
            // (Kept fully separate from the single-volume flow below.)
            Rar5MainArchiveBlock mainArchive = reader.getMainArchive();
            if (mainArchive != null && mainArchive.isVolume()) {
                // Use the ORIGINAL archive path for volume discovery: when the
                // headers were decrypted to a temp file, archiveFile points at
                // that temp file, which has no sibling volumes on disk.
                return extractMultiVolume(new File(archivePath), outputDir, password,
                                          fileFilter, result, isEncryptedArchive);
            }

            List<Rar5FileBlock> fileBlocks = reader.getFileBlocks();
            result.totalFiles = fileBlocks.size();

            // Step 3: Extract each file.
            // Non-solid multi-file archives are processed in parallel using one
            // thread per CPU core. Each thread gets its own ExtractionContext
            // (decoder + pathBuilder) so there is no shared mutable state.
            boolean arcSolid  = mainArchive != null && mainArchive.isSolid();
            boolean anySolid  = arcSolid || fileBlocks.stream().anyMatch(Rar5FileBlock::isSolid);
            boolean canParallel = !anySolid && fileBlocks.size() > 1 && fileFilter == null;

            if (canParallel) {
                final File archiveFileRef = archiveFile;
                int threads = Math.min(fileBlocks.size(),
                                       Math.max(1, Runtime.getRuntime().availableProcessors()));
                ExecutorService pool = Executors.newFixedThreadPool(threads);
                List<Future<?>> futures = new java.util.ArrayList<>();
                try {
                    for (Rar5FileBlock file : fileBlocks) {
                        if (file.isDirectory()) {
                            try {
                                // Use a thread-local SafePathBuilder to avoid race on the static field
                                java.io.File dir = new SafePathBuilder(new java.io.File(outputDir)).buildSafeDirPath(file.getFileName());
                                dir.mkdirs();
                                synchronized (result) { result.successCount++; }
                            } catch (Exception e) {
                                synchronized (result) { result.errorCount++; }
                            }
                            continue;
                        }
                        futures.add(pool.submit(() -> {
                            // Each task owns its RAF and ExtractionContext (decoder + pathBuilder).
                            ExtractionContext ctx = new ExtractionContext(
                                new SafePathBuilder(new java.io.File(outputDir)));
                            try (RandomAccessFile raf = new RandomAccessFile(archiveFileRef, "r")) {
                                ExtractionResult localResult = new ExtractionResult();
                                extractFile(file, raf, reader, outputDir, password, localResult, ctx);
                                synchronized (result) { result.merge(localResult); }
                            } catch (Exception e) {
                                synchronized (result) {
                                    result.errors.add(buildError(file, "Exception during extraction", e));
                                    result.errorCount++;
                                    result.failedFiles.add(file.getFileName());
                                }
                            }
                            return null;
                        }));
                    }
                    for (Future<?> f : futures) {
                        try { f.get(); } catch (java.util.concurrent.ExecutionException e) { /* handled in task */ }
                    }
                } finally {
                    pool.shutdown();
                }
            } else {
                // Sequential path: solid, mono-file, or filtered extraction.
                ExtractionContext ctx = new ExtractionContext(pathBuilder);
                try (RandomAccessFile raf = new RandomAccessFile(archiveFile, "r")) {
                    for (Rar5FileBlock file : fileBlocks) {
                        try {
                            boolean isTarget = (fileFilter == null || fileFilter.equals(file.getFileName()));

                            if (file.isSolid() && !isTarget) {
                                extractFile(file, raf, reader, outputDir, password, result, false, ctx);
                                continue;
                            }

                            if (!isTarget) continue;

                            extractFile(file, raf, reader, outputDir, password, result, ctx);
                            result.unpackedFiles.add(file.getFileName());
                        } catch (Exception e) {
                            result.errors.add(buildError(file, "Exception during extraction", e));
                            result.errorCount++;
                            result.failedFiles.add(file.getFileName());
                        }
                    }
                }
            }            
            
        } catch (Exception e) {
            // Fatal error (reported through result.errors)
            result.errors.add(new ExtractionError((String) null, "Fatal error: " + e.getMessage(), e));
            result.errorCount++;
        } finally {
            // Clean up temp file
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
        
        return result;
    }

    /**
     * Reads encryption info from the archive encryption block (for archives with encrypted headers).
     * This allows password verification BEFORE creating the decrypted temp file.
     * 
     * @param archivePath path to the archive
     * @return crypto info, or null if not found or error
     */
    private static Rar5ExtraCrypto readArchiveEncryptionInfo(String archivePath) {
        try {
            byte[] data = readFileHeader(archivePath, 200);
            if (data == null || data.length < Rar5Constants.RAR5_SIGNATURE.length + 20) {
                return null;
            }
            
            // Skip RAR5 signature
            int offset = Rar5Constants.RAR5_SIGNATURE.length;
            
            // Read header CRC (4 bytes)
            offset += 4;
            
            // Read header size
            VInt headerSize = VIntReader.read(data, offset, data.length);
            if (headerSize == null) return null;
            offset += headerSize.length;
            
            // Read block type
            VInt blockType = VIntReader.read(data, offset, data.length);
            if (blockType == null || blockType.value != Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT) {
                return null;
            }
            offset += blockType.length;
            
            // Read block flags
            VInt blockFlags = VIntReader.read(data, offset, data.length);
            if (blockFlags == null) return null;
            offset += blockFlags.length;
            
            // ARC_ENCRYPT block structure:
            // - Encryption version (VInt)
            // - Encryption flags (VInt)
            // - KDF IterationExponent (1 byte)
            // - Salt (16 bytes)
            // - [Optional] Password check value (12 bytes) if flag 0x01 is set
            
            // Encryption version/algorithm
            VInt encVersion = VIntReader.read(data, offset, data.length);
            if (encVersion == null) return null;
            offset += encVersion.length;
            
            // Encryption flags
            VInt encFlags = VIntReader.read(data, offset, data.length);
            if (encFlags == null) return null;
            offset += encFlags.length;
            
            // KDF IterationExponent (1 byte)
            int kdfIterationExponent = data[offset] & 0xFF;
            offset += 1;
            
            // Salt (16 bytes)
            if (offset + 16 > data.length) return null;
            byte[] salt = Arrays.copyOfRange(data, offset, offset + 16);
            offset += 16;
            
            // Password check value (12 bytes) if present
            byte[] passwordCheck = null;
            boolean hasPasswordCheck = (encFlags.value & Rar5Constants.CRYPTO_FLAG_PASSWORD_CHECK) != 0;
            if (hasPasswordCheck && offset + 12 <= data.length) {
                passwordCheck = Arrays.copyOfRange(data, offset, offset + 12);
            }
            
            return Rar5ExtraCrypto.createForArchiveEncryption(
                encVersion.value,
                encFlags.value,
                kdfIterationExponent,
                salt,
                passwordCheck
            );
            
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypts the headers of an archive made with encrypted headers (rar -hp) into a
     * temporary copy (file data stays encrypted), readable by {@link Rar5Reader}.
     * Used by extraction and by the listing. The caller deletes the returned file.
     *
     * @param archivePath archive whose first block is the archive encryption header
     * @param password    password, or null
     * @return the temporary archive with plain headers
     * @throws ArcanaEncryptedException no password, or the password check value does not match
     * @throws IOException the headers cannot be decrypted
     */
    public static File decryptHeadersToTemp(String archivePath, String password) throws IOException {
        String name = new File(archivePath).getName();
        if (password == null || password.isEmpty()) throw new ArcanaEncryptedException("RAR archive has encrypted headers and no password was provided: " + name);
        // Verify the password BEFORE creating the temp file
        Rar5ExtraCrypto archiveCrypto = readArchiveEncryptionInfo(archivePath);
        if (archiveCrypto != null && archiveCrypto.hasPasswordCheck()) {
            boolean passwordOk;
            try {
                passwordOk = Rar5Crypto.verifyPassword(password, archiveCrypto);
            } catch (Exception e) {
                throw new IOException("RAR5 password check failed: " + e.getMessage(), e);
            }
            if (!passwordOk) throw new ArcanaEncryptedException("Wrong password for RAR archive with encrypted headers: " + name);
        }
        File tempFile = File.createTempFile("unrar5j_dec_", ".rar");
        tempFile.deleteOnExit();
        try {
            new Rar5HeaderDecryptor(password).decryptToFile(archivePath, tempFile.getAbsolutePath());
        } catch (RarDecryptException e) {
            tempFile.delete();
            throw new IOException("RAR5 header decryption failed: " + e.getMessage(), e);
        }
        return tempFile;
    }

    /**
     * Extracts a single file from the archive.
     */
    private static void extractFile(Rar5FileBlock file, RandomAccessFile raf, Rar5Reader reader, String outputDir, String password, ExtractionResult result, ExtractionContext ctx) throws Exception {
      extractFile(file, raf, reader, outputDir, password, result, true, ctx);
    }

    /**
     * Extracts a single file from the archive.
     * @param writeOutput if false, file is decoded but not written to disk (for solid archive skip)
     */
    private static void extractFile(Rar5FileBlock file, RandomAccessFile raf, Rar5Reader reader, String outputDir, String password, ExtractionResult result, boolean writeOutput, ExtractionContext ctx) throws Exception {
        // Handle directories
        if (file.isDirectory()) {
            if (writeOutput) {
                File dir = ctx.pathBuilder.buildSafeDirPath(file.getFileName());
                dir.mkdirs();
            }
            result.successCount++;
            return;
        }
        
        // Handle empty files
        long start = file.getDataStart();
        long end = file.getDataEnd();
        long dataSize = end - start;
        
        if (dataSize == 0) {
            if (writeOutput) {
                File outFile = ctx.pathBuilder.buildSafePath(file.getFileName());
                outFile.getParentFile().mkdirs();
                outFile.createNewFile();
            }
            result.successCount++;
            return;
        }
        
        // Validate data position
        if (start >= end || end > raf.length()) {
            result.errors.add(buildError(file, "Invalid data position: " + start + "-" + end, null));
            result.errorCount++;
            return;
        }

        // Decompression bomb protection: enforced on the bytes actually written, see ExtractionLimits / ExtractionGuard
        long unpackedSize = file.getUnpackedSize();

        // Get the input stream for decompression
        InputStream decompressInput;
        
        if (file.isEncrypted()) {
            // Encrypted: must load into memory for decryption
            if (password == null || password.isEmpty()) {
                result.errors.add(buildError(file, "File is encrypted but no password provided", null));
                result.errorCount++;
                return;
            }
            
            // Verify password first (if password check value is available)
            Rar5ExtraCrypto crypto = file.getCrypto();
            if (crypto != null && crypto.hasPasswordCheck()) {
                try {
                    boolean passwordOk = Rar5Crypto.verifyPassword(password, crypto);
                    if (!passwordOk) {
                        result.errors.add(buildError(file, "Wrong password", null));
                        result.errorCount++;
                        result.passwordStatus = 2; // BAD PASSWORD
                        return;
                    } else {
                        result.passwordStatus = 1; // GOOD PASSWORD
                    }
                } catch (Exception e) {
                    // Password verification failed, continue anyway
                }
            }
        
            // Create decrypting stream (no memory copy)
            raf.seek(start);
            InputStream boundedInput = new BoundedInputStream(raf, dataSize);
            decompressInput = reader.createDecryptingStream(file, boundedInput);
            if (decompressInput == null) {
                result.errors.add(buildError(file, "Decryption setup failed", null));
                result.errorCount++;
                return;
            }
        
        } else {
            // Non-encrypted: use BoundedInputStream directly (no memory copy)
            raf.seek(start);
            decompressInput = new BoundedInputStream(raf, dataSize);
        }
        
        if (writeOutput) {
            // --- Normal mode: decompress to file ---
            File outFile = ctx.pathBuilder.buildSafePath(file.getFileName()); // use ctx, not static field
            outFile.getParentFile().mkdirs();
            
            be.stef.arcana.formats.rar.rar5.extra.Rar5ExtraHash extraHash = file.getHash();
            boolean needBlake2 = extraHash != null && extraHash.isBlake2sp();
            CRC32 crcAcc = file.hasCRC() ? new CRC32() : null;
            Blake2sp.Digest blake2Acc = needBlake2 ? new Blake2sp.Digest() : null;

            boolean success = decompressToFile(file, decompressInput, outFile, crcAcc, blake2Acc, ctx);
            if (!success) {
                result.errors.add(buildError(file, "Decompression failed", null));
                result.errorCount++;
                return;
            }

            // Verify CRC32
            if (file.hasCRC()) {
                long calculatedCRC = crcAcc.getValue();
                long expectedCRC = file.getCRC();
                
                boolean crcOk;
                if (file.isEncrypted() && !isEncryptedArchive) {
                    Rar5ExtraCrypto crypto = file.getCrypto();
                    byte[] hashKeyN16 = Rar5Crypto.deriveCrcHashKeyN16_Standard(password, crypto);
                    crcOk = Rar5Crypto.verifyCrcWithHMAC(calculatedCRC, expectedCRC, hashKeyN16);
                } else {
                    crcOk = (calculatedCRC == expectedCRC);
                }
                
                if (!crcOk) {
                    System.out.printf("CRC mismatch. Calculated: 0x%08X; expected: 0x%08X%n", calculatedCRC, expectedCRC);
                    outFile.delete();
                    throw new RarDecryptException("CRC mismatch - file may be corrupted.");
                }
            }
            
            // BLAKE2sp check (if archive uses BLAKE2sp instead of / in addition to CRC32)
            if (needBlake2) {
                try {
                    boolean blake2ok = blake2Acc.matches(extraHash.getHash());
                    if (!blake2ok) {
                        System.out.println("BLAKE2sp mismatch for: " + file.getFileName());
                        outFile.delete();
                        result.errors.add(buildError(file, "BLAKE2sp mismatch - file may be corrupted.", null));
                        result.errorCount++;
                        return;
                    }
                } catch (Exception e) {
                    result.errors.add(buildError(file, "BLAKE2sp verification failed", e));
                    result.errorCount++;
                    return;
                }
            }
            //--------------
            result.successCount++;
            
        } else {
            // --- Skip mode (solid): decode without writing to disk ---
            // The stream must still be consumed to keep the decoder state
            decompressToNull(file, decompressInput, ctx);
        }
    }
    
    private static OutputStream wrapVerifiers(OutputStream out, CRC32 crc, Blake2sp.Digest blake2) {
        OutputStream o = out;
        if (crc    != null) o = new CrcOutputStream(o, crc);
        if (blake2 != null) o = new Blake2spOutputStream(o, blake2);
        return o;
    }    
    
    
    /**
     * Decompresses from an InputStream directly to a file.
     * 
     * @param file the file block with compression info
     * @param input the input stream (compressed data)
     * @param outputFile the output file to write to
     * @return true if successful
     * @throws Exception corrupted data, unsupported feature, I/O error or extraction limit exceeded
     */
    private static boolean decompressToFile(Rar5FileBlock file, InputStream input, File outputFile, CRC32 crc, Blake2sp.Digest blake2, ExtractionContext ctx) throws Exception {
       ProgressOutputStream progressOut = null;

       try {
           int method = file.getCompressionMethod();
           long unpackedSize = file.getUnpackedSize();

           // Method 0 = store (no compression)
           if (method == Rar5Constants.COMPRESS_METHOD_STORE) {
               try (FileOutputStream fos = ExtractionGuard.open(outputFile);
                   BufferedOutputStream bos = new BufferedOutputStream(fos, 1 << 18)) {
                   
                   OutputStream targetOut = wrapVerifiers(bos, crc, blake2);
                   targetOut = showProgress
                       ? new ProgressOutputStream(targetOut, unpackedSize, file.getFileName())
                       : targetOut;

                   byte[] buffer = new byte[8192];
                   int read;
                   while ((read = input.read(buffer)) != -1) {
                       targetOut.write(buffer, 0, read);
                   }

                   if (targetOut instanceof ProgressOutputStream) {
                       ((ProgressOutputStream) targetOut).finish();
                   }
               }
               return true;
           }

           // All other compression methods 1 => 5
           if (ctx.decoder == null) {
               ctx.decoder = new Rar5LZDecoder();
           } else if (!file.isSolid()) {
               ctx.decoder.reset();
           }

           byte[] properties = Rar5PropertyEncoder.encodeWindowSize(
               file.getWindowSize(),
               file.isSolid(),
               file.isV7()
           );

           ctx.decoder.setDecoderProperties(properties);

           try (FileOutputStream fos = ExtractionGuard.open(outputFile);
                BufferedOutputStream bos = new BufferedOutputStream(fos, 1 << 18)) {
               OutputStream verifiedOut = wrapVerifiers(bos, crc, blake2);
               OutputStream targetOut = showProgress
                   ? new ProgressOutputStream(verifiedOut, unpackedSize, file.getFileName())
                   : verifiedOut;

               if (targetOut instanceof ProgressOutputStream) {
                   progressOut = (ProgressOutputStream) targetOut;
               }

               ctx.decoder.decode(input, targetOut, null, unpackedSize, null);

               if (progressOut != null) {
                   progressOut.finish();
               }
           }

           return true;

       } catch (Exception e) {
           // propagated to the caller, which records it with the file name (no more silent stderr)
           if (progressOut != null) {
               progressOut.finish();
           }
           throw e;
       }
    }
   
    /**
     * Decompresses data from an InputStream without writing output.
     * Used for solid archives when skipping a file but needing to maintain decoder state.
     */
    private static void decompressToNull(Rar5FileBlock file, InputStream input, ExtractionContext ctx) throws IOException {
        try {
            int method = file.getCompressionMethod();
            long unpackedSize = file.getUnpackedSize();
            
            // Method 0 = Store (no compression) - just drain the stream
            if (method == Rar5Constants.COMPRESS_METHOD_STORE) {
                byte[] buf = new byte[8192];
                while (input.read(buf) != -1) {}
                return;
            }
            
            if (ctx.decoder == null) {
                ctx.decoder = new Rar5LZDecoder();
            } else if (!file.isSolid()) {
                ctx.decoder.reset();
            }
            
            byte[] properties = Rar5PropertyEncoder.encodeWindowSize(
                  file.getWindowSize(),
                  file.isSolid(),
                  file.isV7()
            );
            
            ctx.decoder.setDecoderProperties(properties);
            
            // Decode into an OutputStream that discards everything
            OutputStream nullOut = new NullOutputStream();
            
            ctx.decoder.decode(input, nullOut, null, unpackedSize, null);
        } catch (IOException e) {
            throw new IOException("Failed to decode skipped solid file " + file.getFileName() + " (needed for the following files): " + e.getMessage(), e);
        } catch (RuntimeException e) {
            throw new IOException("Failed to decode skipped solid file " + file.getFileName() + " (needed for the following files): " + e.getMessage(), e);
        }
    }
    
    
    /**
     * Reads the first bytes of a file.
     */
    private static byte[] readFileHeader(String path, int size) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) {
            byte[] buffer = new byte[size];
            int read = fis.read(buffer);
            if (read < size) {
                return Arrays.copyOf(buffer, read);
            }
            return buffer;
        }
    }
    
    /**
     * Resets the shared decoder (useful for testing).
     */
    public static void resetDecoder() {
    }
    

    // -------------------------------------------------------------------------
    // Multi-volume extraction (.partNN.rar sets)
    // -------------------------------------------------------------------------

    /**
     * Extracts a multi-volume RAR5 set. A single file may be split across
     * several volumes; its compressed-data chunks are concatenated and fed to
     * the decoder as one continuous stream (mirrors the RAR4 implementation).
     *
     * <p>Supported: plain archives and per-file encrypted archives (clear
     * headers). Header-encrypted (-hp) multi-volume sets are rejected earlier.</p>
     */
    private static ExtractionResult extractMultiVolume(File firstVolume, String outputDir, String password, String fileFilter, ExtractionResult result, boolean headerEncrypted) {
        java.util.List<File> volumes   = discoverVolumes(firstVolume);
        java.util.List<File> tempFiles = new java.util.ArrayList<>();
        System.out.println("Multi-volume archive: " + volumes.size() + " volume(s) found" + (headerEncrypted ? " (encrypted headers)" : ""));

        java.util.List<LogicalFile5> files = buildLogicalFiles(volumes, password, headerEncrypted, tempFiles, result.errors);
        ExtractionContext ctx = new ExtractionContext(pathBuilder);
        result.totalFiles = files.size();

        for (LogicalFile5 lf : files) {
            Rar5FileBlock head = lf.head;
            try {
                boolean isTarget = (fileFilter == null || fileFilter.equals(head.getFileName()));

                if (head.isDirectory()) {
                    if (isTarget) {
                        pathBuilder.buildSafeDirPath(head.getFileName()).mkdirs();
                        result.successCount++;
                    }
                    continue;
                }

                if (head.isSolid() && !isTarget) {
                    // Solid set: decode the skipped file to keep the decoder state
                    decompressToNull(head, openLogicalInput(lf, password), ctx);
                    continue;
                }
                if (!isTarget) {
                    continue;
                }

                File outFile = pathBuilder.buildSafePath(head.getFileName());
                if (outFile == null) {
                    result.errors.add(buildError(head, "Unsafe path", null));
                    result.errorCount++;
                    continue;
                }
                outFile.getParentFile().mkdirs();

                if (lf.unpackedSize == 0) {
                    outFile.createNewFile();
                    result.successCount++;
                    result.unpackedFiles.add(head.getFileName());
                    continue;
                }

                be.stef.arcana.formats.rar.rar5.extra.Rar5ExtraHash extraHash = head.getHash();
                boolean needBlake2 = extraHash != null && extraHash.isBlake2sp();
                CRC32 crcAcc = lf.hasCrc ? new CRC32() : null;
                Blake2sp.Digest blake2Acc = needBlake2 ? new Blake2sp.Digest() : null;

                boolean ok = decompressToFile(head, openLogicalInput(lf, password), outFile, crcAcc, blake2Acc, ctx);
                if (!ok) {
                    result.errors.add(buildError(head, "Decompression failed", null));
                    result.errorCount++;
                    continue;
                }

                // CRC32 check (full-file CRC; last chunk wins)
                if (lf.hasCrc) {
                    long calculatedCRC = crcAcc.getValue();
                    long expectedCRC = lf.crc;
                    boolean crcOk;
                    if (head.isEncrypted() && !isEncryptedArchive) {
                        Rar5ExtraCrypto crypto = head.getCrypto();
                        byte[] hashKeyN16 = Rar5Crypto.deriveCrcHashKeyN16_Standard(password, crypto);
                        crcOk = Rar5Crypto.verifyCrcWithHMAC(calculatedCRC, expectedCRC, hashKeyN16);
                    } else {
                        crcOk = (calculatedCRC == expectedCRC);
                    }
                    if (!crcOk) {
                        System.out.printf("CRC mismatch. Calculated: 0x%08X; expected: 0x%08X%n", calculatedCRC, expectedCRC);
                        outFile.delete();
                        result.errors.add(buildError(head, "CRC mismatch - file may be corrupted.", null));
                        result.errorCount++;
                        continue;
                    }
                }

                // BLAKE2sp check
                if (needBlake2) {
                    try {
                        boolean blake2ok = blake2Acc.matches(extraHash.getHash());
                        if (!blake2ok) {
                            System.out.println("BLAKE2sp mismatch for: " + head.getFileName());
                            outFile.delete();
                            result.errors.add(buildError(head, "BLAKE2sp mismatch - file may be corrupted.", null));
                            result.errorCount++;
                            continue;
                        }
                    } catch (Exception e) {
                        result.errors.add(buildError(head, "BLAKE2sp verification failed", e));
                        result.errorCount++;
                        continue;
                    }
                }
                //------------------------
                
                result.successCount++;
                result.unpackedFiles.add(head.getFileName());

            } catch (Exception e) {
                result.errors.add(buildError(head, "Exception during extraction", e));
                result.errorCount++;
                result.failedFiles.add(head.getFileName());
            }
        }

        // Clean up per-volume temp files created for header decryption
        for (File t : tempFiles) {
            try { t.delete(); } catch (Exception ignore) { /* best effort */ }
        }
        return result;
    }

    /**
     * Opens the concatenated compressed-data stream for a logical file,
     * wrapping it in a single AES-CBC decrypting stream when the file is
     * per-file encrypted (the cipher then spans volume boundaries correctly).
     */
    private static InputStream openLogicalInput(LogicalFile5 lf, String password) throws Exception {
        InputStream in = new Rar5MultiVolumeInputStream(lf.segments);
        if (lf.head.isEncrypted()) {
            InputStream dec = lf.reader.createDecryptingStream(lf.head, in);
            if (dec == null) {
                throw new RarDecryptException("Decryption setup failed");
            }
            in = dec;
        }
        return in;
    }

    /**
     * Discovers all volumes of a .partNN.rar set, starting from the given
     * volume (e.g. archive.part01.rar, archive.part02.rar, ...).
     */
    private static java.util.List<File> discoverVolumes(File firstVolume) {
        java.util.List<File> vols = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("(?i)(.*[^0-9])([0-9]+)(\\.rar)$").matcher(firstVolume.getName());
        if (!m.matches()) {
            vols.add(firstVolume);
            return vols;
        }
        String prefix = m.group(1);
        int    width  = m.group(2).length();
        int    n      = Integer.parseInt(m.group(2));
        String suffix = m.group(3);
        File   dir    = firstVolume.getParentFile();
        // Rewind to the lowest existing volume so opening any part works.
        while (n > 0) {
            File prev = new File(dir, prefix + String.format("%0" + width + "d", n - 1) + suffix);
            if (!prev.exists()) break;
            n--;
        }
        while (true) {
            File vf = new File(dir, prefix + String.format("%0" + width + "d", n) + suffix);
            if (!vf.exists()) break;
            vols.add(vf);
            n++;
        }
        return vols;
    }

    /** A file reconstructed from one or more split chunks across volumes. */
    private static class LogicalFile5 {
        Rar5FileBlock head;          // first chunk: name, size, method, crypto, flags
        Rar5Reader    reader;        // reader of the head's volume (for decryption)
        long          unpackedSize;  // full unpacked size (from the first chunk)
        long          crc;           // full-file CRC (last chunk wins)
        boolean       hasCrc;
        final java.util.List<Rar5MultiVolumeInputStream.Segment> segments =
                new java.util.ArrayList<>();
    }

    /**
     * Parses every volume and groups split chunks into logical files. A file
     * block flagged "continues from previous volume" appends a data segment to
     * the current logical file; any other block starts a new one.
     */
    private static java.util.List<LogicalFile5> buildLogicalFiles(java.util.List<File> volumes,
            String password, boolean headerEncrypted, java.util.List<File> tempFiles, java.util.List<ExtractionError> problems) {
        java.util.List<LogicalFile5> result = new java.util.ArrayList<>();
        LogicalFile5 current = null;
        for (File vol : volumes) {
            // For encrypted headers, decrypt this volume to a temp file first.
            // The temp holds decrypted headers; the file data inside it stays
            // encrypted and is decrypted later, as one stream per logical file.
            File source = vol;
            if (headerEncrypted) {
                try {
                    File tmp = File.createTempFile("unrar5j_mv_", ".rar");
                    tmp.deleteOnExit();
                    new Rar5HeaderDecryptor(password)
                            .decryptToFile(vol.getAbsolutePath(), tmp.getAbsolutePath());
                    tempFiles.add(tmp);
                    source = tmp;
                } catch (Exception e) {
                    problems.add(new ExtractionError(vol.getName(), "Header decryption failed: " + e.getMessage(), e));
                    continue;
                }
            }

            Rar5Reader reader = new Rar5Reader(password);
            if (!reader.read(source)) {
                problems.add(new ExtractionError(vol.getName(), "Unreadable volume"));
                continue;
            }
            for (String pb : reader.getProblems()) problems.add(new ExtractionError(vol.getName(), pb));
            for (Rar5FileBlock fb : reader.getFileBlocks()) {
                long size = fb.getDataEnd() - fb.getDataStart();
                if (fb.isPreviousVolume() && current != null) {
                    // Continuation chunk: append data and adopt this chunk's
                    // CRC. RAR5 stores a cumulative CRC per split part, so the
                    // last chunk carries the full-file CRC (last chunk wins).
                    current.segments.add(new Rar5MultiVolumeInputStream.Segment(
                            source, fb.getDataStart(), size));
                    current.crc    = fb.getCRC();
                    current.hasCrc = fb.hasCRC();
                } else {
                    current = new LogicalFile5();
                    current.head         = fb;
                    current.reader       = reader;
                    current.unpackedSize = fb.getUnpackedSize();
                    current.crc          = fb.getCRC();
                    current.hasCrc       = fb.hasCRC();
                    current.segments.add(new Rar5MultiVolumeInputStream.Segment(
                            source, fb.getDataStart(), size));
                    result.add(current);
                }
            }
        }
        return result;
    }

    /**
     * Builds an {@link ExtractionError} from a RAR5 file block, keeping the
     * RAR5-to-common mapping inside the RAR5 layer.
     */
    private static ExtractionError buildError(Rar5FileBlock file, String message, Exception ex) {
        return new ExtractionError(
                file.getFileName(),
                file.getUnpackedSize(),
                file.getCompressionMethod(),
                file.isV7(),
                file.isSolid(),
                file.isEncrypted(),
                message,
                ex);
    }


}
