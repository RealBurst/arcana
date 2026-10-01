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

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;
import be.stef.arcana.formats.rar.ExtractionError;
import be.stef.arcana.formats.rar.ExtractionResult;
import be.stef.arcana.formats.rar.util.BoundedInputStream;
import be.stef.arcana.formats.rar.util.CrcOutputStream;
import be.stef.arcana.util.ProgressOutputStream;
import be.stef.arcana.formats.rar.util.SafePathBuilder;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;
import be.stef.arcana.formats.rar.rar4.decompress.Rar4Decompressor;
import be.stef.arcana.formats.rar.rar4.decompress.Rar4DecompressorRegistry;

/**
 * High-level API for extracting RAR4 archives.
 *
 * <p>Supported compression methods:</p>
 * <ul>
 *   <li>Store (0x30) - no compression</li>
 *   <li>0x31-0x35 (Fastest to Best), algorithm 2.9: LZ77 and PPMd var.H blocks</li>
 * </ul>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4Extractor {
    public static boolean  showProgress      = true;
    public static SafePathBuilder pathBuilder = null;
    /** @deprecated ignored since 1.3: the declared size is not trusted any more, see {@link be.stef.arcana.util.ExtractionLimits}. */
    @Deprecated
    public static long     maxCompressionRatio = 1000;
    private static final Rar4DecompressorRegistry registry = new Rar4DecompressorRegistry();
    
    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public static ExtractionResult extract(String archivePath, String outputDir, String password) {
        return extract(archivePath, outputDir, password, null);
    }

    public static synchronized ExtractionResult extract(String archivePath, String outputDir, String password, String fileFilter) {
        ExtractionResult result = new ExtractionResult();
        result.archiveName = archivePath;

        try {
            File archiveFile = new File(archivePath);
            if (!archiveFile.exists()) {
                result.errors.add(new ExtractionError(archivePath, "Archive not found"));
                return result;
            }

            File outDir = new File(outputDir);
            if (!outDir.exists()) outDir.mkdirs();

            pathBuilder = new SafePathBuilder(outDir);

            // Parse headers
            Rar4HeaderParser parser = new Rar4HeaderParser();
            if (!parser.parse(archiveFile, password)) {
                result.errors.add(new ExtractionError(archivePath, "Failed to parse RAR4 headers (corrupted archive, or encrypted headers without password)"));
                return result;
            }
            
            if (parser.isVolume()) {
               return extractMultiVolume(archiveFile, outDir, password, fileFilter, result);
            }
            for (String pb : parser.getProblems()) result.errors.add(new ExtractionError(archiveFile.getName(), pb));

            boolean archiveIsSolid = parser.isSolid();
            
            List<Rar4FileBlock> fileBlocks = parser.getFileBlocks();
            result.totalFiles = fileBlocks.size();


            try (RandomAccessFile raf = new RandomAccessFile(archiveFile, "r")) {
                for (Rar4FileBlock file : fileBlocks) {
                    try {
                        boolean isTarget = (fileFilter == null || fileFilter.equals(file.getFileName()));

                        if (!isTarget) continue;

                        if (file.isDirectory()) {
                            createDirectory(file, outDir);
                            result.successCount++;
                            continue;
                        }
                        
                        // Also skip entries with packedSize=0 and unpackedSize=0
                        if (file.getPackedSize() == 0 && file.getUnpackedSize() == 0) {
                            continue;
                        }
                        
                        String error = extractFile(raf, file, outDir, password);
                        if (error == null) {
                            result.successCount++;
                        } else {
                            result.errors.add(new ExtractionError(file.getFileName(), error));
                        }

                    } catch (ArcanaLimitExceededException e) {
                        result.errors.add(new ExtractionError(file.getFileName(), e.getMessage(), e));
                        return result; // extraction limit: stop the whole archive
                    } catch (Exception e) {
                        result.errors.add(new ExtractionError(file.getFileName(), e.getClass().getSimpleName() + ": " + e.getMessage(), e));
                    }
                }
            }

        } catch (Exception e) {
            result.errors.add(new ExtractionError(archivePath, "Extraction error: " + e.getMessage(), e));
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // File extraction
    // -------------------------------------------------------------------------

    /**
     * Extracts one file.
     *
     * @return null on success, otherwise the error message
     * @throws ArcanaLimitExceededException when an extraction limit is hit (stops the archive)
     */
    private static String extractFile(RandomAccessFile raf, Rar4FileBlock file, File outDir, String password) throws IOException {
       int method = file.getCompressionMethod();
       int version = file.getRequiredVersion();

       // Decompression bomb protection: enforced on the bytes actually written (ExtractionLimits / ExtractionGuard)

       File outputFile = pathBuilder.buildSafePath(file.getFileName());
       if (outputFile == null) return "Unsafe path rejected";
       if (outputFile.getParentFile() != null) outputFile.getParentFile().mkdirs();


       Rar4Decompressor decompressor;
       try {
          decompressor = registry.resolve(method, version);
       } catch (Exception e) {
          return "Compression method 0x" + Integer.toHexString(method).toUpperCase() + " (version " + version + ") not supported";
       }

       // Solid: preserve decompressor state across files.
       decompressor.resetState(file.isSolid());
    
       CRC32 crc = new CRC32();
       ProgressOutputStream progressOut = null;

       raf.seek(file.getDataStart());

       try (BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(outputFile))) {
          BoundedInputStream bounded = new BoundedInputStream(raf, file.getPackedSize());

          InputStream source = bounded;
          if (file.isEncrypted()) {
              if (password == null || password.isEmpty()) return "Password required";
              byte[] salt = file.getSalt();
              if (salt == null) return "Encrypted file without salt";
              try {
                  javax.crypto.Cipher cipher = be.stef.arcana.formats.rar.rar4.crypto.Rar4Crypto.buildDecipher(password, salt);
                  source = new be.stef.arcana.formats.rar.rar4.crypto.Rar4DecryptInputStream(bounded, cipher);
              } catch (Exception e) {
                  return "Decryption init failed: " + e.getMessage();
              }
          }
          
          OutputStream out = showProgress ? new ProgressOutputStream(bos, file.getUnpackedSize(), file.getFileName()) : bos;

          if (out instanceof ProgressOutputStream) progressOut = (ProgressOutputStream) out;

          // CRC accumulator wrapped around the output (bulk-capable)
          OutputStream crcOut = new CrcOutputStream(out, crc);

          try {
             decompressor.decompress(source, crcOut, file);
          } catch (ArcanaLimitExceededException e) {
             if (progressOut != null) progressOut.finish();
             throw e;
          } catch (Exception e) {
             if (progressOut != null) progressOut.finish();
             return "Decompression error: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
          }
          
          raf.seek(file.getDataStart() + file.getPackedSize());
          
          if (progressOut != null) progressOut.finish();

       } catch (IOException e) {
          if (progressOut != null) progressOut.finish();
          throw e;
       }

       long computed = crc.getValue();
       long expected = file.getCrc32();
       if (computed != expected) {
          return String.format("CRC32 mismatch: expected %08X, got %08X (corrupted data or wrong password)", expected, computed);
       }

       return null;
    }

    private static ExtractionResult extractMultiVolume(File firstVolume, File outDir, String password, String fileFilter, ExtractionResult result) {
      java.util.List<File> volumes = discoverVolumes(firstVolume);
      java.util.List<String> problems = new java.util.ArrayList<>();
      java.util.List<LogicalFile> files = buildLogicalFiles(volumes, password, problems);
      for (String pb : problems) result.errors.add(new ExtractionError(firstVolume.getName(), pb));
      result.totalFiles = files.size();

      for (LogicalFile lf : files) {
          try {
              Rar4FileBlock head = lf.head;
              if (fileFilter != null && !fileFilter.equals(head.getFileName())) continue;

              if (head.isDirectory()) {
                  createDirectory(head, outDir);
                  result.successCount++;
                  continue;
              }
              if (lf.unpackedSize == 0) continue;

              File outputFile = pathBuilder.buildSafePath(head.getFileName());
              if (outputFile == null) { result.errors.add(new ExtractionError(head.getFileName(), "Unsafe path")); continue; }
              if (outputFile.getParentFile() != null) outputFile.getParentFile().mkdirs();

              Rar4Decompressor decompressor = registry.resolve(head.getCompressionMethod(), head.getRequiredVersion());
              decompressor.resetState(head.isSolid());

              CRC32 crc = new CRC32();
              try (java.io.BufferedOutputStream bos = new java.io.BufferedOutputStream(ExtractionGuard.open(outputFile))) {
                  OutputStream out = showProgress
                          ? new ProgressOutputStream(bos, lf.unpackedSize, head.getFileName()) : bos;
                  OutputStream crcOut = new CrcOutputStream(out, crc);

                  InputStream source = new Rar4MultiVolumeInputStream(lf.segments);
                  if (head.isEncrypted()) {
                      byte[] salt = head.getSalt();
                      javax.crypto.Cipher cipher = be.stef.arcana.formats.rar.rar4.crypto.Rar4Crypto.buildDecipher(password, salt);
                      source = new be.stef.arcana.formats.rar.rar4.crypto.Rar4DecryptInputStream(source, cipher);
                  }

                  decompressor.decompress(source, crcOut, head);
                  if (out instanceof ProgressOutputStream) ((ProgressOutputStream) out).finish();
              }

              if (crc.getValue() != (lf.crc & 0xFFFFFFFFL)) {
                  result.errors.add(new ExtractionError(head.getFileName(), String.format("CRC32 mismatch: expected %08X, got %08X (corrupted data or wrong password)", lf.crc, crc.getValue())));
              } else {
                  result.successCount++;
              }
          } catch (ArcanaLimitExceededException e) {
              result.errors.add(new ExtractionError(lf.head.getFileName(), e.getMessage(), e));
              return result; // extraction limit: stop the whole archive
          } catch (Exception e) {
              result.errors.add(new ExtractionError(lf.head.getFileName(), e.getClass().getSimpleName() + ": " + e.getMessage(), e));
          }
      }
      return result;
   }

    /**
     * Discovers all volumes of a .partNN.rar set, starting from the given volume.
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
        while (true) {
            File vf = new File(dir, prefix + String.format("%0" + width + "d", n) + suffix);
            if (!vf.exists()) break;
            vols.add(vf);
            n++;
        }
        return vols;
    }
    
    private static class LogicalFile {
       Rar4FileBlock head;   // first chunk: name, size, salt, method, flags
       long crc;             // CRC of the last chunk (= full-file CRC)
       long unpackedSize;
       final java.util.List<Rar4MultiVolumeInputStream.Segment> segments = new java.util.ArrayList<>();
    }

    private static java.util.List<LogicalFile> buildLogicalFiles(java.util.List<File> volumes, String password, java.util.List<String> problems) {
       java.util.List<LogicalFile> result = new java.util.ArrayList<>();
       LogicalFile current = null;
       boolean lastContinues = false;
       for (File vol : volumes) {
           Rar4HeaderParser parser = new Rar4HeaderParser();
           if (!parser.parse(vol, password)) {
               problems.add(vol.getName() + ": unreadable volume");
               continue;
           }
           for (String pb : parser.getProblems()) problems.add(vol.getName() + ": " + pb);
           for (Rar4FileBlock fb : parser.getFileBlocks()) {
               lastContinues = fb.isContinuedToNext();
               if (fb.isContinuedFromPrev() && current != null) {
                   current.segments.add(new Rar4MultiVolumeInputStream.Segment(
                           vol, fb.getDataStart(), fb.getPackedSize()));
                   current.crc = fb.getCrc32();   // last chunk wins
               } else {
                   current = new LogicalFile();
                   current.head         = fb;
                   current.unpackedSize = fb.getUnpackedSize();
                   current.crc          = fb.getCrc32();
                   current.segments.add(new Rar4MultiVolumeInputStream.Segment(
                           vol, fb.getDataStart(), fb.getPackedSize()));
                   result.add(current);
               }
           }
       }
       if (lastContinues) problems.add("Missing volume after " + volumes.get(volumes.size() - 1).getName() + " (the last file continues in the next volume)");
       return result;
    }
    
    
    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static void createDirectory(Rar4FileBlock file, File outDir) throws IOException {
       // buildSafeDirPath: no collision renaming - the directory usually already exists
       // (created by mkdirs() for the files it contains, which RAR stores before it)
       File dir = pathBuilder.buildSafeDirPath(file.getFileName());
       if (dir == null) throw new IOException("Unsafe path rejected");
       if (!dir.exists() && !dir.mkdirs()) throw new IOException("Failed to create directory");
    }
    
    /**
     * Checks if an archive requires a password (encrypted headers or first file encrypted).
     */
    public static boolean isEncrypted(String archivePath) {
        try {
            Rar4HeaderParser parser = new Rar4HeaderParser();
            if (!parser.parse(new File(archivePath))) return false;
            if (parser.hasEncryptedHeaders()) return true;
            List<Rar4FileBlock> files = parser.getFileBlocks();
            return !files.isEmpty() && files.get(0).isEncrypted();
        } catch (Exception e) {
            return false;
        }
    }

}