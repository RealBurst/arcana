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
package be.stef.arcana.formats.rar;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.formats.rar.rar4.Rar4Extractor;
import be.stef.arcana.formats.rar.rar4.Rar4HeaderParser;
import be.stef.arcana.formats.rar.rar4.blocks.Rar4FileBlock;
import be.stef.arcana.formats.rar.rar5.Rar5Extractor;
import be.stef.arcana.formats.rar.rar5.Rar5Reader;
import be.stef.arcana.formats.rar.rar5.blocks.Rar5FileBlock;

/**
 * Unified facade for RAR archive extraction.
 * Detects archive format (RAR4/RAR5) and delegates to the appropriate extractor.
 *
 * @author Stef
 * @since 1.0
 */
public class Unrar5j {

    // RAR5 signature : 52 61 72 21 1A 07 01 00
    private static final byte[] RAR5_SIGNATURE = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    // RAR4 signature : 52 61 72 21 1A 07 00
    private static final byte[] RAR4_SIGNATURE = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };

    public static final int FORMAT_UNKNOWN = 0;
    public static final int FORMAT_RAR4    = 4;
    public static final int FORMAT_RAR5    = 5;

    /**
     * Detects the RAR format of an archive.
     *
     * @param archivePath path to the archive
     * @return FORMAT_RAR4, FORMAT_RAR5, or FORMAT_UNKNOWN
     */
    public static int detectFormat(String archivePath) {
        try (FileInputStream fis = new FileInputStream(archivePath)) {
            byte[] header = new byte[8];
            int read = fis.read(header);
            if (read < 7) return FORMAT_UNKNOWN;

            // Check RAR5 first (8 bytes, more specific)
            if (read >= 8 && matchesSignature(header, RAR5_SIGNATURE, 8)) {
                return FORMAT_RAR5;
            }
            // Check RAR4 (7 bytes)
            if (matchesSignature(header, RAR4_SIGNATURE, 7)) {
                return FORMAT_RAR4;
            }
            return FORMAT_UNKNOWN;

        } catch (IOException e) {
            return FORMAT_UNKNOWN;
        }
    }

    private static boolean matchesSignature(byte[] data, byte[] signature, int length) {
        for (int i = 0; i < length; i++) {
            if (data[i] != signature[i]) return false;
        }
        return true;
    }

    /**
     * Extracts a RAR archive (RAR4 or RAR5) to the specified directory.
     *
     * @param archivePath path to the archive
     * @param outputDir   destination directory
     * @param password    password for encrypted archives, or null
     * @return extraction result
     */
    public static ExtractionResult extract(String archivePath, String outputDir, String password) {
        return extract(archivePath, outputDir, password, null);
    }

    /**
     * Extracts a single file from a RAR archive.
     *
     * @param archivePath path to the archive
     * @param outputDir   destination directory
     * @param password    password for encrypted archives, or null
     * @param fileFilter  full path of the file to extract, or null for all
     * @return extraction result
     */
    public static ExtractionResult extract(String archivePath, String outputDir, String password, String fileFilter) {
        int format = detectFormat(archivePath);
        switch (format) {
            case FORMAT_RAR5:
                return Rar5Extractor.extract(archivePath, outputDir, password, fileFilter);
                
            case FORMAT_RAR4:
               return Rar4Extractor.extract(archivePath, outputDir, password, fileFilter);
               
            default:
                ExtractionResult unknown = new ExtractionResult();
                unknown.archiveName = archivePath;
                System.err.println("Unknown or unsupported archive format: " + archivePath);
                return unknown;
        }
    }

    /**
     * Checks if an archive requires a password.
     *
     * @param archivePath path to the archive
     * @return true if encrypted
     * @throws IOException if file cannot be read
     */
    public static boolean isEncrypted(String archivePath) throws IOException {
        int format = detectFormat(archivePath);
        switch (format) {
            case FORMAT_RAR5:
                return Rar5Extractor.isEncrypted(archivePath);
            
            case FORMAT_RAR4:
               return Rar4Extractor.isEncrypted(archivePath);
            
            default:
                return false;
        }
    }

    /**
     * Lists the entries in a RAR archive without extracting any data.
     *
     * <p>For RAR5, uses {@link Rar5Reader} which only reads archive headers
     * (no decompression). For RAR4, uses {@link Rar4HeaderParser} similarly.
     * Neither method writes anything to disk.</p>
     *
     * @param archivePath path to the RAR archive
     * @param password    password for encrypted headers, or null
     * @return list of entries; never null
     * @throws IOException if the archive cannot be read
     */
    public static List<ArcanaEntry> listFiles(String archivePath, String password) throws IOException {
        int format = detectFormat(archivePath);
        switch (format) {
            case FORMAT_RAR5:
                return listRar5(archivePath, password);
            case FORMAT_RAR4:
                return listRar4(archivePath);
            default:
                return new ArrayList<ArcanaEntry>();
        }
    }

    private static List<ArcanaEntry> listRar5(String archivePath, String password) throws IOException {
        List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        Rar5Reader reader = password != null ? new Rar5Reader(password) : new Rar5Reader();
        if (!reader.read(new File(archivePath))) return result;
        for (Rar5FileBlock f : reader.getFileBlocks()) {
            result.add(new ArcanaEntry.Builder(f.getFileName())
                    .uncompressedSize(f.isDirectory() ? -1L : f.getUnpackedSize())
                    .lastModifiedTime(f.getUnixMTime())
                    .directory(f.isDirectory())
                    .format(ArcanaFormat.RAR)
                    .build());
        }
        return result;
    }

    private static List<ArcanaEntry> listRar4(String archivePath) throws IOException {
        List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        Rar4HeaderParser parser = new Rar4HeaderParser();
        if (!parser.parse(new File(archivePath))) return result;
        for (Rar4FileBlock f : parser.getFileBlocks()) {
            result.add(new ArcanaEntry.Builder(f.getFileName())
                    .uncompressedSize(f.isDirectory() ? -1L : f.getUnpackedSize())
                    .lastModifiedTime(-1L) // RAR4 fileTime is MS-DOS format, not Unix epoch
                    .directory(f.isDirectory())
                    .format(ArcanaFormat.RAR)
                    .build());
        }
        return result;
    }

    private static void printBanner() {
        System.out.println("                         ___");
        System.out.println("  _  _ _ _  _ _ __ _ _ _| __| (_)");
        System.out.println(" | || | ' \\| '_/ _` | '_|__ \\ | |");
        System.out.println(" \\__,_|_|_||_| \\__,_|_| |___//__|  v2.0.4 - 2026.08.18");
        System.out.println("    Stephane BURY - Apache 2.0  [RAR4 / RAR5]");
        System.out.println();
    }

    /**
     * Command-line entry point. Detects the archive format (RAR4 or RAR5)
     * automatically, so the user does not have to specify it.
     *
     * @param args archive path followed by optional -o, -p and -f arguments
     */
    public static void main(String[] args) {
        be.stef.arcana.formats.rar.util.ConsoleUtils.useUtf8();
        printBanner();

        if (args.length < 1) {
            System.out.println("Usage: java -jar unrar5j <archive.rar> [-o outputDir] [-p password] [-f filename]");
            System.out.println();
            System.out.println("The archive format (RAR4 or RAR5) is detected automatically.");
            System.out.println();
            System.out.println("Options:");
            System.out.println("  -o <dir>          Extract to specified directory (default: current)");
            System.out.println("  -p <password>     Password for encrypted archives");
            System.out.println("  -f <fullfilename> Extract only this file from the archive");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  unrar5j archive.rar");
            System.out.println("  unrar5j archive.rar -o /tmp/output");
            System.out.println("  unrar5j encrypted.rar -p secret");
            System.out.println("  unrar5j archive.rar -f \"anypath/to/document with spaces.pdf\"");
            System.out.println("  unrar5j encrypted.rar -o /tmp/output -p secret -f anypath/to/myfile.txt");
            return;
        }

        String archivePath = args[0];
        String outputDir   = ".";
        String password    = null;
        String fileFilter  = null;

        // Argument parsing
        for (int i = 1; i < args.length; i++) {
            if ("-o".equals(args[i]) && i + 1 < args.length) {
                outputDir = args[++i];
            } else if ("-p".equals(args[i]) && i + 1 < args.length) {
                password = args[++i];
            } else if ("-f".equals(args[i]) && i + 1 < args.length) {
                fileFilter = args[++i].replace("\\", "/");
            }
        }

        int format = detectFormat(archivePath);
        if (format == FORMAT_UNKNOWN) {
            System.err.println("Unknown or unsupported archive format: " + archivePath);
            return;
        }
        System.out.println("Detected format: " + (format == FORMAT_RAR5 ? "RAR5" : "RAR4"));

        SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy - HH:mm:ss");
        Date start = new Date();
        System.out.println("Extracting to: " + new File(outputDir).getAbsolutePath());
        if (fileFilter != null) {
            System.out.println("Filter: extracting only \"" + fileFilter + "\"");
        }
        System.out.println("Started at " + df.format(start) + " ...");

        ExtractionResult result = extract(archivePath, outputDir, password, fileFilter);
        result.print();

        Date fin = new Date();
        System.out.println("Finished at " + df.format(fin));
        long duration = fin.getTime() - start.getTime();
        System.out.println("Duration: " + (duration / 1000) + "." + (duration % 1000) + "s");
    }
}