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
package be.stef.arcana.extractor;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.rar.ExtractionError;
import be.stef.arcana.formats.rar.ExtractionResult;
import be.stef.arcana.formats.rar.Unrar5j;

/**
 * Extractor for RAR archives (version 4 and 5) using the embedded unrar5j engine.
 *
 * <p>Delegates all extraction operations to {@link Unrar5j}, which provides
 * pure-Java, JNI-free support for RAR4 and RAR5 archives including:</p>
 * <ul>
 *   <li>Solid archives</li>
 *   <li>Multi-volume archives (.part1.rar, .part2.rar, ...)</li>
 *   <li>AES-256 encrypted archives (password required)</li>
 *   <li>Blake2sp and CRC32 integrity verification</li>
 * </ul>
 *
 * <h3>Streaming</h3>
 * <p>RAR extraction requires random access (the format uses a seekable file).
 * {@link #extract(InputStream, File)} is therefore not supported; callers
 * must provide a {@link File}.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class RarExtractor implements ArchiveExtractor {

    /** Optional password for encrypted archives. {@code null} means no password. */
    private final String password;

    /** Creates an extractor for non-encrypted RAR archives. */
    public RarExtractor() {
        this(null);
    }

    /**
     * Creates an extractor that supplies {@code password} when decrypting entries.
     *
     * @param password decryption password, or {@code null} for unencrypted archives
     */
    public RarExtractor(String password) {
        this.password = password;
    }

    @Override
    public boolean supportsStream() {
        return false;
    }

    // =========================================================================
    // extract(File, File)
    // =========================================================================

    @Override
    public void extract(File archive, File destination) throws IOException {
        String archivePath = archive.getAbsolutePath();
        String destPath    = destination.getAbsolutePath();

        // Check encryption before extracting so we can throw a meaningful exception
        if (password == null && Unrar5j.isEncrypted(archivePath)) {
            throw new ArcanaEncryptedException("RAR archive is encrypted and no password was provided: " + archive.getName());
        }

        ExtractionResult result = Unrar5j.extract(archivePath, destPath, password);

        if (!result.isSuccess()) {
            // Check if any error is due to encryption
            for (ExtractionError error : result.errors) {
                if (error.isEncryptedBlock) {
                    throw new ArcanaEncryptedException("Encrypted RAR entry could not be decrypted: " + error.fileName);
                }
            }
            // An extraction limit (decompression bomb, disk full) keeps its own exception type
            for (ExtractionError error : result.errors) {
                if (error.exception instanceof ArcanaLimitExceededException) throw (ArcanaLimitExceededException) error.exception;
            }
            // Build a summary message from all errors
            StringBuilder sb = new StringBuilder("RAR extraction failed for: ").append(archive.getName());
            for (ExtractionError error : result.errors) {
                sb.append("\n  ").append(error.fileName).append(": ").append(error.errorMessage);
                if (error.exception != null && error.exception.getMessage() != null && !error.errorMessage.contains(error.exception.getMessage())) sb.append(" - ").append(error.exception.getMessage());
            }
            throw new ArcanaCorruptedException(sb.toString());
        }
    }

    // =========================================================================
    // extract(InputStream, File) - not supported
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("RAR extraction from an InputStream is not supported \u2014 RAR requires random file access. Use extract(File, File) instead.");
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    /**
     * Returns the list of entries in the RAR archive.
     *
     * <p>The current unrar5j engine does not expose a dedicated listing API
     * without extracting; this method extracts to a temporary directory and
     * maps the results back to {@link ArcanaEntry} objects.  For large archives,
     * prefer {@link #extract(File, File)} directly.</p>
     *
     * <p>TODO: implement listing without extraction once unrar5j exposes a
     * listing-only API.</p>
     */
    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        // Unrar5j.listFiles() reads only archive headers -- no extraction, no disk I/O.
        return Unrar5j.listFiles(archive.getAbsolutePath(), password);
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private List<ArcanaEntry> buildListFromDir(File base, File dir) {
        List<ArcanaEntry> result = new ArrayList<>();
        File[] files = dir.listFiles();
        if (files == null) return result;
        for (File f : files) {
            String rel = f.getAbsolutePath().substring(base.getAbsolutePath().length() + 1).replace('\\', '/');
            result.add(new ArcanaEntry.Builder(rel)
                    .uncompressedSize(f.isDirectory() ? -1L : f.length())
                    .lastModifiedTime(f.lastModified() / 1000L)
                    .directory(f.isDirectory())
                    .format(ArcanaFormat.RAR)
                    .build());
            if (f.isDirectory()) {
                result.addAll(buildListFromDir(base, f));
            }
        }
        return result;
    }

    private static void deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) for (File c : children) deleteRecursive(c);
        }
        f.delete();
    }
}
