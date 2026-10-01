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

import be.stef.arcana.util.ExtractionGuard;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Extractor for BZIP2-compressed single files (.bz2).
 *
 * <p>Uses the pure-Java {@link BZip2InputStream} engine ported from
 * Apache Commons Compress - no external dependency, no JNI.</p>
 *
 * <p>Like GZIP, BZIP2 wraps a single file.  The output file name is derived
 * by stripping the {@code .bz2} or {@code .bzip2} suffix.  This extractor is
 * also used internally by {@link TarBz2Extractor} to chain BZIP2 decompression
 * with TAR parsing.</p>
 *
 * <h3>Concatenated streams</h3>
 * <p>BZIP2 supports concatenated streams (multiple compressed blocks in one
 * file).  This extractor enables concatenation support by default.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class BZip2Extractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    // =========================================================================
    // extract(File, File)
    // =========================================================================

    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        String outputName = deriveOutputName(archive.getName());
        File target = SafePathBuilder.buildSafePath(destination, outputName);

        try (BZip2InputStream bzis = openStream(new BufferedInputStream(new FileInputStream(archive), 65536));
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(bzis, out);
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = SafePathBuilder.buildSafePath(destination, "output");

        try (BZip2InputStream bzis = openStream(in);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(bzis, out);
        }
    }

    /**
     * Opens the BZIP2 stream for chaining with {@link TarBz2Extractor}.
     * The caller is responsible for closing the returned stream.
     *
     * @param in stream positioned at the start of a BZIP2 frame
     * @return decompressed input stream
     * @throws IOException on format or I/O error
     */
    public BZip2InputStream openDecompressedStream(InputStream in) throws IOException {
        return openStream(in);
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    /**
     * Returns a single synthetic entry representing the decompressed content.
     * The uncompressed size is unknown without decompressing ({@code -1}).
     */
    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.BZIP2)
                .build());
        return result;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private BZip2InputStream openStream(InputStream in) throws IOException {
        try {
            // true = support concatenated .bz2 streams
            return new BZip2InputStream(in, true);
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted BZIP2 stream: " + e.getMessage(), e);
        }
    }

    /**
     * Derives the output file name from the archive name by stripping the
     * {@code .bz2} or {@code .bzip2} suffix.
     */
    static String deriveOutputName(String archiveName) {
        String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.bz2"))  return archiveName.substring(0, archiveName.length() - 8) + ".tar";
        if (lower.endsWith(".tbz2"))     return archiveName.substring(0, archiveName.length() - 5) + ".tar";
        if (lower.endsWith(".tbz"))      return archiveName.substring(0, archiveName.length() - 4) + ".tar";
        if (lower.endsWith(".bz2"))      return archiveName.substring(0, archiveName.length() - 4);
        if (lower.endsWith(".bzip2"))    return archiveName.substring(0, archiveName.length() - 6);
        return "output";
    }
}
