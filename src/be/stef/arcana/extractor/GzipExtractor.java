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
import be.stef.arcana.util.ProgressOutputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipException;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Extractor for GZIP-compressed single files (.gz).
 *
 * <p>Delegates to {@code java.util.zip.GZIPInputStream} - no external
 * dependency.  GZIP wraps a single file; it is not an archive format.
 * The output file name is derived by stripping the {@code .gz} or
 * {@code .gzip} suffix from the archive file name.  If the archive name has
 * no such suffix, the output file is named {@code "output"}.</p>
 *
 * <p>This extractor is also used internally by {@link TarGzExtractor} to
 * provide the decompressed stream before TAR parsing.</p>
 *
 * <h3>Streaming</h3>
 * <p>GZIP supports sequential reading so {@link #extract(InputStream, File)}
 * is fully supported.  When called with a stream, the output file is always
 * named {@code "output"} inside the destination directory because the original
 * file name is not available.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class GzipExtractor implements ArchiveExtractor {

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

        try (GZIPInputStream gzis = new GZIPInputStream(new BufferedInputStream(new FileInputStream(archive), 65536));
             // GZIP stores no uncompressed size: pass -1, ProgressOutputStream shows byte count only
             ProgressOutputStream out = new ProgressOutputStream(
                     new BufferedOutputStream(ExtractionGuard.open(target), 65536), -1L, outputName)) {
            ReadAheadInputStream.copy(gzis, out);
            out.finish();
        } catch (ZipException e) {
            throw new ArcanaCorruptedException("Corrupted GZIP archive: " + archive.getName(), e);
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = SafePathBuilder.buildSafePath(destination, "output");

        try (GZIPInputStream gzis = new GZIPInputStream(in);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(gzis, out);
        } catch (ZipException e) {
            throw new ArcanaCorruptedException("Corrupted GZIP stream", e);
        }
    }

    /**
     * Opens the GZIP archive and returns the decompressed stream.
     *
     * <p>Used internally by {@link TarGzExtractor} to chain GZIP decompression
     * with TAR parsing.  The caller is responsible for closing the returned
     * stream.</p>
     *
     * @param archive GZIP file to open
     * @return decompressed input stream
     * @throws IOException on open or format error
     */
    public InputStream openDecompressedStream(File archive) throws IOException {
        try {
            return new GZIPInputStream(new BufferedInputStream(new FileInputStream(archive), 65536));
        } catch (ZipException e) {
            throw new ArcanaCorruptedException("Corrupted GZIP archive: " + archive.getName(), e);
        }
    }

    /**
     * Wraps an existing stream with GZIP decompression.
     *
     * <p>Used internally by {@link TarGzExtractor}.  The caller is responsible
     * for closing the returned stream.</p>
     *
     * @param in stream positioned at the start of a GZIP frame
     * @return decompressed input stream
     * @throws IOException on format error
     */
    public InputStream openDecompressedStream(InputStream in) throws IOException {
        try {
            return new GZIPInputStream(in);
        } catch (ZipException e) {
            throw new ArcanaCorruptedException("Corrupted GZIP stream", e);
        }
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    /**
     * Returns a single synthetic entry representing the decompressed content.
     *
     * <p>GZIP is not a container format; it always holds exactly one file.
     * The entry's compressed size is the archive file size, and the
     * uncompressed size is unknown without decompressing ({@code -1}).</p>
     */
    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.GZIP)
                .build());
        return result;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Derives the output file name from the archive name by stripping the
     * {@code .gz} or {@code .gzip} suffix.
     *
     * @param archiveName archive file name
     * @return output file name
     */
    static String deriveOutputName(String archiveName) {
        String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.gz"))  return archiveName.substring(0, archiveName.length() - 7) + ".tar";
        if (lower.endsWith(".tgz"))     return archiveName.substring(0, archiveName.length() - 4) + ".tar";
        if (lower.endsWith(".gz"))      return archiveName.substring(0, archiveName.length() - 3);
        if (lower.endsWith(".gzip"))    return archiveName.substring(0, archiveName.length() - 5);
        return "output";
    }
}
