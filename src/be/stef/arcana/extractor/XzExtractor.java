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
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.formats.xz.ParallelXZInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for XZ-compressed single files (.xz).
 *
 * <p>Uses the pure-Java {@link XZInputStream} engine (XZ for Java, 0BSD)
 * already ported into the sevenz.lzma package for 7z LZMA2 support.
 * No external dependency, no JNI.</p>
 *
 * <p>Like GZIP and BZIP2, XZ wraps a single file; it is not a container
 * format. The output file name is derived by stripping the {@code .xz}
 * suffix. This extractor is also used internally by {@link TarXzExtractor}
 * to chain XZ decompression with TAR parsing.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class XzExtractor implements ArchiveExtractor {

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

        try (InputStream xzis = ParallelXZInputStream.open(archive); // multi-block files: decoded by several threads
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(xzis, out);
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted XZ archive: " + archive.getName(), e);
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = SafePathBuilder.buildSafePath(destination, "output");

        try (XZInputStream xzis = new XZInputStream(in);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(xzis, out);
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted XZ stream", e);
        }
    }

    /**
     * Opens an XZ file and returns the decompressed stream. A file made of several
     * blocks (xz -T, Arcana) is decoded by several threads.
     * Used internally by {@link TarXzExtractor}. The caller closes it.
     *
     * @param archive XZ file
     * @return decompressed input stream
     * @throws IOException on format error
     */
    public InputStream openDecompressedStream(File archive) throws IOException {
        try {
            return ParallelXZInputStream.open(archive);
        } catch (ArcanaLimitExceededException e) {
            throw e;
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted XZ archive: " + archive.getName(), e);
        }
    }

    /**
     * Opens an existing stream as XZ and returns the decompressed stream.
     * Used internally by {@link TarXzExtractor}. The caller closes it.
     *
     * @param in stream positioned at the start of an XZ frame
     * @return decompressed input stream
     * @throws IOException on format error
     */
    public InputStream openDecompressedStream(InputStream in) throws IOException {
        try {
            return new XZInputStream(in);
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted XZ stream", e);
        }
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.XZ)
                .build());
        return result;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Derives the output file name from the archive name by stripping the
     * {@code .xz} suffix (or turning .txz / .tar.xz into .tar).
     */
    static String deriveOutputName(String archiveName) {
        String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.xz")) return archiveName.substring(0, archiveName.length() - 7) + ".tar";
        if (lower.endsWith(".txz"))    return archiveName.substring(0, archiveName.length() - 4) + ".tar";
        if (lower.endsWith(".xz"))     return archiveName.substring(0, archiveName.length() - 3);
        return "output";
    }
}
