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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.formats.tar.TarEntry;
import be.stef.arcana.formats.tar.TarInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Extractor for uncompressed TAR archives (.tar).
 *
 * <p>Uses the pure-Java {@link TarInputStream} engine ported from
 * Apache Commons Compress - no external dependency, no JNI.</p>
 *
 * <p>This extractor is also used internally by {@link TarGzExtractor} and
 * {@link TarBz2Extractor}, which supply a pre-decompressed stream.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class TarExtractor implements ArchiveExtractor {

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
        try (TarInputStream tis = new TarInputStream(new BufferedInputStream(new FileInputStream(archive), 65536))) {
            extractAll(tis, destination);
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (TarInputStream tis = new TarInputStream(in)) {
            extractAll(tis, destination);
        }
    }

    /**
     * Extracts all entries from an already-open {@link TarInputStream}.
     * Used by {@link TarGzExtractor} and {@link TarBz2Extractor} to chain decompressors.
     *
     * @param tis         open TAR stream
     * @param destination target directory
     * @throws IOException on I/O error
     */
    public void extractFrom(TarInputStream tis, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        extractAll(tis, destination);
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        try (TarInputStream tis = new TarInputStream(new BufferedInputStream(new FileInputStream(archive), 65536))) {
            TarEntry entry;
            while ((entry = tis.getNextTarEntry()) != null) {
                result.add(toJUnpackEntry(entry));
            }
        }
        return result;
    }

    // =========================================================================
    // list(InputStream, ArcanaFormat)
    // =========================================================================

    /**
     * Lists entries from an already-open {@link InputStream} (e.g. a decompressed stream).
     * Used by {@link TarBrotliExtractor} and similar chained decompressors.
     *
     * @param in     raw TAR byte stream (ownership is NOT taken: the caller must close it)
     * @param format the format to report in each {@link ArcanaEntry}
     * @return list of entries
     * @throws IOException on I/O error
     */
    public List<ArcanaEntry> list(InputStream in, ArcanaFormat format) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        TarInputStream tis = new TarInputStream(in);
        TarEntry entry;
        while ((entry = tis.getNextTarEntry()) != null) {
            result.add(new ArcanaEntry.Builder(entry.getName())
                    .uncompressedSize(entry.getSize())
                    .compressedSize(entry.getSize())
                    .lastModifiedTime(entry.getModTime().getTime() / 1000L)
                    .directory(entry.isDirectory())
                    .format(format)
                    .build());
        }
        return result;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private void extractAll(TarInputStream tis, File destination) throws IOException {
        TarEntry entry;
        while ((entry = tis.getNextTarEntry()) != null) {
            File target = SafePathBuilder.buildSafePath(destination, entry.getName());
            if (entry.isDirectory()) {
                IOHelper.mkdirs(target);
                continue;
            }
            IOHelper.mkdirs(target.getParentFile());
            try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                IOHelper.copy(tis, out);
            }
        }
    }

    private ArcanaEntry toJUnpackEntry(TarEntry e) {
        return new ArcanaEntry.Builder(e.getName())
                .uncompressedSize(e.getSize())
                .compressedSize(e.getSize()) // TAR is uncompressed
                .lastModifiedTime(e.getModTime().getTime() / 1000L)
                .directory(e.isDirectory())
                .format(ArcanaFormat.TAR)
                .build();
    }
}
