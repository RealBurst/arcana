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
import be.stef.arcana.formats.lz4.LZ4InputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for LZ4-compressed single files (.lz4).
 *
 * <p>Uses the pure-Java {@link LZ4InputStream} engine (LZ4 Frame format).
 * No external dependency, no JNI. LZ4 is a single-file compressor; it is
 * not an archive format. For directory archives, use TAR+LZ4 (not yet
 * implemented).</p>
 *
 * @author Stef
 * @since 1.1
 */
public class LZ4Extractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final String outputName = deriveOutputName(archive.getName());
        final File target = SafePathBuilder.buildSafePath(destination, outputName);
        try (LZ4InputStream lzis = new LZ4InputStream(new BufferedInputStream(new FileInputStream(archive), 65536)); BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(lzis, out);
        } catch (IOException e) {
            if (e.getMessage() != null && e.getMessage().startsWith("Not an LZ4")) throw new ArcanaCorruptedException("Corrupted LZ4 archive: " + archive.getName(), e);
            throw e;
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final File target = SafePathBuilder.buildSafePath(destination, "output");
        try (LZ4InputStream lzis = new LZ4InputStream(in); BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(lzis, out);
        }
    }

    /**
     * Opens the archive as an LZ4 decompressed stream.
     * Used internally by future TarLz4Extractor.
     */
    public InputStream openDecompressedStream(final InputStream in) throws IOException {
        return new LZ4InputStream(in);
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.LZ4)
                .build());
        return result;
    }

    static String deriveOutputName(final String archiveName) {
        final String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.lz4")) return archiveName.substring(0, archiveName.length() - 8) + ".tar";
        if (lower.endsWith(".tlz4"))    return archiveName.substring(0, archiveName.length() - 5) + ".tar";
        if (lower.endsWith(".lz4"))     return archiveName.substring(0, archiveName.length() - 4);
        return "output";
    }
}
