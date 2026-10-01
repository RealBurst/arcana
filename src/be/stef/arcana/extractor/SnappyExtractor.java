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
import be.stef.arcana.formats.snappy.SnappyInputStream;
//import be.stef.arcana.formats.snappy.SnappyInputStream;
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
 * Extractor for Snappy-compressed single files (.snappy).
 *
 * <p>Uses the pure-Java {@link SnappyInputStream} engine. Supports both the
 * standard Snappy framing format (stream magic {@code FF 06 00 00 sNaPpY})
 * and raw Snappy blocks. No external dependency, no JNI.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class SnappyExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final String outputName = deriveOutputName(archive.getName());
        final File target = SafePathBuilder.buildSafePath(destination, outputName);
        try (SnappyInputStream sis = new SnappyInputStream(new BufferedInputStream(new FileInputStream(archive), 65536)); BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(sis, out);
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted Snappy archive: " + archive.getName(), e);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final File target = SafePathBuilder.buildSafePath(destination, "output");
        try (SnappyInputStream sis = new SnappyInputStream(in); BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(sis, out);
        }
    }

    public InputStream openDecompressedStream(final InputStream in) throws IOException {
        return new SnappyInputStream(in);
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.SNAPPY)
                .build());
        return result;
    }

    static String deriveOutputName(final String archiveName) {
        final String lower = archiveName.toLowerCase();
        if (lower.endsWith(".snappy")) return archiveName.substring(0, archiveName.length() - 7);
        return "output";
    }
}
