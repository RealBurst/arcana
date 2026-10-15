/*
 * Copyright 2026 Stephane Bury
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

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaException;
import be.stef.arcana.formats.lzip.LzipInputStream;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * Extractor for lzip-compressed single files (.lz). A TAR inside (.tar.lz,
 * .tlz) is unpacked by {@link CompressedStreamExtractor}.
 *
 * @author Stef
 * @since 1.4
 */
public class LzipExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        return Collections.singletonList(new ArcanaEntry.Builder(deriveOutputName(archive.getName())).compressedSize(archive.length()).uncompressedSize(-1L).lastModifiedTime(archive.lastModified() / 1000L).directory(false).format(ArcanaFormat.LZIP).build());
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final File target = notOnArchive(SafePathBuilder.buildSafePath(destination, deriveOutputName(archive.getName())), archive);
        decompress(new FileInputStream(archive), target, archive.getName());
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        decompress(in, SafePathBuilder.buildSafePath(destination, "output"), "stream");
    }

    private static void decompress(final InputStream raw, final File target, final String what) throws IOException {
        try (InputStream lz = new LzipInputStream(raw); BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(lz, out);
        } catch (final ArcanaException e) {
            raw.close();
            throw e; // already explicit (corruption, extraction limit)
        } catch (final IOException e) {
            raw.close();
            throw new ArcanaCorruptedException("Corrupted lzip file: " + what, e);
        }
    }

    /** Output name: .tar.lz and .tlz give .tar, .lz is removed, any other name gets ".out" so that the output never replaces the archive. */
    static String deriveOutputName(final String archiveName) {
        final String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.lz") && lower.length() > 7) return archiveName.substring(0, archiveName.length() - 3);
        if (lower.endsWith(".tlz") && lower.length() > 4) return archiveName.substring(0, archiveName.length() - 4) + ".tar";
        if (lower.endsWith(".lz") && lower.length() > 3) return archiveName.substring(0, archiveName.length() - 3);
        return archiveName + ".out";
    }

    /** Adds ".out" when the output file would be the archive itself (extraction into the archive's folder). */
    static File notOnArchive(final File target, final File archive) throws IOException {
        return target.getCanonicalFile().equals(archive.getCanonicalFile()) ? new File(target.getPath() + ".out") : target;
    }
}
