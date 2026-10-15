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
import be.stef.arcana.formats.lzo.LzopInputStream;
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
 * Extractor for lzop-compressed single files (.lzo). The output file takes
 * the name stored in the lzop header (last path component only), else the
 * archive name without .lzo. A TAR inside (.tar.lzo, .tzo) is unpacked by
 * {@link CompressedStreamExtractor}.
 *
 * @author Stef
 * @since 1.4
 */
public class LzopExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final FileInputStream raw = new FileInputStream(archive);
        try (LzopInputStream lz = open(raw, archive.getName())) {
            return Collections.singletonList(new ArcanaEntry.Builder(outputName(lz.getName(), archive.getName())).compressedSize(archive.length()).uncompressedSize(-1L).lastModifiedTime(lz.getModificationTime()).directory(false).format(ArcanaFormat.LZOP).build());
        }
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final FileInputStream raw = new FileInputStream(archive);
        final LzopInputStream lz = open(raw, archive.getName());
        final File target = LzipExtractor.notOnArchive(SafePathBuilder.buildSafePath(destination, outputName(lz.getName(), archive.getName())), archive);
        decompress(lz, raw, target, archive.getName());
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final LzopInputStream lz = open(in, "stream");
        decompress(lz, in, SafePathBuilder.buildSafePath(destination, outputName(lz.getName(), "output")), "stream");
    }

    private static LzopInputStream open(final InputStream raw, final String what) throws IOException {
        try {
            return new LzopInputStream(raw);
        } catch (final ArcanaException e) {
            raw.close();
            throw e;
        } catch (final IOException e) {
            raw.close();
            throw new ArcanaCorruptedException("Corrupted lzop file: " + what, e);
        }
    }

    private static void decompress(final LzopInputStream lz, final InputStream raw, final File target, final String what) throws IOException {
        try (InputStream in = lz; BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(in, out);
        } catch (final ArcanaException e) {
            raw.close();
            throw e; // already explicit (corruption, extraction limit)
        } catch (final IOException e) {
            raw.close();
            throw new ArcanaCorruptedException("Corrupted lzop file: " + what, e);
        }
    }

    /**
     * Output name: the stored name without its folders when it is usable, else
     * the archive name (.tar.lzo and .tzo give .tar, .lzo is removed, any
     * other name gets ".out" so that the output never replaces the archive).
     */
    static String outputName(final String stored, final String archiveName) {
        if (stored != null) {
            final String s = stored.replace('\\', '/');
            final String base = s.substring(s.lastIndexOf('/') + 1).trim();
            if (!base.isEmpty() && !base.equals(".") && !base.equals("..")) return base;
        }
        final String lower = archiveName.toLowerCase();
        if (lower.endsWith(".tar.lzo") && lower.length() > 8) return archiveName.substring(0, archiveName.length() - 4);
        if (lower.endsWith(".tzo") && lower.length() > 4) return archiveName.substring(0, archiveName.length() - 4) + ".tar";
        if (lower.endsWith(".lzo") && lower.length() > 4) return archiveName.substring(0, archiveName.length() - 4);
        return "output".equals(archiveName) ? archiveName : archiveName + ".out";
    }
}
