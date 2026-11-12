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
import be.stef.arcana.formats.adf.AdfVolume;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for Amiga floppy disk images (.adf) with an AmigaDOS file system
 * (OFS or FFS, double or high density). The image is read in memory (1.7 MiB
 * at most). Links are not extracted, and a file whose blocks are not valid
 * (damaged disk, or copy protection: a "file" pointing at specially formatted
 * sectors) is skipped; their names are printed, the other files extracted.
 *
 * @author Stef
 * @since 1.2.0
 */
public class AdfExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        extract(new AdfVolume(Files.readAllBytes(archive.toPath())), destination);
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final ByteArrayOutputStream all = new ByteArrayOutputStream(AdfVolume.HD_BLOCKS * AdfVolume.BLOCK);
        final byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) {
            all.write(buf, 0, n);
            if (all.size() > AdfVolume.HD_BLOCKS * AdfVolume.BLOCK) throw new IOException("Not an Amiga floppy image (too large)");
        }
        extract(new AdfVolume(all.toByteArray()), destination);
    }

    private static void extract(final AdfVolume v, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final List<Object[]> dirTimes = new ArrayList<Object[]>();
        final List<String> skipped = new ArrayList<String>(v.skipped());
        for (final AdfVolume.Entry e : v.entries()) {
            final File target = SafePathBuilder.buildSafePath(destination, e.path);
            if (e.directory) {
                IOHelper.mkdirs(target);
                if (e.time > 0) dirTimes.add(new Object[] {target, e.time * 1000L});
                continue;
            }
            IOHelper.mkdirs(target.getParentFile());
            try {
                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    v.copy(e, out);
                }
            } catch (final ArcanaCorruptedException ex) {
                // one bad file (often a copy protection trick: a "file" pointing at specially formatted sectors) does not stop the others
                if (!target.delete()) target.deleteOnExit();
                skipped.add(e.path + ": " + ex.getMessage());
                continue;
            }
            if (e.time > 0) target.setLastModified(e.time * 1000L);
        }
        for (final Object[] d : dirTimes) ((File) d[0]).setLastModified((Long) d[1]);
        for (final String s : skipped) System.out.println("  skipped: " + s);
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final AdfVolume v = new AdfVolume(Files.readAllBytes(archive.toPath()));
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        for (final AdfVolume.Entry e : v.entries()) result.add(new ArcanaEntry.Builder(e.path).uncompressedSize(e.size).compressedSize(e.size).lastModifiedTime(e.time).directory(e.directory).comment(e.comment).method(e.directory ? null : v.getFileSystem()).format(ArcanaFormat.ADF).build());
        return result;
    }
}
