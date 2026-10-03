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
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.squashfs.SquashfsReader;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for SquashFS 4.0 images (.sqfs, .squashfs, .snap, AppImage payloads).
 *
 * <p>Symbolic links are extracted as empty files, like the CPIO and TAR
 * extractors (no link is created on disk); devices, FIFOs and sockets are
 * listed but not extracted. SquashFS needs random access, so
 * {@link #extract(InputStream, File)} is not supported.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public class SquashfsExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (SquashfsReader reader = new SquashfsReader(archive)) {
            reader.walk(new SquashfsReader.Visitor() {
                @Override
                public void visit(final SquashfsReader.Entry e) throws IOException {
                    final File target = SafePathBuilder.buildSafePath(destination, e.path);
                    if (e.kind == SquashfsReader.DIRECTORY) {
                        IOHelper.mkdirs(target);
                    } else if (e.kind == SquashfsReader.FILE || e.kind == SquashfsReader.SYMLINK) {
                        IOHelper.mkdirs(target.getParentFile());
                        try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                            reader.copyFile(e, out);
                        }
                        if (e.mtime > 0) target.setLastModified(e.mtime * 1000L);
                    }
                }
            });
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("SquashFS requires random file access - use extract(File,File).");
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (SquashfsReader reader = new SquashfsReader(archive)) {
            reader.walk(new SquashfsReader.Visitor() {
                @Override
                public void visit(final SquashfsReader.Entry e) {
                    final boolean dir = e.kind == SquashfsReader.DIRECTORY;
                    result.add(new ArcanaEntry.Builder(e.path)
                            .uncompressedSize(e.kind == SquashfsReader.FILE ? e.size : 0L)
                            .lastModifiedTime(e.mtime)
                            .directory(dir)
                            .format(ArcanaFormat.SQUASHFS)
                            .build());
                }
            });
        }
        return result;
    }
}
