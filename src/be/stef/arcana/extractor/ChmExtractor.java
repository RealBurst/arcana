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
import be.stef.arcana.formats.chm.ChmReader;
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
 * Extractor for Microsoft Compiled HTML Help files (.chm): the pages, images
 * and internal "#" / "$" files of the help, like 7-Zip.
 *
 * @author Stef
 * @since 1.0.4
 */
public class ChmExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (ChmReader reader = new ChmReader(archive)) {
            for (final ChmReader.Entry e : reader.getEntries()) {
                final File target = SafePathBuilder.buildSafePath(destination, e.path);
                if (e.directory) {
                    IOHelper.mkdirs(target);
                    continue;
                }
                IOHelper.mkdirs(target.getParentFile());
                try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    reader.copy(e, out);
                }
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("CHM requires random file access - use extract(File,File).");
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (ChmReader reader = new ChmReader(archive)) {
            for (final ChmReader.Entry e : reader.getEntries()) {
                result.add(new ArcanaEntry.Builder(e.path).uncompressedSize(e.directory ? 0 : e.length).directory(e.directory).format(ArcanaFormat.CHM).build());
            }
        }
        return result;
    }
}
