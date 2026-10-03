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
import be.stef.arcana.formats.arj.ArjEntry;
import be.stef.arcana.formats.arj.ArjReader;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for ARJ archives (.arj): methods 0 to 4, no encryption, no
 * multi-volume entries.
 *
 * @author Stef
 * @since 1.0.4
 */
public class ArjExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(archive), 65536)) {
            extract(in, destination);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final ArjReader arj = new ArjReader(in instanceof BufferedInputStream ? in : new BufferedInputStream(in, 65536));
        final List<Object[]> dirTimes = new ArrayList<Object[]>();
        ArjEntry e;
        while ((e = arj.nextEntry()) != null) {
            final File target = SafePathBuilder.buildSafePath(destination, e.name);
            if (e.directory) {
                IOHelper.mkdirs(target);
                if (e.lastModified > 0) dirTimes.add(new Object[]{target, e.lastModified});
                continue;
            }
            IOHelper.mkdirs(target.getParentFile());
            try (InputStream data = arj.openData(); OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                IOHelper.copy(data, out);
            }
            if (e.lastModified > 0) target.setLastModified(e.lastModified);
        }
        for (final Object[] d : dirTimes) ((File) d[0]).setLastModified((Long) d[1]);
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (ArjReader arj = new ArjReader(new BufferedInputStream(new FileInputStream(archive), 65536))) {
            ArjEntry e;
            while ((e = arj.nextEntry()) != null) {
                result.add(new ArcanaEntry.Builder(e.name).uncompressedSize(e.directory ? 0 : e.size).compressedSize(e.packedSize).lastModifiedTime(e.lastModified / 1000L).directory(e.directory).encrypted(e.isEncrypted()).format(ArcanaFormat.ARJ).build());
            }
        }
        return result;
    }
}
