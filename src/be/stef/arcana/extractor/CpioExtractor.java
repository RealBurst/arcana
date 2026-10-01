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
import be.stef.arcana.formats.cpio.CpioEntry;
import be.stef.arcana.formats.cpio.CpioInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for CPIO archives (.cpio).
 *
 * <p>Uses the pure-Java {@link CpioInputStream} engine. Supports the
 * SVR4 newc (070701), SVR4 newc+crc (070702), and old POSIX ASCII odc
 * (070707) formats. Binary CPIO is not supported.</p>
 *
 * <p>Symbolic links are extracted as empty files (the link target is not
 * restored) since creating symbolic links is not portable across all
 * operating systems.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class CpioExtractor implements ArchiveExtractor {

    private static final int BUFFER_SIZE = 65536;

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (CpioInputStream cis = new CpioInputStream(new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE))) {
            extractFrom(cis, destination);
        } catch (IOException e) {
            if (e.getMessage() != null && e.getMessage().contains("CPIO")) throw new ArcanaCorruptedException("Corrupted CPIO archive: " + archive.getName(), e);
            throw e;
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (CpioInputStream cis = new CpioInputStream(in)) {
            extractFrom(cis, destination);
        }
    }

    private void extractFrom(final CpioInputStream cis, final File destination) throws IOException {
        CpioEntry entry;
        while ((entry = cis.getNextEntry()) != null) {
            final String name = entry.getName();
            if (name.isEmpty()) { cis.closeEntry(); continue; }
            final File target = SafePathBuilder.buildSafePath(destination, name);
            if (entry.isDirectory()) {
                IOHelper.mkdirs(target);
            } else if (entry.isRegularFile() || entry.isSymbolicLink()) {
                IOHelper.mkdirs(target.getParentFile());
                try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), BUFFER_SIZE)) {
                    IOHelper.copy(cis, out);
                }
            }
            // other types (device, fifo, ...) are silently skipped
            cis.closeEntry();
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (CpioInputStream cis = new CpioInputStream(new BufferedInputStream(new FileInputStream(archive), BUFFER_SIZE))) {
            CpioEntry entry;
            while ((entry = cis.getNextEntry()) != null) {
                result.add(new ArcanaEntry.Builder(entry.getName())
                        .compressedSize(entry.getSize())
                        .uncompressedSize(entry.getSize())
                        .lastModifiedTime(entry.getModificationTime())
                        .directory(entry.isDirectory())
                        .format(ArcanaFormat.CPIO)
                        .build());
                cis.closeEntry();
            }
        }
        return result;
    }
}
