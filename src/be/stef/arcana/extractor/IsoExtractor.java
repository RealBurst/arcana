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
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.iso.IsoReader;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for ISO 9660 disc images (.iso), with Joliet and Rock Ridge
 * extension support.
 *
 * <p>Uses the pure-Java {@link IsoReader} engine. An ISO is a random-access
 * file system, so {@link #extract(InputStream, File)} is not supported
 * (a {@link ArcanaUnsupportedFormatException} is thrown) - use the
 * file-based methods instead.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class IsoExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    // =========================================================================
    // extract(File, File)
    // =========================================================================

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (IsoReader reader = new IsoReader(archive)) {
            reader.walk(new IsoReader.IsoVisitor() {
                public void visit(String path, boolean isDir, long extentLba, long dataLength, long epochSeconds) throws IOException {
                    File target = SafePathBuilder.buildSafePath(destination, path);
                    if (isDir) {
                        IOHelper.mkdirs(target);
                    } else {
                        IOHelper.mkdirs(target.getParentFile());
                        try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                            reader.copyFileData(extentLba, dataLength, out);
                        }
                    }
                }
            });
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("ISO 9660 requires random file access - use extract(File,File).");
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (IsoReader reader = new IsoReader(archive)) {
            reader.walk(new IsoReader.IsoVisitor() {
                public void visit(String path, boolean isDir, long extentLba, long dataLength, long epochSeconds) throws IOException {
                    result.add(new ArcanaEntry.Builder(path)
                            .uncompressedSize(isDir ? 0L : dataLength)
                            .compressedSize(isDir ? 0L : dataLength) // ISO is uncompressed
                            .lastModifiedTime(epochSeconds)
                            .directory(isDir)
                            .format(ArcanaFormat.ISO)
                            .build());
                }
            });
        }
        return result;
    }
}
