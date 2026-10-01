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

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.formats.tar.TarEntry;
import be.stef.arcana.formats.tar.TarInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for TAR archives compressed with XZ (.tar.xz, .txz).
 *
 * <p>Chains {@link XzExtractor} for the outer XZ frame with
 * {@link TarExtractor} for the inner TAR archive. Both components are
 * pure-Java with no external dependency.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class TarXzExtractor implements ArchiveExtractor {

    private final XzExtractor  xz  = new XzExtractor();
    private final TarExtractor tar = new TarExtractor();

    @Override
    public boolean supportsStream() {
        return true;
    }

    // =========================================================================
    // extract(File, File)
    // =========================================================================

    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream decompressed = ReadAheadInputStream.wrap(xz.openDecompressedStream(archive)); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            tar.extractFrom(tis, destination);
            IOHelper.drain(decompressed); // read to the real end: verifies the trailing checksum of the compressor
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream decompressed = ReadAheadInputStream.wrap(xz.openDecompressedStream(in)); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            tar.extractFrom(tis, destination);
            IOHelper.drain(decompressed); // read to the real end: verifies the trailing checksum of the compressor
        }
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        try (InputStream decompressed = ReadAheadInputStream.wrap(xz.openDecompressedStream(archive)); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            TarEntry entry;
            while ((entry = tis.getNextTarEntry()) != null) {
                result.add(new ArcanaEntry.Builder(entry.getName())
                        .uncompressedSize(entry.getSize())
                        .lastModifiedTime(entry.getModTime().getTime() / 1000L)
                        .directory(entry.isDirectory())
                        .format(ArcanaFormat.TAR_XZ)
                        .build());
            }
        }
        return result;
    }
}
