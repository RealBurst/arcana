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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for TAR archives compressed with LZ4 (.tar.lz4, .tlz4).
 *
 * <p>Chains {@link LZ4Extractor} for the outer LZ4 Frame decompression
 * with {@link TarExtractor} for the inner TAR archive. Both components
 * are pure-Java with no external dependency.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class TarLz4Extractor implements ArchiveExtractor {

    private final LZ4Extractor lz4 = new LZ4Extractor();
    private final TarExtractor tar = new TarExtractor();

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream decompressed = ReadAheadInputStream.wrap(lz4.openDecompressedStream(new BufferedInputStream(new FileInputStream(archive), 65536))); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            tar.extractFrom(tis, destination);
            IOHelper.drain(decompressed); // read to the real end: verifies the trailing checksum of the compressor
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (InputStream decompressed = ReadAheadInputStream.wrap(lz4.openDecompressedStream(in)); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            tar.extractFrom(tis, destination);
            IOHelper.drain(decompressed); // read to the real end: verifies the trailing checksum of the compressor
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (InputStream decompressed = ReadAheadInputStream.wrap(lz4.openDecompressedStream(new BufferedInputStream(new FileInputStream(archive), 65536))); // decompression runs ahead in its own thread
             TarInputStream tis = new TarInputStream(decompressed)) {
            TarEntry entry;
            while ((entry = tis.getNextTarEntry()) != null) {
                result.add(new ArcanaEntry.Builder(entry.getName())
                        .uncompressedSize(entry.getSize())
                        .lastModifiedTime(entry.getModTime().getTime() / 1000L)
                        .directory(entry.isDirectory())
                        .format(ArcanaFormat.TAR_LZ4)
                        .build());
            }
        }
        return result;
    }
}
