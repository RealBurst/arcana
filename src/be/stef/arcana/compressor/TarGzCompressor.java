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
package be.stef.arcana.compressor;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import be.stef.arcana.formats.gzip.ParallelGzipOutputStream;
import be.stef.arcana.formats.tar.TarOutputStream;

/**
 * Compressor for TAR archives compressed with GZIP (.tar.gz, .tgz).
 *
 * <p>Chains {@link TarCompressor} for the inner TAR stream with
 * {@link ParallelGzipOutputStream} (multithreaded) for the outer GZIP frame. Both components are
 * pure-Java with no external dependency.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class TarGzCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final TarCompressor tar = new TarCompressor();

    @Override
    public boolean supportsDirectories() {
        return true;
    }

    // =========================================================================
    // compress(File, File)
    // =========================================================================

    @Override
    public void compress(File source, File target) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        try (OutputStream gzos = ParallelGzipOutputStream.create(new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE))) { // multithreaded when possible
            TarOutputStream tos = new TarOutputStream(gzos);
            tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
            tos.finish(); // write TAR end-of-archive into the GZIP stream
            ParallelGzipOutputStream.finish(gzos); // flush and finish the GZIP frame (stream is closed by try-with-resources)
        }
    }

    // =========================================================================
    // compress(File, OutputStream)
    // =========================================================================

    @Override
    public void compress(File source, OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final OutputStream gzos = ParallelGzipOutputStream.create(out); // multithreaded when possible
        TarOutputStream tos = new TarOutputStream(gzos);
        tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish();
        ParallelGzipOutputStream.finish(gzos); // do NOT close the underlying stream
    }
}