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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import be.stef.arcana.util.ProgressInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPOutputStream;
import be.stef.arcana.formats.gzip.ParallelGzipOutputStream;

/**
 * Compressor for GZIP-compressed single files (.gz).
 *
 * <p>Delegates to {@code java.util.zip.GZIPOutputStream} - no external
 * dependency. GZIP wraps a single file; it is not a container format.
 * For directory compression, use {@link TarGzCompressor} instead.</p>
 *
 * <p>If {@code source} is a directory, an {@link IOException} is thrown.
 * Use {@link #supportsDirectories()} to check before calling.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class GzipCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    @Override
    public boolean supportsDirectories() {
        return false;
    }

    // =========================================================================
    // compress(File, File)
    // =========================================================================

    @Override
    public void compress(File source, File target) throws IOException {
        if (source.isDirectory()) {
            throw new IOException("GZIP does not support directories. Use TarGzCompressor for directories.");
        }
        try (ProgressInputStream in = new ProgressInputStream(
                     new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE),
                     source.length(), source.getName());
             OutputStream gzos = ParallelGzipOutputStream.create(new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE))) { // multithreaded when possible
            pipe(in, gzos);
            in.finish();
        }
    }

    // =========================================================================
    // compress(File, OutputStream)
    // =========================================================================

    /**
     * Wraps {@code out} with a {@link GZIPOutputStream} and writes the
     * compressed content of {@code source} into it.
     *
     * <p>Used internally by {@link TarGzCompressor} to chain TAR + GZIP.
     * The {@link GZIPOutputStream#finish()} is called but the underlying
     * stream is not closed.</p>
     */
    @Override
    public void compress(File source, OutputStream out) throws IOException {
        if (source.isDirectory()) {
            throw new IOException("GZIP does not support directories. Use TarGzCompressor for directories.");
        }
        final OutputStream gzos = ParallelGzipOutputStream.create(out); // multithreaded when possible
        try (InputStream in = new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE)) {
            pipe(in, gzos);
        }
        ParallelGzipOutputStream.finish(gzos); // flush compressed data; do NOT close the underlying stream
    }

    /**
     * Wraps {@code out} with a {@link GZIPOutputStream} and returns it.
     * The caller is responsible for writing data and finishing the stream.
     * Used by {@link TarGzCompressor} to write a TAR stream through GZIP.
     *
     * @param out underlying output stream
     * @return a new GZIPOutputStream wrapping {@code out}
     */
    public GZIPOutputStream openCompressedStream(OutputStream out) throws IOException {
        return new GZIPOutputStream(out);
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private static void pipe(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
    }
}
