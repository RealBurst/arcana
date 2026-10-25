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
package be.stef.arcana.compressor;

import be.stef.arcana.formats.zstd.ZstdOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Compressor for single Zstandard files (.zst): levels 1 and 2 (see
 * {@link ZstdOutputStream}). For directories, use {@link TarZstdCompressor}.
 *
 * @author Stef
 * @since 1.2.0
 */
public class ZstdCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final int level;

    /** Level {@link ZstdOutputStream#DEFAULT_LEVEL}. */
    public ZstdCompressor() {
        this(ZstdOutputStream.DEFAULT_LEVEL);
    }

    /** @param level 1 or 2 (lower values give 1, higher values 2) */
    public ZstdCompressor(final int level) {
        this.level = level;
    }

    @Override
    public boolean supportsDirectories() {
        return false;
    }

    @Override
    public void compress(final File source, final File target) throws IOException {
        try (OutputStream fos = new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE)) {
            compress(source, fos);
            fos.flush();
        }
    }

    /** Writes the frame (with the content size) to {@code out}, which stays open. */
    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        if (source.isDirectory()) throw new IOException("Zstandard compresses a single file. Use TarZstdCompressor for directories.");
        final ZstdOutputStream zst = new ZstdOutputStream(out, level, source.length());
        try (InputStream in = new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE)) {
            final byte[] buf = new byte[BUFFER_SIZE];
            int n;
            while ((n = in.read(buf)) >= 0) zst.write(buf, 0, n);
        }
        zst.finish();
    }
}
