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
import be.stef.arcana.formats.lz4.LZ4OutputStream;
import be.stef.arcana.formats.tar.TarOutputStream;

/**
 * Compressor for TAR archives compressed with LZ4 (.tar.lz4, .tlz4).
 *
 * <p>Chains {@link TarCompressor} for the inner TAR stream with
 * {@link LZ4OutputStream} for the outer LZ4 frame.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class TarLz4Compressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final TarCompressor tar = new TarCompressor();

    @Override
    public boolean supportsDirectories() {
        return true;
    }

    @Override
    public void compress(final File source, final File target) throws IOException {
        try (OutputStream fos = new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE)) {
            compress(source, fos);
            fos.flush();
        }
    }

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final LZ4OutputStream lz4 = new LZ4OutputStream(out);
        final TarOutputStream tos = new TarOutputStream(lz4);
        tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish(); // write TAR end-of-archive into the LZ4 frame
        lz4.finish(); // write end mark and content checksum; do NOT close the underlying stream
    }
}
