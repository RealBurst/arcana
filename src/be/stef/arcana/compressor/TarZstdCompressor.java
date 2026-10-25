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

import be.stef.arcana.formats.tar.TarOutputStream;
import be.stef.arcana.formats.zstd.ZstdOutputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Compressor for TAR + Zstandard archives (.tar.zst): files and directories,
 * levels 1 to 12 (see {@link ZstdOutputStream}).
 *
 * @author Stef
 * @since 1.2.0
 */
public class TarZstdCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final TarCompressor tar = new TarCompressor();
    private final int level;

    /** Level {@link ZstdOutputStream#DEFAULT_LEVEL}. */
    public TarZstdCompressor() {
        this(ZstdOutputStream.DEFAULT_LEVEL);
    }

    /** @param level 1 to 12 (values out of range are brought into it) */
    public TarZstdCompressor(final int level) {
        this.level = level;
    }

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

    /** Writes the archive to {@code out}, which stays open. */
    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final ZstdOutputStream zst = new ZstdOutputStream(out, level);
        final TarOutputStream tos = new TarOutputStream(zst);
        tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish(); // TAR end-of-archive inside the Zstandard frame
        zst.finish(); // last block and checksum; the underlying stream stays open
    }
}
