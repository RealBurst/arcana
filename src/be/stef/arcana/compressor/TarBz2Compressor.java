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
import be.stef.arcana.formats.bzip2.BZip2OutputStream;
import be.stef.arcana.formats.tar.TarOutputStream;

/**
 * Compressor for TAR archives compressed with BZIP2 (.tar.bz2, .tbz2).
 *
 * <p>Chains {@link TarCompressor} for the inner TAR stream with
 * {@link BZip2OutputStream} for the outer BZIP2 frame. Both components are
 * pure-Java with no external dependency.</p>
 *
 * <p>The default block size is 9 (900 KB blocks, best compression).
 * Use {@link #TarBz2Compressor(int)} to specify a block size between 1 and 9.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class TarBz2Compressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final TarCompressor tar = new TarCompressor();
    private final int blockSize;

    /** Creates a TarBz2Compressor with maximum block size (9). */
    public TarBz2Compressor() {
        this(BZip2OutputStream.MAX_BLOCKSIZE);
    }

    /**
     * Creates a TarBz2Compressor with the given BZIP2 block size.
     *
     * @param blockSize 1 (fastest) to 9 (best compression)
     */
    public TarBz2Compressor(int blockSize) {
        this.blockSize = blockSize;
    }

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
        try (BZip2OutputStream bzos = new BZip2OutputStream(new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE), blockSize)) {
            TarOutputStream tos = new TarOutputStream(bzos);
            tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
            tos.finish();
            bzos.finish();
        }
    }

    // =========================================================================
    // compress(File, OutputStream)
    // =========================================================================

    @Override
    public void compress(File source, OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        BZip2OutputStream bzos = new BZip2OutputStream(out, blockSize);
        TarOutputStream tos = new TarOutputStream(bzos);
        tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish();
        bzos.finish(); // do NOT close the underlying stream
    }
}