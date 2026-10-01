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
import be.stef.arcana.formats.tar.TarOutputStream;
import be.stef.arcana.formats.xz.LZMA2Options;
import be.stef.arcana.formats.xz.FinishableOutputStream;
import be.stef.arcana.formats.xz.ParallelXZOutputStream;

/**
 * Compressor for TAR archives compressed with XZ (.tar.xz, .txz).
 *
 * <p>Chains {@link TarCompressor} for the inner TAR stream with
 * {@link ParallelXZOutputStream} (LZMA2, multithreaded) for the outer XZ container.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class TarXzCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final TarCompressor tar = new TarCompressor();
    private final int preset;

    /** Creates a TarXzCompressor with default compression level (6). */
    public TarXzCompressor() {
        this(LZMA2Options.PRESET_DEFAULT);
    }

    /**
     * Creates a TarXzCompressor with the given LZMA2 preset.
     *
     * @param preset 0 (fastest) to 9 (best compression)
     */
    public TarXzCompressor(final int preset) {
        if (preset < LZMA2Options.PRESET_MIN || preset > LZMA2Options.PRESET_MAX) throw new IllegalArgumentException("preset must be 0..9");
        this.preset = preset;
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

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        final FinishableOutputStream xzos = ParallelXZOutputStream.create(out, new LZMA2Options(preset), totalSize(abs)); // multithreaded when possible
        final TarOutputStream tos = new TarOutputStream(xzos);
        tar.addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish(); // write TAR end-of-archive into the XZ stream
        xzos.finish(); // write XZ index and footer; do NOT close the underlying stream
    }

    /**
     * Expected TAR size of {@code f} (lets the parallel encoder balance its blocks):
     * file sizes + about 1 KB per entry (header, padding).
     */
    static long totalSize(final File f) {
        if (f.isFile()) return f.length() + 1024;
        long sum = 1024;
        final File[] children = f.listFiles();
        if (children != null) for (final File c : children) sum += totalSize(c);
        return sum;
    }
}
