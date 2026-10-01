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

import be.stef.arcana.formats.xz.LZMA2Options;
import be.stef.arcana.formats.xz.FinishableOutputStream;
import be.stef.arcana.formats.xz.ParallelXZOutputStream;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Compresses a single file into the XZ format (.xz) using LZMA2.
 *
 * <p>The XZ container adds integrity checking (CRC64 by default) on top of
 * LZMA2 compression. It is the standard format produced by {@code xz(1)} on
 * Linux and is widely supported.</p>
 *
 * <p>Uses the pure-Java LZMA2 encoder already ported from XZ for Java (0BSD).</p>
 *
 * @author Stef
 * @since 1.1
 */
public class XzCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final int preset;

    /** Creates an XzCompressor with default compression level (6). */
    public XzCompressor() {
        this(LZMA2Options.PRESET_DEFAULT);
    }

    /**
     * Creates an XzCompressor with the given LZMA2 preset.
     *
     * @param preset 0 (fastest) to 9 (best compression)
     */
    public XzCompressor(final int preset) {
        if (preset < LZMA2Options.PRESET_MIN || preset > LZMA2Options.PRESET_MAX) throw new IllegalArgumentException("preset must be 0..9");
        this.preset = preset;
    }

    @Override
    public boolean supportsDirectories() { return false; }

    @Override
    public void compress(final File source, final File target) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(target)) {
            compress(source, fos);
        }
    }

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final LZMA2Options opts = new LZMA2Options(preset);
        try (FinishableOutputStream xzOut = ParallelXZOutputStream.create(out, opts, source.length()); // multithreaded when possible
             BufferedInputStream in = new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE)) {
            final byte[] buf = new byte[BUFFER_SIZE];
            int n;
            while ((n = in.read(buf)) >= 0) xzOut.write(buf, 0, n);
        }
    }
}
