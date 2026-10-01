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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import be.stef.arcana.formats.bzip2.BZip2OutputStream;

/**
 * Compressor for BZIP2-compressed single files (.bz2).
 *
 * <p>Uses {@link BZip2OutputStream} - the pure-Java BZIP2 writer that mirrors
 * the existing {@code BZip2InputStream} from the JUnpack port of Commons Compress.
 * No external dependency, no JNI.</p>
 *
 * <p>BZIP2 wraps a single file; it is not a container format.
 * For directory compression, use {@link TarBz2Compressor} instead.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class BZip2Compressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

    private final int blockSize;

    /** Creates a BZip2Compressor with maximum block size (9). */
    public BZip2Compressor() {
        this(BZip2OutputStream.MAX_BLOCKSIZE);
    }

    /**
     * Creates a BZip2Compressor with the given block size.
     *
     * @param blockSize 1 (fastest) to 9 (best compression)
     */
    public BZip2Compressor(int blockSize) {
        this.blockSize = blockSize;
    }

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
            throw new IOException("BZIP2 does not support directories. Use TarBz2Compressor for directories.");
        }
        try (InputStream in = new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE);
             BZip2OutputStream bzos = new BZip2OutputStream(new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE), blockSize)) {
            pipe(in, bzos);
        }
    }

    // =========================================================================
    // compress(File, OutputStream)
    // =========================================================================

    @Override
    public void compress(File source, OutputStream out) throws IOException {
        if (source.isDirectory()) {
            throw new IOException("BZIP2 does not support directories. Use TarBz2Compressor for directories.");
        }
        BZip2OutputStream bzos = new BZip2OutputStream(out, blockSize);
        try (InputStream in = new BufferedInputStream(new FileInputStream(source), BUFFER_SIZE)) {
            pipe(in, bzos);
        }
        bzos.finish(); // do NOT close the underlying stream
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
