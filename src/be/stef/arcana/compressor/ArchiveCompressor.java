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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Common contract for all JUnpack archive compressors.
 *
 * <p>Each supported archive format has a dedicated implementation of this
 * interface. The {@link be.stef.arcana.Arcana} facade selects the correct
 * implementation based on the target {@link be.stef.arcana.ArcanaFormat}
 * and delegates all operations through this interface.</p>
 *
 * <h3>Thread safety</h3>
 * <p>Implementations are <strong>not</strong> required to be thread-safe.
 * Create one instance per compression operation.</p>
 *
 * @author Stef
 * @since 1.0
 */
public interface ArchiveCompressor {

    /**
     * Compresses the given source file or directory into the target archive.
     *
     * <p>If {@code source} is a directory, all files and subdirectories are
     * included recursively. If {@code source} is a single file, the archive
     * will contain that file only.</p>
     *
     * <p>The parent directory of {@code target} must exist. Any existing file
     * at {@code target} is overwritten without warning.</p>
     *
     * @param source  file or directory to compress
     * @param target  archive file to create
     * @throws IOException if an I/O error occurs
     */
    void compress(File source, File target) throws IOException;

    /**
     * Writes the compressed content of {@code source} into the given stream.
     *
     * <p>Used when the caller already manages the output stream (e.g. writing
     * directly to a network socket or a zip entry). The stream is not closed
     * by this method.</p>
     *
     * @param source source file or directory
     * @param out    writable output stream
     * @throws IOException if an I/O error occurs
     */
    void compress(File source, OutputStream out) throws IOException;

    /**
     * Returns whether this compressor can handle directories recursively.
     *
     * <p>Container formats (ZIP, TAR, TAR+GZ, TAR+BZ2) return {@code true}.
     * Single-file compressors (GZIP, BZIP2) return {@code false}.</p>
     *
     * @return {@code true} if directories are supported
     */
    boolean supportsDirectories();
}
