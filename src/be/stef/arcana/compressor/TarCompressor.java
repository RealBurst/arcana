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
import be.stef.arcana.formats.tar.TarEntry;
import be.stef.arcana.formats.tar.TarOutputStream;

/**
 * Compressor for uncompressed TAR archives (.tar).
 *
 * <p>Uses {@link TarOutputStream} - the pure-Java TAR writer that mirrors
 * the existing {@code TarInputStream} from the JUnpack port of Commons Compress.
 * No external dependency, no JNI.</p>
 *
 * <p>This class is also used internally by {@link TarGzCompressor} and
 * {@link TarBz2Compressor}, which add an outer compression layer.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class TarCompressor implements ArchiveCompressor {

    private static final int BUFFER_SIZE = 65536;

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
        try (TarOutputStream tos = new TarOutputStream(new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE))) {
            addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        }
    }

    // =========================================================================
    // compress(File, OutputStream)
    // =========================================================================

    /**
     * Writes the TAR content into the given stream and calls
     * {@link TarOutputStream#finish()} without closing the stream.
     * Used by {@link TarGzCompressor} and {@link TarBz2Compressor}.
     */
    @Override
    public void compress(File source, OutputStream out) throws IOException {
        final File abs = source.getAbsoluteFile(); // getParentFile() returns null on bare relative paths
        TarOutputStream tos = new TarOutputStream(out);
        addToTar(abs, abs.isDirectory() ? abs : abs.getParentFile(), tos);
        tos.finish(); // write end-of-archive; do NOT close the outer stream
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Adds a file or directory recursively to the TAR stream.
     *
     * @param file   current file or directory
     * @param root   root used to compute relative entry names
     * @param tos    target TAR stream
     */
    void addToTar(File file, File root, TarOutputStream tos) throws IOException {
        String entryName = getRelativePath(root, file);
        if (file.isDirectory()) {
            if (!entryName.isEmpty()) {
                TarEntry dirEntry = new TarEntry(file, entryName + "/");
                tos.putNextEntry(dirEntry);
                tos.closeEntry();
            }
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    addToTar(child, root, tos);
                }
            }
        } else {
            TarEntry entry = new TarEntry(file, entryName);
            tos.putNextEntry(entry);
            try (ProgressInputStream in = new ProgressInputStream(
                    new BufferedInputStream(new FileInputStream(file), BUFFER_SIZE), file.length(), file.getName())) {
                byte[] buf = new byte[BUFFER_SIZE];
                int n;
                while ((n = in.read(buf)) != -1) {
                    tos.write(buf, 0, n);
                }
                in.finish();
            }
            tos.closeEntry();
        }
    }

    /**
     * Computes the TAR entry path for {@code file} relative to {@code root}.
     * Uses forward slashes as required by the TAR specification.
     */
    static String getRelativePath(File root, File file) {
        String rootPath = root.getAbsolutePath();
        String filePath = file.getAbsolutePath();
        if (filePath.equals(rootPath)) {
            return ""; // the root itself: no entry (children are stored relative to it, without its name)
        }
        String relative = filePath.substring(rootPath.length());
        if (relative.startsWith(File.separator)) {
            relative = relative.substring(File.separator.length());
        }
        return relative.replace(File.separatorChar, '/');
    }
}