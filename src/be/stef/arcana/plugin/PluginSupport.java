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
package be.stef.arcana.plugin;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ProgressOutputStream;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Helpers for plugin extractors: the same protections as the built-in formats.
 *
 * @author Stef
 * @since 1.3
 */
public final class PluginSupport {

    private PluginSupport() {}

    /**
     * Creates the output file of an archive entry: the name is sanitized (no
     * absolute path, no "..", no characters forbidden by Windows), parent
     * directories are created, and the bytes written are counted by Arcana's
     * extraction limits (decompression bombs, free disk space).
     *
     * @param destination extraction directory
     * @param entryName   name of the entry in the archive ("dir/file.txt")
     * @return a buffered stream; the caller closes it
     */
    public static OutputStream openOutput(final File destination, final String entryName) throws IOException {
        final File target = SafePathBuilder.buildSafePath(destination, entryName);
        IOHelper.mkdirs(target.getParentFile());
        return new BufferedOutputStream(ExtractionGuard.open(target), 65536);
    }

    /**
     * Same as {@link #openOutput(File, String)}, with a progress bar on the
     * console while the entry is written, as for Arcana's own formats:
     * {@code [=====     ] 1.2 GB  40% (secure/xxx.nca)}, then the elapsed time
     * when the stream is closed.
     *
     * @param size size of the entry in bytes (0 or less if unknown: only the byte count is shown)
     * @since 1.2.0
     */
    public static OutputStream openOutput(final File destination, final String entryName, final long size) throws IOException {
        return new ProgressOutputStream(openOutput(destination, entryName), size, entryName) {
            private boolean closed;

            @Override
            public void close() throws IOException {
                if (closed) return;
                closed = true;
                try {
                    super.close();
                } finally {
                    finish(); // completes the line: elapsed time, then a new line
                }
            }
        };
    }

    /** Creates the directory of a directory entry (sanitized name). */
    public static File createDirectory(final File destination, final String entryName) throws IOException {
        final File dir = SafePathBuilder.buildSafePath(destination, entryName);
        IOHelper.mkdirs(dir);
        return dir;
    }
}
