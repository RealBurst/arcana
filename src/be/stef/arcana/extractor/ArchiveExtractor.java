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
package be.stef.arcana.extractor;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.exceptions.ArcanaException;

/**
 * Common contract for all JUnpack archive extractors.
 *
 * <p>Each supported archive format has a dedicated implementation of this
 * interface.  The {@link be.stef.arcana.Arcana} facade selects the correct
 * implementation based on the detected {@link be.stef.arcana.ArcanaFormat}
 * and delegates all operations through this interface, so callers never need
 * to reference format-specific classes directly.</p>
 *
 * <h3>Thread safety</h3>
 * <p>Implementations are <strong>not</strong> required to be thread-safe.
 * Create one instance per extraction operation.</p>
 *
 * @author Stef
 * @since 1.0
 */
public interface ArchiveExtractor {

    /**
     * Extracts all entries of the archive file to the given destination directory.
     *
     * <p>The destination directory is created if it does not exist.  Existing
     * files are overwritten without warning.</p>
     *
     * @param archive     archive file to extract
     * @param destination target directory; created if absent
     * @throws ArcanaException if a format-specific or logical error occurs
     * @throws IOException      if a raw I/O error occurs
     */
    void extract(File archive, File destination) throws IOException;

    /**
     * Extracts all entries of the archive read from {@code in} to the given
     * destination directory.
     *
     * <p>This method is useful when the archive comes from a network stream,
     * a classpath resource, or any source that is not a plain file.
     * Not all formats support streaming input (e.g. RAR uses random access);
     * in that case the implementation must throw
     * {@link be.stef.arcana.exceptions.ArcanaUnsupportedFormatException} with a clear
     * message.</p>
     *
     * @param in          stream positioned at the start of the archive
     * @param destination target directory; created if absent
     * @throws ArcanaException if a format-specific or logical error occurs
     * @throws IOException      if a raw I/O error occurs
     */
    void extract(InputStream in, File destination) throws IOException;

    /**
     * Returns the list of entries contained in the archive without extracting them.
     *
     * <p>Entries are returned in the order they appear in the archive.
     * Directory entries are included.</p>
     *
     * @param archive archive file to inspect
     * @return ordered list of entries, never null, may be empty
     * @throws ArcanaException if a format-specific or logical error occurs
     * @throws IOException      if a raw I/O error occurs
     */
    List<ArcanaEntry> list(File archive) throws IOException;

    /**
     * Returns whether this extractor supports reading from a sequential
     * {@link InputStream} (as opposed to requiring a random-access file).
     *
     * <p>Callers can use this to decide whether to buffer the stream to a
     * temporary file before calling {@link #extract(InputStream, File)}.</p>
     *
     * @return {@code true} if {@link #extract(InputStream, File)} is supported
     */
    boolean supportsStream();
}
