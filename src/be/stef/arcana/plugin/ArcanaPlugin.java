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

import be.stef.arcana.compressor.ArchiveCompressor;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.formats.carve.FileCarver;
import be.stef.arcana.formats.recover.ArchiveRecoverer;
import java.io.IOException;

/**
 * Service provider interface of an Arcana format plugin.
 *
 * <p>A plugin adds support for an archive or file format that Arcana does not
 * handle natively. It is a JAR placed in a plugin directory (see
 * {@link PluginManager}) that contains:</p>
 * <ul>
 *   <li>the compiled classes and <b>their Java source files</b> (same path,
 *       {@code .java}): a JAR without the source of every class is refused;</li>
 *   <li>{@code META-INF/services/be.stef.arcana.plugin.ArcanaPlugin} naming the
 *       implementation class(es) of this interface;</li>
 *   <li>optionally, in {@code META-INF/MANIFEST.MF}:
 *       {@code Arcana-Plugin-Source-Url} and {@code Arcana-Plugin-License}.</li>
 * </ul>
 *
 * <p>Detection order when an archive is opened: the plugins with a priority
 * greater than 0 ({@link #getPriority()}), Arcana's built-in formats recognized
 * by their content, the other plugins ({@link #matches}), then the built-in
 * detection by extension and the self-extracting archive search.</p>
 *
 * <p>Arcana's own formats implement this same interface ({@link BuiltinFormat},
 * see {@link FormatRegistry}).</p>
 *
 * <p>The implementation must have a public no-argument constructor and must be
 * thread-safe (a single instance serves every extraction).</p>
 *
 * @author Stef
 * @since 1.3
 */
public interface ArcanaPlugin {

    /** Unique identifier, reverse domain style (e.g. "org.example.pak"). */
    String getId();

    /** Display name of the format (e.g. "Quake PAK archive"). */
    String getName();

    /** Plugin version (e.g. "1.0.0"). */
    String getVersion();

    /** Author or organization. */
    default String getAuthor() {
        return "";
    }

    /** Public location of the source code (repository URL). Required. */
    String getSourceUrl();

    /** License of the plugin, preferably an SPDX identifier (e.g. "Apache-2.0"). Required. */
    String getLicense();

    /** File extensions of the format, without dot, lower case (e.g. {"pak"}). Used by -f / -t and by detection. */
    String[] getExtensions();

    /** Number of bytes of the file start passed to {@link #matches} (at most 4 MiB are read). */
    default int getProbeSize() {
        return 512;
    }

    /**
     * Returns true if the file is in this plugin's format.
     *
     * @param header   the first {@link #getProbeSize()} bytes of the file (fewer if the file is shorter)
     * @param fileName name of the file (without directory), may be used as a hint
     */
    boolean matches(byte[] header, String fileName);

    /**
     * Creates an extractor for this format. Extractors should create their output
     * files with {@link PluginSupport#openOutput} (safe paths, extraction limits).
     *
     * @param password password given by the user, or null
     */
    ArchiveExtractor createExtractor(byte[] password) throws IOException;

    /**
     * Creates a compressor for this format, or returns null if the plugin only extracts.
     *
     * @param level compression level requested by the user (0-9), or -1 for the default
     */
    default ArchiveCompressor createCompressor(final int level) throws IOException {
        return null;
    }

    /**
     * Creates a compressor that encrypts with {@code password} (null = no encryption).
     * The default ignores the password: override it if the format supports encryption.
     */
    default ArchiveCompressor createCompressor(final int level, final byte[] password) throws IOException {
        return createCompressor(level);
    }

    /**
     * Priority against Arcana's built-in formats. 0 (default): the built-in formats
     * recognized by their content, and the built-in format names given to -f / -t,
     * come first. Greater than 0: this plugin is consulted <b>before</b> the built-in
     * formats (to replace a built-in format by a newer implementation, for example).
     */
    default int getPriority() {
        return 0;
    }

    /**
     * Optional recovery strategy for a damaged archive of this format
     * ({@code arcana r}). The default returns null: forced extraction then does a
     * normal extraction and keeps whatever was written before the error. Override
     * it to salvage more (skip the damaged part, resynchronize, check what can be
     * checked). See {@link ArchiveRecoverer}.
     *
     * @param password password given by the user, or null
     */
    default ArchiveRecoverer createRecoverer(final byte[] password) throws IOException {
        return null;
    }

    /**
     * Optional carving probe ({@code arcana s}): recognizes a file of this format
     * embedded in another file, at a given position. The default returns null (the
     * format is not searched inside other files). See {@link FileCarver.FormatProbe}.
     */
    default FileCarver.FormatProbe createProbe() {
        return null;
    }
}
