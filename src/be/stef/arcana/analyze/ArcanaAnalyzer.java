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
package be.stef.arcana.analyze;

import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;

/**
 * Service provider interface of a file <b>analyzer</b>: it inspects a file and
 * says what it is (type, version, details), without extracting or decompressing
 * anything. This is the second, transversal plugin type (the first being the
 * format plugin {@code ArcanaPlugin}): an analyzer is not tied to a single
 * archive format, it can recognize archives, executables, images, documents,
 * databases, and so on.
 *
 * <p>Built-in analyzers are listed by {@link AnalyzerRegistry}. An external
 * analyzer is distributed like a format plugin (a JAR in a plugin directory,
 * with its sources included; the same checks apply) but declares a
 * {@code META-INF/services/be.stef.arcana.analyze.ArcanaAnalyzer} entry.</p>
 *
 * <p>The implementation must have a public no-argument constructor and be
 * thread-safe.</p>
 *
 * @author Stef
 * @since 1.4
 */
public interface ArcanaAnalyzer {

    /** Unique identifier of the analyzer (e.g. "arcana.executable", "org.example.myformat"). */
    String getId();

    /**
     * Identifies the file, or returns null if this analyzer does not recognize it.
     *
     * @param source   random-access view of the file (do not close it: the caller owns it)
     * @param fileName name of the file without directory, usable as a hint
     */
    Identification analyze(ByteSource source, String fileName) throws IOException;

    /**
     * Order of consultation, highest first (default 0). The first analyzer that
     * returns a non-null result wins. Raise it to run before the built-in
     * analyzers.
     */
    default int getPriority() {
        return 0;
    }

    /** Public location of the source code. Required for an external analyzer plugin. */
    default String getSourceUrl() {
        return "";
    }

    /** License (SPDX identifier). Required for an external analyzer plugin. */
    default String getLicense() {
        return "";
    }
}
