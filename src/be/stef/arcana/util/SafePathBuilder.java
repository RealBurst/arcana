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
package be.stef.arcana.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Stateless path-safety utilities shared by all JUnpack extractors.
 *
 * <p>Provides protection against:</p>
 * <ul>
 *   <li><strong>Path traversal</strong> - entry names containing {@code ..} or
 *       absolute paths that would escape the destination directory.</li>
 *   <li><strong>Illegal characters</strong> - characters that are invalid on
 *       Windows file systems ({@code < > : " | ? *} and control chars).</li>
 *   <li><strong>Reserved names</strong> - Windows device names such as
 *       {@code CON}, {@code NUL}, {@code COM1}, etc.</li>
 * </ul>
 *
 * <p>This class provides a lightweight static API.  For archives that require
 * stateful collision detection (e.g. RAR via unrar5j), use
 * {@code be.stef.arcana.formats.rar.util.SafePathBuilder} instead.</p>
 *
 * @author Stef
 * @since 1.0
 */
public final class SafePathBuilder {

    private static final Pattern ILLEGAL_CHARS = Pattern.compile("[<>:\"|?*\u0000-\u001F]");

    private static final List<String> RESERVED_NAMES = Arrays.asList(
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    );

    private SafePathBuilder() {}

    /**
     * Resolves {@code entryName} against {@code baseDir} with full path-safety
     * checks.
     *
     * <p>The method normalises separators, sanitises each path component, and
     * verifies that the resulting canonical path is strictly under
     * {@code baseDir} (path-traversal protection).</p>
     *
     * @param baseDir   the extraction root directory
     * @param entryName the raw entry name as stored in the archive
     * @return the safe, resolved {@link File} target
     * @throws IOException if the resolved path would escape {@code baseDir}
     */
    public static File buildSafePath(File baseDir, String entryName) throws IOException {
        // Normalise separators
        String normalized = entryName.replace('\\', '/');

        // Build sanitised path component by component
        Path p = Paths.get(normalized);
        Path safe = Paths.get("");
        for (Path component : p) {
            String raw = component.toString();
            if (raw.isEmpty() || raw.equals(".")) continue; // "./usr/bin" (TAR, CPIO, DEB) must not become "_/usr/bin"
            String sanitized = sanitize(raw);
            safe = safe.resolve(sanitized);
        }

        File target = new File(baseDir, safe.toString());

        // Path traversal guard
        if (!target.getCanonicalPath().startsWith(baseDir.getCanonicalPath() + File.separator)
                && !target.getCanonicalPath().equals(baseDir.getCanonicalPath())) {
            throw new IOException("Security: path traversal attempt blocked: " + entryName);
        }

        return target;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private static String sanitize(String name) {
        // 1. Replace illegal characters
        String clean = ILLEGAL_CHARS.matcher(name).replaceAll("_");

        // 2. Trim and replace trailing dots (problematic on Windows)
        clean = clean.trim();
        while (clean.endsWith(".")) {
            clean = clean.substring(0, clean.length() - 1) + "_";
        }

        // 3. Handle empty component
        if (clean.isEmpty()) return "_empty_";

        // 4. Handle Windows reserved device names (e.g. AUX.txt -> _AUX_.txt)
        String nameNoExt = clean.contains(".") ? clean.substring(0, clean.lastIndexOf('.')) : clean;
        if (RESERVED_NAMES.contains(nameNoExt.toUpperCase(Locale.ROOT))) {
            clean = "_" + clean + "_";
        }

        return clean;
    }
}
