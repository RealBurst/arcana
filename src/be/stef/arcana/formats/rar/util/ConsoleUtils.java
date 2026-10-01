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
package be.stef.arcana.formats.rar.util;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;

/**
 * Console helpers for the command-line entry points.
 *
 * @author Stef
 * @since 1.0
 */
public final class ConsoleUtils {

    private ConsoleUtils() {
        // Utility class - no instantiation
    }

    /**
     * Routes {@code System.out} and {@code System.err} through UTF-8 print
     * streams so that non-ASCII file names (Cyrillic, accented characters,
     * CJK, ...) are written to the console without becoming '?' placeholders.
     *
     * <p>This is needed under Java 8, whose default console charset follows the
     * platform (often Cp1252 or an OEM code page on Windows). It is meant for
     * the CLI entry points; it is not called by the library API, which must not
     * reconfigure global streams on behalf of an embedding application.</p>
     *
     * <p>On legacy Windows consoles the code page may also need to be switched
     * with {@code chcp 65001} for the glyphs to render.</p>
     */
    public static void useUtf8() {
        try {
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8"));
            System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is guaranteed by the JVM; nothing to do if this ever fails.
        }
    }
}
