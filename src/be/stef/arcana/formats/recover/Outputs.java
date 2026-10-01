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
package be.stef.arcana.formats.recover;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * Output files of a forced extraction: safe paths (no escape from the
 * destination), writes counted by the extraction guard, and no silent
 * overwrite: a name recovered twice (the same entry found again after a
 * resynchronization, or two damaged versions) gets a "_2", "_3"... suffix.
 *
 * @author Stef
 * @since 1.3
 */
final class Outputs {

    private final File root;
    private final Set<String> used = new HashSet<String>();
    private File last;

    Outputs(final File root) {
        this.root = root;
    }

    File root() {
        return root;
    }

    void directory(final String name) throws IOException {
        IOHelper.mkdirs(SafePathBuilder.buildSafePath(root, name));
    }

    /** Opens a new output file for the entry {@code name}. */
    OutputStream file(final String name) throws IOException {
        File f = SafePathBuilder.buildSafePath(root, name);
        String key = f.getAbsolutePath();
        int n = 2;
        while (used.contains(key)) {
            f = suffixed(SafePathBuilder.buildSafePath(root, name), n++);
            key = f.getAbsolutePath();
        }
        used.add(key);
        last = f;
        IOHelper.mkdirs(f.getParentFile());
        return new BufferedOutputStream(ExtractionGuard.open(f), 65536);
    }

    /** Deletes the file opened last if it is empty (an entry of which nothing could be decoded). */
    void dropLastIfEmpty() {
        if (last != null && last.isFile() && last.length() == 0 && !last.delete()) last.deleteOnExit();
    }

    private static File suffixed(final File f, final int n) {
        final String name = f.getName();
        final int dot = name.lastIndexOf('.');
        final String s = dot > 0 ? name.substring(0, dot) + "_" + n + name.substring(dot) : name + "_" + n;
        return new File(f.getParentFile(), s);
    }
}
