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
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Registry of file analyzers: the built-in ones and the external ones
 * contributed by plugins (registered through {@link #addExternal}). Analyzers
 * are consulted from the highest priority to the lowest; the first that returns
 * a non-null {@link Identification} wins.
 *
 * <p>External analyzers are loaded by the plugin manager when the plugins are
 * loaded, so identifying a file with {@code arcana i} loads the plugins first.</p>
 *
 * @author Stef
 * @since 1.4
 */
public final class AnalyzerRegistry {

    private static final List<ArcanaAnalyzer> BUILTINS = Collections.unmodifiableList(new ArrayList<ArcanaAnalyzer>() {{
        add(new ExecutableAnalyzer());
        add(new ArchiveAnalyzer());
        add(new MediaAnalyzer());
        add(new DataAnalyzer());
    }});

    private static final CopyOnWriteArrayList<ArcanaAnalyzer> EXTERNAL = new CopyOnWriteArrayList<ArcanaAnalyzer>();

    private AnalyzerRegistry() {}

    /** Built-in analyzers, in default order. */
    public static List<ArcanaAnalyzer> builtins() {
        return BUILTINS;
    }

    /** Adds an external analyzer (called by the plugin manager). Ignores a duplicate id. */
    public static void addExternal(final ArcanaAnalyzer a) {
        if (a == null) return;
        for (final ArcanaAnalyzer e : EXTERNAL) if (id(e).equals(id(a))) return;
        EXTERNAL.add(a);
    }

    /** Identifies {@code file}, never null (falls back to an "unknown" identification). */
    public static Identification identify(final File file) throws IOException {
        try (ByteSource s = new ByteSource(file)) {
            return identify(s, file.getName());
        }
    }

    /**
     * Identifies the file behind {@code source}. The caller keeps ownership of
     * {@code source}. Never null.
     */
    public static Identification identify(final ByteSource source, final String fileName) throws IOException {
        final List<ArcanaAnalyzer> all = new ArrayList<ArcanaAnalyzer>(EXTERNAL);
        all.addAll(BUILTINS);
        // stable sort by priority, highest first; equal priorities keep external-before-builtin then declaration order
        all.sort((a, b) -> Integer.compare(priority(b), priority(a)));
        for (final ArcanaAnalyzer a : all) {
            try {
                final Identification id = a.analyze(source, fileName);
                if (id != null) return id;
            } catch (final RuntimeException | LinkageError ignored) {
                // a faulty analyzer must not stop the others
            }
        }
        return Identification.of("data", "unknown").description("unrecognized data (no analyzer matched)").confidence(0).build();
    }

    private static int priority(final ArcanaAnalyzer a) {
        try {
            return a.getPriority();
        } catch (final RuntimeException e) {
            return 0;
        }
    }

    private static String id(final ArcanaAnalyzer a) {
        try {
            final String s = a.getId();
            return s != null ? s : "";
        } catch (final RuntimeException e) {
            return "";
        }
    }
}
