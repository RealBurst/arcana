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

import be.stef.arcana.analyze.AnalyzerRegistry;
import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.formats.carve.FileCarver;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Discovers, checks and serves the format plugins ({@link ArcanaPlugin}).
 *
 * <h3>Where plugins are searched</h3>
 * <ol>
 *   <li>the directories of the system property {@code arcana.plugins.dir}
 *       (several directories separated by the path separator); if it is not set:
 *       {@code <user home>/.arcana/plugins}, {@code plugins/} next to the Arcana
 *       JAR and {@code plugins/} in the working directory;</li>
 *   <li>the application class path (plugins bundled by an application that
 *       embeds Arcana, through {@code META-INF/services});</li>
 *   <li>plugins registered by code with {@link #register(ArcanaPlugin)}.</li>
 * </ol>
 *
 * <h3>Checks on a plugin JAR (refused otherwise)</h3>
 * <ul>
 *   <li>every class has its source file in the JAR ({@code a/b/C.class} requires
 *       {@code a/b/C.java}, also accepted under {@code src/} or {@code src/main/java/});</li>
 *   <li>a source URL and a license are declared (by the plugin, or by the
 *       manifest attributes {@code Arcana-Plugin-Source-Url} / {@code Arcana-Plugin-License});</li>
 *   <li>the plugin id is unique.</li>
 * </ul>
 *
 * <p><b>Security:</b> a plugin is Java code that runs with the rights of the
 * application. The mandatory sources allow it to be reviewed; the SHA-256 of
 * each JAR is shown by {@code arcana plugins} to identify exactly what is loaded.
 * Only install plugins you trust.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class PluginManager {

    /** Manifest attribute: public location of the source code. */
    public static final String ATTR_SOURCE_URL = "Arcana-Plugin-Source-Url";
    /** Manifest attribute: license (SPDX identifier). */
    public static final String ATTR_LICENSE = "Arcana-Plugin-License";

    /** State of a plugin (loaded or refused, and why). */
    public static final class PluginInfo {
        public final String id;
        public final String name;
        public final String version;
        public final String author;
        public final String sourceUrl;
        public final String license;
        public final String[] extensions;
        /** JAR file, or null for a class path / registered plugin. */
        public final File jar;
        /** SHA-256 of the JAR (hex), or null. */
        public final String sha256;
        /** Null when the plugin is loaded, otherwise the reason it was refused. */
        public final String problem;
        final ArcanaPlugin plugin;

        /** Entry for an external analyzer (not a format plugin). */
        PluginInfo(final String id, final String name, final File jar, final String sha256, final String sourceUrl, final String license, final String problem) {
            this.plugin = null;
            this.id = id;
            this.name = name;
            this.version = "";
            this.author = "";
            this.extensions = new String[0];
            this.jar = jar;
            this.sha256 = sha256;
            this.sourceUrl = sourceUrl;
            this.license = license;
            this.problem = problem;
        }

        PluginInfo(final ArcanaPlugin p, final File jar, final String sha256, final String sourceUrl, final String license, final String problem) {
            this.plugin = problem == null ? p : null;
            this.id = p != null ? safe(p::getId) : "?";
            this.name = p != null ? safe(p::getName) : "?";
            this.version = p != null ? safe(p::getVersion) : "?";
            this.author = p != null ? safe(p::getAuthor) : "";
            String[] ext = new String[0];
            if (p != null) {
                try {
                    final String[] e = p.getExtensions();
                    if (e != null) ext = e.clone();
                } catch (final RuntimeException ignored) { /* reported as no extension */ }
            }
            this.extensions = ext;
            this.jar = jar;
            this.sha256 = sha256;
            this.sourceUrl = sourceUrl;
            this.license = license;
            this.problem = problem;
        }

        public boolean isLoaded() {
            return problem == null;
        }

        /** The plugin instance, or null if refused. */
        public ArcanaPlugin getPlugin() {
            return plugin;
        }

        @Override
        public String toString() {
            return id + " " + version + " (" + name + ")" + (problem != null ? " REFUSED: " + problem : "");
        }
    }

    private interface Getter {
        String get();
    }

    private static String safe(final Getter g) {
        try {
            final String s = g.get();
            return s == null ? "" : s;
        } catch (final RuntimeException e) {
            return "";
        }
    }

    private static volatile PluginManager instance;

    private final List<PluginInfo> infos = new ArrayList<PluginInfo>();
    private final Map<String, ArcanaPlugin> active = new LinkedHashMap<String, ArcanaPlugin>();

    private PluginManager() {}

    /** The plugin manager, loading the plugins on first use. */
    public static PluginManager get() {
        PluginManager m = instance;
        if (m == null) {
            synchronized (PluginManager.class) {
                m = instance;
                if (m == null) {
                    m = new PluginManager();
                    m.loadAll();
                    instance = m;
                }
            }
        }
        return m;
    }

    /** Forgets the loaded plugins; they are searched again on the next {@link #get()}. */
    public static synchronized void reset() {
        instance = null;
    }

    /** Registers a plugin by code (applications embedding Arcana). No source check is done. */
    public synchronized void register(final ArcanaPlugin p) {
        final String problem = checkDeclared(p, null, null);
        final String id = safe(p::getId);
        final String err = problem != null ? problem : active.containsKey(id) ? "duplicate plugin id " + id : null;
        infos.add(new PluginInfo(p, null, null, safe(p::getSourceUrl), safe(p::getLicense), err));
        if (err == null) {
            active.put(id, p);
            registerProbe(p);
        }
    }

    /** Registers a plugin's carving probe (if any) with the file carver. */
    private static void registerProbe(final ArcanaPlugin p) {
        try {
            final FileCarver.FormatProbe probe = p.createProbe();
            if (probe != null) FileCarver.addProbe(probe);
        } catch (final RuntimeException | LinkageError ignored) {
            // a faulty plugin must not break carving
        }
    }

    /** Every plugin found, loaded or refused. */
    public synchronized List<PluginInfo> getPlugins() {
        return Collections.unmodifiableList(new ArrayList<PluginInfo>(infos));
    }

    /** The loaded plugins. */
    public synchronized List<ArcanaPlugin> getActivePlugins() {
        return Collections.unmodifiableList(new ArrayList<ArcanaPlugin>(active.values()));
    }

    public synchronized ArcanaPlugin findById(final String id) {
        return active.get(id);
    }

    /** Loaded plugin handling this extension (without dot, any case), or null. */
    public synchronized ArcanaPlugin findByExtension(final String ext) {
        if (ext == null) return null;
        final String e = ext.toLowerCase();
        for (final PluginInfo i : infos) {
            if (!i.isLoaded()) continue;
            for (final String x : i.extensions) if (x != null && x.toLowerCase().equals(e)) return i.plugin;
        }
        return null;
    }

    /**
     * Loaded plugin recognizing {@code file} ({@link ArcanaPlugin#matches}), or null.
     * A plugin that throws is ignored for this file.
     */
    public ArcanaPlugin detect(final File file) throws IOException {
        final ArcanaPlugin p = detect(file, true);
        return p != null ? p : detect(file, false);
    }

    /** Largest probe read for the plugins (4 MiB: the Inno Setup loader table can lie after the first MiB). */
    private static final int MAX_PROBE = 4 << 20;

    /**
     * Same as {@link #detect(File)} restricted to the plugins with a priority
     * greater than 0 ({@code priority = true}) or to the others.
     */
    public ArcanaPlugin detect(final File file, final boolean priority) throws IOException {
        final List<ArcanaPlugin> list = new ArrayList<ArcanaPlugin>();
        for (final ArcanaPlugin p : getActivePlugins()) {
            int prio;
            try { prio = p.getPriority(); } catch (final RuntimeException e) { prio = 0; }
            if ((prio > 0) == priority) list.add(p);
        }
        if (priority) list.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        if (list.isEmpty()) return null;
        int probe = 0;
        for (final ArcanaPlugin p : list) {
            try {
                probe = Math.max(probe, Math.min(MAX_PROBE, Math.max(0, p.getProbeSize())));
            } catch (final RuntimeException ignored) { /* default below */ }
        }
        final byte[] head = new byte[(int) Math.min(probe, file.length())];
        try (InputStream in = new FileInputStream(file)) {
            int n = 0;
            while (n < head.length) {
                final int k = in.read(head, n, head.length - n);
                if (k < 0) break;
                n += k;
            }
        }
        for (final ArcanaPlugin p : list) {
            try {
                final int size = Math.min(head.length, Math.max(0, p.getProbeSize()));
                if (p.matches(Arrays.copyOf(head, size), file.getName())) return p;
            } catch (final RuntimeException | LinkageError ignored) {
                // a faulty plugin must not prevent the other formats from working
            }
        }
        return null;
    }

    // =========================================================================
    // Loading
    // =========================================================================

    /** Directories searched for plugin JARs. */
    public static List<File> pluginDirectories() {
        final List<File> dirs = new ArrayList<File>();
        final String prop = System.getProperty("arcana.plugins.dir");
        if (prop != null && !prop.trim().isEmpty()) {
            for (final String d : prop.split(java.util.regex.Pattern.quote(File.pathSeparator))) if (!d.trim().isEmpty()) dirs.add(new File(d.trim()));
            return dirs;
        }
        dirs.add(new File(new File(System.getProperty("user.home"), ".arcana"), "plugins"));
        try {
            final URL loc = PluginManager.class.getProtectionDomain().getCodeSource().getLocation();
            final File self = new File(loc.toURI());
            if (self.isFile()) dirs.add(new File(self.getParentFile(), "plugins"));
        } catch (final Exception ignored) {
            // no code source (unusual class loader): skip
        }
        dirs.add(new File("plugins"));
        return dirs;
    }

    private void loadAll() {
        FileCarver.clearProbes(); // fresh registration on (re)load
        // 1. JAR files of the plugin directories
        final Set<String> seen = new HashSet<String>();
        for (final File dir : pluginDirectories()) {
            final File[] jars = dir.listFiles((d, n) -> n.toLowerCase().endsWith(".jar"));
            if (jars == null) continue;
            Arrays.sort(jars);
            for (final File jar : jars) {
                try {
                    if (seen.add(jar.getCanonicalPath())) loadJar(jar);
                } catch (final IOException e) {
                    infos.add(new PluginInfo(null, jar, null, "", "", "cannot read the JAR: " + e.getMessage()));
                }
            }
        }
        // 2. Class path (embedding applications)
        try {
            final Iterator<ArcanaPlugin> it = ServiceLoader.load(ArcanaPlugin.class, PluginManager.class.getClassLoader()).iterator();
            while (it.hasNext()) {
                try {
                    final ArcanaPlugin p = it.next();
                    if (!active.containsKey(safe(p::getId))) register(p);
                } catch (final ServiceConfigurationError e) {
                    infos.add(new PluginInfo(null, null, null, "", "", "class path plugin cannot be loaded: " + e.getMessage()));
                }
            }
        } catch (final ServiceConfigurationError e) {
            infos.add(new PluginInfo(null, null, null, "", "", "class path plugins cannot be listed: " + e.getMessage()));
        }
        // 3. Analyzers of the class path (no source check for embedded ones)
        loadAnalyzers(PluginManager.class.getClassLoader(), null, null, null, null);
    }

    /** Loads the {@link ArcanaAnalyzer} services of {@code loader} and registers them. */
    private int loadAnalyzers(final ClassLoader loader, final File jar, final String sha, final String mfSource, final String mfLicense) {
        int found = 0;
        try {
            final Iterator<ArcanaAnalyzer> it = ServiceLoader.load(ArcanaAnalyzer.class, loader).iterator();
            while (it.hasNext()) {
                final ArcanaAnalyzer a;
                try {
                    a = it.next();
                } catch (final ServiceConfigurationError e) {
                    infos.add(new PluginInfo("?", "(analyzer)", jar, sha, mfSource, mfLicense, "analyzer cannot be created: " + e.getMessage()));
                    continue;
                }
                if (jar != null && a.getClass().getClassLoader() != loader) continue; // provider of another JAR
                found++;
                final String src = nonEmpty(safe(a::getSourceUrl), mfSource);
                final String lic = nonEmpty(safe(a::getLicense), mfLicense);
                final String id = safe(a::getId);
                String problem = null;
                if (id.trim().isEmpty()) problem = "empty analyzer id";
                else if (jar != null && src == null) problem = "no source URL declared (getSourceUrl() or manifest " + ATTR_SOURCE_URL + ")";
                else if (jar != null && lic == null) problem = "no license declared (getLicense() or manifest " + ATTR_LICENSE + ")";
                infos.add(new PluginInfo(id.isEmpty() ? "?" : id, "(analyzer)", jar, sha, src, lic, problem));
                if (problem == null) AnalyzerRegistry.addExternal(a);
            }
        } catch (final ServiceConfigurationError e) {
            infos.add(new PluginInfo("?", "(analyzer)", jar, sha, mfSource, mfLicense, "analyzers cannot be listed: " + e.getMessage()));
        }
        return found;
    }

    @SuppressWarnings("resource") // the class loader stays open while the plugin is in use
    private void loadJar(final File jar) throws IOException {
        final String sha = sha256(jar);
        final String sourceProblem;
        final String namespaceProblem;
        final String mfSource, mfLicense;
        final List<String> declared;
        try (JarFile jf = new JarFile(jar)) {
            sourceProblem = checkSources(jf);
            namespaceProblem = checkNamespace(jf);
            declared = readServiceEntries(jf, ArcanaPlugin.class.getName());
            final Manifest mf = jf.getManifest();
            final Attributes a = mf != null ? mf.getMainAttributes() : null;
            mfSource = a != null ? a.getValue(ATTR_SOURCE_URL) : null;
            mfLicense = a != null ? a.getValue(ATTR_LICENSE) : null;
        }
        if (sourceProblem != null) {
            infos.add(new PluginInfo(null, jar, sha, mfSource, mfLicense, sourceProblem));
            return;
        }
        if (namespaceProblem != null) {
            infos.add(new PluginInfo(null, jar, sha, mfSource, mfLicense, namespaceProblem));
            return;
        }
        final URLClassLoader loader = new URLClassLoader(new URL[] {jar.toURI().toURL()}, PluginManager.class.getClassLoader());
        int found = 0;
        int errors = 0;
        try {
            final Iterator<ArcanaPlugin> it = ServiceLoader.load(ArcanaPlugin.class, loader).iterator();
            while (it.hasNext()) {
                final ArcanaPlugin p;
                try {
                    p = it.next();
                } catch (final ServiceConfigurationError e) {
                    infos.add(new PluginInfo(null, jar, sha, mfSource, mfLicense, "plugin class cannot be created: " + e.getMessage()));
                    errors++;
                    continue;
                }
                if (p.getClass().getClassLoader() != loader) continue; // provider of another JAR / of the class path
                found++;
                final String src = nonEmpty(safe(p::getSourceUrl), mfSource);
                final String lic = nonEmpty(safe(p::getLicense), mfLicense);
                String problem = checkDeclared(p, src, lic);
                final String id = safe(p::getId);
                if (problem == null && active.containsKey(id)) problem = "duplicate plugin id " + id;
                infos.add(new PluginInfo(p, jar, sha, src, lic, problem));
                if (problem == null) {
                    active.put(id, p);
                    registerProbe(p);
                }
            }
        } catch (final ServiceConfigurationError e) {
            infos.add(new PluginInfo(null, jar, sha, mfSource, mfLicense, "plugin cannot be loaded: " + e.getMessage()));
            return;
        }
        final int analyzers = loadAnalyzers(loader, jar, sha, mfSource, mfLicense);
        if (found == 0 && analyzers == 0 && errors == 0) infos.add(new PluginInfo(null, jar, sha, mfSource, mfLicense, noPluginProblem(declared)));
    }

    /** Explains why a JAR without error yields no plugin, from the provider names declared in its own service file. */
    private static String noPluginProblem(final List<String> declared) {
        final String file = "META-INF/services/" + ArcanaPlugin.class.getName();
        if (declared == null) return "no " + file + " entry in the JAR";
        if (declared.isEmpty()) return file + " is empty (expected the fully qualified name of the plugin class)";
        return "plugin class " + declared + " loaded from Arcana's own class path instead of this JAR (the same class is also packaged in the Arcana JAR?)";
    }

    /** Provider class names listed in META-INF/services/{service} of the JAR, or null if the JAR has no such file. */
    static List<String> readServiceEntries(final JarFile jf, final String service) throws IOException {
        final JarEntry e = jf.getJarEntry("META-INF/services/" + service);
        if (e == null) return null;
        final List<String> names = new ArrayList<String>();
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(jf.getInputStream(e), "UTF-8"))) {
            for (String line; (line = r.readLine()) != null; ) {
                final int hash = line.indexOf('#');
                final String n = (hash >= 0 ? line.substring(0, hash) : line).trim();
                if (!n.isEmpty()) names.add(n);
            }
        }
        return names;
    }

    /** Checks the declared metadata; returns the problem or null. */
    private static String checkDeclared(final ArcanaPlugin p, final String src, final String lic) {
        final String id = safe(p::getId);
        if (id.trim().isEmpty()) return "empty plugin id";
        if (nonEmpty(src, safe(p::getSourceUrl)) == null) return "no source URL declared (getSourceUrl() or manifest " + ATTR_SOURCE_URL + ")";
        if (nonEmpty(lic, safe(p::getLicense)) == null) return "no license declared (getLicense() or manifest " + ATTR_LICENSE + ")";
        return null;
    }

    private static String nonEmpty(final String a, final String b) {
        if (a != null && !a.trim().isEmpty()) return a.trim();
        if (b != null && !b.trim().isEmpty()) return b.trim();
        return null;
    }

    /**
     * Every class of the JAR must come with its source file.
     *
     * @return null if complete, otherwise the problem
     */
    static String checkSources(final JarFile jf) {
        final Set<String> sources = new HashSet<String>();
        final List<String> classes = new ArrayList<String>();
        for (final Enumeration<JarEntry> e = jf.entries(); e.hasMoreElements(); ) {
            final String n = e.nextElement().getName();
            if (n.endsWith(".java")) sources.add(n);
            else if (n.endsWith(".class") && !n.startsWith("META-INF/")) classes.add(n);
        }
        if (classes.isEmpty()) return "no class in the JAR";
        final java.util.Set<String> missing = new java.util.LinkedHashSet<String>();
        for (final String c : classes) {
            String base = c.substring(0, c.length() - 6);
            final int dollar = base.indexOf('$', base.lastIndexOf('/') + 1);
            if (dollar >= 0) base = base.substring(0, dollar); // nested class: source of the outer class
            if (base.endsWith("module-info") || base.endsWith("package-info")) continue;
            final String java = base + ".java";
            if (!sources.contains(java) && !sources.contains("src/" + java) && !sources.contains("src/main/java/" + java)) missing.add(java);
        }
        if (missing.isEmpty()) return null;
        final List<String> m = new ArrayList<String>(missing);
        return "source code missing for " + m.size() + " file(s): " + (m.size() > 5 ? m.subList(0, 5) + "..." : m.toString()) + " (the sources must be included in the plugin JAR)";
    }

    /**
     * Checks that no class in the JAR uses the reserved package be.stef.arcana.
     *
     * @return null if clean, otherwise the refusal reason
     */
    static String checkNamespace(final JarFile jf) {
        for (final Enumeration<JarEntry> e = jf.entries(); e.hasMoreElements(); ) {
            final String n = e.nextElement().getName();
            if (n.endsWith(".class") && !n.startsWith("META-INF/") && n.startsWith("be/stef/arcana/")) return "plugin class in reserved namespace be.stef.arcana (use your own package, e.g. io.github.yourname.arcana.plugin.xxx)";
        }
        return null;
    }

    private static String sha256(final File f) {
        try (InputStream in = new FileInputStream(f)) {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            final byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            final StringBuilder sb = new StringBuilder();
            for (final byte b : md.digest()) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        } catch (final Exception e) {
            return null;
        }
    }
}
