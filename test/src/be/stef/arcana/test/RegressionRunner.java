/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.test;

import be.stef.arcana.Arcana;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.analyze.Identification;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Non-regression tests of Arcana: every sample is identified, listed and
 * extracted, and the result is compared with its reference file.
 *
 * <p>Two sets of samples:</p>
 * <ul>
 *   <li>{@code test/samples}: small files committed with the project, references
 *       in {@code test/expected} (same relative path + ".txt");</li>
 *   <li>the corpus: real files kept outside the project (third-party installers,
 *       large archives...), in the folder given by {@code --corpus} or the
 *       environment variable {@code ARCANA_CORPUS}; references in
 *       {@code test/corpus}. A corpus file that is missing is skipped.</li>
 * </ul>
 *
 * <p>A file {@code ignore.txt} in a reference folder lists the files that are
 * not samples by themselves (volumes after the first, cabinet headers...).</p>
 *
 * <p>A reference holds: the SHA-256 and size of the input, the identification,
 * the listing (sorted) and the SHA-256 and size of every extracted file
 * (sorted), or the error raised by each step. A line "password: xxx" in a
 * reference gives the password of the sample; it is kept by {@code --update}.</p>
 *
 * <pre>
 * java -cp bin;test/bin be.stef.arcana.test.RegressionRunner [options] [filter]
 *   --update          write the references of new samples and of the ones that differ
 *   --corpus DIR      folder of the corpus (default: ARCANA_CORPUS)
 *   --root DIR        root of the project (default: current folder)
 *   --timeout SEC     time limit per sample (default 300)
 *   filter            only the samples whose path contains this text
 * </pre>
 *
 * <p>Exit code: 0 when everything matches, 1 otherwise.</p>
 *
 * @author Stef
 * @since 1.0.5
 */
public final class RegressionRunner {

    private static final String HEADER = "# Arcana regression reference (RegressionRunner --update)";

    /** The real standard output: Arcana's own messages (progress bars...) are discarded while the samples run. */
    private static final PrintStream CONSOLE = System.out;

    private boolean update;
    private File root = new File(".");
    private File corpus;
    private long timeoutSeconds = 300;
    private String filter;

    private int ok, diff, created, skipped, failed;
    private final List<String> problems = new ArrayList<String>();

    public static void main(final String[] args) throws Exception {
        System.setOut(new PrintStream(new OutputStream() {
            @Override
            public void write(final int b) {
                // discarded
            }

            @Override
            public void write(final byte[] b, final int off, final int len) {
                // discarded
            }
        }));
        final RegressionRunner r = new RegressionRunner();
        for (int i = 0; i < args.length; i++) {
            final String a = args[i];
            if ("--update".equals(a)) r.update = true;
            else if ("--corpus".equals(a) && i + 1 < args.length) r.corpus = new File(args[++i]);
            else if ("--root".equals(a) && i + 1 < args.length) r.root = new File(args[++i]);
            else if ("--timeout".equals(a) && i + 1 < args.length) r.timeoutSeconds = Long.parseLong(args[++i]);
            else if (a.startsWith("--")) { System.err.println("Unknown option: " + a); System.exit(2); }
            else r.filter = a;
        }
        if (r.corpus == null && System.getenv("ARCANA_CORPUS") != null && !System.getenv("ARCANA_CORPUS").trim().isEmpty()) r.corpus = new File(System.getenv("ARCANA_CORPUS").trim());
        System.exit(r.run() ? 0 : 1);
    }

    private boolean run() throws Exception {
        root = root.getCanonicalFile();
        if (System.getProperty("arcana.plugins.dir") == null) System.setProperty("arcana.plugins.dir", pluginDirs());
        CONSOLE.println("Arcana " + Arcana.getVersion() + " - regression tests" + (update ? " (update)" : ""));
        CONSOLE.println("Plugins: " + System.getProperty("arcana.plugins.dir"));
        final ExecutorService pool = Executors.newCachedThreadPool(runnable -> {
            final Thread t = new Thread(runnable, "regression");
            t.setDaemon(true);
            return t;
        });
        try {
            runSet("samples", new File(root, "test/samples"), new File(root, "test/expected"), false, pool);
            if (corpus != null) runSet("corpus", corpus.getCanonicalFile(), new File(root, "test/corpus"), true, pool);
            else CONSOLE.println("Corpus: not set (--corpus DIR or ARCANA_CORPUS), skipped");
        } finally {
            pool.shutdownNow();
        }
        CONSOLE.println();
        CONSOLE.println(String.format("Result: %d ok, %d different, %d failed, %d new, %d skipped", ok, diff, failed, created, skipped));
        for (int i = 0; i < problems.size() && i < 30; i++) CONSOLE.println("  " + problems.get(i));
        if (problems.size() > 30) CONSOLE.println("  ... and " + (problems.size() - 30) + " more");
        return diff == 0 && failed == 0 && (update || created == 0);
    }

    /** Plugin JAR folders of the project (plugins/arcana-plugin-x/jar). */
    private String pluginDirs() {
        final StringBuilder sb = new StringBuilder();
        final File[] plugins = new File(root, "plugins").listFiles();
        if (plugins != null) {
            final List<File> list = new ArrayList<File>();
            Collections.addAll(list, plugins);
            Collections.sort(list);
            for (final File p : list) {
                final File jar = new File(p, "jar");
                if (jar.isDirectory()) sb.append(sb.length() == 0 ? "" : File.pathSeparator).append(jar.getPath());
            }
        }
        return sb.length() == 0 ? new File(root, "plugins").getPath() : sb.toString();
    }

    /** Runs every sample of a folder (and the references without sample, for the corpus). */
    private void runSet(final String name, final File dir, final File refs, final boolean isCorpus, final ExecutorService pool) throws Exception {
        CONSOLE.println();
        CONSOLE.println("== " + name + ": " + dir.getPath());
        final List<String> paths = new ArrayList<String>();
        if (dir.isDirectory()) collect(dir, "", paths);
        else if (!isCorpus) CONSOLE.println("   folder missing");
        // corpus references whose file is missing: reported as skipped
        final List<String> refPaths = new ArrayList<String>();
        if (refs.isDirectory()) collect(refs, "", refPaths);
        for (final String r : refPaths) {
            if (!r.endsWith(".txt") || r.equals("ignore.txt")) continue;
            final String sample = r.substring(0, r.length() - 4);
            if (!paths.contains(sample) && matches(sample)) {
                skipped++;
                CONSOLE.println("SKIP     " + sample + " (file not found)");
            }
        }
        Collections.sort(paths);
        final List<String> ignored = ignoreList(new File(refs, "ignore.txt"));
        for (final String p : paths) {
            if (!matches(p) || isReadme(p) || isIgnored(p, ignored)) continue;
            runOne(new File(dir, p), p, new File(refs, p + ".txt"), pool);
        }
    }

    /** Patterns of files that are not samples by themselves (volumes after the first, headers...): one per line, "*", "?" and "[2-9]" allowed, "#" for comments. */
    private static List<String> ignoreList(final File f) throws IOException {
        final List<String> list = new ArrayList<String>();
        if (!f.isFile()) return list;
        for (final String line : new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).split("\r?\n")) {
            final String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) list.add(t);
        }
        return list;
    }

    private static boolean isIgnored(final String path, final List<String> patterns) {
        for (final String p : patterns) {
            final StringBuilder re = new StringBuilder();
            for (int i = 0; i < p.length(); i++) {
                final char c = p.charAt(i);
                final int close = c == '[' ? p.indexOf(']', i) : -1;
                if (c == '*') re.append(".*");
                else if (c == '?') re.append('.');
                else if (close > i) { re.append(p, i, close + 1); i = close; }
                else re.append(java.util.regex.Pattern.quote(String.valueOf(c)));
            }
            if (path.matches("(?i)" + re)) return true;
        }
        return false;
    }

    private static boolean isReadme(final String p) {
        final String n = p.substring(p.lastIndexOf('/') + 1).toLowerCase();
        return n.equals("readme.md") || n.equals("readme.txt");
    }

    private boolean matches(final String p) {
        return filter == null || p.toLowerCase().contains(filter.toLowerCase());
    }

    private static void collect(final File dir, final String prefix, final List<String> out) {
        final File[] files = dir.listFiles();
        if (files == null) return;
        for (final File f : files) {
            if (f.isDirectory()) collect(f, prefix + f.getName() + "/", out);
            else if (f.isFile()) out.add(prefix + f.getName());
        }
    }

    private void runOne(final File sample, final String path, final File ref, final ExecutorService pool) throws IOException {
        final String expected = ref.isFile() ? new String(Files.readAllBytes(ref.toPath()), StandardCharsets.UTF_8).replace("\r\n", "\n") : null;
        final String password = expected == null ? null : value(expected, "password: ");
        final long start = System.nanoTime();
        String actual;
        final Future<String> f = pool.submit(() -> describe(sample, password));
        try {
            actual = f.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (final TimeoutException e) {
            f.cancel(true);
            actual = null;
            failed++;
            problems.add(path + ": time limit exceeded (" + timeoutSeconds + " s)");
            CONSOLE.println("TIMEOUT  " + path);
            return;
        } catch (final InterruptedException | ExecutionException e) {
            final Throwable c = e.getCause() != null ? e.getCause() : e;
            failed++;
            problems.add(path + ": runner error " + c);
            CONSOLE.println("FAILED   " + path + " (" + c + ")");
            return;
        }
        final String ms = String.format(" (%d ms)", (System.nanoTime() - start) / 1000000);
        if (expected == null) {
            created++;
            if (update) write(ref, actual);
            CONSOLE.println("NEW      " + path + ms + (update ? " - reference written" : " - run with --update to write its reference"));
        } else if (expected.equals(actual)) {
            ok++;
            CONSOLE.println("OK       " + path + ms);
        } else {
            diff++;
            problems.add(path + ": " + firstDifference(expected, actual));
            CONSOLE.println("DIFF     " + path + ms + " - " + firstDifference(expected, actual));
            if (update) write(ref, actual);
            else write(new File(root, "test/out/" + path + ".actual.txt"), actual);
        }
    }

    private static String value(final String text, final String key) {
        for (final String line : text.split("\n")) {
            if (line.startsWith(key)) return line.substring(key.length());
        }
        return null;
    }

    private static void write(final File f, final String text) throws IOException {
        final File dir = f.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) throw new IOException("Cannot create " + dir);
        Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
    }

    /** "line N: expected ... / actual ..."; a changed input file is reported first. */
    private static String firstDifference(final String expected, final String actual) {
        final String[] a = expected.split("\n", -1);
        final String[] b = actual.split("\n", -1);
        if (a.length > 1 && b.length > 1 && !a[1].equals(b[1])) {
            final String restA = expected.substring(expected.indexOf('\n', expected.indexOf('\n') + 1));
            final String restB = actual.substring(actual.indexOf('\n', actual.indexOf('\n') + 1));
            return "the sample file changed (" + (restA.equals(restB) ? "same results" : "results differ too: " + firstDifference(restA, restB)) + ")";
        }
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            final String x = i < a.length ? a[i] : "<end>";
            final String y = i < b.length ? b[i] : "<end>";
            if (!x.equals(y)) return "line " + (i + 1) + ": expected [" + x + "] got [" + y + "]";
        }
        return "?";
    }

    // =========================================================================
    // Description of a sample
    // =========================================================================

    /** The reference text of a sample: input, identification, listing, extracted files. */
    static String describe(final File sample, final String password) throws IOException {
        final StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append('\n');
        sb.append("input: ").append(sha256(sample)).append(' ').append(sample.length()).append('\n');
        if (password != null) sb.append("password: ").append(password).append('\n');
        final Arcana arcana = password == null ? null : Arcana.withPassword(password.getBytes(StandardCharsets.UTF_8));
        // identification
        try {
            final Identification id = Arcana.identify(sample);
            sb.append("identify: ").append(id.category).append(" | ").append(clean(id.oneLine(), sample)).append('\n');
            for (final Map.Entry<String, String> d : id.getDetails().entrySet()) sb.append("  ").append(d.getKey()).append(": ").append(clean(d.getValue(), sample)).append('\n');
        } catch (final Exception | StackOverflowError e) {
            sb.append("identify: ERROR ").append(error(e, sample)).append('\n');
        }
        // listing
        try {
            final List<ArcanaEntry> entries = arcana != null ? arcana.list(sample) : Arcana.listEntries(sample);
            final List<String> lines = new ArrayList<String>();
            for (final ArcanaEntry e : entries) lines.add(e.getName() + (e.isDirectory() ? " (folder)" : " " + e.getUncompressedSize()) + (e.isEncrypted() ? " encrypted" : ""));
            Collections.sort(lines);
            sb.append("list: ").append(lines.size()).append(" entries\n");
            for (final String l : lines) sb.append("  ").append(l).append('\n');
        } catch (final Exception | StackOverflowError e) {
            sb.append("list: ERROR ").append(error(e, sample)).append('\n');
        }
        // extraction
        final File out = Files.createTempDirectory("arcana-regression-").toFile();
        try {
            try {
                if (arcana != null) arcana.extract(sample, out);
                else Arcana.extractTo(sample, out);
            } catch (final Exception | StackOverflowError e) {
                // what was written before the error depends on timing (parallel extraction): not compared
                sb.append("extract: ERROR ").append(error(e, sample)).append('\n');
                return sb.toString();
            }
            final List<String> files = new ArrayList<String>();
            hashTree(out, "", files);
            Collections.sort(files);
            sb.append("extracted: ").append(files.size()).append(" items\n");
            for (final String l : files) sb.append("  ").append(l).append('\n');
        } finally {
            delete(out);
        }
        return sb.toString();
    }

    private static String error(final Throwable e, final File sample) {
        final String m = e.getMessage();
        return e.getClass().getSimpleName() + (m == null ? "" : ": " + clean(m, sample));
    }

    /** Removes what depends on the machine (paths of the sample and of the temporary folders). */
    private static String clean(final String s, final File sample) {
        String r = s.replace(sample.getAbsolutePath(), "<sample>");
        final String tmp = System.getProperty("java.io.tmpdir");
        if (tmp != null && !tmp.isEmpty()) r = r.replace(new File(tmp).getAbsolutePath(), "<tmp>");
        r = r.replaceAll("arcana-[a-z]+-[0-9]+", "arcana-tmp");
        return r.replace('\r', ' ').replace('\n', ' ');
    }

    private static void hashTree(final File dir, final String prefix, final List<String> out) throws IOException {
        final File[] files = dir.listFiles();
        if (files == null) return;
        for (final File f : files) {
            if (f.isDirectory()) {
                final String[] inside = f.list();
                if (inside != null && inside.length == 0) out.add(prefix + f.getName() + "/ (empty folder)");
                hashTree(f, prefix + f.getName() + "/", out);
            } else {
                out.add(prefix + f.getName() + " " + f.length() + " " + sha256(f));
            }
        }
    }

    static String sha256(final File f) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            final byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            final StringBuilder sb = new StringBuilder(64);
            for (final byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (final NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    private static void delete(final File f) {
        final File[] files = f.listFiles();
        if (files != null) for (final File c : files) delete(c);
        if (!f.delete()) f.deleteOnExit();
    }
}
