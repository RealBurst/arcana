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
package be.stef.arcana;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import be.stef.arcana.compressor.ArchiveCompressor;
import be.stef.arcana.detector.ArchiveDetector;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.extractor.SfxExtractor;
import be.stef.arcana.analyze.AnalyzerRegistry;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.FileCarver;
import be.stef.arcana.formats.recover.ArchiveRecoverer;
import be.stef.arcana.formats.recover.ForceUnpacker;
import be.stef.arcana.plugin.ArcanaPlugin;
import be.stef.arcana.plugin.BuiltinFormat;
import be.stef.arcana.plugin.FormatRegistry;
import be.stef.arcana.plugin.PluginManager;
import be.stef.arcana.formats.recover.RecoveryReport;

/**
 * Main entry point for the Arcana archive library.
 *
 * <p>Provides a unified, pure-Java, JNI-free API for extracting and compressing
 * archives in multiple formats.</p>
 *
 * <h3>Simple usage</h3>
 * <pre>
 *     // Auto-detect format and extract
 *     Arcana.extractTo(new File("archive.tar.gz"), new File("/tmp/out"));
 *
 *     // List entries without extracting
 *     List&lt;ArcanaEntry&gt; entries = Arcana.listEntries(new File("archive.rar"));
 *
 *     // Force a specific format
 *     Arcana.with(ArcanaFormat.BZIP2).extract(stream, destination);
 *
 *     // Encrypted archive
 *     Arcana.withPassword("secret".getBytes()).extract(archive, dest);
 * </pre>
 *
 * <h3>Command-line usage</h3>
 * <pre>
 *     arcana x  archive.zip  [dest]  [-p password]  [-f format]
 *     arcana l  archive.rar          [-p password]  [-f format]
 *     arcana c  source  archive.7z   -t 7z          [-l level]
 *     arcana s  file.exe  [dest]  [-n]
 *     arcana r  damaged.zip  [dest]
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public final class Arcana {

    private final ArcanaFormat forcedFormat;
    private final ArcanaPlugin forcedPlugin; // format handled by a plugin (see PluginManager)
    private final byte[]       password;

    private Arcana(final ArcanaFormat format, final byte[] password) {
        this(format, null, password);
    }

    private Arcana(final ArcanaFormat format, final ArcanaPlugin plugin, final byte[] password) {
        this.forcedFormat = format;
        this.forcedPlugin = plugin;
        this.password     = password != null ? password.clone() : null; // defensive copy
    }

    // =========================================================================
    // Static convenience API
    // =========================================================================

    public static void extractTo(final File archive, final File destination) throws IOException {
        new Arcana(null, null).doExtract(archive, destination);
    }

    public static void extractTo(final String archivePath, final String destinationPath) throws IOException {
        extractTo(new File(archivePath), new File(destinationPath));
    }

    public static List<ArcanaEntry> listEntries(final File archive) throws IOException {
        return new Arcana(null, null).doList(archive);
    }

    // =========================================================================
    // Forced extraction of a damaged archive
    // =========================================================================

    /**
     * Forced extraction of a DAMAGED archive: recovers as much as possible instead
     * of stopping at the first error. <b>The result is uncertain</b>: files may be
     * incomplete or contain garbage. The returned report (also written as
     * {@value RecoveryReport#REPORT_FILE} in the destination) gives the status of
     * every file (OK, UNVERIFIED, BAD_CHECKSUM, PARTIAL, LOST).
     */
    public static RecoveryReport forceUnpack(final File archive, final File destination) throws IOException {
        return new Arcana(null, null).doForceUnpack(archive, destination);
    }

    /** Same as {@link #forceUnpack(File, File)} with this instance's format / password. */
    public RecoveryReport forceExtract(final File archive, final File destination) throws IOException {
        return doForceUnpack(archive, destination);
    }

    private RecoveryReport doForceUnpack(final File archive, final File destination) throws IOException {
        final ArcanaPlugin plugin = forcedPlugin != null ? forcedPlugin : forcedFormat != null ? null : detectPlugin(archive);
        if (plugin != null) {
            try (ExtractionGuard.Scope scope = ExtractionGuard.begin(archive)) {
                final ArchiveRecoverer recoverer = plugin.createRecoverer(password);
                if (recoverer != null) return ForceUnpacker.unpack(archive, destination, archive.getName(), recoverer);
                // no recovery strategy: normal extraction by the plugin, keeping everything written before an error
                return ForceUnpacker.unpack(archive, destination, ArcanaFormat.UNKNOWN, (a, d) -> plugin.createExtractor(password).extract(a, d), password);
            }
        }
        ArcanaFormat format;
        try {
            format = resolveFormat(archive);
        } catch (final ArcanaUnsupportedFormatException e) {
            format = ArchiveDetector.detectByExtension(archive.getName()); // damaged header: trust the name
            if (format == ArcanaFormat.UNKNOWN) throw e;
        }
        try (ExtractionGuard.Scope scope = ExtractionGuard.begin(archive)) {
            final ArcanaFormat f = format;
            return ForceUnpacker.unpack(archive, destination, f, (a, d) -> createExtractor(f, password).extract(a, d), password);
        }
    }

    // =========================================================================
    // Split (files glued one after the other)
    // =========================================================================

    /**
     * Lists the files embedded one after the other in {@code file} (EXE, DLL,
     * archives, images... and unrecognized gaps), without writing anything.
     */
    public static List<FileCarver.Item> scanEmbedded(final File file) throws IOException {
        PluginManager.get(); // registers plugin carving probes, if any
        return FileCarver.scan(file);
    }

    /**
     * Identifies {@code file}: what kind of file it is, its version when known,
     * and a few details (see {@link AnalyzerRegistry}). Never null.
     */
    public static Identification identify(final File file) throws IOException {
        PluginManager.get(); // registers external analyzers, if any
        final Identification id = AnalyzerRegistry.identify(file);
        if (!"unknown".equals(id.type)) return id;
        // no analyzer matched: name it from the format detection (plugins, then built-in formats)
        final ArcanaPlugin plugin = PluginManager.get().detect(file);
        if (plugin != null) return Identification.of("archive", plugin.getName()).description(plugin.getName() + " (plugin " + plugin.getId() + ")").build();
        final ArcanaFormat fmt = ArchiveDetector.detectByContent(file);
        if (fmt != ArcanaFormat.UNKNOWN && fmt != ArcanaFormat.SFX) return Identification.of("archive", fmt.getLabel()).description(fmt.getLabel() + " archive").build();
        return id;
    }

    /**
     * Splits {@code file} into the files it is made of (see {@link FileCarver}).
     * The pieces are written into {@code destination/<file name without extension>}
     * ({@code _split} is appended if a file of that name exists).
     *
     * @return the pieces written, in file order
     */
    public static List<FileCarver.Item> split(final File file, final File destination) throws IOException {
        PluginManager.get(); // registers plugin carving probes, if any
        return FileCarver.split(file, splitDirectory(file, destination));
    }

    /** Directory receiving the pieces of {@code file}. */
    public static File splitDirectory(final File file, final File destination) {
        String base = file.getName();
        final int dot = base.lastIndexOf('.');
        if (dot > 0) base = base.substring(0, dot);
        File dir = new File(destination, base);
        if (dir.exists() && !dir.isDirectory()) dir = new File(destination, base + "_split");
        return dir;
    }

    // =========================================================================
    // Fluent API
    // =========================================================================

    /** Returns an Arcana instance that forces the given format (bypasses auto-detection). */
    public static Arcana with(final ArcanaFormat format) {
        return new Arcana(format, null);
    }

    /** Returns an Arcana instance configured with a password for encrypted archives. */
    public static Arcana withPassword(final byte[] password) {
        return new Arcana(null, password);
    }

    /** Returns an Arcana instance that forces the given format and uses the given password. */
    public static Arcana with(final ArcanaFormat format, final byte[] password) {
        return new Arcana(format, password);
    }

    /** Returns an Arcana instance that uses the given plugin (bypasses auto-detection). */
    public static Arcana with(final ArcanaPlugin plugin, final byte[] password) {
        return new Arcana(null, plugin, password);
    }

    /**
     * Returns an Arcana instance that uses the plugin with this id or extension.
     *
     * @throws ArcanaUnsupportedFormatException if no loaded plugin matches
     */
    public static Arcana withPlugin(final String idOrExtension, final byte[] password) throws ArcanaUnsupportedFormatException {
        final PluginManager pm = PluginManager.get();
        ArcanaPlugin p = pm.findById(idOrExtension);
        if (p == null) p = pm.findByExtension(idOrExtension);
        if (p == null) throw new ArcanaUnsupportedFormatException("No plugin for: " + idOrExtension);
        return new Arcana(null, p, password);
    }

    public void extract(final File archive, final File destination) throws IOException {
        doExtract(archive, destination);
    }

    public void extract(final InputStream in, final File destination) throws IOException {
        if (forcedFormat == null && forcedPlugin == null) throw new ArcanaUnsupportedFormatException(
                "Format must be specified via Arcana.with(format) when extracting from a stream.");
        try (ExtractionGuard.Scope scope = ExtractionGuard.begin(0L)) {
            (forcedPlugin != null ? forcedPlugin.createExtractor(password) : createExtractor(forcedFormat, password)).extract(in, destination);
        }
    }

    public List<ArcanaEntry> list(final File archive) throws IOException {
        return doList(archive);
    }

    // =========================================================================
    // Internal dispatch
    // =========================================================================

    private void doExtract(final File archive, final File destination) throws IOException {
        try (ExtractionGuard.Scope scope = ExtractionGuard.begin(archive)) {
            extractorFor(archive).extract(archive, destination);
        }
    }

    private List<ArcanaEntry> doList(final File archive) throws IOException {
        return extractorFor(archive).list(archive);
    }

    /**
     * Extractor of {@code archive}: forced plugin / format, else the built-in
     * formats recognized by their content, else the plugins, else the built-in
     * detection by extension and the self-extracting archive search.
     */
    private ArchiveExtractor extractorFor(final File archive) throws IOException {
        if (forcedPlugin != null) return forcedPlugin.createExtractor(password);
        if (forcedFormat != null) return createExtractor(forcedFormat, password);
        final ArcanaPlugin plugin = detectPlugin(archive);
        if (plugin != null) return plugin.createExtractor(password);
        return createExtractor(resolveFormat(archive), password);
    }

    /**
     * Plugin handling {@code archive}, or null: first the plugins with a priority
     * (they may replace a built-in format), then - only when no built-in format
     * recognizes the content - the other plugins.
     */
    private static ArcanaPlugin detectPlugin(final File archive) throws IOException {
        final PluginManager pm = PluginManager.get();
        final ArcanaPlugin priority = pm.detect(archive, true);
        if (priority != null) return priority;
        final ArcanaFormat byContent = ArchiveDetector.detectByContent(archive);
        if (byContent != ArcanaFormat.UNKNOWN && byContent != ArcanaFormat.SFX) return null;
        return pm.detect(archive, false);
    }

    private ArcanaFormat resolveFormat(final File archive) throws IOException {
        if (forcedFormat != null) return forcedFormat;
        ArcanaFormat detected = ArchiveDetector.detect(archive);
        if (detected == ArcanaFormat.GZIP) {
            final String n = archive.getName().toLowerCase();
            if (n.endsWith(".tar.gz") || n.endsWith(".tgz")) return ArcanaFormat.TAR_GZ;
        }
        if (detected == ArcanaFormat.BZIP2) {
            final String n = archive.getName().toLowerCase();
            if (n.endsWith(".tar.bz2") || n.endsWith(".tbz2") || n.endsWith(".tbz")) return ArcanaFormat.TAR_BZ2;
        }
        if (detected == ArcanaFormat.XZ) {
            final String n = archive.getName().toLowerCase();
            if (n.endsWith(".tar.xz") || n.endsWith(".txz")) return ArcanaFormat.TAR_XZ;
        }
        if (detected == ArcanaFormat.ZSTD) {
            final String n = archive.getName().toLowerCase();
            if (n.endsWith(".tar.zst") || n.endsWith(".tzst")) return ArcanaFormat.TAR_ZSTD;
        }
        if (detected == ArcanaFormat.LZ4) {
            final String n = archive.getName().toLowerCase();
            if (n.endsWith(".tar.lz4") || n.endsWith(".tlz4")) return ArcanaFormat.TAR_LZ4;
        }
        if (detected == ArcanaFormat.UNKNOWN) {
            // Unknown prefix followed by an archive (script + ZIP, stub + 7z...)?
            try {
                SfxExtractor.locate(archive);
                return ArcanaFormat.SFX;
            } catch (final ArcanaUnsupportedFormatException e) {
                final java.util.regex.Matcher volume = java.util.regex.Pattern.compile("(?i)(.*\\.7z\\.)(\\d+)").matcher(archive.getName());
                if (volume.matches() && !volume.group(2).matches("0*[01]")) {
                    final String first = String.format("%0" + volume.group(2).length() + "d", 1);
                    throw new ArcanaUnsupportedFormatException("Volume of a split 7z archive: open the first volume, " + volume.group(1) + first);
                }
                throw new ArcanaUnsupportedFormatException("Cannot detect archive format for: " + archive.getName());
            }
        }
        return detected;
    }

    /** Extractor of a built-in format (see {@link FormatRegistry}). */
    private static ArchiveExtractor createExtractor(final ArcanaFormat format, final byte[] password) throws IOException {
        return FormatRegistry.builtin(format).createExtractor(password);
    }

    // =========================================================================
    // Command-line interface
    // =========================================================================

    /**
     * Command-line entry point.
     *
     * <pre>
     * EXTRACTION:
     *   arcana x  &lt;archive&gt; [dest]   [-p password]  [-f format]
     *   arcana l  &lt;archive&gt;          [-p password]  [-f format]
     *
     * COMPRESSION:
     *   arcana c  &lt;source&gt; &lt;archive&gt;  -t format     [-l 0-9]
     *
     * Commands:
     *   x  Extract archive to destination (default: current directory)
     *   l  List archive contents
     *   c  Compress source file or directory into archive
     *
     * Options:
     *   -p &lt;password&gt;  Password for encrypted archives (ZIP, 7z, RAR)
     *   -f &lt;format&gt;   Force archive format for extraction
     *   -t &lt;format&gt;   Target format for compression
     *   -l &lt;level&gt;    Compression level 0-9 (for 7z and xz, default 6)
     *
     * Extract formats : zip rar 7z tar tar.gz tar.bz2 tar.xz tar.lz4 tar.zst tar.br
     *                   gz bz2 xz lzma Z lz4 zst snappy br
     *                   lzh cab a deb rpm xar cpio iso
     * Compress formats: zip tar tar.gz tar.bz2 tar.xz tar.lz4 gz bz2 7z xz lzh cab
     *
     * Examples:
     *   arcana x archive.zip
     *   arcana x archive.rar  ./out  -p secret
     *   arcana x archive.7z   ./out  -p secret
     *   arcana l archive.tar.gz
     *   arcana c ./mydir   archive.zip    -t zip
     *   arcana c ./mydir   archive.7z     -t 7z   -l 9
     *   arcana c file.txt  file.tar.gz    -t tar.gz
     * </pre>
     */
    public static void main(final String[] args) {
        printPluginStatus();
        if (args.length > 0 && (args[0].equals("-v") || args[0].equals("--version") || args[0].equalsIgnoreCase("version"))) { System.out.println("Arcana " + versionLabel()); return; }
        if (args.length == 0) { printUsage(); System.exit(1); }
        if (args[0].equals("-h") || args[0].equals("--help") || args[0].equals("--h") || args[0].equalsIgnoreCase("help")) { printHelp(); return; }

        final String cmd = args[0].toLowerCase();
        if (!cmd.equals("x") && !cmd.equals("l") && !cmd.equals("c") && !cmd.equals("s") && !cmd.equals("r") && !cmd.equals("i") && !cmd.equals("id") && !cmd.equals("formats") && !cmd.equals("plugins")) {
            System.err.println("Unknown command: " + args[0]);
            printUsage();
            System.exit(1);
        }

        final java.util.List<String> positional = new java.util.ArrayList<String>();
        String password = null, forcedFmt = null, targetFmt = null, outputDir = null;
        int level = -1;
        boolean listOnly = false;

        for (int i = 1; i < args.length; i++) {
            final String a = args[i];
            if      (a.equals("-n")) { listOnly = true; }
            else if (a.equals("-p") && i+1 < args.length) { password  = args[++i]; }
            else if (a.equals("-f") && i+1 < args.length) { forcedFmt = args[++i]; }
            else if (a.equals("-t") && i+1 < args.length) { targetFmt = args[++i]; }
            else if (a.equals("-o") && i+1 < args.length) { outputDir = args[++i]; }
            else if (a.equals("-l") && i+1 < args.length) {
                try { level = Integer.parseInt(args[++i]); }
                catch (NumberFormatException e) { System.err.println("Invalid level: " + args[i]); System.exit(1); }
            }
            else if (!a.startsWith("-")) { positional.add(a); }
            else { System.err.println("Unknown option: " + a); printUsage(); System.exit(1); }
        }

        try {
            if (cmd.equals("plugins")) {
                if (positional.isEmpty()) printPlugins();
                else printPluginDetection(new File(positional.get(0)));
                return;
            }
            if (cmd.equals("formats")) {
                final String sub = positional.isEmpty() ? "all" : positional.get(0).toLowerCase();
                printFormats(sub); return;
            }
            if (cmd.equals("r")) {
                if (positional.isEmpty()) { System.err.println("Missing archive path."); System.exit(1); }
                final File archive = new File(positional.get(0));
                if (!archive.isFile()) { System.err.println("File not found: " + archive); System.exit(1); }
                final File dest = new File(outputDir != null ? outputDir : positional.size() > 1 ? positional.get(1) : ".");
                final byte[] pwd = password != null ? password.getBytes("UTF-8") : null;
                final Arcana arcana = forcedArcana(forcedFmt, pwd);
                System.out.println("*** " + RecoveryReport.WARNING + " ***");
                System.out.println("Recovering " + archive + " -> " + dest.getAbsolutePath());
                final RecoveryReport report = arcana.forceExtract(archive, dest);
                System.out.println();
                System.out.println(report.toText());
                System.out.println("Report written to " + new File(dest, RecoveryReport.REPORT_FILE).getAbsolutePath());
                return;
            }
            if (cmd.equals("i") || cmd.equals("id")) {
                if (positional.isEmpty()) { System.err.println("Missing file path."); System.exit(1); }
                final File file = new File(positional.get(0));
                if (!file.isFile()) { System.err.println("File not found: " + file); System.exit(1); }
                final Identification id = identify(file);
                System.out.println("File       : " + file.getName());
                System.out.println("Category   : " + id.category);
                System.out.println("Type       : " + id.type + (id.version != null && !id.version.isEmpty() ? " " + id.version : ""));
                System.out.println("Description: " + id.description);
                for (final java.util.Map.Entry<String, String> e : id.getDetails().entrySet()) {
                    System.out.printf("  %-14s : %s%n", e.getKey(), e.getValue());
                }
                if (id.confidence < 100) System.out.println("(confidence: " + id.confidence + "%)");
                return;
            }
            if (cmd.equals("s")) {
                if (positional.isEmpty()) { System.err.println("Missing file path."); System.exit(1); }
                final File file = new File(positional.get(0));
                if (!file.isFile()) { System.err.println("File not found: " + file); System.exit(1); }
                PluginManager.get(); // registers plugin carving probes, if any
                final List<FileCarver.Item> items;
                if (listOnly) {
                    items = scanEmbedded(file);
                } else {
                    final File dir = splitDirectory(file, new File(outputDir != null ? outputDir : positional.size() > 1 ? positional.get(1) : "."));
                    System.out.println("Splitting " + file + " -> " + dir.getAbsolutePath());
                    items = FileCarver.split(file, dir);
                }
                System.out.println("  Offset         Size  Type     Description");
                int known = 0, padding = 0;
                for (final FileCarver.Item it : items) {
                    System.out.println("  " + it);
                    if (it.isPadding()) padding++;
                    else if (!it.isUnknown()) known++;
                }
                System.out.println("  " + (items.size() - padding) + " piece(s), " + known + " recognized" + (padding > 0 ? ", " + padding + " zero-filled gap(s) skipped" : ""));
                return;
            }
            if (cmd.equals("x") || cmd.equals("l")) {
                if (positional.isEmpty()) { System.err.println("Missing archive path."); System.exit(1); }
                final File  archive = new File(positional.get(0));
                if (!archive.exists()) { System.err.println("File not found: " + archive); System.exit(1); }
                final byte[] pwd    = password != null ? password.getBytes("UTF-8") : null;
                final Arcana arcana = forcedArcana(forcedFmt, pwd);

                if (cmd.equals("l")) {
                    final List<ArcanaEntry> entries = arcana.list(archive);
                    System.out.printf("%-12s  %-19s  %s%n", "Size", "Modified", "Name");
                    System.out.println("------------  -------------------  ----------------------------------------");
                    for (final ArcanaEntry e : entries) {
                        final String size  = e.getUncompressedSize() >= 0 ? String.valueOf(e.getUncompressedSize()) : "?";
                        final String mtime = e.getLastModifiedTime() > 0
                                ? new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                                        .format(new java.util.Date(e.getLastModifiedTime() * 1000L))
                                : "-";
                        System.out.printf("%12s  %-19s  %s%s%n",
                                size, mtime, e.getName(), e.isDirectory() ? "/" : "");
                    }
                    System.out.println("  " + entries.size() + " entr" + (entries.size() == 1 ? "y" : "ies"));
                } else {
                    final File dest = new File(outputDir != null ? outputDir : positional.size() > 1 ? positional.get(1) : ".");
                    dest.mkdirs();
                    System.out.println("Extracting " + archive + " -> " + dest.getAbsolutePath());
                    arcana.extract(archive, dest);
                    System.out.println("Done.");
                }

            } else {
                // compress
                if (positional.size() < 2) {
                    System.err.println("Usage: arcana c <source> <archive> -t <format>"); System.exit(1);
                }
                final File source  = new File(positional.get(0));
                final File archive = new File(positional.get(1));
                if (!source.exists()) { System.err.println("Source not found: " + source); System.exit(1); }
                final ArchiveCompressor comp = resolveCompressor(targetFmt, archive, level, password != null ? password.getBytes("UTF-8") : null);
                System.out.println("Compressing " + source + " -> " + archive);
                final long t = System.currentTimeMillis();
                comp.compress(source, archive);
                System.out.printf("Done. %d bytes in %d ms.%n", archive.length(), System.currentTimeMillis() - t);
            }
        } catch (final Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        }
    }

    /** Arcana instance for the CLI option -f: format name of the registry (built-in or plugin). */
    private static Arcana forcedArcana(final String fmt, final byte[] pwd) {
        if (fmt == null) return new Arcana(null, pwd);
        final ArcanaPlugin h = FormatRegistry.byName(fmt);
        if (h instanceof BuiltinFormat) return new Arcana(((BuiltinFormat) h).getFormat(), pwd);
        if (h != null) return new Arcana(null, h, pwd);
        System.err.println("Unknown format: " + fmt);
        System.exit(1);
        return null;
    }

    /** Compressor for the CLI command c: -t name, else the longest known extension of the archive name. */
    private static ArchiveCompressor resolveCompressor(final String targetFmt, final File archive, final int level, final byte[] pwd) throws IOException {
        final ArcanaPlugin h = targetFmt != null ? FormatRegistry.byName(targetFmt) : FormatRegistry.byFileName(archive.getName());
        if (h == null) {
            System.err.println(targetFmt != null ? "Unknown format: " + targetFmt : "Cannot infer format from filename, use -t.");
            System.exit(1);
        }
        final ArchiveCompressor c = h.createCompressor(level, pwd);
        if (c == null) {
            System.err.println("Arcana cannot create " + h.getName() + " archives (extraction only). See: arcana formats compress");
            System.exit(1);
        }
        return c;
    }

    /**
     * Prints the plugin status to stderr on every invocation.
     * Reports refused plugins (with their reason) and warns when no plugin is found.
     * Does nothing if all plugins loaded cleanly.
     */
    private static void printPluginStatus() {
        final List<PluginManager.PluginInfo> all = PluginManager.get().getPlugins();
        if (all.isEmpty()) {
            System.err.println("[plugins] No plugin found in any plugin directory.");
            return;
        }
        int loaded = 0, refused = 0;
        for (final PluginManager.PluginInfo i : all) { if (i.isLoaded()) loaded++; else refused++; }
        if (refused == 0) return; // all clean: nothing to report
        System.err.println("[plugins] " + loaded + " loaded, " + refused + " refused:");
        for (final PluginManager.PluginInfo i : all) {
            if (!i.isLoaded()) {
                final String title = "?".equals(i.id) && i.jar != null ? i.jar.getName() : i.id + (i.version != null && !i.version.isEmpty() ? " " + i.version : "") + " - " + i.name;
                System.err.println("  [REFUSED] " + title + " : " + i.problem);
            }
        }
        System.err.println("  (run 'arcana plugins' for details)");
        System.err.println();
    }

    /**
     * Returns the Arcana version, read from the Implementation-Version attribute of the JAR manifest
     * (written by build.bat / build.sh from the VERSION file).
     * Returns "dev" when running from classes that are not packaged in a JAR (e.g. from Eclipse).
     */
    public static String getVersion() {
        final Package p = Arcana.class.getPackage();
        final String v = p != null ? p.getImplementationVersion() : null;
        return v != null && !v.isEmpty() ? v : "dev";
    }

    /** "v1.0.0" when packaged, "(dev)" when running from unpackaged classes. */
    private static String versionLabel() {
        final String v = getVersion();
        return "dev".equals(v) ? "(dev)" : "v" + v;
    }

    /** Usage, printed when Arcana is run without arguments or with a wrong command/option. */
    private static void printUsage() {
        System.out.println("Arcana " + versionLabel() + " - multi-format archive tool");
        System.out.println("Usage:");
        System.out.println("  arcana x <archive> [-o dest] [-p password]  [-f format]");
        System.out.println("  arcana l <archive>           [-p password]  [-f format]");
        System.out.println("  arcana c <source>  <archive> [-t format]    [-l 0-9]    [-p password]");
        System.out.println("  arcana s <file>    [-o dest] [-n]");
        System.out.println("  arcana r <archive> [-o dest] [-p password]  [-f format]");
        System.out.println("  arcana i <file>");
        System.out.println("  arcana formats [extract|compress]");
        System.out.println("  arcana plugins [<file>]");
        System.out.println("  arcana version | help");
        System.out.println();
        System.out.println("Run 'arcana help' (or -h, --help) for the description of the commands, options and examples.");
        System.out.println("Run 'arcana formats [extract|compress]' for handled formats.");
    }

    /** Full help: arcana help, -h, --help. */
    private static void printHelp() {
        System.out.println("Arcana " + versionLabel() + " - multi-format archive tool");
        System.out.println("Usage: arcana <command> [options] <file> [...]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  x <archive> [-o dest] [-p password] [-f format]");
        System.out.println("        Extract an archive (default destination: current directory)");
        System.out.println("  l <archive> [-p password] [-f format]");
        System.out.println("        List the contents of an archive");
        System.out.println("  c <source> <archive> [-t format] [-l 0-9] [-p password]");
        System.out.println("        Compress a file or directory (format inferred from the archive extension)");
        System.out.println("  r <archive> [-o dest] [-p password] [-f format]");
        System.out.println("        Recover a DAMAGED archive: forced extraction + recovery report");
        System.out.println("  s <file> [-o dest] [-n]");
        System.out.println("        Split a file made of files glued together (EXE, archives, images...)");
        System.out.println("        into dest/<file name>/");
        System.out.println("  i <file>");
        System.out.println("        Identify a file: type, version and details (archive, executable, image, DB...)");
        System.out.println("  formats [extract|compress]");
        System.out.println("        List the supported formats");
        System.out.println("  plugins [<file>]");
        System.out.println("        List the plugins (loaded or refused); with a <file>, show which format is chosen and why");
        System.out.println("  version   Print the version (also -v, --version)");
        System.out.println("  help      Print this help (also -h, --help)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -o <dir>       Output directory for x, r and s (also accepted as second positional arg)");
        System.out.println("  -p <password>  Password: decryption, or encryption with c (zip and 7z: AES-256)");
        System.out.println("  -f <format>    Force the input format (bypasses auto-detection)");
        System.out.println("  -t <format>    Force the output format of c");
        System.out.println("  -l <level>     Compression level 0-9 for 7z and xz (default: 6)");
        System.out.println("  -n             With s: list the pieces without extracting");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  arcana x archive.rar -o ./out -p secret");
        System.out.println("  arcana l archive.tar.gz");
        System.out.println("  arcana c ./mydir backup.tar.xz");
        System.out.println("  arcana c ./mydir vault.7z -l 9 -p secret");
        System.out.println("  arcana r damaged.zip -o ./rescue");
        System.out.println("  arcana s setup.exe -n");
    }

    private static void printPlugins() {
        System.out.println("Plugin directories:");
        for (final File d : PluginManager.pluginDirectories()) System.out.println("  " + d.getAbsolutePath() + (d.isDirectory() ? "" : "  (does not exist)"));
        final List<PluginManager.PluginInfo> list = PluginManager.get().getPlugins();
        System.out.println();
        if (list.isEmpty()) { System.out.println("No plugin found."); return; }
        for (final PluginManager.PluginInfo i : list) {
            final String title = "?".equals(i.id) && i.jar != null ? i.jar.getName() : i.id + " " + i.version + " - " + i.name + (i.author.isEmpty() ? "" : " (" + i.author + ")");
            System.out.println((i.isLoaded() ? "[LOADED]  " : "[REFUSED] ") + title);
            if (i.isLoaded() && i.getPlugin() != null) {
                System.out.println("    priority   : " + priorityOf(i.getPlugin()) + "   capabilities: " + capabilitiesOf(i.getPlugin()));
            }
            System.out.println("    extensions : " + String.join(" ", i.extensions));
            System.out.println("    source     : " + (i.sourceUrl != null ? i.sourceUrl : "-") + "   license: " + (i.license != null ? i.license : "-"));
            if (i.jar != null) System.out.println("    jar        : " + i.jar.getAbsolutePath() + "   sha256: " + i.sha256);
            if (!i.isLoaded()) System.out.println("    problem    : " + i.problem);
        }
    }

    private static int priorityOf(final ArcanaPlugin p) {
        try {
            return p.getPriority();
        } catch (final RuntimeException e) {
            return 0;
        }
    }

    /** Lists which optional methods the plugin implements, to confirm they are seen. */
    private static String capabilitiesOf(final ArcanaPlugin p) {
        final StringBuilder sb = new StringBuilder("extract");
        try { if (p.createCompressor(-1) != null) sb.append(", compress"); } catch (final Exception ignored) { /* not a capability */ }
        try { if (p.createRecoverer(null) != null) sb.append(", recover"); } catch (final Exception ignored) { /* not a capability */ }
        try { if (p.createProbe() != null) sb.append(", carve-probe"); } catch (final Exception ignored) { /* not a capability */ }
        return sb.toString();
    }

    /**
     * Diagnostic: for a given file, prints every loaded plugin, whether it matches
     * the file, and which format or plugin Arcana finally chooses (and why). Meant
     * to answer "why is my plugin not used for this file?".
     */
    private static void printPluginDetection(final File file) throws IOException {
        if (!file.isFile()) { System.err.println("File not found: " + file); System.exit(1); }
        final PluginManager pm = PluginManager.get();
        System.out.println("Detection trace for: " + file.getName());
        System.out.println();
        // Built-in content detection (magic bytes / structure), used to decide plugin vs built-in.
        final ArcanaFormat byContent = ArchiveDetector.detectByContent(file);
        final ArcanaFormat byExt = ArchiveDetector.detectByExtension(file.getName());
        System.out.println("Built-in content detection : " + byContent + (byContent == ArcanaFormat.UNKNOWN ? "" : " (" + byContent.getLabel() + ")"));
        System.out.println("Built-in extension guess   : " + byExt + (byExt == ArcanaFormat.UNKNOWN ? "" : " (" + byExt.getLabel() + ")"));
        System.out.println();
        // Every loaded plugin: priority and whether matches() returns true for this file.
        int refused = 0;
        for (final PluginManager.PluginInfo pi : pm.getPlugins()) if (!pi.isLoaded()) refused++;
        if (refused > 0) System.out.println("WARNING: " + refused + " plugin(s) REFUSED and not usable - run 'arcana plugins' to see why (missing sources, license, or duplicate id).");
        System.out.println();
        final List<ArcanaPlugin> plugins = pm.getActivePlugins();
        if (plugins.isEmpty()) {
            System.out.println("No plugin loaded (see 'arcana plugins' for refused ones and the directories searched).");
        } else {
            System.out.println("Loaded plugins and their match on this file:");
            for (final ArcanaPlugin p : plugins) {
                String verdict;
                try {
                    verdict = pluginMatches(p, file) ? "MATCHES" : "no match";
                } catch (final RuntimeException | LinkageError e) {
                    verdict = "ERROR in matches(): " + e;
                }
                System.out.printf("  %-28s priority=%-3d probeSize=%-6d %s%n", safeId(p), priorityOf(p), probeSizeOf(p), verdict);
            }
        }
        System.out.println();
        // Reproduce the extraction dispatch to name the winner.
        System.out.println("Arcana would use: " + chosenFor(file, pm, byContent));
    }

    private static String chosenFor(final File file, final PluginManager pm, final ArcanaFormat byContent) throws IOException {
        final ArcanaPlugin priority = pm.detect(file, true);
        if (priority != null) return "plugin " + safeId(priority) + " (priority " + priorityOf(priority) + ", consulted before the built-in formats)";
        if (byContent != ArcanaFormat.UNKNOWN && byContent != ArcanaFormat.SFX) return "built-in format " + byContent.getLabel() + " (recognized by content; a non-priority plugin cannot override it)";
        final ArcanaPlugin other = pm.detect(file, false);
        if (other != null) return "plugin " + safeId(other) + " (matched after the built-in content detection)";
        try {
            return "built-in format " + resolveFormatStatic(file).getLabel();
        } catch (final ArcanaUnsupportedFormatException e) {
            return "nothing: " + e.getMessage();
        }
    }

    /** resolveFormat without an instance (same rules), for the diagnostic. */
    private static ArcanaFormat resolveFormatStatic(final File file) throws IOException {
        return new Arcana(null, null).resolveFormat(file);
    }

    private static boolean pluginMatches(final ArcanaPlugin p, final File file) throws IOException {
        final int probe = Math.min(1 << 20, Math.max(0, probeSizeOf(p)));
        final byte[] head = new byte[(int) Math.min(probe, file.length())];
        try (InputStream in = new java.io.FileInputStream(file)) {
            int n = 0;
            while (n < head.length) {
                final int k = in.read(head, n, head.length - n);
                if (k < 0) break;
                n += k;
            }
        }
        return p.matches(head, file.getName());
    }

    private static int probeSizeOf(final ArcanaPlugin p) {
        try {
            return Math.max(0, p.getProbeSize());
        } catch (final RuntimeException e) {
            return 0;
        }
    }

    private static String safeId(final ArcanaPlugin p) {
        try {
            return p.getId();
        } catch (final RuntimeException e) {
            return "?";
        }
    }

    private static void printFormats(final String filter) {
        final boolean showExtract  = filter.equals("all") || filter.equals("extract");
        final boolean showCompress = filter.equals("all") || filter.equals("compress");

        if (showExtract) {
            System.out.println("=== Extraction formats ===");
            final String[] titles = {"Archives", "Single-file compression", "Other"};
            final BuiltinFormat.Category[] cats = BuiltinFormat.Category.values();
            for (int c = 0; c < cats.length; c++) {
                System.out.println();
                System.out.println("  " + titles[c]);
                for (final BuiltinFormat b : FormatRegistry.builtins()) {
                    if (b.getCategory() == cats[c]) System.out.printf("    %-30s  %s%n", b.getDisplayExtensions(), b.getDescription());
                }
                if (cats[c] == BuiltinFormat.Category.SINGLE_FILE) System.out.println("    (a TAR or CPIO inside any of these is unpacked automatically: cpio.gz, cpio.xz, cpio.zst, tar.lzma, ...)");
            }
            System.out.println();
            System.out.println("  ZIP-based document formats (use -f zip or auto-detected by extension)");
            System.out.println("    docx docm dotx dotm             Microsoft Word");
            System.out.println("    xlsx xlsm xltx xltm             Microsoft Excel");
            System.out.println("    pptx pptm potx potm             Microsoft PowerPoint");
            System.out.println("    odt  ods  odp  odg  odf  odb   OpenDocument formats");
            System.out.println("    epub                            eBook");
            System.out.println("    apk  ipa                        Android / iOS package");
            System.out.println("    xpi  crx  vsix  nupkg           Browser/IDE extensions, NuGet");
            System.out.println("    kmz  aar  whl   egg             Google Earth, Android lib, Python");
            System.out.println("    cbz                             Comic Book ZIP");
            System.out.println("    xps  oxps  fcstd  3mf           XPS, FreeCAD, 3D Manufacturing");
        }

        if (showExtract && showCompress) System.out.println();

        if (showCompress) {
            System.out.println("=== Compression formats (-t parameter) ===");
            System.out.println();
            for (final BuiltinFormat b : FormatRegistry.builtins()) {
                if (b.canCompress()) System.out.printf("    %-30s  %s%n", String.join("  ", b.getExtensions()), b.getCompressDescription());
            }
        }
        final List<ArcanaPlugin> plugins = PluginManager.get().getActivePlugins();
        if (!plugins.isEmpty()) {
            System.out.println();
            System.out.println("=== Plugin formats (see: arcana plugins) ===");
            for (final ArcanaPlugin p : plugins) {
                boolean compress;
                try { compress = p.createCompressor(-1, null) != null; } catch (final Exception e) { compress = false; }
                int prio;
                try { prio = p.getPriority(); } catch (final RuntimeException e) { prio = 0; }
                System.out.printf("    %-30s  %s%s%s%n", String.join(" ", p.getExtensions()), p.getName(), compress ? " (extract + compress)" : " (extract)", prio > 0 ? " [priority " + prio + ": replaces built-in formats]" : "");
            }
        }
    }
}