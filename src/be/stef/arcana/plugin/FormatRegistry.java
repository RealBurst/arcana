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

import static be.stef.arcana.plugin.BuiltinFormat.Category.ARCHIVE;
import static be.stef.arcana.plugin.BuiltinFormat.Category.OTHER;
import static be.stef.arcana.plugin.BuiltinFormat.Category.SINGLE_FILE;

import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.compressor.BZip2Compressor;
import be.stef.arcana.compressor.CabCompressor;
import be.stef.arcana.compressor.GzipCompressor;
import be.stef.arcana.compressor.LhaCompressor;
import be.stef.arcana.compressor.SevenZCompressor;
import be.stef.arcana.compressor.TarBz2Compressor;
import be.stef.arcana.compressor.TarCompressor;
import be.stef.arcana.compressor.TarGzCompressor;
import be.stef.arcana.compressor.TarLz4Compressor;
import be.stef.arcana.compressor.TarXzCompressor;
import be.stef.arcana.compressor.XzCompressor;
import be.stef.arcana.compressor.ZipCompressor;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.extractor.ArExtractor;
import be.stef.arcana.extractor.BZip2Extractor;
import be.stef.arcana.extractor.BrotliExtractor;
import be.stef.arcana.extractor.CabExtractor;
import be.stef.arcana.extractor.ArjExtractor;
import be.stef.arcana.extractor.ChmExtractor;
import be.stef.arcana.extractor.MsLzExtractor;
import be.stef.arcana.extractor.CompressedStreamExtractor;
import be.stef.arcana.extractor.CpioExtractor;
import be.stef.arcana.extractor.GzipExtractor;
import be.stef.arcana.extractor.IsoExtractor;
import be.stef.arcana.extractor.LZ4Extractor;
import be.stef.arcana.extractor.LhaExtractor;
import be.stef.arcana.extractor.LzmaExtractor;
import be.stef.arcana.extractor.OleExtractor;
import be.stef.arcana.extractor.RarExtractor;
import be.stef.arcana.extractor.RpmExtractor;
import be.stef.arcana.extractor.SevenZExtractor;
import be.stef.arcana.extractor.SfxExtractor;
import be.stef.arcana.extractor.SnappyExtractor;
import be.stef.arcana.extractor.SquashfsExtractor;
import be.stef.arcana.extractor.TarBrotliExtractor;
import be.stef.arcana.extractor.TarBz2Extractor;
import be.stef.arcana.extractor.TarExtractor;
import be.stef.arcana.extractor.TarGzExtractor;
import be.stef.arcana.extractor.TarLz4Extractor;
import be.stef.arcana.extractor.TarXzExtractor;
import be.stef.arcana.extractor.TarZstdExtractor;
import be.stef.arcana.extractor.UdfExtractor;
import be.stef.arcana.extractor.WimExtractor;
import be.stef.arcana.extractor.XarExtractor;
import be.stef.arcana.extractor.XzExtractor;
import be.stef.arcana.extractor.ZExtractor;
import be.stef.arcana.extractor.ZipExtractor;
import be.stef.arcana.extractor.ZstdExtractor;
import be.stef.arcana.formats.lha.Lh5Encoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Single registry of every format: Arcana's built-in formats (as
 * {@link BuiltinFormat}) and the plugins ({@link PluginManager}). Extraction,
 * compression, the names accepted by -f / -t and the format listings all come
 * from here, so a new format (built-in or plugin) is declared in one place.
 *
 * @author Stef
 * @since 1.3
 */
public final class FormatRegistry {

    private static final List<BuiltinFormat> BUILTINS;
    private static final Map<ArcanaFormat, BuiltinFormat> BY_FORMAT = new EnumMap<ArcanaFormat, BuiltinFormat>(ArcanaFormat.class);

    static {
        final List<BuiltinFormat> l = new ArrayList<BuiltinFormat>();
        // ---- Archives ----
        l.add(new BuiltinFormat(ArcanaFormat.ZIP, ARCHIVE, names("zip"), "zip  jar  war  ear", "ZIP archive and Java archives", pw -> pw != null ? new ZipExtractor(pw) : new ZipExtractor(),
                "ZIP archive (files + directories) [-p: AES-256]", (level, pw) -> pw != null ? new ZipCompressor(pw) : new ZipCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.RAR, ARCHIVE, names("rar"), "rar  cbr", "RAR archive (v4 and v5), Comic Book RAR", pw -> pw != null ? new RarExtractor(new String(pw, StandardCharsets.UTF_8)) : new RarExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.SEVEN_Z, ARCHIVE, names("7z"), "7z   cb7", "7-Zip archive, Comic Book 7z", pw -> pw != null ? new SevenZExtractor(pw) : new SevenZExtractor(),
                "7-Zip LZMA2 (files + directories) [-l 0-9] [-p: AES-256]", (level, pw) -> new SevenZCompressor(level >= 0 ? level : 6, pw)));
        l.add(new BuiltinFormat(ArcanaFormat.TAR, ARCHIVE, names("tar"), "tar  gem", "TAR archive, RubyGems package", pw -> new TarExtractor(), "TAR archive (files + directories)", (level, pw) -> new TarCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_GZ, ARCHIVE, names("tar.gz", "tgz"), "tar.gz   tgz", "TAR + GZip", pw -> new TarGzExtractor(), "TAR + GZip  (files + directories)", (level, pw) -> new TarGzCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_BZ2, ARCHIVE, names("tar.bz2", "tbz2", "tbz"), "tar.bz2  tbz2", "TAR + BZip2", pw -> new TarBz2Extractor(), "TAR + BZip2 (files + directories)", (level, pw) -> new TarBz2Compressor()));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_XZ, ARCHIVE, names("tar.xz", "txz"), "tar.xz   txz", "TAR + XZ", pw -> new TarXzExtractor(), "TAR + XZ    (files + directories) [-l 0-9]", (level, pw) -> level >= 0 ? new TarXzCompressor(level) : new TarXzCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_LZ4, ARCHIVE, names("tar.lz4", "tlz4"), "tar.lz4  tlz4", "TAR + LZ4", pw -> new TarLz4Extractor(), "TAR + LZ4   (files + directories)", (level, pw) -> new TarLz4Compressor()));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_ZSTD, ARCHIVE, names("tar.zst", "tzst"), "tar.zst  tzst", "TAR + Zstandard", pw -> new TarZstdExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.TAR_BROTLI, ARCHIVE, names("tar.br", "tbr"), "tar.br   tbr", "TAR + Brotli", pw -> new TarBrotliExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.LHA, ARCHIVE, names("lzh", "lha"), "lzh  lha", "LHA/LZH archive (-lh0-, -lh4- to -lh7-)", pw -> new LhaExtractor(),
                "LHA (files + directories) [-l 5|6|7: -lh5- (default) / -lh6- / -lh7-]", (level, pw) -> new LhaCompressor(level == 7 ? Lh5Encoder.LH7 : level == 6 ? Lh5Encoder.LH6 : Lh5Encoder.LH5)));
        l.add(new BuiltinFormat(ArcanaFormat.CAB, ARCHIVE, names("cab"), "cab", "Microsoft Cabinet (stored, MSZIP, LZX)", pw -> new CabExtractor(), "Cabinet MSZIP (files + directories)", (level, pw) -> new CabCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.CPIO, ARCHIVE, names("cpio"), "cpio", "CPIO (newc SVR4 and odc formats)", pw -> new CpioExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.AR, ARCHIVE, names("a", "deb"), "a    deb", "AR archive, Debian package (deb: contents unpacked, control files in DEBIAN/)", pw -> new ArExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.RPM, ARCHIVE, names("rpm"), "rpm", "RPM package (gzip/bzip2/xz/zstd payload)", pw -> new RpmExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.XAR, ARCHIVE, names("xar"), "xar", "XAR archive (Apple)", pw -> new XarExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.ISO, ARCHIVE, names("iso"), "iso", "ISO 9660 disc image", pw -> new IsoExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.UDF, ARCHIVE, names("udf"), "udf", "UDF disc image (DVD, Blu-ray, Windows media), revisions 1.02 to 2.60", pw -> new UdfExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.SQUASHFS, ARCHIVE, names("sqfs", "squashfs", "snap"), "sqfs squashfs snap", "SquashFS 4.0 (gzip, LZMA, LZO, XZ, LZ4, Zstandard)", pw -> new SquashfsExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.WIM, ARCHIVE, names("wim", "swm", "esd"), "wim  esd", "Windows Imaging Format (XPRESS, LZX; not LZMS)", pw -> new WimExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.OLE, ARCHIVE, names("msi", "msp", "doc", "xls", "ppt", "msg"), "msi  msp  doc  xls  ppt  msg", "OLE compound file (MSI: installed file tree; Office 97-2003, Outlook: streams)", pw -> new OleExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.ARJ, ARCHIVE, names("arj"), "arj", "ARJ archive (methods 0 to 4)", pw -> new ArjExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.CHM, ARCHIVE, names("chm", "chi", "chq", "chw"), "chm", "Compiled HTML Help (LZX)", pw -> new ChmExtractor(), null, null));
        // ---- Single-file compression (a TAR or CPIO inside is unpacked automatically) ----
        l.add(new BuiltinFormat(ArcanaFormat.GZIP, SINGLE_FILE, names("gz", "gzip"), "gz   gzip", "GZip", pw -> new CompressedStreamExtractor(ArcanaFormat.GZIP, new GzipExtractor()), "GZip (single file only)", (level, pw) -> new GzipCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.BZIP2, SINGLE_FILE, names("bz2", "bzip2"), "bz2  bzip2", "BZip2", pw -> new CompressedStreamExtractor(ArcanaFormat.BZIP2, new BZip2Extractor()), "BZip2 (single file only)", (level, pw) -> new BZip2Compressor()));
        l.add(new BuiltinFormat(ArcanaFormat.XZ, SINGLE_FILE, names("xz"), "xz", "XZ / LZMA2", pw -> new CompressedStreamExtractor(ArcanaFormat.XZ, new XzExtractor()), "XZ / LZMA2  (single file only) [-l 0-9]", (level, pw) -> level >= 0 ? new XzCompressor(level) : new XzCompressor()));
        l.add(new BuiltinFormat(ArcanaFormat.LZMA, SINGLE_FILE, names("lzma"), "lzma", "Raw LZMA stream", pw -> new CompressedStreamExtractor(ArcanaFormat.LZMA, new LzmaExtractor()), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.MSLZ, SINGLE_FILE, names("szdd", "mslz"), "ex_  dl_ ...", "MS compress.exe file (SZDD)", pw -> new MsLzExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.Z, SINGLE_FILE, names("z"), "Z", "Unix compress (LZW)", pw -> new ZExtractor(), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.LZ4, SINGLE_FILE, names("lz4"), "lz4", "LZ4", pw -> new CompressedStreamExtractor(ArcanaFormat.LZ4, new LZ4Extractor()), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.ZSTD, SINGLE_FILE, names("zst", "zstd"), "zst  zstd", "Zstandard", pw -> new CompressedStreamExtractor(ArcanaFormat.ZSTD, new ZstdExtractor()), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.SNAPPY, SINGLE_FILE, names("snappy"), "snappy", "Snappy", pw -> new CompressedStreamExtractor(ArcanaFormat.SNAPPY, new SnappyExtractor()), null, null));
        l.add(new BuiltinFormat(ArcanaFormat.BROTLI, SINGLE_FILE, names("br"), "br", "Brotli", pw -> new CompressedStreamExtractor(ArcanaFormat.BROTLI, new BrotliExtractor()), null, null));
        // ---- Other ----
        l.add(new BuiltinFormat(ArcanaFormat.SFX, OTHER, names("exe", "sfx"), "exe", "Self-extracting archive (ZIP, RAR, 7z, CAB/IExpress inside an executable)", pw -> new SfxExtractor(f -> builtin(f).createExtractor(pw)), null, null));
        BUILTINS = Collections.unmodifiableList(l);
        for (final BuiltinFormat b : l) BY_FORMAT.put(b.getFormat(), b);
    }

    private FormatRegistry() {}

    private static String[] names(final String... n) {
        return n;
    }

    /** Arcana's built-in formats, in listing order. */
    public static List<BuiltinFormat> builtins() {
        return BUILTINS;
    }

    /**
     * Built-in handler of a format.
     *
     * @throws ArcanaUnsupportedFormatException for UNKNOWN
     */
    public static BuiltinFormat builtin(final ArcanaFormat format) throws ArcanaUnsupportedFormatException {
        final BuiltinFormat b = BY_FORMAT.get(format);
        if (b == null) throw new ArcanaUnsupportedFormatException("Unsupported format: " + format);
        return b;
    }

    /** Loaded plugins with a priority greater than 0 (consulted before the built-in formats). */
    public static List<ArcanaPlugin> priorityPlugins() {
        final List<ArcanaPlugin> r = new ArrayList<ArcanaPlugin>();
        for (final ArcanaPlugin p : PluginManager.get().getActivePlugins()) {
            try {
                if (p.getPriority() > 0) r.add(p);
            } catch (final RuntimeException ignored) { /* faulty plugin: normal priority */ }
        }
        r.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
        return r;
    }

    /**
     * Handler for a format name given by the user (-f / -t): plugin id or name
     * of a priority plugin, else built-in name ("zip", "tar.gz", "tgz"...), else
     * plugin id or extension. Null if unknown.
     */
    public static ArcanaPlugin byName(final String name) {
        if (name == null) return null;
        final String n = name.toLowerCase();
        for (final ArcanaPlugin p : priorityPlugins()) if (hasName(p, n)) return p;
        for (final BuiltinFormat b : BUILTINS) if (hasName(b, n)) return b;
        final PluginManager pm = PluginManager.get();
        final ArcanaPlugin byId = pm.findById(name);
        return byId != null ? byId : pm.findByExtension(n);
    }

    private static boolean hasName(final ArcanaPlugin p, final String n) {
        try {
            if (n.equals(p.getId().toLowerCase())) return true;
            for (final String e : p.getExtensions()) if (e != null && e.toLowerCase().equals(n)) return true;
        } catch (final RuntimeException ignored) { /* faulty plugin */ }
        return false;
    }

    /**
     * Handler whose name is the longest extension of {@code fileName}
     * ("x.tar.gz" gives tar.gz rather than gz), or null.
     */
    public static ArcanaPlugin byFileName(final String fileName) {
        final String lower = fileName.toLowerCase();
        ArcanaPlugin best = null;
        int bestLen = 0;
        final List<ArcanaPlugin> all = new ArrayList<ArcanaPlugin>(priorityPlugins());
        all.addAll(BUILTINS);
        all.addAll(PluginManager.get().getActivePlugins());
        for (final ArcanaPlugin p : all) {
            try {
                for (final String e : p.getExtensions()) {
                    if (e != null && lower.endsWith("." + e.toLowerCase()) && e.length() > bestLen) {
                        best = p;
                        bestLen = e.length();
                    }
                }
            } catch (final RuntimeException ignored) { /* faulty plugin */ }
        }
        return best;
    }
}
