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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.carve.DotNetBundle;
import be.stef.arcana.formats.carve.FileCarver;
import be.stef.arcana.formats.carve.PeImage;
import be.stef.arcana.formats.carve.PeResources;
import be.stef.arcana.formats.cab.CabEntry;
import be.stef.arcana.formats.cab.CabReader;
import be.stef.arcana.formats.ole.CompoundFile;
import be.stef.arcana.formats.ole.MsiPackage;
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for self-extracting archives (executables carrying an archive:
 * Windows PE, and Linux ELF for the 7-Zip SFX).
 *
 * <p>The archive is searched:</p>
 * <ol>
 *   <li>after the executable image (the "overlay"): WinRAR SFX (RAR 4/5),
 *       7-Zip SFX (a configuration text may sit between the stub and the 7z),
 *       WinZip / Info-ZIP SFX (ZIP), and GZIP / XZ payloads;</li>
 *   <li>in the resources: Windows Installer packages (.msi) with their external
 *       cabinets (installers such as the Java one: the files get their real
 *       names and folders from the package, the other resources go to
 *       "[resources]/type/name");</li>
 *   <li>inside the executable: IExpress packages (Microsoft CAB stored in the
 *       resources), 7z / ZIP / RAR stored as resources.</li>
 * </ol>
 * <p>The archive is then extracted by the usual extractor of its format. A ZIP that
 * ends at the end of the file is read in place (ZIP readers handle the offset of an
 * SFX stub); a ZIP followed by other data is copied with the bytes before it, up to
 * its end of central directory; the other formats are copied to a temporary file.</p>
 *
 * <p>Also used for any file whose format is not recognized but which contains an
 * archive after a prefix (e.g. a shell script followed by a ZIP).</p>
 *
 * <p>.NET single-file applications ({@code PublishSingleFile}) are extracted from
 * their bundle manifest: every file with its path (compressed files inflated).</p>
 *
 * <p>Installers with their own proprietary format (NSIS, Inno Setup,
 * InstallShield, WiX Burn) are reported as such.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class SfxExtractor implements ArchiveExtractor {

    /** Creates the extractor of an embedded archive format. */
    public interface ExtractorFactory {
        ArchiveExtractor create(ArcanaFormat format) throws IOException;
    }

    /** Archive found in an executable. */
    public static final class Payload {
        public final ArcanaFormat format;
        public final long offset;
        public final long length;
        public final String description;

        Payload(final ArcanaFormat format, final long offset, final long length, final String description) {
            this.format = format;
            this.offset = offset;
            this.length = length;
            this.description = description;
        }

        @Override
        public String toString() {
            return String.format("%s at 0x%X (%d bytes)", description, offset, length);
        }
    }

    private final ExtractorFactory factory;

    public SfxExtractor(final ExtractorFactory factory) {
        this.factory = factory;
    }

    @Override
    public boolean supportsStream() {
        return true;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        if (extractDotNet(archive, destination)) return;
        final Payload p = locate(archive);
        if (p.format == ArcanaFormat.OLE) {
            try (ResourceSet r = new ResourceSet(archive)) {
                r.extract(destination);
            }
            return;
        }
        if (p.format == ArcanaFormat.ZIP && zipAtEnd(archive, p)) {
            factory.create(ArcanaFormat.ZIP).extract(archive, destination); // the ZIP reader skips the stub itself
            return;
        }
        final File tmp = copyPayload(archive, zipRange(p));
        try {
            factory.create(p.format).extract(tmp, destination);
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final File tmp = File.createTempFile("arcana-sfx-", ".exe");
        try {
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
                IOHelper.copy(in, out);
            }
            extract(tmp, destination);
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> dotNet = listDotNet(archive);
        if (dotNet != null) return dotNet;
        final Payload p = locate(archive);
        if (p.format == ArcanaFormat.OLE) {
            try (ResourceSet r = new ResourceSet(archive)) {
                return r.list();
            }
        }
        if (p.format == ArcanaFormat.ZIP && zipAtEnd(archive, p)) return factory.create(ArcanaFormat.ZIP).list(archive);
        final File tmp = copyPayload(archive, zipRange(p));
        try {
            return factory.create(p.format).list(tmp);
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    // =========================================================================
    // .NET single-file bundle
    // =========================================================================

    /** Extracts the files of a .NET single-file bundle; false if {@code exe} is not one. */
    private static boolean extractDotNet(final File exe, final File destination) throws IOException {
        try (ByteSource s = new ByteSource(exe)) {
            final DotNetBundle.Manifest m = DotNetBundle.findInExecutable(s);
            if (m == null) return false;
            for (final DotNetBundle.Entry e : m.entries) {
                final File target = SafePathBuilder.buildSafePath(destination, e.path.replace('\\', '/'));
                IOHelper.mkdirs(target.getParentFile());
                try (InputStream in = DotNetBundle.open(s, e); OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    IOHelper.copy(in, out);
                }
            }
            return true;
        }
    }

    /** Entries of a .NET single-file bundle, or null if {@code exe} is not one. */
    private static List<ArcanaEntry> listDotNet(final File exe) throws IOException {
        try (ByteSource s = new ByteSource(exe)) {
            final DotNetBundle.Manifest m = DotNetBundle.findInExecutable(s);
            if (m == null) return null;
            final List<ArcanaEntry> list = new ArrayList<ArcanaEntry>(m.entries.size());
            for (final DotNetBundle.Entry e : m.entries) list.add(new ArcanaEntry.Builder(e.path.replace('\\', '/')).uncompressedSize(e.size).compressedSize(e.storedSize()).build());
            return list;
        }
    }

    // =========================================================================
    // Payload search
    // =========================================================================

    /**
     * Finds the archive carried by an executable.
     *
     * @throws ArcanaUnsupportedFormatException if none is found (the message names
     *         the installer type when it is recognized)
     */
    public static Payload locate(final File exe) throws IOException {
        try (ByteSource s = new ByteSource(exe)) {
            // End of the executable image: PE (Windows), ELF (7-Zip SFX for Linux) or MS-DOS MZ
            final long imageEnd;
            final PeImage pe = PeImage.parse(s, 0);
            if (pe != null) {
                imageEnd = pe.sectionsEnd;
            } else {
                // ELF / MS-DOS stub, or any other prefix (shell script + ZIP...): the archive may follow
                final FileCarver.Item first = FileCarver.identifyAt(s, 0);
                imageEnd = first != null && ("elf".equals(first.type) || "mz".equals(first.type)) ? first.length : 0;
            }
            // 1. After the image (overlay)
            final List<FileCarver.Item> items = FileCarver.scan(exe);
            for (final FileCarver.Item it : items) {
                if (it.offset < imageEnd) continue;
                final ArcanaFormat f = archiveFormat(it.type);
                if (f != null) return new Payload(f, it.offset, it.length, it.description);
            }
            // 2. Windows Installer package in the resources
            for (final PeResources.Resource r : PeResources.read(s)) {
                if (isMsiPackage(s, r)) return new Payload(ArcanaFormat.OLE, r.offset, r.size, "Windows Installer package in the resources (" + r.type + "/" + r.name + ")");
            }
            // 3. Inside the image (resources): IExpress CAB, 7z / ZIP / RAR resources
            final Payload inside = searchInside(s, Math.min(imageEnd, s.length()));
            if (inside != null) return inside;
            // 4. Nothing: name the installer type if possible
            final String kind = installerKind(s);
            if (kind != null) throw new ArcanaUnsupportedFormatException(exe.getName() + " is a " + kind + " installer: its proprietary format is not supported (no standard archive inside)" + pluginHint(kind));
            throw new ArcanaUnsupportedFormatException("No archive found in " + exe.getName() + " (not a self-extracting archive)");
        }
    }

    private static ArcanaFormat archiveFormat(final String type) {
        switch (type) {
            case "zip":  return ArcanaFormat.ZIP;
            case "7z":   return ArcanaFormat.SEVEN_Z;
            case "rar":  return ArcanaFormat.RAR;
            case "cab":  return ArcanaFormat.CAB;
            case "gzip": return ArcanaFormat.GZIP;
            case "xz":   return ArcanaFormat.XZ;
            default:     return null;
        }
    }

    private static final byte[][] INSIDE_SIGNATURES = {
        {'M', 'S', 'C', 'F', 0, 0, 0, 0},
        {'7', 'z', (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C},
        {'R', 'a', 'r', '!', 0x1A, 0x07},
        {'P', 'K', 3, 4},
    };

    /** Largest archive stored inside the image, or null. */
    private static Payload searchInside(final ByteSource s, final long end) throws IOException {
        Payload best = null;
        final byte[] buf = new byte[1 << 20];
        long pos = 0;
        while (pos < end) {
            final int n = s.read(pos, buf, 0, (int) Math.min(buf.length, end - pos));
            if (n <= 0) break;
            for (int i = 0; i < n; i++) {
                final int c = buf[i] & 0xFF;
                if (c != 'M' && c != '7' && c != 'R' && c != 'P') continue;
                final long p = pos + i;
                for (final byte[] sig : INSIDE_SIGNATURES) {
                    if (!s.matches(p, sig)) continue;
                    final FileCarver.Item it = FileCarver.identifyAt(s, p);
                    if (it == null || it.truncated || it.length < 64 || p + it.length > end) continue;
                    final ArcanaFormat f = archiveFormat(it.type);
                    if (f != null && (best == null || it.length > best.length)) best = new Payload(f, it.offset, it.length, it.description + " (inside the executable)");
                }
            }
            pos += n;
        }
        return best;
    }

    /** The plugin that extracts an installer type, as a hint in the error message. */
    private static String pluginHint(final String kind) {
        if (kind.startsWith("NSIS")) return " - the arcana-plugin-nsis plugin extracts it";
        if ("Inno Setup".equals(kind)) return " - the arcana-plugin-innosetup plugin extracts it";
        if ("InstallShield".equals(kind)) return " - the arcana-plugin-installshield plugin extracts its embedded files";
        return "";
    }

    /** Known proprietary installers, recognized by strings of their stubs / data. */
    private static String installerKind(final ByteSource s) throws IOException {
        final long len = Math.min(s.length(), 64L << 20);
        if (s.indexOf("NullsoftInst".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "NSIS (Nullsoft)";
        if (s.indexOf("Inno Setup Setup Data".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0 || s.indexOf("rDlPtS".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "Inno Setup";
        if (s.indexOf(".wixburn".getBytes(StandardCharsets.US_ASCII), 0, Math.min(len, 4096)) >= 0) return "WiX Burn";
        if (s.indexOf("InstallShield".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "InstallShield";
        return null;
    }

    // =========================================================================
    // Windows Installer packages in the resources
    // =========================================================================

    private static final byte[] OLE_SIGNATURE = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
    private static final byte[] CAB_SIGNATURE = {'M', 'S', 'C', 'F', 0, 0, 0, 0};
    private static final String RESOURCES = "[resources]";

    /** True if the resource is an installation package: compound file whose root storage has the package CLSID. */
    static boolean isMsiPackage(final ByteSource s, final PeResources.Resource r) throws IOException {
        if (r.size < 1536 || !s.matches(r.offset, OLE_SIGNATURE)) return false;
        final int shift = s.u16le(r.offset + 0x1E);
        if (shift != 9 && shift != 12) return false;
        final long rootEntry = (s.u32le(r.offset + 0x30) + 1) << shift;
        if (rootEntry + 0x80 > r.size) return false;
        final byte[] clsid = s.bytes(r.offset + rootEntry + 0x50, 16);
        final String text = String.format("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (clsid[0] & 0xFFL) | (clsid[1] & 0xFFL) << 8 | (clsid[2] & 0xFFL) << 16 | (clsid[3] & 0xFFL) << 24, (clsid[4] & 0xFF) | (clsid[5] & 0xFF) << 8, (clsid[6] & 0xFF) | (clsid[7] & 0xFF) << 8, clsid[8], clsid[9], clsid[10], clsid[11], clsid[12], clsid[13], clsid[14], clsid[15]);
        return MsiPackage.CLSID_PACKAGE.equals(text);
    }

    /**
     * Executable whose resources hold installation packages: each package is
     * extracted with the files of its external cabinets (taken from the cabinet
     * resources holding them), the other resources (except the user interface
     * ones) are copied to "[resources]/type/name.ext".
     */
    private static final class ResourceSet implements OleExtractor.CabinetResolver, AutoCloseable {
        private final ByteSource source;
        private final List<PeResources.Resource> resources;
        private final List<PeResources.Resource> packages = new ArrayList<PeResources.Resource>();
        private final List<PeResources.Resource> cabinets = new ArrayList<PeResources.Resource>();
        private final Map<PeResources.Resource, File> cabinetFiles = new HashMap<PeResources.Resource, File>();
        private final Map<PeResources.Resource, Set<String>> cabinetNames = new HashMap<PeResources.Resource, Set<String>>();
        private final Set<PeResources.Resource> used = new HashSet<PeResources.Resource>();
        private final List<File> temporary = new ArrayList<File>();

        ResourceSet(final File exe) throws IOException {
            source = new ByteSource(exe);
            try {
                resources = PeResources.read(source);
                for (final PeResources.Resource r : resources) {
                    if (isMsiPackage(source, r)) packages.add(r);
                    else if (r.size >= 64 && source.matches(r.offset, CAB_SIGNATURE)) cabinets.add(r);
                }
            } catch (final IOException | RuntimeException e) {
                source.close();
                throw e;
            }
        }

        /** The cabinet resource holding the most of the expected files. */
        @Override
        public File resolve(final String cabinet, final Set<String> keys) throws IOException {
            PeResources.Resource best = null;
            int bestCount = 0;
            for (final PeResources.Resource r : cabinets) {
                int count = 0;
                for (final String name : names(r)) {
                    if (keys.contains(name)) count++;
                }
                if (count > bestCount) {
                    best = r;
                    bestCount = count;
                }
            }
            if (best == null) return null;
            used.add(best);
            return file(best, "cab");
        }

        private Set<String> names(final PeResources.Resource r) throws IOException {
            Set<String> names = cabinetNames.get(r);
            if (names == null) {
                names = new HashSet<String>();
                try (CabReader cab = new CabReader(file(r, "cab").getPath())) {
                    for (final CabEntry e : cab.getEntries()) names.add(e.getName());
                } catch (final IOException | RuntimeException e) {
                    names.clear(); // not a readable cabinet
                }
                cabinetNames.put(r, names);
            }
            return names;
        }

        private File file(final PeResources.Resource r, final String ext) throws IOException {
            File f = cabinetFiles.get(r);
            if (f == null) {
                f = File.createTempFile("arcana-res-", "." + ext);
                temporary.add(f);
                try (OutputStream out = new BufferedOutputStream(new FileOutputStream(f), 65536)) {
                    copy(r, out);
                }
                cabinetFiles.put(r, f);
            }
            return f;
        }

        private void copy(final PeResources.Resource r, final OutputStream out) throws IOException {
            final byte[] buf = new byte[65536];
            long pos = r.offset;
            final long end = r.offset + r.size;
            while (pos < end) {
                final int n = source.read(pos, buf, 0, (int) Math.min(buf.length, end - pos));
                if (n <= 0) throw new IOException("Resource truncated: " + r);
                out.write(buf, 0, n);
                pos += n;
            }
        }

        /** Folder of a package: the root when there is only one. */
        private String folder(final PeResources.Resource p) {
            return packages.size() == 1 ? "" : safe(p.type) + "_" + safe(p.name) + "/";
        }

        void extract(final File destination) throws IOException {
            IOHelper.mkdirs(destination);
            for (final PeResources.Resource p : packages) {
                final String folder = folder(p);
                new OleExtractor(this).extract(file(p, "msi"), folder.isEmpty() ? destination : SafePathBuilder.buildSafePath(destination, folder.substring(0, folder.length() - 1)));
            }
            for (final Map.Entry<String, PeResources.Resource> e : others().entrySet()) {
                final File target = SafePathBuilder.buildSafePath(destination, e.getKey());
                IOHelper.mkdirs(target.getParentFile());
                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    copy(e.getValue(), out);
                }
            }
        }

        List<ArcanaEntry> list() throws IOException {
            final List<ArcanaEntry> list = new ArrayList<ArcanaEntry>();
            for (final PeResources.Resource p : packages) {
                final File msi = file(p, "msi");
                markUsed(msi);
                final String folder = folder(p);
                for (final ArcanaEntry e : new OleExtractor(this).list(msi)) list.add(new ArcanaEntry.Builder(folder + e.getName()).uncompressedSize(e.getUncompressedSize()).format(ArcanaFormat.OLE).build());
            }
            for (final Map.Entry<String, PeResources.Resource> e : others().entrySet()) list.add(new ArcanaEntry.Builder(e.getKey()).uncompressedSize(e.getValue().size).build());
            return list;
        }

        /** Resolves the external cabinets of a package (listing only: extraction does it itself). */
        private void markUsed(final File msi) throws IOException {
            try (CompoundFile cf = new CompoundFile(msi)) {
                final Map<String, Set<String>> keys = new LinkedHashMap<String, Set<String>>();
                for (final MsiPackage.InstalledFile f : new MsiPackage(cf).getFiles()) {
                    if (f.externalCabinet == null) continue;
                    Set<String> k = keys.get(f.externalCabinet);
                    if (k == null) keys.put(f.externalCabinet, k = new HashSet<String>());
                    k.add(f.key);
                }
                for (final Map.Entry<String, Set<String>> e : keys.entrySet()) resolve(e.getKey(), e.getValue());
            } catch (final IOException | RuntimeException e) {
                // unreadable tables: the cabinets stay listed as resources
            }
        }

        /** Resources other than the user interface and the cabinets used by the packages, by path. */
        private Map<String, PeResources.Resource> others() throws IOException {
            final Map<String, PeResources.Resource> m = new LinkedHashMap<String, PeResources.Resource>();
            final Set<String> names = new HashSet<String>();
            for (final PeResources.Resource r : resources) {
                if (r.isStandardUi() || used.contains(r) || r.size == 0) continue;
                final String base = RESOURCES + "/" + safe(r.type) + "/" + safe(r.name);
                final String ext = "." + extension(r);
                String path = base + ext;
                if (names.contains(path.toLowerCase())) path = base + "_" + r.lang + ext;
                for (int n = 2; names.contains(path.toLowerCase()); n++) path = base + "_" + r.lang + "_" + n + ext;
                names.add(path.toLowerCase());
                m.put(path, r);
            }
            return m;
        }

        private String extension(final PeResources.Resource r) throws IOException {
            if (packages.contains(r)) return "msi";
            if (source.matches(r.offset, CAB_SIGNATURE)) return "cab";
            if (source.matches(r.offset, OLE_SIGNATURE)) return "ole";
            if (source.matches(r.offset, new byte[] {'P', 'K', 3, 4})) return "zip";
            if (source.matches(r.offset, new byte[] {'7', 'z', (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C})) return "7z";
            if (source.matches(r.offset, new byte[] {'R', 'a', 'r', '!', 0x1A, 0x07})) return "rar";
            if (r.size >= 64 && source.u16le(r.offset) == 0x5A4D) {
                try {
                    final PeImage pe = PeImage.parse(source, r.offset);
                    if (pe != null) return pe.extension();
                } catch (final IOException | RuntimeException e) {
                    // not a PE image
                }
                return "exe";
            }
            if (source.matches(r.offset, "<?xml".getBytes(StandardCharsets.US_ASCII))) return "xml";
            return "bin";
        }

        private static String safe(final String name) {
            final StringBuilder sb = new StringBuilder(name.length());
            for (int i = 0; i < name.length(); i++) {
                final char c = name.charAt(i);
                sb.append(c < 0x20 || c > 0x7E || "/\\:*?\"<>|".indexOf(c) >= 0 ? '_' : c);
            }
            final String s = sb.toString();
            return s.isEmpty() || s.equals(".") || s.equals("..") ? "_" + s : s;
        }

        @Override
        public void close() throws IOException {
            for (final File f : temporary) {
                if (!f.delete()) f.deleteOnExit();
            }
            source.close();
        }
    }

    /** True if the ZIP payload ends at the end of the file: the ZIP reader then finds its end of central directory in place. */
    private static boolean zipAtEnd(final File exe, final Payload p) {
        return p.offset + p.length >= exe.length();
    }

    /**
     * Range to copy for a payload. A ZIP followed by other data (stored inside the image, or before
     * a certificate) is copied from the start of the file to its end of central directory: the ZIP
     * reader looks for that record at the end of the file only, and keeping the bytes before the ZIP
     * keeps working both for offsets relative to the ZIP and for offsets relative to the file.
     */
    private static Payload zipRange(final Payload p) {
        if (p.format != ArcanaFormat.ZIP) return p;
        return new Payload(p.format, 0, p.offset + p.length, p.description);
    }

    private static File copyPayload(final File exe, final Payload p) throws IOException {
        final String ext = p.format.getExtensions().length > 0 ? p.format.getExtensions()[0] : "bin";
        final File tmp = File.createTempFile("arcana-sfx-", "." + ext);
        try (ByteSource s = new ByteSource(exe); OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
            final byte[] buf = new byte[65536];
            long pos = p.offset;
            final long end = p.offset + p.length;
            while (pos < end) {
                final int n = s.read(pos, buf, 0, (int) Math.min(buf.length, end - pos));
                if (n <= 0) break;
                out.write(buf, 0, n);
                pos += n;
            }
        } catch (final IOException | RuntimeException e) {
            if (!tmp.delete()) tmp.deleteOnExit();
            throw e;
        }
        return tmp;
    }
}