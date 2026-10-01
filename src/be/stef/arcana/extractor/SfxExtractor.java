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
import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 *   <li>inside the executable: IExpress packages (Microsoft CAB stored in the
 *       resources), 7z / ZIP / RAR stored as resources.</li>
 * </ol>
 * <p>The archive is then extracted by the usual extractor of its format. A ZIP is
 * read in place (ZIP readers handle the offset of an SFX stub); the other formats
 * are first copied to a temporary file.</p>
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
        if (p.format == ArcanaFormat.ZIP) {
            factory.create(ArcanaFormat.ZIP).extract(archive, destination); // the ZIP reader skips the stub itself
            return;
        }
        final File tmp = copyPayload(archive, p);
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
        if (p.format == ArcanaFormat.ZIP) return factory.create(ArcanaFormat.ZIP).list(archive);
        final File tmp = copyPayload(archive, p);
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
            // 2. Inside the image (resources): IExpress CAB, 7z / ZIP / RAR resources
            final Payload inside = searchInside(s, Math.min(imageEnd, s.length()));
            if (inside != null) return inside;
            // 3. Nothing: name the installer type if possible
            final String kind = installerKind(s);
            if (kind != null) throw new ArcanaUnsupportedFormatException(exe.getName() + " is a " + kind + " installer: its proprietary format is not supported (no standard archive inside)");
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

    /** Known proprietary installers, recognized by strings of their stubs / data. */
    private static String installerKind(final ByteSource s) throws IOException {
        final long len = Math.min(s.length(), 64L << 20);
        if (s.indexOf("NullsoftInst".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "NSIS (Nullsoft)";
        if (s.indexOf("Inno Setup Setup Data".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0 || s.indexOf("rDlPtS".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "Inno Setup";
        if (s.indexOf(".wixburn".getBytes(StandardCharsets.US_ASCII), 0, Math.min(len, 4096)) >= 0) return "WiX Burn";
        if (s.indexOf("InstallShield".getBytes(StandardCharsets.US_ASCII), 0, len) >= 0) return "InstallShield";
        return null;
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