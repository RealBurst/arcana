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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Extractor for OLE compound files: Windows Installer packages (.msi) and
 * other structured storage files (.msp, legacy .doc / .xls / .ppt, .msg).
 *
 * <p>An installation package is extracted as the tree of the files it
 * installs, with their real names and folders (read from the File, Component
 * and Directory tables, data taken from the embedded cabinets); its other
 * streams (Binary and Icon tables, custom actions) go to "[streams]/". Any
 * other compound file, or a package whose tables cannot be read, is extracted
 * as its storages (folders) and streams (files); control characters in names
 * become "[n]", like 7-Zip ("[5]SummaryInformation").</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public class OleExtractor implements ArchiveExtractor {

    private static final String STREAMS = "[streams]";

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (CompoundFile cf = new CompoundFile(archive)) {
            final MsiPackage msi = msi(cf);
            if (msi == null) {
                extractStorage(cf, cf.getRoot(), "", destination, isInstaller(cf));
                return;
            }
            // installed files, cabinet by cabinet
            final Map<CompoundFile.Node, Map<String, List<String>>> byCab = new LinkedHashMap<CompoundFile.Node, Map<String, List<String>>>();
            for (final MsiPackage.InstalledFile f : msi.getFiles()) {
                if (f.cabinet == null) continue; // external file: not in the package
                Map<String, List<String>> m = byCab.get(f.cabinet);
                if (m == null) byCab.put(f.cabinet, m = new HashMap<String, List<String>>());
                List<String> paths = m.get(f.key);
                if (paths == null) m.put(f.key, paths = new ArrayList<String>());
                paths.add(f.path);
            }
            for (final Map.Entry<CompoundFile.Node, Map<String, List<String>>> e : byCab.entrySet()) {
                final File tmp = File.createTempFile("arcana-msi-", ".cab");
                try {
                    try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 65536)) {
                        cf.copy(e.getKey(), out);
                    }
                    try (CabReader cab = new CabReader(tmp.getPath())) {
                        for (final CabEntry ce : cab.getEntries()) {
                            final List<String> paths = e.getValue().get(ce.getName());
                            if (paths == null) continue;
                            for (final String path : paths) {
                                final File target = SafePathBuilder.buildSafePath(destination, path);
                                IOHelper.mkdirs(target.getParentFile());
                                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                                    cab.extract(ce, out);
                                }
                            }
                        }
                    }
                } finally {
                    if (!tmp.delete()) tmp.deleteOnExit();
                }
            }
            for (final Map.Entry<String, CompoundFile.Node> s : msi.getOtherStreams().entrySet()) {
                final File target = SafePathBuilder.buildSafePath(destination, STREAMS + "/" + safeName(s.getKey()));
                IOHelper.mkdirs(target.getParentFile());
                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    cf.copy(s.getValue(), out);
                }
            }
        }
    }

    private static void extractStorage(final CompoundFile cf, final CompoundFile.Node storage, final String prefix, final File destination, final boolean msiNames) throws IOException {
        for (final CompoundFile.Node n : storage.children) {
            final String path = prefix + safeName(msiNames ? MsiPackage.decodeName(n.name) : n.name);
            final File target = SafePathBuilder.buildSafePath(destination, path);
            if (n.storage) {
                IOHelper.mkdirs(target);
                extractStorage(cf, n, path + "/", destination, msiNames);
            } else {
                IOHelper.mkdirs(target.getParentFile());
                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    cf.copy(n, out);
                }
            }
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("OLE compound files require random file access - use extract(File,File).");
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (CompoundFile cf = new CompoundFile(archive)) {
            final MsiPackage msi = msi(cf);
            if (msi == null) {
                listStorage(cf.getRoot(), "", result, isInstaller(cf));
                return result;
            }
            for (final MsiPackage.InstalledFile f : msi.getFiles()) {
                // files outside the package (external cabinet) are listed with an unknown packed size
                result.add(new ArcanaEntry.Builder(f.path).uncompressedSize(f.size).format(ArcanaFormat.OLE).build());
            }
            for (final Map.Entry<String, CompoundFile.Node> s : msi.getOtherStreams().entrySet()) {
                result.add(new ArcanaEntry.Builder(STREAMS + "/" + safeName(s.getKey())).uncompressedSize(s.getValue().size).format(ArcanaFormat.OLE).build());
            }
        }
        return result;
    }

    private static void listStorage(final CompoundFile.Node storage, final String prefix, final List<ArcanaEntry> out, final boolean msiNames) {
        for (final CompoundFile.Node n : storage.children) {
            final String path = prefix + safeName(msiNames ? MsiPackage.decodeName(n.name) : n.name);
            out.add(new ArcanaEntry.Builder(path).uncompressedSize(n.storage ? 0 : n.size).lastModifiedTime(n.mtime).directory(n.storage).format(ArcanaFormat.OLE).build());
            if (n.storage) listStorage(n, path + "/", out, msiNames);
        }
    }

    /** Package, patch or transform: stream names are packed (see {@link MsiPackage#decodeName}). */
    private static boolean isInstaller(final CompoundFile cf) {
        final String c = cf.getRootClsid();
        return MsiPackage.CLSID_PACKAGE.equals(c) || MsiPackage.CLSID_PATCH.equals(c) || "{000C1082-0000-0000-C000-000000000046}".equals(c);
    }

    /** The installation package view, or null for another compound file or unreadable tables. */
    private static MsiPackage msi(final CompoundFile cf) {
        final String clsid = cf.getRootClsid();
        if (!MsiPackage.CLSID_PACKAGE.equals(clsid)) return null;
        try {
            return new MsiPackage(cf);
        } catch (final IOException | RuntimeException e) {
            return null; // damaged or unusual tables: fall back to the raw streams
        }
    }

    /** Control characters become "[n]"; '/' and '\' become '_'. */
    private static String safeName(final String name) {
        final StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            final char c = name.charAt(i);
            if (c < 0x20) sb.append('[').append((int) c).append(']');
            else if (c == '/' || c == '\\') sb.append('_');
            else sb.append(c);
        }
        final String s = sb.toString();
        return s.isEmpty() || s.equals(".") || s.equals("..") ? "_" + s : s;
    }
}
