/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.wixburn;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.formats.cab.CabEntry;
import be.stef.arcana.formats.cab.CabReader;
import be.stef.arcana.plugin.PluginSupport;
import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extracts a WiX Burn bundle: the manifest as ux/BurnManifest.xml, the files of
 * the bootstrapper application under ux/, the packages and their files at their
 * FilePath. Payloads that are not in the bundle file (external, downloaded,
 * detached containers) are listed with a note and not extracted.
 */
final class WixBurnExtractor implements ArchiveExtractor {

    /** Suffix of the listed names of the payloads that are not in the bundle. */
    static final String NOT_INCLUDED = " (not in the bundle: ";

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("WiX Burn bundles require random file access - use extract(File,File).");
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try (BurnBundle b = BurnBundle.open(archive)) {
            try (OutputStream out = PluginSupport.openOutput(destination, BurnBundle.MANIFEST_NAME)) {
                out.write(b.manifest);
            }
            final Set<String> used = b.usedNames();
            final Set<BurnBundle.Payload> done = new HashSet<BurnBundle.Payload>();
            for (final BurnBundle.Container c : b.embeddedContainers()) {
                final File tmp = b.copyContainer(c);
                try (CabReader cab = new CabReader(tmp.getPath())) {
                    for (final CabEntry e : cab.getEntries()) {
                        if (c == b.ux && "0".equals(e.getName())) continue;
                        final List<BurnBundle.Payload> ps = b.payloadsOf(c, e.getName());
                        if (ps.isEmpty()) {
                            try (OutputStream out = PluginSupport.openOutput(destination, b.orphanName(c, e.getName(), used))) {
                                cab.extract(e, out);
                            }
                            continue;
                        }
                        for (final BurnBundle.Payload p : ps) {
                            write(cab, e, p, destination);
                            done.add(p);
                        }
                    }
                } finally {
                    b.release(tmp);
                }
            }
            for (final BurnBundle.Payload p : b.payloads) {
                if (p.embedded() && !done.contains(p)) throw new ArcanaCorruptedException(b.damage != null ? b.damage : "WiX Burn payload " + p.id + " (" + p.sourcePath + ") missing from its container");
            }
        } catch (final ArcanaException e) {
            throw e;
        } catch (final IOException e) {
            final IOException r = new ArcanaCorruptedException("WiX Burn bundle truncated or damaged" + (e.getMessage() != null ? " (" + e.getMessage() + ")" : ""));
            r.initCause(e);
            throw r;
        }
    }

    /** Writes one payload, checking its size and hash when the manifest gives them. */
    private static void write(final CabReader cab, final CabEntry e, final BurnBundle.Payload p, final File destination) throws IOException {
        if (p.size >= 0 && p.size != e.getSize()) throw new ArcanaCorruptedException("WiX Burn payload " + p.outName + ": " + e.getSize() + " bytes in the container, " + p.size + " in the manifest");
        final MessageDigest md = BurnBundle.digest(p.hash);
        try (OutputStream out = PluginSupport.openOutput(destination, p.outName)) {
            cab.extract(e, md == null ? out : new DigestOutput(out, md));
        }
        if (md != null && !BurnBundle.hex(md.digest()).equalsIgnoreCase(p.hash)) throw new ArcanaCorruptedException("WiX Burn payload " + p.outName + " damaged (hash mismatch)");
    }

    /** Passes the bytes through and adds them to a digest. */
    private static final class DigestOutput extends FilterOutputStream {
        private final MessageDigest md;

        DigestOutput(final OutputStream out, final MessageDigest md) {
            super(out);
            this.md = md;
        }

        @Override
        public void write(final int x) throws IOException {
            md.update((byte) x);
            out.write(x);
        }

        @Override
        public void write(final byte[] buf, final int off, final int len) throws IOException {
            md.update(buf, off, len);
            out.write(buf, off, len);
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (BurnBundle b = BurnBundle.open(archive)) {
            if (b.damage != null) throw new ArcanaCorruptedException(b.damage);
            result.add(new ArcanaEntry.Builder(BurnBundle.MANIFEST_NAME).uncompressedSize(b.manifest.length).build());
            final Set<String> used = b.usedNames();
            for (final BurnBundle.Container c : b.embeddedContainers()) {
                for (final BurnBundle.CabFile f : b.cabFiles(c)) {
                    if (c == b.ux && "0".equals(f.name)) continue;
                    final List<BurnBundle.Payload> ps = b.payloadsOf(c, f.name);
                    if (ps.isEmpty()) result.add(new ArcanaEntry.Builder(b.orphanName(c, f.name, used)).uncompressedSize(f.size).build());
                    for (final BurnBundle.Payload p : ps) result.add(new ArcanaEntry.Builder(p.outName).uncompressedSize(f.size).build());
                }
            }
            for (final BurnBundle.Payload p : b.missingPayloads()) result.add(new ArcanaEntry.Builder(p.outName + NOT_INCLUDED + p.whereLabel() + ")").uncompressedSize(p.size).build());
        }
        return result;
    }
}
