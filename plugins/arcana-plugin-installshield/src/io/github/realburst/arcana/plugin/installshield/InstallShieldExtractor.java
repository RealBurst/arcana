/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.installshield;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * Extracts InstallShield cabinet sets (data1.hdr / data1.cab...: "group/directory/name")
 * and the files embedded in InstallShield setup.exe launchers.
 */
final class InstallShieldExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("InstallShield files require random file access - use extract(File,File).");
    }

    /** True for a cabinet or header ("ISc(" signature). */
    static boolean isCabinet(final File f) throws IOException {
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            if (r.length() < 4) return false;
            final byte[] b = new byte[4];
            r.readFully(b);
            return IsCabinet.le32(b, 0) == IsCabinet.SIGNATURE;
        }
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try {
            if (isCabinet(archive)) {
                try (IsCabinet cab = IsCabinet.open(archive)) {
                    for (final IsCabinet.Item it : cab.items) {
                        try (OutputStream out = PluginSupport.openOutput(destination, it.path)) {
                            cab.copy(it, out, false);
                            continue;
                        } catch (final IOException e) {
                            if (!cab.compressed(it)) throw e;
                        }
                        // old layout of the compressed data: the file is written again
                        try (OutputStream out = PluginSupport.openOutput(destination, it.path)) {
                            cab.copy(it, out, true);
                        }
                    }
                }
                return;
            }
            try (IsSetup setup = IsSetup.open(archive)) {
                final byte[] buf = new byte[65536];
                for (final IsSetup.Item it : setup.items) {
                    try (InputStream in = setup.open(it); OutputStream out = PluginSupport.openOutput(destination, it.path)) {
                        int n;
                        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    }
                }
            }
        } catch (final ArcanaException e) {
            throw e;
        } catch (final IOException e) {
            final IOException r = new ArcanaCorruptedException("InstallShield data truncated or damaged" + (e.getMessage() != null ? " (" + e.getMessage() + ")" : ""));
            r.initCause(e);
            throw r;
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        if (isCabinet(archive)) {
            try (IsCabinet cab = IsCabinet.open(archive)) {
                for (final IsCabinet.Item it : cab.items) result.add(new ArcanaEntry.Builder(it.path).uncompressedSize(it.size).build());
            }
        } else {
            try (IsSetup setup = IsSetup.open(archive)) {
                for (final IsSetup.Item it : setup.items) result.add(new ArcanaEntry.Builder(it.path).compressedSize(it.size).uncompressedSize(it.deflated ? -1 : it.size).build());
            }
        }
        return result;
    }
}
