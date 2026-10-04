/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.jexepack;

import be.stef.arcana.ArcanaEntry;
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
 * Extracts a JexePack executable: the jar files and DLLs of the program, its
 * bootstrap class (Boot.class) and its settings (jexepack-settings.txt).
 */
final class JexePackExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("JexePack executables require random file access - use extract(File,File).");
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        for (final JexePackArchive.Item it : read(archive).items) {
            try (OutputStream out = PluginSupport.openOutput(destination, it.name)) {
                out.write(it.data);
            }
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        for (final JexePackArchive.Item it : read(archive).items) result.add(new ArcanaEntry.Builder(it.name).uncompressedSize(it.data.length).build());
        return result;
    }

    static JexePackArchive read(final File file) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            return JexePackArchive.read(new JexePackArchive.Source() {
                @Override
                public long length() throws IOException {
                    return raf.length();
                }

                @Override
                public void readFully(final long pos, final byte[] b, final int off, final int len) throws IOException {
                    raf.seek(pos);
                    raf.readFully(b, off, len);
                }
            });
        }
    }
}
