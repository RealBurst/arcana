/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.formats.lha.LhaEntry;
import be.stef.arcana.formats.lha.LhaReader;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for LHA and LZH archives ({@code .lzh}, {@code .lha}).
 *
 * <p>Supported decompression methods: -lh0- (stored), -lz4- (stored),
 * -lh4-, -lh5-, -lh6-, -lh7- (LZH adaptive Huffman with various window sizes).
 * Header levels 0, 1 and 2 are all supported.</p>
 *
 * <p>Entries with unsupported compression methods are silently skipped
 * during extraction but still appear in {@link #list(File)}.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class LhaExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() { return true; }

    // =========================================================================
    // extract
    // =========================================================================

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (final LhaReader lha = new LhaReader(new BufferedInputStream(new FileInputStream(archive), 65536))) {
            extractFrom(lha, destination);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (final LhaReader lha = new LhaReader(in instanceof BufferedInputStream ? in : new BufferedInputStream(in, 65536))) {
            extractFrom(lha, destination);
        }
    }

    private void extractFrom(final LhaReader lha, final File destination) throws IOException {
        LhaEntry entry;
        try {
            while ((entry = lha.nextEntry()) != null) {
                final File target = SafePathBuilder.buildSafePath(destination, entry.getName());
                if (entry.isDirectory()) {
                    target.mkdirs();
                    continue;
                }
                if (!lha.canReadEntryData()) {
                    // Unsupported compression method - skip
                    continue;
                }
                target.getParentFile().mkdirs();
                try (final BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    IOHelper.copy(lha, out);
                }
                if (entry.getLastModified() > 0) target.setLastModified(entry.getLastModified());
            }
        } catch (final IOException e) {
            throw new ArcanaCorruptedException("Corrupted LHA archive: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // list
    // =========================================================================

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (final LhaReader lha = new LhaReader(new BufferedInputStream(new FileInputStream(archive), 65536))) {
            LhaEntry entry;
            while ((entry = lha.nextEntry()) != null) {
                result.add(new ArcanaEntry.Builder(entry.getName())
                        .uncompressedSize(entry.isDirectory() ? -1L : entry.getOriginalSize())
                        .compressedSize(entry.getCompressedSize())
                        .lastModifiedTime(entry.getLastModified() / 1000L)
                        .directory(entry.isDirectory())
                        .format(ArcanaFormat.LHA)
                        .build());
            }
        } catch (final IOException e) {
            throw new ArcanaCorruptedException("Corrupted LHA archive: " + e.getMessage(), e);
        }
        return result;
    }
}
