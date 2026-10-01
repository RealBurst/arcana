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
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.ReadAheadInputStream;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/** Extractor for raw LZMA streams (.lzma). Single-file format: 13-byte header + LZMA data. */
public class LzmaExtractor implements ArchiveExtractor {

    @Override public boolean supportsStream() { return true; }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final String name = stripExt(archive.getName(), ".lzma");
        return Collections.singletonList(new ArcanaEntry.Builder(name).format(ArcanaFormat.LZMA).build());
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        final File out = SafePathBuilder.buildSafePath(destination, stripExt(archive.getName(), ".lzma"));
        try (LZMAInputStream lz = new LZMAInputStream(new BufferedInputStream(new FileInputStream(archive)));
             BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(out))) {
            ReadAheadInputStream.copy(lz, bos);
        }
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (LZMAInputStream lz = new LZMAInputStream(in);
             BufferedOutputStream bos = new BufferedOutputStream(ExtractionGuard.open(new File(destination, "output")))) {
            ReadAheadInputStream.copy(lz, bos);
        }
    }

    private static String stripExt(final String name, final String ext) {
        return name.toLowerCase().endsWith(ext.toLowerCase()) ? name.substring(0, name.length() - ext.length()) : name;
    }
}
