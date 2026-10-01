/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.formats.brotli.BrotliInputStream;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import be.stef.arcana.util.ReadAheadInputStream;

/**
 * Extractor for TAR archives compressed with Brotli ({@code .tar.br}, {@code .tbr}).
 *
 * <p>Decompresses the Brotli stream on the fly and passes the resulting TAR
 * byte stream to {@link TarExtractor}.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class TarBrotliExtractor implements ArchiveExtractor {

    private final TarExtractor tar = new TarExtractor();

    @Override public boolean supportsStream() { return true; }

    @Override
    public void extract(File archive, File destination) throws IOException {
        try (BufferedInputStream raw = new BufferedInputStream(new FileInputStream(archive), 65536);
             InputStream brot = ReadAheadInputStream.wrap(new BrotliInputStream(raw))) { // decompression runs ahead in its own thread
            tar.extract(brot, destination);
        }
    }

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        try (InputStream brot = ReadAheadInputStream.wrap(new BrotliInputStream(in))) { // decompression runs ahead in its own thread
            tar.extract(brot, destination);
        }
    }

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        try (BufferedInputStream raw = new BufferedInputStream(new FileInputStream(archive), 65536);
             BrotliInputStream brot = new BrotliInputStream(raw)) {
            return tar.list(brot, ArcanaFormat.TAR_BROTLI);
        }
    }
}
