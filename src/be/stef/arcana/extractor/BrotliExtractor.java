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
import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.formats.brotli.BrotliInputStream;
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

/**
 * Extractor for Brotli-compressed single files ({@code .br}).
 *
 * <p>Brotli does not define a container format: a {@code .br} file is simply
 * a raw Brotli-compressed byte stream with no embedded file name or metadata.
 * The original file name is inferred by stripping the {@code .br} suffix.</p>
 *
 * <p>Uses Google's pure-Java Brotli decoder ported into
 * {@code be.stef.arcana.formats.brotli}.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class BrotliExtractor implements ArchiveExtractor {

    @Override public boolean supportsStream() { return true; }

    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = SafePathBuilder.buildSafePath(destination, stripBrSuffix(archive.getName()));
        try (BufferedInputStream raw = new BufferedInputStream(new FileInputStream(archive), 65536);
             BrotliInputStream brot = new BrotliInputStream(raw);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(brot, out);
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted Brotli stream: " + e.getMessage(), e);
        }
    }

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = new File(destination, "output");
        try (BrotliInputStream brot = new BrotliInputStream(in);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            ReadAheadInputStream.copy(brot, out);
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted Brotli stream: " + e.getMessage(), e);
        }
    }

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        String name = stripBrSuffix(archive.getName());
        return Collections.singletonList(new ArcanaEntry.Builder(name)
                .uncompressedSize(-1L)
                .compressedSize(archive.length())
                .format(ArcanaFormat.BROTLI)
                .build());
    }

    static String stripBrSuffix(String name) {
        if (name.toLowerCase().endsWith(".br") && name.length() > 3) return name.substring(0, name.length() - 3);
        return name + ".out";
    }
}
