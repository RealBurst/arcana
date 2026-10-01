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
import be.stef.arcana.formats.cab.CabEntry;
import be.stef.arcana.formats.cab.CabReader;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.SafePathBuilder;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Extractor for Microsoft Cabinet ({@code .cab}) archives.
 *
 * <p>Supports NONE, MSZIP and LZX compression. Quantum is not supported.</p>
 *
 * <p>Streaming is not supported: CAB extraction requires random file access.</p>
 *
 * @author Stef
 * @since 1.3
 */
public class CabExtractor implements ArchiveExtractor {

    @Override public boolean supportsStream() { return false; }

    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (CabReader cab = new CabReader(archive.getAbsolutePath())) {
            for (CabEntry entry : cab.getEntries()) {
                File target = SafePathBuilder.buildSafePath(destination, entry.getName());
                if (entry.isDirectory()) { target.mkdirs(); continue; }
                target.getAbsoluteFile().getParentFile().mkdirs();
                try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
                    cab.extract(entry, out);
                }
                if (entry.getLastModified() > 0) target.setLastModified(entry.getLastModified());
            }
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted Cabinet archive: " + e.getMessage(), e);
        }
    }

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        throw new IOException("CAB extraction requires random access; use extract(File, File) instead.");
    }

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (CabReader cab = new CabReader(archive.getAbsolutePath())) {
            for (CabEntry entry : cab.getEntries()) {
                result.add(new ArcanaEntry.Builder(entry.getName())
                        .uncompressedSize(entry.isDirectory() ? -1L : entry.getSize())
                        .lastModifiedTime(entry.getLastModified() / 1000L)
                        .directory(entry.isDirectory())
                        .format(ArcanaFormat.CAB)
                        .build());
            }
        } catch (ArcanaLimitExceededException e) {
            throw e; // extraction limit (decompression bomb): not a corruption
        } catch (IOException e) {
            throw new ArcanaCorruptedException("Corrupted Cabinet archive: " + e.getMessage(), e);
        }
        return result;
    }
}
