/*
 * Arcana plugin: Nintendo SARC archives (.sarc, .pack, .szs...).
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.sarc;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** Extracts and lists SARC archives, plain or Yaz0-compressed (.szs). */
final class SarcExtractor implements ArchiveExtractor {

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        extract(Files.readAllBytes(archive.toPath()), destination);
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final ByteArrayOutputStream all = new ByteArrayOutputStream();
        final byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) all.write(buf, 0, n);
        extract(all.toByteArray(), destination);
    }

    private static void extract(final byte[] file, final File destination) throws IOException {
        final Sarc sarc = open(file);
        for (final Sarc.Entry e : sarc.entries()) {
            try (OutputStream out = PluginSupport.openOutput(destination, e.name, e.size)) {
                out.write(sarc.data(), e.offset, e.size);
            }
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        for (final Sarc.Entry e : open(Files.readAllBytes(archive.toPath())).entries()) result.add(new ArcanaEntry.Builder(e.name).compressedSize(e.size).uncompressedSize(e.size).method("Stored").build());
        return result;
    }

    @Override
    public boolean supportsStream() {
        return true;
    }

    /** The archive of a plain or Yaz0-compressed SARC file. */
    static Sarc open(final byte[] file) throws IOException {
        if (Yaz0.is(file)) {
            final byte[] plain = Yaz0.decompress(file);
            if (!Sarc.is(plain)) throw new IOException("Yaz0 file that does not hold a SARC archive");
            return new Sarc(plain);
        }
        return new Sarc(file);
    }
}
