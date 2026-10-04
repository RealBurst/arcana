/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.jexepack;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.EOFException;
import java.io.IOException;

/** "arcana i": identifies Java programs packed by JexePack (packager version, main class, embedded files) instead of a plain PE executable. */
public final class JexePackAnalyzer implements ArcanaAnalyzer {

    @Override public String getId() { return "io.github.realburst.jexepack"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-jexepack"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (s.length() < 1024 || s.u8(0) != 'M' || s.u8(1) != 'Z') return null;
        final JexePackArchive.Source src = new JexePackArchive.Source() {
            @Override
            public long length() {
                return s.length();
            }

            @Override
            public void readFully(final long pos, final byte[] b, final int off, final int len) throws IOException {
                if (s.read(pos, b, off, len) != len) throw new EOFException("JexePack data truncated");
            }
        };
        if (JexePackArchive.findFirst(src) < 0) return null;
        final JexePackArchive arc;
        try {
            arc = JexePackArchive.read(src);
        } catch (final IOException e) {
            return Identification.of("archive", "JexePack").description("Java program packed by JexePack (data not readable: " + e.getMessage() + ")").confidence(70).build();
        }
        final StringBuilder files = new StringBuilder();
        for (final JexePackArchive.Item it : arc.items) {
            if (files.length() > 0) files.append(", ");
            files.append(it.name);
        }
        final Identification.Builder b = Identification.of("archive", "JexePack")
                .description("Java program packed into an executable by " + (arc.packager.isEmpty() ? "JexePack" : arc.packager) + " (extract it to check the jar files)")
                .detail("files", files.toString())
                .confidence(95);
        if (!arc.packager.isEmpty()) b.version(arc.packager.replace("JexePack", "").trim());
        if (!arc.mainClass.isEmpty()) b.detail("main class", arc.mainClass);
        return b.build();
    }
}
