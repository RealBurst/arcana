/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.nsis;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;

/** "arcana i": identifies NSIS installers (version, compression, number of files) instead of a plain PE executable. */
public final class NsisAnalyzer implements ArcanaAnalyzer {

    @Override public String getId() { return "io.github.realburst.nsis"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-nsis"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (s.length() < 1024 || s.u8(0) != 'M' || s.u8(1) != 'Z') return null;
        final NsisStreams.Source src = new NsisStreams.Source() {
            @Override
            public long length() {
                return s.length();
            }

            @Override
            public int read(final long pos, final byte[] b, final int off, final int len) throws IOException {
                return s.read(pos, b, off, len);
            }
        };
        if (NsisArchive.findFirstHeader(src) < 0) return null;
        final NsisArchive arc;
        try {
            arc = NsisArchive.open(src);
        } catch (final IOException e) {
            return Identification.of("archive", "NSIS").description("NSIS installer (header not readable: " + e.getMessage() + ")").confidence(70).build();
        }
        final String kind = arc.isUninstaller() ? "NSIS uninstaller" : "NSIS installer";
        final String strings = arc.unicode ? "Unicode" : "ANSI";
        return Identification.of("archive", "NSIS")
                .version(arc.major + ".x")
                .description(kind + " (" + arc.method.label + (arc.solid ? ", solid" : "") + ", " + strings + ")")
                .detail("compression", arc.method.label + (arc.solid ? " solid" : ""))
                .detail("strings", strings + (arc.pointer64 ? ", 64-bit target" : ""))
                .detail("files", arc.items.size())
                .detail("data offset", arc.firstHeader)
                .confidence(95)
                .build();
    }
}
