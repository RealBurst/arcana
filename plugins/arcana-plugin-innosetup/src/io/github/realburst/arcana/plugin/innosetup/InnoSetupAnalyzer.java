/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.innosetup;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.EOFException;
import java.io.IOException;

/** "arcana i": identifies Inno Setup installers (format version, application, compression, files) instead of a plain PE executable. */
public final class InnoSetupAnalyzer implements ArcanaAnalyzer {

    @Override public String getId() { return "io.github.realburst.innosetup"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-innosetup"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (s.length() < 1024 || s.u8(0) != 'M' || s.u8(1) != 'Z') return null;
        final InnoSetupArchive.Source src = new InnoSetupArchive.Source() {
            @Override
            public long length() {
                return s.length();
            }

            @Override
            public void readFully(final long pos, final byte[] b, final int off, final int len) throws IOException {
                if (s.read(pos, b, off, len) != len) throw new EOFException("Inno Setup data truncated");
            }

            @Override
            public void close() {
                // the ByteSource belongs to the caller
            }
        };
        if (InnoSetupArchive.findOffsetTable(src) < 0) return null;
        final InnoSetupArchive arc;
        try {
            arc = InnoSetupArchive.open(src, null, fileName, null);
        } catch (final ArcanaEncryptedException e) {
            final String id = InnoSetupArchive.readSetupId(src);
            final Identification.Builder b = Identification.of("archive", "Inno Setup").description("Inno Setup installer (setup data encrypted: password needed)").detail("encryption", "XChaCha20 (setup data too)");
            if (id != null) b.version(InnoSetupArchive.formatVersion(id));
            return b.confidence(95).build();
        } catch (final IOException e) {
            final String id = InnoSetupArchive.readSetupId(src);
            final Identification.Builder b = Identification.of("archive", "Inno Setup").description("Inno Setup installer (setup data not readable: " + e.getMessage() + ")");
            if (id != null) b.version(InnoSetupArchive.formatVersion(id));
            return b.confidence(70).build();
        }
        final String app = (arc.appName + " " + arc.appVersion).trim();
        final StringBuilder d = new StringBuilder("Inno Setup installer");
        if (!app.isEmpty()) d.append(" of ").append(app);
        d.append(" (").append(arc.method).append(arc.crypt != InnoSetupArchive.Crypt.NONE ? ", encrypted" : "").append(')');
        final Identification.Builder b = Identification.of("archive", "Inno Setup")
                .version(arc.formatVersion())
                .description(d.toString())
                .detail("application", app)
                .detail("compression", arc.method)
                .detail("files", arc.items.size())
                .detail("encryption", arc.crypt == InnoSetupArchive.Crypt.NONE ? "none" : arc.crypt.label + (arc.fullEncryption ? " (setup data too)" : " (files)"));
        if (arc.externalData()) b.detail("data files", arc.sliceName(0) + "...");
        return b.confidence(95).build();
    }
}
