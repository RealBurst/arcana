/*
 * Arcana plugin: Nintendo Switch XCI (NX Card Image) archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.xci;

import be.stef.arcana.compressor.ArchiveCompressor;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.formats.recover.ArchiveRecoverer;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor for Nintendo Switch XCI archives.
 *
 * <p>An XCI is a gamecard image. It starts with a 0x200-byte card header
 * (magic "HEAD" at offset 0x100), or with the 0x1000-byte key area followed
 * by the header (HEAD at 0x1100). The header points (0x130 / 0x138) to the
 * root HFS0, which lists the partitions (update, normal, logo, secure), each
 * an HFS0 holding the files (NCA...). See {@link XciFormat}.</p>
 */
public final class XciPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.xci"; }
    @Override public String getName() { return "Nintendo Switch XCI archive"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-xci"; }
    @Override public String getLicense() { return "Apache-2.0"; }
    @Override public String[] getExtensions() { return new String[] {"xci"}; }
    @Override public int getProbeSize() { return 0x1104; } // up to the HEAD magic of a dump with key area

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        // "HEAD" at 0x100 (usual dump) or at 0x1100 (dump with the 0x1000-byte key area)
        return XciFormat.isHead(h, 0x100) || XciFormat.isHead(h, 0x1100);
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new XciExtractor();
    }

    @Override
    public ArchiveCompressor createCompressor(final int level) {
        // XCI is a gamecard image; we do not provide a compressor for it.
        return null;
    }

    /** Recovery strategy: salvages a damaged XCI ("arcana r"). */
    @Override
    public ArchiveRecoverer createRecoverer(final byte[] password) {
        return new XciRecoverer();
    }
}