/*
 * Arcana plugin: Quake PAK archives (id Software, 1996).
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import be.stef.arcana.compressor.ArchiveCompressor;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.formats.carve.FileCarver;
import be.stef.arcana.formats.recover.ArchiveRecoverer;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor: declares the format and creates the extractor / compressor.
 *
 * <p>Format: "PACK" (4 bytes), directory offset (int32 LE), directory size
 * (int32 LE); the directory is a list of 64-byte records: name (56 bytes, NUL
 * padded, '/' separators), data offset (int32 LE), data size (int32 LE).</p>
 */
public final class PakPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.pak"; }
    @Override public String getName() { return "Quake PAK archive"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-pak"; }
    @Override public String getLicense() { return "Apache-2.0"; }
    @Override public String[] getExtensions() { return new String[] {"pak"}; }
    @Override public int getProbeSize() { return 12; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        return h.length >= 12 && h[0] == 'P' && h[1] == 'A' && h[2] == 'C' && h[3] == 'K' && PakFormat.le32(h, 8) % 64 == 0;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new PakExtractor();
    }

    @Override
    public ArchiveCompressor createCompressor(final int level) {
        return new PakCompressor();
    }

    /** Carving probe: recognizes a PAK embedded in another file ("arcana s"). */
    @Override
    public FileCarver.FormatProbe createProbe() {
        return new PakProbe();
    }

    /** Recovery strategy: salvages a damaged PAK ("arcana r"). */
    @Override
    public ArchiveRecoverer createRecoverer(final byte[] password) {
        return new PakRecoverer();
    }
}
