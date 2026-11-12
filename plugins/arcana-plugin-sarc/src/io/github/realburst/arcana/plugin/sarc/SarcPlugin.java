/*
 * Arcana plugin: Nintendo SARC archives (.sarc, .pack, .szs...).
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.sarc;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor of Nintendo SARC archives: the archives of the "sead"
 * library (Wii U, Switch), plain ("SARC" at offset 0: .sarc, .pack,
 * .bactorpack, .blarc...) or compressed with Yaz0 (.szs). A SARC compressed
 * with Zstandard (.pack.zs) is first decompressed by Arcana (a file without
 * the .zs), then opened by this plugin. See {@link Sarc} and {@link Yaz0}.
 */
public final class SarcPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.sarc"; }
    @Override public String getName() { return "Nintendo SARC archive"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-sarc"; }
    @Override public String getLicense() { return "Apache-2.0"; }
    @Override public String[] getExtensions() { return new String[] {"sarc", "szs", "pack", "blarc", "bactorpack"}; }
    @Override public int getProbeSize() { return 21; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        if (Sarc.is(h)) return true;
        // Yaz0: the first flag byte says the first 4 bytes are literals, and they are "SARC"
        return Yaz0.is(h) && h.length >= 21 && (h[16] & 0xF0) == 0xF0 && h[17] == 'S' && h[18] == 'A' && h[19] == 'R' && h[20] == 'C';
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new SarcExtractor();
    }
}
