/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.jexepack;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor: Java programs packed into a Windows executable by
 * JexePack (Duckware). Extracts the jar files, the DLLs, the bootstrap class
 * and the settings, to check what the program contains. Extraction only.
 */
public final class JexePackPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.jexepack"; }
    @Override public String getName() { return "JexePack Java executable"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-jexepack"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    /** No real extension (.exe files): "jexepack" only lets the user name the format. */
    @Override public String[] getExtensions() { return new String[] {"jexepack"}; }

    /** The records follow the small launcher (a few dozen KiB). */
    @Override public int getProbeSize() { return 1 << 20; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        if (h.length < 1024 || h[0] != 'M' || h[1] != 'Z') return false;
        for (int i = 0; i + JexePackArchive.HEADER <= h.length; i += 16) {
            if (h[i] == 0x4A && JexePackArchive.isSignature(h, i)) return true;
        }
        return false;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new JexePackExtractor();
    }
}
