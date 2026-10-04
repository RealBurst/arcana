/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.innosetup;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor: Inno Setup installers.
 *
 * <p>Supports the setup data formats of Inno Setup 5.4.2 to 7.x (ANSI and
 * Unicode), zlib / bzip2 / LZMA / LZMA2 / stored, solid or not, data inside
 * the installer or in setup-1.bin... files, and encrypted installers when the
 * password is given. Extraction only.</p>
 */
public final class InnoSetupPlugin implements ArcanaPlugin {

    /** The loader offset table sits in the resources of the loader, in its first MiB or two. */
    static final int PROBE = 4 << 20;

    @Override public String getId() { return "io.github.realburst.innosetup"; }
    @Override public String getName() { return "Inno Setup installer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-innosetup"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    /** No real extension (installers are .exe files): "inno" only lets the user name the format. */
    @Override public String[] getExtensions() { return new String[] {"inno", "innosetup"}; }

    @Override public int getProbeSize() { return PROBE; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        if (h.length < 1024 || h[0] != 'M' || h[1] != 'Z') return false;
        return find(h) >= 0;
    }

    /** Position of the loader offset table in the probed bytes, or -1. */
    static int find(final byte[] h) {
        for (int i = 64; i + InnoSetupArchive.LDR_MAGIC.length + 4 <= h.length; i++) {
            if (h[i] == 'r' && InnoSetupArchive.matches(h, i, InnoSetupArchive.LDR_MAGIC)) return i;
        }
        return -1;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new InnoSetupExtractor(password);
    }
}
