/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.nsis;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor: Nullsoft Scriptable Install System (NSIS) installers.
 *
 * <p>Supports NSIS 2.x and 3.x, ANSI and Unicode, zlib / bzip2 / LZMA,
 * solid or not. Extraction only: an installer cannot be rebuilt.</p>
 */
public final class NsisPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.nsis"; }
    @Override public String getName() { return "NSIS installer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-nsis"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    /** No real extension (installers are .exe files): "nsis" only lets the user name the format. */
    @Override public String[] getExtensions() { return new String[] {"nsis"}; }

    /** The installer data follows the executable stub, usually within the first few hundred KiB. */
    @Override public int getProbeSize() { return 1 << 20; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        if (h.length < 1024 || h[0] != 'M' || h[1] != 'Z') return false;
        for (int off = 512; off + NsisArchive.FIRST_HEADER_SIZE <= h.length; off += 512) {
            if (NsisArchive.isFirstHeader(h, off)) return true;
        }
        return false;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new NsisExtractor();
    }
}
