/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.wixburn;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/**
 * Plugin descriptor: WiX Burn bundles (setup.exe bootstrappers made by the WiX
 * toolset 3.x to 6), recognized by the ".wixburn" section of their PE header.
 * Extraction only.
 */
public final class WixBurnPlugin implements ArcanaPlugin {

    @Override public String getId() { return "io.github.realburst.wixburn"; }
    @Override public String getName() { return "WiX Burn bundle"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-wixburn"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override public String[] getExtensions() { return new String[] {"wixburn"}; }

    /** The section table of the PE header is in the first 4 KiB. */
    @Override public int getProbeSize() { return 4096; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        return BurnBundle.hasSection(h);
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new WixBurnExtractor();
    }
}
