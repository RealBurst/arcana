/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.installshield;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;
import java.nio.charset.StandardCharsets;

/**
 * Plugin descriptor: InstallShield cabinets (data1.hdr, data1.cab... "ISc(")
 * and the files embedded in InstallShield setup.exe launchers. Extraction only.
 */
public final class InstallShieldPlugin implements ArcanaPlugin {

    private static final byte[] SIG_OLD = "InstallShield\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SIG_STREAM = "ISSetupStream\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WIDE_NAME = "I\0n\0s\0t\0a\0l\0l\0S\0h\0i\0e\0l\0d\0".getBytes(StandardCharsets.US_ASCII);

    @Override public String getId() { return "io.github.realburst.installshield"; }
    @Override public String getName() { return "InstallShield cabinet / setup"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getAuthor() { return "Stephane Bury"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-installshield"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override public String[] getExtensions() { return new String[] {"hdr", "installshield"}; }

    /** The data of a setup.exe follows its launcher, often 1 to 4 MiB long. */
    @Override public int getProbeSize() { return 4 << 20; }

    @Override
    public boolean matches(final byte[] h, final String fileName) {
        if (h.length >= 4 && h[0] == 'I' && h[1] == 'S' && h[2] == 'c' && h[3] == '(') return true;
        if (h.length < 1024 || h[0] != 'M' || h[1] != 'Z') return false;
        // embedded file list within the probe, or the product name in the version resource of the launcher
        return indexOf(h, SIG_OLD) >= 0 || indexOf(h, SIG_STREAM) >= 0 || indexOf(h, WIDE_NAME) >= 0;
    }

    static int indexOf(final byte[] h, final byte[] p) {
        outer:
        for (int i = 0; i + p.length <= h.length; i++) {
            if (h[i] != p[0]) continue;
            for (int k = 1; k < p.length; k++) {
                if (h[i + k] != p[k]) continue outer;
            }
            return i;
        }
        return -1;
    }

    @Override
    public ArchiveExtractor createExtractor(final byte[] password) {
        return new InstallShieldExtractor();
    }
}
