/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.installshield;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;

/** "arcana i": identifies InstallShield cabinets and headers (data1.hdr, data1.cab). */
public final class InstallShieldAnalyzer implements ArcanaAnalyzer {

    @Override public String getId() { return "io.github.realburst.installshield"; }
    @Override public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-installshield"; }
    @Override public String getLicense() { return "Apache-2.0"; }

    @Override
    public Identification analyze(final ByteSource s, final String fileName) throws IOException {
        if (s.length() < 20 || s.u32le(0) != (IsCabinet.SIGNATURE & 0xffffffffL)) return null;
        final long version = s.u32le(4);
        int major;
        if (version >>> 24 == 1) major = (int) ((version >>> 12) & 0xf);
        else if (version >>> 24 == 2 || version >>> 24 == 4) major = (int) (version & 0xffff) / 100;
        else major = 0;
        final boolean header = s.u32le(16) != 0;
        final String what = fileName != null && fileName.toLowerCase().endsWith(".hdr") ? "InstallShield cabinet header" : header ? "InstallShield cabinet (with header)" : "InstallShield cabinet volume";
        return Identification.of("archive", "InstallShield cabinet")
                .version(major == 0 ? "5 or older" : String.valueOf(major))
                .description(what + (header ? "" : ": open data1.hdr or data1.cab to extract the set"))
                .confidence(95)
                .build();
    }
}
