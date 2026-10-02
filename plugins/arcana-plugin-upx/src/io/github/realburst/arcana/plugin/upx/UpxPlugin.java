/*
 * Copyright 2026 Stephane Bury.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package io.github.realburst.arcana.plugin.upx;

import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.ArcanaPlugin;

/** Read-only UPX payload extraction for static inspection. */
public final class UpxPlugin implements ArcanaPlugin {
    public String getId() { return "io.github.realburst.upx"; }
    public String getName() { return "UPX executable decompression (PE/ELF)"; }
    public String getVersion() { return "0.3.0"; }
    public String getAuthor() { return "Stephane Bury"; }
    public String getSourceUrl() { return "https://github.com/RealBurst/arcana/tree/main/plugins/arcana-plugin-upx"; }
    public String getLicense() { return "GPL-3.0-or-later"; }
    public String[] getExtensions() { return new String[0]; }
    public int getProbeSize() { return 65536; }

    public boolean matches(byte[] h, String fileName) {
        if (h.length < 64) return false;
        boolean elf = h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F';
        boolean pe = h[0] == 'M' && h[1] == 'Z';
        if (!elf && !pe) return false;
        if (pe) {
            int off = (h[0x3c] & 255) | ((h[0x3d] & 255) << 8)
                    | ((h[0x3e] & 255) << 16) | ((h[0x3f] & 255) << 24);
            if (off < 0 || off + 24 > h.length || h[off] != 'P' || h[off + 1] != 'E'
                    || h[off + 2] != 0 || h[off + 3] != 0) return false;
            int n = (h[off + 6] & 255) | ((h[off + 7] & 255) << 8);
            int opt = (h[off + 20] & 255) | ((h[off + 21] & 255) << 8);
            int sections = off + 24 + opt;
            if (n < 2 || sections < 0 || sections + 80 > h.length) return false;
            return name(h, sections, "UPX0") && name(h, sections + 40, "UPX1");
        }
        // l_info or the appended PackHeader normally contains this signature.
        for (int i = 0; i + 3 < h.length; ++i)
            if (h[i] == 'U' && h[i+1] == 'P' && h[i+2] == 'X' && h[i+3] == '!') return true;
        return false;
    }

    private static boolean name(byte[] h, int off, String value) {
        for (int i = 0; i < value.length(); i++) if (h[off+i] != value.charAt(i)) return false;
        return h[off+value.length()] == 0;
    }

    public ArchiveExtractor createExtractor(byte[] password) { return new UpxExtractor(); }
}
