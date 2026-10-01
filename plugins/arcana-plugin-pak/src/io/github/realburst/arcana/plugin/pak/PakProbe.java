/*
 * Sample Arcana plugin: Quake PAK archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import be.stef.arcana.formats.carve.ByteSource;
import be.stef.arcana.formats.carve.FileCarver;
import java.io.IOException;

/**
 * Carving probe: lets "arcana s" recognize a PAK archive embedded at an
 * arbitrary position inside another file. Registered automatically because
 * PakPlugin.createProbe() returns it.
 */
public final class PakProbe implements FileCarver.FormatProbe {

    @Override
    public int[] leadBytes() {
        return new int[] {'P'}; // "PACK"
    }

    @Override
    public FileCarver.Probe probeAt(final ByteSource s, final long p) throws IOException {
        if (s.u8(p) != 'P' || s.u8(p + 1) != 'A' || s.u8(p + 2) != 'C' || s.u8(p + 3) != 'K') return null;
        final long dirOffset = s.u32le(p + 4);
        final long dirSize = s.u32le(p + 8);
        if (dirSize == 0 || dirSize % PakFormat.RECORD != 0) return null;
        final long count = dirSize / PakFormat.RECORD;
        if (count > 100000) return null;
        final long fileLen = s.length();
        final long dirStart = p + dirOffset;
        if (dirOffset < 12 || dirStart + dirSize > fileLen) return null;
        // The archive ends at the furthest of the directory and the file data it points to.
        long end = dirStart + dirSize;
        for (long r = 0; r < dirSize; r += PakFormat.RECORD) {
            final long off = s.u32le(dirStart + r + PakFormat.NAME);
            final long size = s.u32le(dirStart + r + PakFormat.NAME + 4);
            if (p + off + size > fileLen) return null; // points outside the file: not a real PAK here
            end = Math.max(end, p + off + size);
        }
        return new FileCarver.Probe(end - p, "pak", "pak", "Quake PAK archive (" + count + " files)", null);
    }
}
