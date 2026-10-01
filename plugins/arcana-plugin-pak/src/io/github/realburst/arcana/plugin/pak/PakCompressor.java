/*
 * Sample Arcana plugin: Quake PAK archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import be.stef.arcana.compressor.ArchiveCompressor;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Creates PAK archives (files are stored, PAK has no compression). */
final class PakCompressor implements ArchiveCompressor {

    @Override
    public void compress(final File source, final File target) throws IOException {
        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(target))) {
            compress(source, out);
        }
    }

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File base = source.isDirectory() ? source : source.getAbsoluteFile().getParentFile();
        final List<File> files = new ArrayList<File>();
        collect(source, files);
        final ByteArrayOutputStream dir = new ByteArrayOutputStream();
        long pos = 12;
        final long[] offsets = new long[files.size()];
        for (int i = 0; i < files.size(); i++) {
            offsets[i] = pos;
            pos += files.get(i).length();
        }
        if (pos > 0xFFFFFFFFL) throw new IOException("PAK archives are limited to 4 GB");
        out.write(new byte[] {'P', 'A', 'C', 'K'});
        writeLe32(out, pos);
        writeLe32(out, files.size() * PakFormat.RECORD);
        final byte[] buf = new byte[65536];
        for (int i = 0; i < files.size(); i++) {
            final File f = files.get(i);
            try (InputStream in = new FileInputStream(f)) {
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
            String name = base.toURI().relativize(f.toURI()).getPath();
            final byte[] nb = name.getBytes(StandardCharsets.ISO_8859_1);
            if (nb.length >= PakFormat.NAME) throw new IOException("Name too long for PAK (55 bytes max): " + name);
            final byte[] rec = new byte[PakFormat.RECORD];
            System.arraycopy(nb, 0, rec, 0, nb.length);
            putLe32(rec, PakFormat.NAME, offsets[i]);
            putLe32(rec, PakFormat.NAME + 4, f.length());
            dir.write(rec);
        }
        dir.writeTo(out);
        out.flush();
    }

    @Override
    public boolean supportsDirectories() {
        return true;
    }

    private static void collect(final File f, final List<File> out) {
        if (f.isFile()) { out.add(f); return; }
        final File[] children = f.listFiles();
        if (children == null) return;
        java.util.Arrays.sort(children);
        for (final File c : children) collect(c, out);
    }

    private static void writeLe32(final OutputStream out, final long v) throws IOException {
        out.write((int) v); out.write((int) (v >>> 8)); out.write((int) (v >>> 16)); out.write((int) (v >>> 24));
    }

    private static void putLe32(final byte[] b, final int p, final long v) {
        b[p] = (byte) v; b[p + 1] = (byte) (v >>> 8); b[p + 2] = (byte) (v >>> 16); b[p + 3] = (byte) (v >>> 24);
    }
}
