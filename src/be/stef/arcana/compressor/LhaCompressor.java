/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.compressor;

import be.stef.arcana.formats.lha.Lh5Encoder;
import be.stef.arcana.formats.lha.LhaWriter;
import be.stef.arcana.util.IOHelper;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Compresses files and directories into LHA ({@code .lzh}, {@code .lha}) archives
 * using <b>-lh5-</b> compression and header level 2.
 *
 * <p>-lh5- (13-bit dictionary, adaptive Huffman) is the most widely compatible
 * LZH compression method.  All mainstream tools (WinLHA, 7-Zip, FreeArc, etc.)
 * can extract it.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class LhaCompressor implements ArchiveCompressor {

    /** Creates a LhaCompressor. */
    private final int dictBits;

    /** LHA archive with -lh5- (8 KB dictionary), readable by every LHA tool. */
    public LhaCompressor() { this(Lh5Encoder.LH5); }

    /**
     * LHA archive with the given method.
     *
     * @param dictBits {@link Lh5Encoder#LH5} (-lh5-), {@link Lh5Encoder#LH6} (-lh6-) or
     *                 {@link Lh5Encoder#LH7} (-lh7-, 64 KB dictionary, best ratio)
     */
    public LhaCompressor(final int dictBits) {
        Lh5Encoder.methodFor(dictBits); // validates
        this.dictBits = dictBits;
    }

    @Override public boolean supportsDirectories() { return true; }

    @Override
    public void compress(final File source, final File target) throws IOException {
        try (final FileOutputStream fos = new FileOutputStream(target)) {
            compress(source, fos);
        }
    }

    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File abs  = source.getAbsoluteFile();
        final File base = abs.isDirectory() ? abs : abs.getParentFile();

        final List<File> files = new ArrayList<File>();
        final List<File> dirs  = new ArrayList<File>();
        collectAll(abs, files, dirs);

        try (final LhaWriter lha = new LhaWriter(new BufferedOutputStream(out, 65536), dictBits)) {
            // Write file entries first
            for (final File file : files) {
                final String entryName = relativePath(base, file);
                final byte[] data = readFile(file);
                lha.writeEntry(entryName, data, file.lastModified());
            }
            // Then directory entries
            for (final File dir : dirs) {
                String entryName = relativePath(base, dir);
                if (!entryName.endsWith("/")) entryName += "/";
                lha.writeDirectory(entryName, dir.lastModified());
            }
            lha.finish();
        }
    }

    // ---- Helpers ---------------------------------------------------------

    private static void collectAll(final File current, final List<File> files, final List<File> dirs) {
        if (current.isFile()) { files.add(current); return; }
        final File[] children = current.listFiles();
        if (children == null) return;
        Arrays.sort(children);
        for (final File child : children) {
            if (child.isDirectory()) { dirs.add(child); collectAll(child, files, dirs); }
            else                     { files.add(child); }
        }
    }

    private static byte[] readFile(final File file) throws IOException {
        final java.io.ByteArrayOutputStream baos =
                new java.io.ByteArrayOutputStream((int) Math.min(file.length(), Integer.MAX_VALUE));
        try (final FileInputStream fis = new FileInputStream(file)) { IOHelper.copy(fis, baos); }
        return baos.toByteArray();
    }

    private static String relativePath(final File base, final File file) {
        final String bp = base.getAbsolutePath().replace('\\', '/');
        final String fp = file.getAbsolutePath().replace('\\', '/');
        if (fp.startsWith(bp + "/")) return fp.substring(bp.length() + 1);
        return file.getName();
    }
}
