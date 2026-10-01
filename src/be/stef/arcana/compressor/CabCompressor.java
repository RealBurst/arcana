/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.compressor;

import be.stef.arcana.formats.cab.CabWriter;
import be.stef.arcana.util.IOHelper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Compresses files into Microsoft Cabinet ({@code .cab}) archives using MSZIP.
 *
 * @author Stef
 * @since 1.3
 */
public final class CabCompressor implements ArchiveCompressor {

    @Override public boolean supportsDirectories() { return false; }

    @Override
    public void compress(File source, File target) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(target)) {
            compress(source, fos);
        }
    }

    @Override
    public void compress(File source, OutputStream out) throws IOException {
        File abs  = source.getAbsoluteFile();
        File base = abs.isDirectory() ? abs : abs.getParentFile();

        List<File> files = new ArrayList<File>();
        collectFiles(abs, files);

        try (CabWriter cab = new CabWriter(out)) {
            for (File file : files) {
                String name = relativePath(base, file).replace('/', '\\');
                byte[] data = readFile(file);
                cab.addFile(name, data, file.lastModified());
            }
        }
    }

    private static void collectFiles(File current, List<File> out) {
        if (current.isFile()) { out.add(current); return; }
        File[] children = current.listFiles();
        if (children == null) return;
        Arrays.sort(children);
        for (File child : children) if (child.isFile()) out.add(child);
        for (File child : children) if (child.isDirectory()) collectFiles(child, out);
    }

    private static byte[] readFile(File file) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream((int) Math.min(file.length(), Integer.MAX_VALUE));
        try (FileInputStream fis = new FileInputStream(file)) { IOHelper.copy(fis, baos); }
        return baos.toByteArray();
    }

    private static String relativePath(File base, File file) {
        String bp = base.getAbsolutePath().replace('\\', '/');
        String fp = file.getAbsolutePath().replace('\\', '/');
        if (fp.startsWith(bp + "/")) return fp.substring(bp.length() + 1);
        return file.getName();
    }
}
