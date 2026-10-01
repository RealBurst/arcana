/*
 * Sample Arcana plugin: Quake PAK archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Reading of the PAK directory. */
final class PakFormat {

    static final int RECORD = 64;
    static final int NAME = 56;

    /** One file of the archive. */
    static final class Entry {
        final String name;
        final long offset;
        final long size;

        Entry(final String name, final long offset, final long size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }
    }

    private PakFormat() {}

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    static List<Entry> readDirectory(final RandomAccessFile raf) throws IOException {
        final byte[] h = new byte[12];
        raf.seek(0);
        raf.readFully(h);
        if (h[0] != 'P' || h[1] != 'A' || h[2] != 'C' || h[3] != 'K') throw new IOException("Not a PAK archive");
        final long dirOffset = le32(h, 4) & 0xFFFFFFFFL;
        final long dirSize = le32(h, 8) & 0xFFFFFFFFL;
        if (dirSize % RECORD != 0 || dirOffset + dirSize > raf.length()) throw new IOException("Corrupted PAK directory");
        final byte[] dir = new byte[(int) dirSize];
        raf.seek(dirOffset);
        raf.readFully(dir);
        final List<Entry> list = new ArrayList<Entry>();
        for (int p = 0; p < dir.length; p += RECORD) {
            int n = 0;
            while (n < NAME && dir[p + n] != 0) n++;
            final String name = new String(dir, p, n, StandardCharsets.ISO_8859_1);
            final long off = le32(dir, p + NAME) & 0xFFFFFFFFL;
            final long size = le32(dir, p + NAME + 4) & 0xFFFFFFFFL;
            if (off + size > raf.length()) throw new IOException("Corrupted PAK entry: " + name);
            list.add(new Entry(name, off, size));
        }
        return list;
    }
}
