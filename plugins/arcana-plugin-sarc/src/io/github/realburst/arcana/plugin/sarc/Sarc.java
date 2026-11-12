/*
 * Arcana plugin: Nintendo SARC archives (.sarc, .pack, .szs...).
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.sarc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SARC archive (Nintendo "sead" library), read from memory.
 *
 * <ul>
 *   <li>Header (0x14): "SARC", header size (u16), byte order mark (FE FF read
 *       in the archive's byte order: bytes FF FE = little-endian, Switch;
 *       FE FF = big-endian, Wii U), file size (u32), data offset (u32),
 *       version (u16, 0x0100), reserved.</li>
 *   <li>SFAT: "SFAT", header size (u16, 0xC), node count (u16), hash key
 *       (u32, 0x65); then 16-byte nodes: name hash, attributes (bit 24 set:
 *       the file has a name, at (attributes &amp; 0xFFFF) * 4 in the name
 *       table), start and end of the data, counted from the data offset.</li>
 *   <li>SFNT: "SFNT", header size (u16, 8), reserved; then the names,
 *       NUL-terminated, each on a 4-byte boundary.</li>
 * </ul>
 * A file without a name is called "0xHASH.bin" (8 hexadecimal digits).
 */
public final class Sarc {

    /** A file of the archive. */
    public static final class Entry {
        public final String name;
        public final int offset;
        public final int size;

        Entry(final String name, final int offset, final int size) {
            this.name = name;
            this.offset = offset;
            this.size = size;
        }
    }

    private final byte[] data;
    private final boolean little;
    private final List<Entry> entries = new ArrayList<Entry>();

    /** True if {@code b} starts with "SARC". */
    public static boolean is(final byte[] b) {
        return b.length >= 4 && b[0] == 'S' && b[1] == 'A' && b[2] == 'R' && b[3] == 'C';
    }

    /** Reads the archive held by {@code data} (not copied). */
    public Sarc(final byte[] data) throws IOException {
        this.data = data;
        if (data.length < 0x14 || !is(data)) throw new IOException("Not a SARC archive");
        if ((data[6] & 0xFF) == 0xFF && (data[7] & 0xFF) == 0xFE) little = true;
        else if ((data[6] & 0xFF) == 0xFE && (data[7] & 0xFF) == 0xFF) little = false;
        else throw new IOException("SARC: invalid byte order mark");
        final int headerSize = u16(4);
        final long dataOffset = u32(0x0C);
        if (headerSize < 0x14 || dataOffset > data.length) throw new IOException("Corrupted SARC header");
        int p = headerSize;
        if (!magic(p, "SFAT")) throw new IOException("SARC: SFAT section not found");
        final int sfatSize = u16(p + 4);
        final int count = u16(p + 6);
        p += sfatSize;
        if ((long) p + count * 16L + 8 > data.length) throw new IOException("Corrupted SARC file table");
        final int nodes = p;
        p += count * 16;
        if (!magic(p, "SFNT")) throw new IOException("SARC: SFNT section not found");
        final int names = p + u16(p + 4);
        final Set<String> seen = new HashSet<String>();
        for (int i = 0; i < count; i++) {
            final int n = nodes + i * 16;
            final long hash = u32(n);
            final long attr = u32(n + 4);
            final long start = u32(n + 8);
            final long end = u32(n + 12);
            String name = null;
            if ((attr & 0x01000000L) != 0) name = cString(names + (int) (attr & 0xFFFF) * 4);
            if (name == null || name.isEmpty()) name = String.format(Locale.ROOT, "0x%08X.bin", hash);
            if (!seen.add(name)) name = name + "~" + i;
            if (end < start || dataOffset + end > data.length) throw new IOException("Corrupted SARC entry (data beyond the end): " + name);
            entries.add(new Entry(name, (int) (dataOffset + start), (int) (end - start)));
        }
    }

    public List<Entry> entries() {
        return entries;
    }

    /** The bytes of an entry. */
    public byte[] bytes(final Entry e) {
        return java.util.Arrays.copyOfRange(data, e.offset, e.offset + e.size);
    }

    /** The underlying bytes (entries are ranges of it). */
    public byte[] data() {
        return data;
    }

    private boolean magic(final int p, final String m) {
        if (p + 4 > data.length) return false;
        for (int i = 0; i < 4; i++) if (data[p + i] != m.charAt(i)) return false;
        return true;
    }

    private int u16(final int p) throws IOException {
        if (p + 2 > data.length) throw new IOException("SARC truncated");
        return little ? (data[p] & 0xFF) | ((data[p + 1] & 0xFF) << 8) : ((data[p] & 0xFF) << 8) | (data[p + 1] & 0xFF);
    }

    private long u32(final int p) throws IOException {
        if (p + 4 > data.length) throw new IOException("SARC truncated");
        if (little) return (data[p] & 0xFFL) | ((data[p + 1] & 0xFFL) << 8) | ((data[p + 2] & 0xFFL) << 16) | ((data[p + 3] & 0xFFL) << 24);
        return ((data[p] & 0xFFL) << 24) | ((data[p + 1] & 0xFFL) << 16) | ((data[p + 2] & 0xFFL) << 8) | (data[p + 3] & 0xFFL);
    }

    private String cString(final int p) {
        if (p < 0 || p >= data.length) return null;
        int end = p;
        while (end < data.length && data[end] != 0) end++;
        return new String(data, p, end - p, StandardCharsets.UTF_8);
    }
}
