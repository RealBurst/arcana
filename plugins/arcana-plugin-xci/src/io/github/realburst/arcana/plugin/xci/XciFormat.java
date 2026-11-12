/*
 * Arcana plugin: Nintendo Switch XCI (NX Card Image) archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.xci;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Reading of the XCI gamecard header and of its HFS0 partitions.
 *
 * <p>Layout (switchbrew, "XCI"): the card header (0x200 bytes) holds the
 * magic "HEAD" at 0x100 and, at 0x130 / 0x138, the address and size of the
 * root HFS0, counted from the start of the header (usually 0xF000). Most
 * dumps start with the header (HEAD at file offset 0x100); dumps that keep
 * the 0x1000-byte key area put it at 0x1000 (HEAD at 0x1100).</p>
 *
 * <p>The root HFS0 lists the partitions ("update", "normal", "logo",
 * "secure"), each one an HFS0 of its own holding the files (NCA...). The
 * entries are returned as "partition/file".</p>
 */
final class XciFormat {

    /** Offset of the HFS0 address field inside the card header. */
    static final int HFS0_OFFSET_FIELD = 0x130;

    /** Offset of the HFS0 header size field inside the card header. */
    static final int HFS0_SIZE_FIELD = 0x138;

    /** Size of one HFS0 file entry. */
    static final int HFS0_ENTRY_SIZE = 0x40;

    /** Size of the key area that some dumps keep before the card header. */
    static final int KEY_AREA_SIZE = 0x1000;

    /** Sanity limits of an HFS0 header. */
    static final int MAX_FILES = 100000;
    static final int MAX_STRING_TABLE = 0x1000000;

    /** One file of the XCI. */
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

    private XciFormat() {}

    static long le64(final byte[] b, final int p) {
        return (b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8) | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24) | ((b[p + 4] & 0xFFL) << 32) | ((b[p + 5] & 0xFFL) << 40) | ((b[p + 6] & 0xFFL) << 48) | ((b[p + 7] & 0xFFL) << 56);
    }

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    /** True if {@code b} holds "HEAD" at {@code p}. */
    static boolean isHead(final byte[] b, final int p) {
        return b.length >= p + 4 && b[p] == 'H' && b[p + 1] == 'E' && b[p + 2] == 'A' && b[p + 3] == 'D';
    }

    /** True if {@code b} holds "HFS0" at {@code p}. */
    static boolean isHfs0(final byte[] b, final int p) {
        return b.length >= p + 4 && b[p] == 'H' && b[p + 1] == 'F' && b[p + 2] == 'S' && b[p + 3] == '0';
    }

    /** File offset of the card header: 0 (usual dump) or 0x1000 (dump with the key area). */
    static long headerOffset(final RandomAccessFile raf) throws IOException {
        final byte[] m = new byte[4];
        for (final long base : new long[] {0, KEY_AREA_SIZE}) {
            if (raf.length() < base + 0x200) continue;
            raf.seek(base + 0x100);
            raf.readFully(m);
            if (isHead(m, 0)) return base;
        }
        throw new IOException("Not an XCI archive (missing HEAD magic at 0x100 or 0x1100)");
    }

    /** File offset of the root HFS0. */
    static long rootOffset(final RandomAccessFile raf, final long headerOffset) throws IOException {
        final byte[] header = new byte[0x200];
        raf.seek(headerOffset);
        raf.readFully(header);
        final long address = le64(header, HFS0_OFFSET_FIELD);
        if (address < 0x200 || address > raf.length()) throw new IOException("Corrupted XCI: invalid root HFS0 address 0x" + Long.toHexString(address));
        return headerOffset + address;
    }

    /** All the files of the XCI, as "partition/file". */
    static List<Entry> readEntries(final RandomAccessFile raf) throws IOException {
        final long root = rootOffset(raf, headerOffset(raf));
        final List<Entry> list = new ArrayList<Entry>();
        final byte[] magic = new byte[4];
        for (final Entry partition : readHfs0(raf, root)) {
            boolean nested = false;
            if (partition.size >= 0x10) {
                raf.seek(partition.offset);
                raf.readFully(magic);
                nested = isHfs0(magic, 0);
            }
            if (!nested) {
                list.add(partition); // not a partition: kept as a file
                continue;
            }
            for (final Entry e : readHfs0(raf, partition.offset)) {
                if (e.offset + e.size > partition.offset + partition.size) throw new IOException("Corrupted XCI entry (outside its partition): " + partition.name + "/" + e.name);
                list.add(new Entry(partition.name + "/" + e.name, e.offset, e.size));
            }
        }
        return list;
    }

    /** The files of the HFS0 starting at file offset {@code start} (absolute offsets). */
    static List<Entry> readHfs0(final RandomAccessFile raf, final long start) throws IOException {
        final long fileLen = raf.length();
        if (start + 0x10 > fileLen) throw new IOException("Corrupted XCI: HFS0 beyond the end of the file");
        final byte[] h = new byte[0x10];
        raf.seek(start);
        raf.readFully(h);
        if (!isHfs0(h, 0)) throw new IOException("Not an HFS0 partition at 0x" + Long.toHexString(start));
        final int fileCount = le32(h, 4);
        final int stringTableSize = le32(h, 8);
        if (fileCount < 0 || fileCount > MAX_FILES || stringTableSize < 0 || stringTableSize > MAX_STRING_TABLE) throw new IOException("Corrupted HFS0 header at 0x" + Long.toHexString(start));
        final long entryTableStart = start + 0x10;
        final long stringTableStart = entryTableStart + (long) fileCount * HFS0_ENTRY_SIZE;
        final long dataStart = stringTableStart + stringTableSize;
        if (dataStart > fileLen) throw new IOException("Corrupted HFS0 header at 0x" + Long.toHexString(start));
        final byte[] entries = new byte[fileCount * HFS0_ENTRY_SIZE];
        raf.seek(entryTableStart);
        raf.readFully(entries);
        final byte[] strings = new byte[stringTableSize];
        raf.readFully(strings);
        final List<Entry> list = new ArrayList<Entry>(fileCount);
        for (int i = 0; i < fileCount; i++) {
            final int p = i * HFS0_ENTRY_SIZE;
            final long offset = le64(entries, p);
            final long size = le64(entries, p + 8);
            final String name = name(strings, le32(entries, p + 0x10));
            if (name == null) throw new IOException("Corrupted HFS0 entry " + i + " (bad name offset) at 0x" + Long.toHexString(start));
            if (offset < 0 || size < 0 || dataStart + offset + size > fileLen || dataStart + offset < dataStart) throw new IOException("Corrupted XCI entry (data beyond EOF): " + name);
            list.add(new Entry(name, dataStart + offset, size));
        }
        return list;
    }

    /** NUL-terminated name at {@code off} of the string table, or null if out of the table. */
    static String name(final byte[] strings, final int off) {
        if (off < 0 || off >= strings.length) return null;
        int end = off;
        while (end < strings.length && strings[end] != 0) end++;
        return new String(strings, off, end - off, StandardCharsets.UTF_8);
    }
}
