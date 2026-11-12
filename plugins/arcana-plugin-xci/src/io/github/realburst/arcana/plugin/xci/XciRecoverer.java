/*
 * Arcana plugin: Nintendo Switch XCI (NX Card Image) archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.xci;

import be.stef.arcana.formats.recover.ArchiveRecoverer;
import be.stef.arcana.formats.recover.RecoveredFile;
import be.stef.arcana.formats.recover.RecoveryReport;
import be.stef.arcana.plugin.PluginSupport;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * Recovery strategy: lets "arcana r" salvage a damaged XCI. The root HFS0 and
 * the partitions are read record by record; a record that points outside the
 * file, or whose data cannot be fully read, still yields whatever bytes are
 * present instead of aborting the whole archive.
 */
public final class XciRecoverer implements ArchiveRecoverer {

    @Override
    public List<RecoveredFile> recover(final File archive, final File destination) throws IOException {
        final List<RecoveredFile> result = new ArrayList<RecoveredFile>();
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final long root = XciFormat.rootOffset(raf, XciFormat.headerOffset(raf));
            recoverHfs0(raf, root, "", destination, result, true);
        }
        return result;
    }

    /** Salvages the files of the HFS0 at {@code start}; in the root, the partitions are walked too. */
    private static void recoverHfs0(final RandomAccessFile raf, final long start, final String prefix, final File destination, final List<RecoveredFile> result, final boolean root) throws IOException {
        final long len = raf.length();
        if (start + 0x10 > len) {
            result.add(new RecoveredFile(prefix.isEmpty() ? "root" : prefix, RecoveryReport.Status.LOST, 0, "HFS0 header beyond the end of the file"));
            return;
        }
        final byte[] h = new byte[0x10];
        raf.seek(start);
        raf.readFully(h);
        if (!XciFormat.isHfs0(h, 0)) {
            result.add(new RecoveredFile(prefix.isEmpty() ? "root" : prefix, RecoveryReport.Status.LOST, 0, "no HFS0 header at 0x" + Long.toHexString(start)));
            return;
        }
        final int fileCount = XciFormat.le32(h, 4);
        final int stringTableSize = XciFormat.le32(h, 8);
        if (fileCount < 0 || fileCount > XciFormat.MAX_FILES || stringTableSize < 0 || stringTableSize > XciFormat.MAX_STRING_TABLE) {
            result.add(new RecoveredFile(prefix.isEmpty() ? "root" : prefix, RecoveryReport.Status.LOST, 0, "corrupted HFS0 header"));
            return;
        }
        final long entryTableStart = start + 0x10;
        final long stringTableStart = entryTableStart + (long) fileCount * XciFormat.HFS0_ENTRY_SIZE;
        final long dataStart = stringTableStart + stringTableSize;
        // string table: what is present (missing names become entry_N)
        final byte[] strings = new byte[(int) Math.max(0, Math.min(stringTableSize, len - stringTableStart))];
        if (strings.length > 0) {
            raf.seek(stringTableStart);
            raf.readFully(strings);
        }
        final byte[] e = new byte[XciFormat.HFS0_ENTRY_SIZE];
        final byte[] magic = new byte[4];
        final byte[] buf = new byte[65536];
        for (int i = 0; i < fileCount; i++) {
            final long entryPos = entryTableStart + (long) i * XciFormat.HFS0_ENTRY_SIZE;
            if (entryPos + XciFormat.HFS0_ENTRY_SIZE > len) {
                result.add(new RecoveredFile(prefix + "entry_" + i, RecoveryReport.Status.LOST, 0, "file entry beyond the end of the file"));
                continue;
            }
            raf.seek(entryPos);
            raf.readFully(e);
            final long dataOffset = XciFormat.le64(e, 0);
            final long dataSize = XciFormat.le64(e, 8);
            final String n = XciFormat.name(strings, XciFormat.le32(e, 0x10));
            final String name = prefix + (n == null || n.isEmpty() ? "entry_" + i : n);
            final long absolute = dataStart + dataOffset;
            if (dataOffset < 0 || dataSize < 0 || absolute >= len) {
                result.add(new RecoveredFile(name, RecoveryReport.Status.LOST, 0, "data beyond the end of the file"));
                continue;
            }
            if (root && dataSize >= 0x10) {
                raf.seek(absolute);
                raf.readFully(magic);
                if (XciFormat.isHfs0(magic, 0)) {
                    recoverHfs0(raf, absolute, name + "/", destination, result, false); // a partition
                    continue;
                }
            }
            final long available = Math.min(dataSize, len - absolute);
            long written = 0;
            try (OutputStream o = PluginSupport.openOutput(destination, name)) {
                raf.seek(absolute);
                while (written < available) {
                    final int k = raf.read(buf, 0, (int) Math.min(buf.length, available - written));
                    if (k < 0) break;
                    o.write(buf, 0, k);
                    written += k;
                }
            }
            if (written == dataSize) result.add(RecoveredFile.ok(name, written));
            else result.add(RecoveredFile.partial(name, written, "truncated: " + written + " of " + dataSize + " bytes"));
        }
    }
}
