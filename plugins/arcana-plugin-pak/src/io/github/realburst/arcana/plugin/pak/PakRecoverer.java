/*
 * Sample Arcana plugin: Quake PAK archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import be.stef.arcana.formats.recover.ArchiveRecoverer;
import be.stef.arcana.formats.recover.RecoveredFile;
import be.stef.arcana.plugin.PluginSupport;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Recovery strategy: lets "arcana r" salvage a damaged PAK. The directory is
 * read record by record; a record that points outside the file, or whose data
 * cannot be fully read, still yields whatever bytes are present instead of
 * aborting the whole archive. Registered because PakPlugin.createRecoverer()
 * returns it.
 */
public final class PakRecoverer implements ArchiveRecoverer {

    @Override
    public List<RecoveredFile> recover(final File archive, final File destination) throws IOException {
        final List<RecoveredFile> result = new ArrayList<RecoveredFile>();
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final long len = raf.length();
            final byte[] h = new byte[12];
            raf.seek(0);
            raf.readFully(h);
            if (h[0] != 'P' || h[1] != 'A' || h[2] != 'C' || h[3] != 'K') throw new IOException("not a PAK archive (bad magic)");
            final long dirOffset = PakFormat.le32(h, 4) & 0xFFFFFFFFL;
            long dirSize = PakFormat.le32(h, 8) & 0xFFFFFFFFL;
            if (dirOffset >= len) throw new IOException("PAK directory offset beyond the file");
            if (dirOffset + dirSize > len) dirSize = (len - dirOffset) / PakFormat.RECORD * PakFormat.RECORD; // truncated directory
            final byte[] dir = new byte[(int) dirSize];
            raf.seek(dirOffset);
            raf.readFully(dir);
            final byte[] buf = new byte[65536];
            for (int r = 0; r + PakFormat.RECORD <= dir.length; r += PakFormat.RECORD) {
                int n = 0;
                while (n < PakFormat.NAME && dir[r + n] != 0) n++;
                final String name = new String(dir, r, n, StandardCharsets.ISO_8859_1);
                final long off = PakFormat.le32(dir, r + PakFormat.NAME) & 0xFFFFFFFFL;
                final long size = PakFormat.le32(dir, r + PakFormat.NAME + 4) & 0xFFFFFFFFL;
                if (name.isEmpty() || off >= len) {
                    result.add(new RecoveredFile(name.isEmpty() ? "entry_" + (r / PakFormat.RECORD) : name, be.stef.arcana.formats.recover.RecoveryReport.Status.LOST, 0, "data beyond the file"));
                    continue;
                }
                final long avail = Math.min(size, len - off);
                long written = 0;
                try (OutputStream o = PluginSupport.openOutput(destination, name)) {
                    raf.seek(off);
                    while (written < avail) {
                        final int k = raf.read(buf, 0, (int) Math.min(buf.length, avail - written));
                        if (k < 0) break;
                        o.write(buf, 0, k);
                        written += k;
                    }
                }
                if (written == size) result.add(RecoveredFile.ok(name, written));
                else result.add(RecoveredFile.partial(name, written, "truncated: " + written + " of " + size + " bytes"));
            }
        }
        return result;
    }
}
