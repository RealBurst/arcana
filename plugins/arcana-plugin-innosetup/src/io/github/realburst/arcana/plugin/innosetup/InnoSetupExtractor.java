/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.innosetup;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import be.stef.arcana.util.SafePathBuilder;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * Extracts and lists the files of an Inno Setup installer.
 *
 * <p>Paths are relative to the application directory: "{app}\bin\x.exe"
 * gives "bin/x.exe"; files installed elsewhere keep their folder constant as
 * first directory ("sys/x.dll", "tmp/helper.dll", "commonappdata/..."). The
 * uninstaller is not extracted (Setup writes its own executable).</p>
 */
final class InnoSetupExtractor implements ArchiveExtractor {

    private static final int BUFFER = 65536; // also the unit of the CALL/JMP conversion

    private final byte[] password;

    InnoSetupExtractor(final byte[] password) {
        this.password = password;
    }

    @Override
    public boolean supportsStream() {
        return false;
    }

    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("Inno Setup installers require random file access - use extract(File,File).");
    }

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try (InnoSetupArchive arc = InnoSetupArchive.open(archive, password)) {
            final Map<Integer, List<String>> byLoc = new LinkedHashMap<Integer, List<String>>();
            for (final InnoSetupArchive.Item it : arc.items) {
                List<String> l = byLoc.get(it.location);
                if (l == null) byLoc.put(it.location, l = new ArrayList<String>());
                l.add(it.path);
            }
            final List<Integer> order = new ArrayList<Integer>(byLoc.keySet());
            Collections.sort(order, new Comparator<Integer>() {
                @Override
                public int compare(final Integer a, final Integer b) {
                    final InnoSetupArchive.Location x = arc.locations[a];
                    final InnoSetupArchive.Location y = arc.locations[b];
                    if (x.firstSlice != y.firstSlice) return x.firstSlice < y.firstSlice ? -1 : 1;
                    if (x.startOffset != y.startOffset) return x.startOffset < y.startOffset ? -1 : 1;
                    return Long.compare(x.chunkSuboffset, y.chunkSuboffset);
                }
            });
            final byte[] buf = new byte[BUFFER];
            InputStream chunk = null;
            InnoSetupArchive.Location current = null;
            long pos = 0;
            try {
                for (final int index : order) {
                    final InnoSetupArchive.Location l = arc.locations[index];
                    final List<String> names = byLoc.get(index);
                    if (chunk == null || current.firstSlice != l.firstSlice || current.startOffset != l.startOffset || l.chunkSuboffset < pos) {
                        if (chunk != null) chunk.close();
                        chunk = arc.openChunk(l);
                        current = l;
                        pos = 0;
                    }
                    skip(chunk, l.chunkSuboffset - pos, buf);
                    copy(arc, chunk, l, names, destination, buf);
                    pos = l.chunkSuboffset + l.size;
                    if (l.time > 0) {
                        for (final String n : names) SafePathBuilder.buildSafePath(destination, n).setLastModified(l.time);
                    }
                }
            } catch (final ArcanaException e) {
                throw e;
            } catch (final IOException e) {
                // decoder errors ("incorrect data check", end of input...)
                final IOException r = new ArcanaCorruptedException("Inno Setup installer truncated or damaged" + (e.getMessage() != null ? " (" + e.getMessage() + ")" : ""));
                r.initCause(e);
                throw r;
            } finally {
                if (chunk != null) chunk.close();
            }
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        try (InnoSetupArchive arc = InnoSetupArchive.open(archive, password)) {
            final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
            for (final InnoSetupArchive.Item it : arc.items) {
                final InnoSetupArchive.Location l = arc.locations[it.location];
                final ArcanaEntry.Builder b = new ArcanaEntry.Builder(it.path).uncompressedSize(l.size).lastModifiedTime(l.time / 1000L).encrypted(l.encrypted);
                // the packed size is known when the chunk holds this file only (non-solid installers)
                if (l.chunkSuboffset == 0 && arc.chunkSize(l) == l.size) b.compressedSize(l.chunkPackedSize);
                result.add(b.build());
            }
            return result;
        }
    }

    private static void skip(final InputStream in, long n, final byte[] buf) throws IOException {
        while (n > 0) {
            final int r = in.read(buf, 0, (int) Math.min(buf.length, n));
            if (r < 0) throw new EOFException("chunk shorter than its files");
            n -= r;
        }
    }

    /** Copies one file to all its destinations, undoing the CALL conversion and checking the checksum. */
    private static void copy(final InnoSetupArchive arc, final InputStream in, final InnoSetupArchive.Location l, final List<String> names, final File destination, final byte[] buf) throws IOException {
        final String hashName = arc.hashName();
        final MessageDigest md = "SHA256Sum".equals(hashName) ? InnoCrypto.digest("SHA-256") : "SHA1Sum".equals(hashName) ? InnoCrypto.digest("SHA-1") : "MD5Sum".equals(hashName) ? InnoCrypto.digest("MD5") : null;
        final CRC32 crc = md == null ? new CRC32() : null;
        final OutputStream[] outs = new OutputStream[names.size()];
        try {
            for (int i = 0; i < outs.length; i++) outs[i] = PluginSupport.openOutput(destination, names.get(i));
            long left = l.size;
            int addr = 0;
            while (left > 0) {
                final int n = (int) Math.min(buf.length, left);
                InnoSetupArchive.readFully(in, buf, 0, n);
                if (l.callOptimized) {
                    InnoSetupArchive.untransformCalls(buf, n, addr);
                    addr += n;
                }
                if (md != null) md.update(buf, 0, n);
                else crc.update(buf, 0, n);
                for (final OutputStream out : outs) out.write(buf, 0, n);
                left -= n;
            }
        } finally {
            IOException first = null;
            for (final OutputStream out : outs) {
                if (out == null) continue;
                try {
                    out.close();
                } catch (final IOException e) {
                    if (first == null) first = e;
                }
            }
            if (first != null) throw first;
        }
        final boolean ok = md != null ? MessageDigest.isEqual(md.digest(), l.hash) : (int) crc.getValue() == InnoSetupArchive.le32(l.hash, 0);
        if (!ok) throw new ArcanaCorruptedException("Checksum error in Inno Setup file " + names.get(0) + (l.encrypted ? " (wrong password?)" : ""));
    }
}
