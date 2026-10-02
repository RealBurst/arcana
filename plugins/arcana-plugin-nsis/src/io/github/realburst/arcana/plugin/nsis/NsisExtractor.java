/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.nsis;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import be.stef.arcana.util.SafePathBuilder;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Extracts and lists the files of an NSIS installer.
 *
 * <p>Names are relative to $INSTDIR (like 7-Zip); files sent elsewhere keep
 * their root as first directory ("$PLUGINSDIR/...", "$SYSDIR/..."). The
 * uninstaller written by "WriteUninstaller" is not extracted: NSIS builds it
 * at install time from the stub and a separate data block.</p>
 */
final class NsisExtractor implements ArchiveExtractor {

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try {
            extractFile(archive, destination);
        } catch (final EOFException e) {
            throw truncated(e);
        }
    }

    private void extractFile(final File archive, final File destination) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final NsisArchive arc = NsisArchive.open(fileSource(raf));
            final Map<Long, List<NsisArchive.Item>> groups = byOffset(arc);
            final byte[] buf = new byte[65536];
            if (arc.solid) {
                try (InputStream in = solidData(arc)) {
                    long pos = 0;
                    for (final Map.Entry<Long, List<NsisArchive.Item>> g : groups.entrySet()) {
                        if (g.getKey() < pos) throw new IOException("Overlapping NSIS data blocks");
                        NsisStreams.skipFully(in, g.getKey() - pos);
                        final long len = NsisStreams.readInt(in);
                        copy(in, len, g.getValue(), destination, buf);
                        pos = g.getKey() + 4 + len;
                    }
                }
            } else {
                for (final Map.Entry<Long, List<NsisArchive.Item>> g : groups.entrySet()) {
                    try (InputStream in = block(arc, g.getKey(), null)) {
                        copy(in, -1, g.getValue(), destination, buf);
                    }
                }
            }
            for (final NsisArchive.Item item : arc.items) {
                if (item.time > 0) SafePathBuilder.buildSafePath(destination, item.name).setLastModified(item.time * 1000L);
            }
        }
    }

    /** The installer needs random access: the stream is copied to a temporary file. */
    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final File tmp = File.createTempFile("nsis-", ".exe");
        try {
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp))) {
                final byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
            extract(tmp, destination);
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    @Override
    public List<ArcanaEntry> list(final File archive) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final NsisArchive arc = NsisArchive.open(fileSource(raf));
            try {
                computeSizes(arc);
            } catch (final EOFException e) {
                throw truncated(e);
            }
            final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
            for (final NsisArchive.Item item : arc.items) {
                result.add(new ArcanaEntry.Builder(item.name).compressedSize(item.packedSize).uncompressedSize(item.size).lastModifiedTime(item.time).build());
            }
            return result;
        }
    }

    @Override
    public boolean supportsStream() {
        return true;
    }

    /** The decoders report a premature end of input without a message. */
    private static IOException truncated(final EOFException e) {
        final IOException r = new IOException("NSIS installer truncated or damaged" + (e.getMessage() != null ? " (" + e.getMessage() + ")" : ""));
        r.initCause(e);
        return r;
    }

    // =========================================================================
    // Data access
    // =========================================================================

    static NsisStreams.Source fileSource(final RandomAccessFile raf) {
        return new NsisStreams.Source() {
            @Override
            public long length() {
                try {
                    return raf.length();
                } catch (final IOException e) {
                    return 0;
                }
            }

            @Override
            public int read(final long pos, final byte[] b, final int off, final int len) throws IOException {
                raf.seek(pos);
                return raf.read(b, off, len);
            }
        };
    }

    /** Items sharing a data block (NSIS stores identical files once) are written together. */
    private static Map<Long, List<NsisArchive.Item>> byOffset(final NsisArchive arc) {
        final Map<Long, List<NsisArchive.Item>> groups = new TreeMap<Long, List<NsisArchive.Item>>();
        for (final NsisArchive.Item item : arc.items) {
            List<NsisArchive.Item> l = groups.get(item.offset);
            if (l == null) {
                l = new ArrayList<NsisArchive.Item>();
                groups.put(item.offset, l);
            }
            l.add(item);
        }
        return groups;
    }

    /** Solid installers: decompressed data positioned just after the header. */
    private static InputStream solidData(final NsisArchive arc) throws IOException {
        final long start = arc.firstHeader + NsisArchive.FIRST_HEADER_SIZE;
        final InputStream in = NsisStreams.decoder(NsisStreams.range(arc.src, start, arc.end - start), arc.method);
        NsisStreams.skipFully(in, 4L + arc.headerLength);
        return in;
    }

    /** Non-solid installers: decompressed content of the block at offset (stored size in sizes[0], file size in sizes[1] if known). */
    private static InputStream block(final NsisArchive arc, final long offset, final long[] sizes) throws IOException {
        final long pos = arc.dataStart + offset;
        final long avail = arc.end - pos - 4;
        if (avail < 0) throw new IOException("NSIS data block outside the installer");
        final byte[] len4 = new byte[4];
        NsisStreams.readFully(arc.src, pos, len4);
        final long raw = NsisArchive.le32(len4, 0) & 0xffffffffL;
        final long len = raw & 0x7fffffffL;
        if (len > avail) throw new IOException("NSIS data block truncated");
        if (sizes != null) sizes[0] = len;
        final InputStream data = NsisStreams.range(arc.src, pos + 4, len);
        if ((raw & 0x80000000L) == 0) {
            if (sizes != null) sizes[1] = len;
            return data;
        }
        final int n = (int) Math.min(16, len);
        final byte[] first = new byte[n];
        NsisStreams.readFully(arc.src, pos + 4, first);
        return NsisStreams.decoder(data, NsisStreams.detect(first, 0));
    }

    /** Fills packedSize (non-solid) and size of every item; decompresses the data once. */
    private static void computeSizes(final NsisArchive arc) throws IOException {
        final Map<Long, List<NsisArchive.Item>> groups = byOffset(arc);
        if (arc.solid) {
            try (InputStream in = solidData(arc)) {
                long pos = 0;
                for (final Map.Entry<Long, List<NsisArchive.Item>> g : groups.entrySet()) {
                    NsisStreams.skipFully(in, g.getKey() - pos);
                    final long len = NsisStreams.readInt(in);
                    for (final NsisArchive.Item item : g.getValue()) item.size = len;
                    NsisStreams.skipFully(in, len);
                    pos = g.getKey() + 4 + len;
                }
            }
            return;
        }
        final byte[] buf = new byte[65536];
        for (final Map.Entry<Long, List<NsisArchive.Item>> g : groups.entrySet()) {
            final long[] sizes = {-1, -1};
            try (InputStream in = block(arc, g.getKey(), sizes)) {
                if (sizes[1] < 0) {
                    long total = 0;
                    int k;
                    while ((k = in.read(buf)) > 0) total += k;
                    sizes[1] = total;
                }
            }
            for (final NsisArchive.Item item : g.getValue()) {
                item.packedSize = sizes[0];
                item.size = sizes[1];
            }
        }
    }

    /** Copies len bytes (all remaining bytes if len < 0) to the files of a group. */
    private static void copy(final InputStream in, final long len, final List<NsisArchive.Item> targets, final File destination, final byte[] buf) throws IOException {
        final OutputStream[] outs = new OutputStream[targets.size()];
        try {
            for (int i = 0; i < outs.length; i++) outs[i] = PluginSupport.openOutput(destination, targets.get(i).name);
            long left = len < 0 ? Long.MAX_VALUE : len;
            while (left > 0) {
                final int n = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (n < 0) {
                    if (len < 0) break;
                    throw new IOException("Truncated NSIS file: " + targets.get(0).name);
                }
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
    }
}
