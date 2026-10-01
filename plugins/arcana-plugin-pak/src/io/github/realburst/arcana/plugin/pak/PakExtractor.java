/*
 * Sample Arcana plugin: Quake PAK archives.
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.pak;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.plugin.PluginSupport;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/** Extracts and lists PAK archives. */
final class PakExtractor implements ArchiveExtractor {

    @Override
    public void extract(final File archive, final File destination) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            final byte[] buf = new byte[65536];
            for (final PakFormat.Entry e : PakFormat.readDirectory(raf)) {
                // PluginSupport: safe path inside destination + Arcana's extraction limits
                try (OutputStream out = PluginSupport.openOutput(destination, e.name)) {
                    raf.seek(e.offset);
                    long left = e.size;
                    while (left > 0) {
                        final int n = raf.read(buf, 0, (int) Math.min(buf.length, left));
                        if (n < 0) throw new IOException("Truncated PAK entry: " + e.name);
                        out.write(buf, 0, n);
                        left -= n;
                    }
                }
            }
        }
    }

    /** PAK needs random access: the stream is copied to a temporary file. */
    @Override
    public void extract(final InputStream in, final File destination) throws IOException {
        final File tmp = File.createTempFile("pak-", ".pak");
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
        final List<ArcanaEntry> result = new ArrayList<ArcanaEntry>();
        try (RandomAccessFile raf = new RandomAccessFile(archive, "r")) {
            for (final PakFormat.Entry e : PakFormat.readDirectory(raf)) {
                result.add(new ArcanaEntry.Builder(e.name).compressedSize(e.size).uncompressedSize(e.size).build());
            }
        }
        return result;
    }

    @Override
    public boolean supportsStream() {
        return true;
    }
}
