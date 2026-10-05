/* Copyright 2025 Stephane Bury. Apache License 2.0. */
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.sevenz.SevenZEntry;
import be.stef.arcana.formats.sevenz.MultiVolumeChannel;
import be.stef.arcana.formats.sevenz.SevenZFile;
import be.stef.arcana.util.ArcanaConcurrency;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.NullOutputStream;
import be.stef.arcana.util.ParallelRunner;
import be.stef.arcana.util.ProgressOutputStream;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Extractor for 7z archives (.7z).
 * Supports LZMA, LZMA2 (default), BZIP2, Deflate, BCJ filters, AES-256.
 * Deflate64 and PPMd (variant H) are supported (decode only).
 * @author Stef
 * @since 1.0
 */
public class SevenZExtractor implements ArchiveExtractor {

    // 128 MiB: LZMA2 with a 64 MiB dictionary (7-Zip -mx9 / Arcana -l 9) needs slightly more than 64 MiB to decode
    private static final int DEFAULT_MEMORY_LIMIT_KIB = 128 * 1024;
    private final byte[] password;
    private final int memoryLimitKiB;

    public SevenZExtractor() { this(null, DEFAULT_MEMORY_LIMIT_KIB); }
    public SevenZExtractor(byte[] password) { this(password, DEFAULT_MEMORY_LIMIT_KIB); }
    public SevenZExtractor(byte[] password, int memoryLimitKiB) {
        this.password = password; this.memoryLimitKiB = memoryLimitKiB;
    }

    @Override public boolean supportsStream() { return false; }

    /**
     * 7-Zip derives the AES key from the password encoded in UTF-16LE. The byte[] overload of
     * SevenZFile.Builder.setPassword() expects bytes ALREADY in UTF-16LE, so we decode the
     * caller's bytes (UTF-8, as produced by the command line) and pass a String instead.
     */
    private String sevenZipPassword() { return password == null ? null : new String(password, StandardCharsets.UTF_8); }

    private SevenZFile open(final File archive) throws IOException {
        // split archive (x.7z.001, x.7z.002...): the volumes are read as one file
        final MultiVolumeChannel volumes = MultiVolumeChannel.open(archive);
        if (volumes != null) {
            try {
                return SevenZFile.builder().setSeekableByteChannel(volumes).setDefaultName(archive.getName()).setPassword(sevenZipPassword()).setMaxMemoryLimitKiB(memoryLimitKiB).get();
            } catch (final IOException | RuntimeException e) {
                volumes.close();
                throw e;
            }
        }
        return SevenZFile.builder().setFile(archive).setPassword(sevenZipPassword()).setMaxMemoryLimitKiB(memoryLimitKiB).get();
    }

    /**
     * Extracts every entry. Since 1.3, when the archive holds several folders
     * (independent solid blocks, e.g. a non-solid archive or 7-Zip solid blocks),
     * the folders are decoded in parallel, one per thread, each thread with its
     * own {@link SevenZFile}. A single-folder archive is extracted sequentially.
     */
    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        try (SevenZFile sz = open(archive)) {
            if (!extractParallel(archive, destination, sz)) extractSequential(destination, sz);
        }
    }

    private void extractSequential(final File destination, final SevenZFile sz) throws IOException {
        SevenZEntry entry;
        while ((entry = sz.getNextEntry()) != null) {
            File target = SafePathBuilder.buildSafePath(destination, entry.getName());
            if (entry.isDirectory()) { IOHelper.mkdirs(target); continue; }
            IOHelper.mkdirs(target.getParentFile());
            try (InputStream in = sz.getInputStream(entry);
                 ProgressOutputStream out = new ProgressOutputStream(
                         new BufferedOutputStream(ExtractionGuard.open(target), 65536),
                         entry.getSize(), entry.getName())) {
                long copied = IOHelper.copy(in, out);
                out.finish();
                // a damaged stream can end early, before the CRC is checked: the size catches it
                if (copied != entry.getSize()) throw new ArcanaCorruptedException("7z entry '" + entry.getName() + "' is truncated: " + copied + " bytes instead of " + entry.getSize());
            }
        }
    }

    /** A SevenZFile and its entries (same order as the first reader's). */
    private static final class Reader {
        final SevenZFile file;
        final List<SevenZEntry> entries;

        Reader(final SevenZFile file, final List<SevenZEntry> entries) {
            this.file = file;
            this.entries = entries;
        }
    }

    /** @return false if the archive is not worth (or not suitable for) parallel extraction */
    private boolean extractParallel(final File archive, final File destination, final SevenZFile sz) throws IOException {
        final int folders = sz.getFolderCount();
        if (folders < 2) return false;
        final long perWorker = (long) memoryLimitKiB * 1024L + (16L << 20);
        final int threads = Math.min(folders, ArcanaConcurrency.workersFor(perWorker));
        if (threads <= 1) return false;
        final List<SevenZEntry> entries = new ArrayList<SevenZEntry>();
        for (final SevenZEntry e : sz.getEntries()) {
            if (e.getName() == null) return false; // unnamed entries get their default name in sequential mode
            entries.add(e);
        }
        final int[] folderOf = sz.getFolderIndexes();

        // Pass 1 (sequential): directories, parent directories, entries without data
        final File[] targets = new File[entries.size()];
        final Map<File, Integer> lastByTarget = new HashMap<File, Integer>();
        for (int i = 0; i < entries.size(); i++) {
            final SevenZEntry e = entries.get(i);
            targets[i] = SafePathBuilder.buildSafePath(destination, e.getName());
            if (e.isDirectory()) { IOHelper.mkdirs(targets[i]); continue; }
            IOHelper.mkdirs(targets[i].getParentFile());
            lastByTarget.put(targets[i], i);
        }
        final List<List<Integer>> byFolder = new ArrayList<List<Integer>>(folders);
        for (int f = 0; f < folders; f++) byFolder.add(new ArrayList<Integer>());
        for (int i = 0; i < entries.size(); i++) {
            final SevenZEntry e = entries.get(i);
            if (e.isDirectory()) continue;
            if (folderOf[i] < 0) {
                if (lastByTarget.get(targets[i]) == i) ExtractionGuard.open(targets[i]).close(); // empty file
                continue;
            }
            byFolder.get(folderOf[i]).add(i);
        }

        // Pass 2 (parallel): one task per folder; entries of a folder are read in order
        // Each reader has its own entry objects: getInputStream() needs the entries of ITS archive
        final ConcurrentLinkedQueue<Reader> readers = new ConcurrentLinkedQueue<Reader>();
        final ConcurrentLinkedQueue<SevenZFile> opened = new ConcurrentLinkedQueue<SevenZFile>();
        readers.add(new Reader(sz, entries));
        final List<ParallelRunner.IOTask> tasks = new ArrayList<ParallelRunner.IOTask>();
        for (final List<Integer> folderEntries : byFolder) {
            if (folderEntries.isEmpty()) continue;
            tasks.add(() -> {
                Reader reader = readers.poll();
                if (reader == null) {
                    final SevenZFile f = open(archive);
                    opened.add(f);
                    final List<SevenZEntry> own = new ArrayList<SevenZEntry>();
                    for (final SevenZEntry e : f.getEntries()) own.add(e);
                    if (own.size() != entries.size()) throw new ArcanaCorruptedException("7z archive changed during extraction");
                    reader = new Reader(f, own);
                }
                try {
                    for (final int i : folderEntries) {
                        final SevenZEntry e = reader.entries.get(i);
                        // A name stored twice: every copy is decoded (solid stream) but only the last one is kept
                        final boolean keep = lastByTarget.get(targets[i]) == i;
                        final long start = System.nanoTime();
                        final long copied;
                        try (InputStream in = reader.file.getInputStream(e)) {
                            if (keep) {
                                try (OutputStream out = new BufferedOutputStream(ExtractionGuard.open(targets[i]), 65536)) {
                                    copied = IOHelper.copy(in, out);
                                }
                            } else {
                                copied = IOHelper.copy(in, new NullOutputStream());
                            }
                        }
                        if (copied != e.getSize()) throw new ArcanaCorruptedException("7z entry '" + e.getName() + "' is truncated: " + copied + " bytes instead of " + e.getSize());
                        if (keep) {
                            final String line = "[==============================] " + ProgressOutputStream.formatSize(e.getSize()) + " 100% (" + e.getName() + ") -> " + ProgressOutputStream.formatDuration((System.nanoTime() - start) / 1_000_000L);
                            synchronized (System.out) {
                                System.out.println(line);
                            }
                        }
                    }
                } finally {
                    readers.add(reader);
                }
            });
        }
        try {
            ParallelRunner.runAll(tasks, threads);
        } finally {
            for (final SevenZFile f : opened) {
                try { f.close(); } catch (final IOException ignored) { /* extraction result already known */ }
            }
        }
        return true;
    }

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        throw new ArcanaUnsupportedFormatException("7z requires random file access - use extract(File,File).");
    }

    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        try (SevenZFile sz = open(archive)) {
            for (SevenZEntry e : sz.getEntries()) {
                result.add(new ArcanaEntry.Builder(e.getName())
                    .compressedSize(e.getCompressedSize()).uncompressedSize(e.getSize())
                    .lastModifiedTime(e.getHasLastModifiedDate() ? e.getLastModifiedTime() : -1L).directory(e.isDirectory())
                    .format(ArcanaFormat.SEVEN_Z).build());
            }
        }
        return result;
    }
}
