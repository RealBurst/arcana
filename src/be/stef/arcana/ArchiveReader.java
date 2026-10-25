/*
 * Copyright 2026 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana;

import be.stef.arcana.exceptions.ArcanaLimitExceededException;
import be.stef.arcana.util.ExtractionLimits;
import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Reads the entries of an archive one after the other, in archive order,
 * without writing anything to the disk.
 *
 * <pre>
 *     try (ArchiveReader reader = Arcana.read(new File("upload.tar.gz"))) {
 *         for (ArchiveItem item : reader) {
 *             ArcanaEntry e = item.getEntry();
 *             if (!e.isDirectory() &amp;&amp; e.getName().endsWith(".xml")) {
 *                 try (InputStream in = item.openStream()) {
 *                     process(e, in);
 *                 }
 *             }
 *         }
 *     }
 * </pre>
 *
 * <p>Each {@link ArchiveItem} is valid until the next one is read: its
 * content must be read before moving on. {@link #next()} is the same loop
 * without the {@link Iterable} (it throws {@link IOException} instead of
 * {@link UncheckedIOException}).</p>
 *
 * <p>ZIP, 7z, RAR, TAR (plain or compressed: .tar.gz, .tar.xz, .tar.zst...),
 * CPIO and single compressed files are decoded entry by entry
 * ({@link #isStreaming()} is true). The other formats are first extracted to a
 * temporary directory, deleted by {@link #close()}.</p>
 *
 * <p>The bytes read through the entry streams are counted against the
 * {@link ExtractionLimits} of the reader (total size and ratio to the archive
 * size): pass {@code ExtractionLimits.none()} to {@link Arcana#limits} to read
 * without limit. A reader is not thread-safe.</p>
 *
 * @author Stef
 * @since 1.1.0
 */
public abstract class ArchiveReader implements Iterable<ArchiveItem>, Closeable {

    private final ArcanaFormat format;
    private final long archiveSize;
    private final ExtractionLimits.Values limits;
    private long totalRead;
    private ArchiveItem current;
    private boolean iterated;
    private boolean closed;
    private boolean ended;

    /**
     * @param format      format of the archive
     * @param archiveSize size of the archive in bytes, 0 if unknown (the ratio is then not checked)
     * @param limits      limits of this reader, or {@code null} for the global {@link ExtractionLimits}
     */
    protected ArchiveReader(final ArcanaFormat format, final long archiveSize, final ExtractionLimits.Values limits) {
        this.format = format;
        this.archiveSize = archiveSize;
        this.limits = limits != null ? limits.copy() : null;
    }

    /** @return the format of the archive */
    public ArcanaFormat getFormat() {
        return format;
    }

    /**
     * @return {@code true} when the entries are decoded one by one from the
     *         archive, {@code false} when the archive was extracted to a
     *         temporary directory first
     */
    public abstract boolean isStreaming();

    /**
     * Moves to the next entry. The previous item can no longer be read.
     *
     * @return the next entry, or {@code null} at the end of the archive
     */
    public final ArchiveItem next() throws IOException {
        if (closed) throw new IllegalStateException("Archive reader is closed");
        if (current != null) {
            current.invalidate();
            current = null;
        }
        if (ended) return null;
        current = readNext();
        if (current == null) ended = true;
        return current;
    }

    /**
     * Reads the next entry; {@code null} at the end. Implementations build the
     * items with {@link #item(ArcanaEntry, ArchiveItem.Opener)}.
     */
    protected abstract ArchiveItem readNext() throws IOException;

    /** Releases the resources of the implementation (files, temporary directory). */
    protected abstract void release() throws IOException;

    /** Item whose content stream is counted against the limits of this reader. */
    protected final ArchiveItem item(final ArcanaEntry entry, final ArchiveItem.Opener opener) {
        return new ArchiveItem(entry, opener == null ? null : () -> new CountingStream(opener.open(), entry.getName()));
    }

    /**
     * The entries, in archive order. Single use: the reader reads the archive
     * once. An I/O error is thrown as {@link UncheckedIOException}.
     */
    @Override
    public Iterator<ArchiveItem> iterator() {
        if (iterated) throw new IllegalStateException("An archive reader can be iterated only once");
        iterated = true;
        return new Iterator<ArchiveItem>() {
            private ArchiveItem pending;
            private boolean fetched;

            @Override
            public boolean hasNext() {
                if (!fetched) {
                    try {
                        pending = ArchiveReader.this.next();
                    } catch (final IOException e) {
                        throw new UncheckedIOException(e);
                    }
                    fetched = true;
                }
                return pending != null;
            }

            @Override
            public ArchiveItem next() {
                if (!hasNext()) throw new NoSuchElementException();
                fetched = false;
                return pending;
            }
        };
    }

    @Override
    public final void close() throws IOException {
        if (closed) return;
        closed = true;
        if (current != null) current.invalidate();
        current = null;
        release();
    }

    private void account(final long n, final String name) throws ArcanaLimitExceededException {
        totalRead += n;
        final long maxTotal = limits != null ? limits.getMaxTotalBytes() : ExtractionLimits.maxTotalBytes;
        if (maxTotal > 0 && totalRead > maxTotal) throw new ArcanaLimitExceededException("Reading stopped: more than " + maxTotal + " bytes decoded (ExtractionLimits.maxTotalBytes) - possible decompression bomb, at " + name);
        final long maxRatio = limits != null ? limits.getMaxRatio() : ExtractionLimits.maxRatio;
        final long threshold = limits != null ? limits.getRatioThreshold() : ExtractionLimits.ratioThreshold;
        if (maxRatio > 0 && archiveSize > 0 && totalRead > threshold && totalRead / archiveSize > maxRatio) {
            throw new ArcanaLimitExceededException("Reading stopped: " + totalRead + " bytes decoded from a " + archiveSize + "-byte archive, ratio above " + maxRatio + ":1 (ExtractionLimits.maxRatio) - possible decompression bomb, at " + name);
        }
    }

    /** Counts the decoded bytes of an entry against the limits. */
    private final class CountingStream extends FilterInputStream {
        private final String name;

        CountingStream(final InputStream in, final String name) {
            super(in);
            this.name = name;
        }

        @Override
        public int read() throws IOException {
            final int b = super.read();
            if (b >= 0) account(1, name);
            return b;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = super.read(b, off, len);
            if (n > 0) account(n, name);
            return n;
        }

        @Override
        public long skip(final long n) throws IOException {
            // skipped bytes are decoded too: count them through read()
            final byte[] buf = new byte[(int) Math.min(8192, Math.max(1, n))];
            long done = 0;
            while (done < n) {
                final int k = read(buf, 0, (int) Math.min(buf.length, n - done));
                if (k < 0) break;
                done += k;
            }
            return done;
        }
    }
}
