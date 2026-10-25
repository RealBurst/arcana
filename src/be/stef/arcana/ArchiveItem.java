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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * One entry of an archive read with an {@link ArchiveReader}: its metadata
 * ({@link #getEntry()}) and, on demand, its content ({@link #openStream()}).
 *
 * <p>An item is valid until the reader moves to the next entry or is closed.
 * The content is decoded only if {@link #openStream()} is called: skipping an
 * entry costs nothing more than the format requires (a TAR entry is skipped,
 * an entry of a solid 7z block is decoded and discarded).</p>
 *
 * @author Stef
 * @since 1.1.0
 */
public final class ArchiveItem {

    /** Opens the content of an entry (used by the readers). */
    public interface Opener {
        InputStream open() throws IOException;
    }

    private final ArcanaEntry entry;
    private final Opener opener;
    private boolean valid = true;
    private boolean opened;
    private InputStream stream;

    /**
     * @param entry  metadata of the entry
     * @param opener opens its content; {@code null} for an entry without content (directory)
     */
    public ArchiveItem(final ArcanaEntry entry, final Opener opener) {
        if (entry == null) throw new IllegalArgumentException("entry must not be null");
        this.entry = entry;
        this.opener = opener;
    }

    /** @return the metadata of the entry (name as stored, sizes, dates, method, mode, link target...) */
    public ArcanaEntry getEntry() {
        return entry;
    }

    /**
     * Opens the decoded content of the entry: decrypted, decompressed, and
     * checked (CRC, size) when the stream reaches its end. A directory gives an
     * empty stream. Can be called once per item, while the item is valid.
     *
     * <p>The entry name is the name stored in the archive: sanitize it before
     * using it as a file path (see {@code be.stef.arcana.util.SafePathBuilder}).</p>
     *
     * @throws IllegalStateException if the reader has moved on or the stream was already opened
     */
    public synchronized InputStream openStream() throws IOException {
        if (!valid) throw new IllegalStateException("Entry '" + entry.getName() + "' is no longer readable: the reader has moved to the next entry or was closed");
        if (opened) throw new IllegalStateException("The content of entry '" + entry.getName() + "' was already opened");
        opened = true;
        final InputStream in = opener == null || entry.isDirectory() ? new ByteArrayInputStream(new byte[0]) : opener.open();
        stream = new ItemStream(in);
        return stream;
    }

    /** Called by the reader when it moves on: the content can no longer be read. */
    synchronized void invalidate() {
        valid = false;
        if (stream != null) {
            try {
                stream.close();
            } catch (final IOException ignored) {
                // the next entry is read anyway
            }
        }
    }

    @Override
    public String toString() {
        return entry.toString();
    }

    /** Refuses to read once the item is no longer valid. */
    private final class ItemStream extends FilterInputStream {
        private boolean closed;

        ItemStream(final InputStream in) {
            super(in);
        }

        private void check() throws IOException {
            if (closed || !valid) throw new IOException("Entry '" + entry.getName() + "' is no longer readable: the reader has moved to the next entry or was closed");
        }

        @Override
        public int read() throws IOException {
            check();
            return super.read();
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            check();
            return super.read(b, off, len);
        }

        @Override
        public long skip(final long n) throws IOException {
            check();
            return super.skip(n);
        }

        @Override
        public int available() throws IOException {
            return closed || !valid ? 0 : super.available();
        }

        @Override
        public void close() throws IOException {
            if (!closed) {
                closed = true;
                super.close();
            }
        }
    }
}
