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
package be.stef.arcana.extractor;

import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.ArchiveItem;
import be.stef.arcana.ArchiveReader;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.formats.rar.ExtractionError;
import be.stef.arcana.formats.rar.RarOutput;
import be.stef.arcana.formats.rar.Unrar5j;
import be.stef.arcana.util.ExtractionLimits;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.SynchronousQueue;

/**
 * Per-entry reader of RAR 4 and RAR 5 archives (single or multi-volume,
 * solid, encrypted), without writing anything to the disk.
 *
 * <p>The RAR extractors write what they decode; here they run in a
 * background thread with a {@link RarOutput.Sink}: each file entry is decoded
 * into a small bounded buffer read by the entry stream, so the decoder waits
 * when the reader is slower. An entry that is not read is decoded and
 * discarded (a solid archive needs it for the next entries). The verdict of an
 * entry (CRC32, BLAKE2sp, password) is known when its data ends: the stream
 * reports an error at that moment.</p>
 *
 * @author Stef
 * @since 1.1.0
 */
final class RarArchiveReader extends ArchiveReader {

    /** Size of the buffer between the decoder and the reader of an entry. */
    private static final int PIPE_SIZE = 256 * 1024;

    private static final Object END = new Object();

    private final File archive;
    private final File scratch;
    private final File deleteOnClose;
    private final SynchronousQueue<Object> queue = new SynchronousQueue<Object>();
    private final List<ExtractionError> archiveErrors = new ArrayList<ExtractionError>();
    private final Thread producer;
    private volatile boolean closed;
    private volatile Throwable fatal;
    private Pipe lastPipe;
    private boolean ended;

    /** An entry handed from the decoder thread to the reader. */
    private static final class Event {
        final ArcanaEntry entry;
        final Pipe pipe;
        final IOException error;

        Event(final ArcanaEntry entry, final Pipe pipe, final IOException error) {
            this.entry = entry;
            this.pipe = pipe;
            this.error = error;
        }
    }

    /**
     * @param deleteOnClose file deleted by {@link #close()} (a copy of a stream), or null
     */
    RarArchiveReader(final File archive, final String password, final ExtractionLimits.Values limits, final File deleteOnClose) throws IOException {
        super(ArcanaFormat.RAR, archive.length(), limits);
        this.archive = archive;
        this.deleteOnClose = deleteOnClose;
        if (password == null && Unrar5j.isEncrypted(archive.getAbsolutePath())) throw new ArcanaEncryptedException("RAR archive is encrypted and no password was provided: " + archive.getName());
        // the extractors want an output folder: an empty one, never written to (the sink receives everything)
        this.scratch = Files.createTempDirectory("arcana-rar-").toFile();
        this.producer = new Thread(() -> run(password), "arcana-rar-reader");
        producer.setDaemon(true);
        producer.start();
    }

    @Override
    public boolean isStreaming() {
        return true;
    }

    /** Decoder thread: runs the extraction with the sink, then signals the end. */
    private void run(final String password) {
        final Sink sink = new Sink();
        RarOutput.setSink(sink);
        try {
            Unrar5j.extract(archive.getAbsolutePath(), scratch.getAbsolutePath(), password); // every error goes through the sink
            sink.commit();
        } catch (final Throwable t) {
            fatal = t;
        } finally {
            RarOutput.setSink(null);
            sink.commit();
            try {
                if (!closed) queue.put(END);
            } catch (final InterruptedException ignored) {
                // closed by the reader
            }
        }
    }

    @Override
    protected ArchiveItem readNext() throws IOException {
        if (lastPipe != null) {
            lastPipe.discard(); // not read (or not to the end): the decoder goes on
            lastPipe = null;
        }
        if (ended) return null;
        final Object o;
        try {
            o = queue.take();
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while reading " + archive.getName());
        }
        if (o == END) {
            ended = true;
            if (fatal != null) throw fatal instanceof IOException ? (IOException) fatal : new ArcanaCorruptedException("RAR reading failed for " + archive.getName() + ": " + fatal, fatal instanceof Exception ? (Exception) fatal : null);
            if (!archiveErrors.isEmpty()) throw RarExtractor.toException(archiveErrors, archive.getName());
            return null;
        }
        final Event e = (Event) o;
        if (e.error != null) return item(e.entry, () -> { throw e.error; });
        if (e.pipe == null) return item(e.entry, null);
        lastPipe = e.pipe;
        return item(e.entry, e.pipe::input);
    }

    @Override
    protected void release() {
        closed = true;
        if (lastPipe != null) lastPipe.discard();
        producer.interrupt();
        try {
            producer.join(10000);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        deleteTree(scratch);
        if (deleteOnClose != null && !deleteOnClose.delete()) deleteOnClose.deleteOnExit();
    }

    private static void deleteTree(final File f) {
        final File[] children = f.isDirectory() && !Files.isSymbolicLink(f.toPath()) ? f.listFiles() : null;
        if (children != null) for (final File c : children) deleteTree(c);
        if (!f.delete()) f.deleteOnExit();
    }

    // =========================================================================
    // Sink (decoder thread)
    // =========================================================================

    private final class Sink implements RarOutput.Sink {
        private Pipe current;
        private String currentName;

        @Override
        public void directory(final ArcanaEntry entry) throws IOException {
            commit();
            publish(new Event(entry, null, null));
        }

        @Override
        public OutputStream file(final ArcanaEntry entry) throws IOException {
            commit();
            final Pipe p = new Pipe(entry.getName());
            publish(new Event(entry, p, null));
            current = p;
            currentName = entry.getName();
            return p.output();
        }

        @Override
        public void error(final ExtractionError error) {
            final String name = error.fileName != null ? error.fileName.replace('\\', '/') : null; // RAR 4 names may use '\\'
            final String raw = error.fileName;
            if (current != null && name != null && name.equals(currentName)) {
                current.fail(asException(error)); // CRC, BLAKE2sp, decoding error of the entry being read
                return;
            }
            if (raw == null || raw.equals(archive.getName()) || raw.equals(archive.getAbsolutePath()) || raw.equals(archive.getPath())) {
                archiveErrors.add(error); // the whole archive: reported at the end
                return;
            }
            // an entry that fails before any data (wrong password...): given to the reader with its error
            commit();
            final ArcanaEntry entry = new ArcanaEntry.Builder(name).uncompressedSize(error.unpackedSize).encrypted(error.isEncryptedBlock).format(ArcanaFormat.RAR).build();
            try {
                publish(new Event(entry, null, asException(error)));
            } catch (final IOException interrupted) {
                // reader closed
            }
        }

        /** The previous entry is complete and checked: its stream can end (with its error, if any). */
        void commit() {
            if (current != null) current.commit();
            current = null;
            currentName = null;
        }

        private void publish(final Event e) throws IOException {
            if (closed) throw new InterruptedIOException("Archive reader closed");
            try {
                queue.put(e);
            } catch (final InterruptedException ex) {
                throw new InterruptedIOException("Archive reader closed");
            }
        }

        private IOException asException(final ExtractionError error) {
            final List<ExtractionError> one = new ArrayList<ExtractionError>();
            one.add(error);
            return RarExtractor.toException(one, archive.getName());
        }
    }

    // =========================================================================
    // Bounded buffer between the decoder (writer) and the entry stream (reader)
    // =========================================================================

    private final class Pipe {
        private final String name;
        private final byte[] buf = new byte[PIPE_SIZE];
        private int head;
        private int count;
        private boolean writerClosed;
        private boolean committed;
        private boolean discarded;
        private IOException error;
        private boolean opened;

        Pipe(final String name) {
            this.name = name;
        }

        synchronized void write(final byte[] b, int off, int len) throws IOException {
            while (len > 0) {
                if (closed) throw new InterruptedIOException("Archive reader closed");
                if (discarded) return;
                if (count == buf.length) {
                    try {
                        wait();
                    } catch (final InterruptedException e) {
                        throw new InterruptedIOException("Archive reader closed");
                    }
                    continue;
                }
                final int tail = (head + count) % buf.length;
                final int n = Math.min(len, Math.min(buf.length - count, buf.length - tail));
                System.arraycopy(b, off, buf, tail, n);
                count += n;
                off += n;
                len -= n;
                notifyAll();
            }
        }

        synchronized void closeWriter() {
            writerClosed = true;
            notifyAll();
        }

        synchronized void fail(final IOException e) {
            if (error == null) error = e;
            notifyAll();
        }

        synchronized void commit() {
            committed = true;
            notifyAll();
        }

        synchronized void discard() {
            discarded = true;
            count = 0;
            notifyAll();
        }

        synchronized int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            while (count == 0) {
                if (discarded) throw new IOException("Entry '" + name + "' is no longer readable");
                if (writerClosed && committed) {
                    if (error != null) throw error;
                    return -1;
                }
                if (closed) throw new InterruptedIOException("Archive reader closed");
                if (writerClosed && error != null) throw error;
                try {
                    wait(1000);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("Interrupted while reading entry '" + name + "'");
                }
            }
            final int n = Math.min(len, Math.min(count, buf.length - head));
            System.arraycopy(buf, head, b, off, n);
            head = (head + n) % buf.length;
            count -= n;
            notifyAll();
            return n;
        }

        OutputStream output() {
            return new OutputStream() {
                @Override
                public void write(final int b) throws IOException {
                    Pipe.this.write(new byte[] {(byte) b}, 0, 1);
                }

                @Override
                public void write(final byte[] b, final int off, final int len) throws IOException {
                    Pipe.this.write(b, off, len);
                }

                @Override
                public void close() {
                    closeWriter();
                }
            };
        }

        synchronized InputStream input() {
            if (opened) throw new IllegalStateException("Entry '" + name + "' already opened");
            opened = true;
            return new InputStream() {
                @Override
                public int read() throws IOException {
                    final byte[] one = new byte[1];
                    final int n = Pipe.this.read(one, 0, 1);
                    return n < 0 ? -1 : one[0] & 0xFF;
                }

                @Override
                public int read(final byte[] b, final int off, final int len) throws IOException {
                    return Pipe.this.read(b, off, len);
                }

                @Override
                public void close() {
                    discard(); // the rest of the entry is decoded and dropped
                }
            };
        }
    }
}
