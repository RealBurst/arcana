/*
 * Copyright 2025 Stephane Bury
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
package be.stef.arcana.formats.rar.util;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Producer/consumer pipeline between the LZ decoder and the output stream.
 *
 * <p>The decoder thread writes decompressed chunks into this pipeline's
 * {@link PipelineOutputStream}. A dedicated writer thread drains the queue and
 * forwards each chunk to the real {@link OutputStream} (disk + CRC/BLAKE2sp).
 * Both threads run concurrently, so CPU-bound decoding and I/O-bound writing
 * overlap in time.</p>
 *
 * <p>Usage:</p>
 * <pre>
 * DecoderPipeline pipeline = new DecoderPipeline(realOutputStream, CHUNK_SIZE);
 * pipeline.start();
 * // Give pipeline.getPipelineOutputStream() to the decoder instead of realOutputStream.
 * // After the decoder finishes:
 * pipeline.finish();          // flushes + waits for the writer thread
 * pipeline.rethrowIfError();  // propagates any writer-side IOException
 * </pre>
 *
 * <p>Thread safety: {@link PipelineOutputStream} is called only from the decoder
 * thread; all other methods are called from the same caller thread. No
 * cross-thread sharing of mutable state beyond the queue and the error flag.</p>
 *
 * @author Stef
 * @since 2.0.2
 */
public final class DecoderPipeline {

    // -- Tunables ------------------------------------------------------------

    /**
     * Number of chunks that can sit in the queue at once.
     *
     * <p>4 x 256 KB = 1 MB of buffering. Enough to absorb short write stalls
     * without blocking the decoder; small enough to stay in L3 cache.</p>
     */
    private static final int QUEUE_CAPACITY = 4;

    /** Sentinel chunk: signals the writer thread that no more data is coming. */
    private static final byte[] POISON = new byte[0];

    // -- State ----------------------------------------------------------------

    private final OutputStream sink;
    private final int chunkSize;
    private final BlockingQueue<byte[]> queue;
    private final AtomicReference<Throwable> writerError = new AtomicReference<>();
    private Thread writerThread;

    /** The OutputStream handed to the decoder. */
    private final PipelineOutputStream pipelineOut;

    // -- Constructor ----------------------------------------------------------

    /**
     * Creates a pipeline targeting the given sink.
     *
     * @param sink      the real output stream (disk + checksums)
     * @param chunkSize size of each transfer chunk in bytes; should match
     *                  {@code WRITE_STEP} in the LZ decoder (256 KB)
     */
    public DecoderPipeline(OutputStream sink, int chunkSize) {
        this.sink      = sink;
        this.chunkSize = chunkSize;
        this.queue     = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
        this.pipelineOut = new PipelineOutputStream();
    }

    // -- Public API -----------------------------------------------------------

    /**
     * Returns the {@link OutputStream} that the decoder should write into.
     *
     * <p>Must be called before {@link #start()}.</p>
     */
    public OutputStream getPipelineOutputStream() {
        return pipelineOut;
    }

    /**
     * Starts the writer thread. Must be called before the decoder begins writing.
     */
    public void start() {
        writerThread = new Thread(this::writerLoop, "unrar5j-writer");
        writerThread.setDaemon(true);
        writerThread.start();
    }

    /**
     * Flushes any partial chunk and waits for the writer thread to finish.
     *
     * <p>Must be called after the decoder has written all its data.</p>
     *
     * @throws InterruptedException if the current thread is interrupted while
     *                              waiting for the writer to finish
     */
    public void finish() throws InterruptedException {
        pipelineOut.flushPartial();     // push the last partial chunk if any
        enqueue(POISON);                // signal the writer to stop
        writerThread.join();
    }

    /**
     * Re-throws any {@link IOException} caught by the writer thread.
     *
     * <p>Must be called after {@link #finish()} returns.</p>
     *
     * @throws IOException if the writer thread encountered an I/O error
     */
    public void rethrowIfError() throws IOException {
        Throwable t = writerError.get();
        if (t instanceof IOException) throw (IOException) t;
        if (t != null) throw new IOException("Writer thread failed", t);
    }

    // -- Writer thread --------------------------------------------------------

    private void writerLoop() {
        try {
            while (true) {
                byte[] chunk;
                try {
                    chunk = queue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (chunk == POISON) break;
                sink.write(chunk, 0, chunk.length);
            }
            sink.flush();
        } catch (Throwable t) {
            writerError.set(t);
            // Drain the queue so the decoder never blocks on a full queue
            // after an error on the writer side.
            queue.clear();
        }
    }

    // -- Helper ---------------------------------------------------------------

    private void enqueue(byte[] chunk) {
        // If the writer already failed, don't block: the decoder will see the
        // error when it calls rethrowIfError() after finish().
        if (writerError.get() != null) return;
        try {
            queue.put(chunk);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // -- PipelineOutputStream -------------------------------------------------

    /**
     * OutputStream that accumulates data into fixed-size chunks and hands each
     * full chunk to the pipeline queue.
     *
     * <p>Called exclusively from the decoder thread - no synchronisation needed
     * inside this class.</p>
     */
    public final class PipelineOutputStream extends OutputStream {
        private byte[] current = new byte[chunkSize];
        private int    pos     = 0;

        @Override
        public void write(int b) throws IOException {
            checkError();
            current[pos++] = (byte) b;
            if (pos == chunkSize) sendCurrent();
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            checkError();
            while (len > 0) {
                int space = chunkSize - pos;
                int take  = Math.min(space, len);
                System.arraycopy(b, off, current, pos, take);
                pos += take; off += take; len -= take;
                if (pos == chunkSize) sendCurrent();
            }
        }

        /** Sends the last partial chunk (called by {@link DecoderPipeline#finish()}). */
        void flushPartial() {
            if (pos > 0) {
                byte[] partial = new byte[pos];
                System.arraycopy(current, 0, partial, 0, pos);
                enqueue(partial);
                pos = 0;
            }
        }

        @Override
        public void flush() {
            // Intentionally no-op: partial chunks are held until full or finish().
        }

        @Override
        public void close() {
            // Lifecycle managed by DecoderPipeline.finish().
        }

        private void sendCurrent() {
            enqueue(current);
            current = new byte[chunkSize];
            pos     = 0;
        }

        private void checkError() throws IOException {
            Throwable t = writerError.get();
            if (t instanceof IOException) throw (IOException) t;
            if (t != null) throw new IOException("Writer thread failed", t);
        }
    }
}