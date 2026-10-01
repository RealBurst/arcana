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
package be.stef.arcana.util;

import java.io.IOException;
import java.io.InputStream;

/**
 * An {@link InputStream} wrapper that limits the number of bytes readable from
 * an underlying stream.
 *
 * <p>Unlike {@link be.stef.arcana.formats.rar.util.BoundedInputStream} which is coupled to a
 * {@link java.io.RandomAccessFile}, this implementation wraps any
 * {@code InputStream} and is used by the TAR and BZIP2 decompressors to isolate
 * individual entry data regions within a sequential stream.</p>
 *
 * <p>Closing this stream does <em>not</em> close the underlying stream - the
 * underlying stream is owned by the caller.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class StreamBoundedInputStream extends InputStream {

    private final InputStream in;
    private long remaining;

    /**
     * Creates a bounded view of {@code in} that allows reading at most
     * {@code limit} bytes.
     *
     * @param in    the underlying stream, must not be null
     * @param limit maximum number of bytes to allow reading; must be &gt;= 0
     */
    public StreamBoundedInputStream(InputStream in, long limit) {
        if (in == null) throw new IllegalArgumentException("in must not be null");
        if (limit < 0)  throw new IllegalArgumentException("limit must be >= 0");
        this.in        = in;
        this.remaining = limit;
    }

    @Override
    public int read() throws IOException {
        if (remaining <= 0) return -1;
        int b = in.read();
        if (b != -1) remaining--;
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (remaining <= 0) return -1;
        int toRead = (int) Math.min(len, remaining);
        int read = in.read(b, off, toRead);
        if (read != -1) remaining -= read;
        return read;
    }

    @Override
    public long skip(long n) throws IOException {
        long toSkip = Math.min(n, remaining);
        long skipped = in.skip(toSkip);
        remaining -= skipped;
        return skipped;
    }

    @Override
    public int available() throws IOException {
        return (int) Math.min(in.available(), remaining);
    }

    /**
     * Returns the number of bytes still available within the limit.
     *
     * @return remaining byte count
     */
    public long getRemaining() {
        return remaining;
    }

    /**
     * Does <em>not</em> close the underlying stream.
     * The underlying stream is owned and managed by the caller.
     */
    @Override
    public void close() {
        // intentionally does not close the underlying stream
    }
}
