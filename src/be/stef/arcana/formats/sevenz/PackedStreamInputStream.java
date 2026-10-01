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
package be.stef.arcana.formats.sevenz;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

/**
 * One packed stream of a 7z folder, read on demand from the archive channel.
 *
 * <p>The stream keeps its own position and sets the channel position before each
 * read, so several packed streams of the same folder (BCJ2 has four) can be read
 * alternately. Replaces the former eager loading of the whole packed stream in a
 * {@code byte[]}, which needed as much heap as the compressed folder and failed
 * above 2 GB.</p>
 *
 * <p>Not thread-safe: all the streams of one channel must be read by one thread
 * at a time (the SevenZFile owner, or its read-ahead thread).</p>
 *
 * @author Stef
 * @since 1.3
 */
final class PackedStreamInputStream extends InputStream {

    private static final int BUFFER_SIZE = 65536;

    private final SeekableByteChannel channel;
    private final ByteBuffer buffer;
    private long position;  // next file position to read
    private long remaining; // bytes not yet read from the file

    PackedStreamInputStream(final SeekableByteChannel channel, final long start, final long size) {
        this.channel = channel;
        this.position = start;
        this.remaining = size;
        this.buffer = ByteBuffer.allocate((int) Math.max(1, Math.min(BUFFER_SIZE, size)));
        this.buffer.limit(0);
    }

    private boolean fill() throws IOException {
        if (remaining <= 0) return false;
        buffer.clear();
        if (remaining < buffer.capacity()) buffer.limit((int) remaining);
        channel.position(position);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) throw new EOFException("Truncated 7z archive: packed stream ends early");
        }
        buffer.flip();
        position += buffer.limit();
        remaining -= buffer.limit();
        return true;
    }

    @Override
    public int read() throws IOException {
        if (!buffer.hasRemaining() && !fill()) return -1;
        return buffer.get() & 0xFF;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        if (!buffer.hasRemaining() && !fill()) return -1;
        final int n = Math.min(len, buffer.remaining());
        buffer.get(b, off, n);
        return n;
    }

    @Override
    public long skip(final long n) throws IOException {
        if (n <= 0) return 0;
        final long inBuffer = Math.min(n, buffer.remaining());
        buffer.position(buffer.position() + (int) inBuffer);
        final long fromFile = Math.min(n - inBuffer, remaining);
        position += fromFile;
        remaining -= fromFile;
        return inBuffer + fromFile;
    }

    @Override
    public int available() {
        return buffer.remaining();
    }

    @Override
    public void close() {
        // the channel belongs to SevenZFile
    }
}
