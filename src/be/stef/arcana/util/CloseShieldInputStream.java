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
 * An {@link InputStream} wrapper that prevents the underlying stream from being
 * closed when {@link #close()} is called on this wrapper.
 *
 * <p>This is a minimal replacement for {@code org.apache.commons.io.input.CloseShieldInputStream}
 * used by the BZIP2 decompressor to protect {@code System.in} and other shared
 * streams from being inadvertently closed by library code that closes its input
 * stream in a finally block.</p>
 *
 * <p>Example use:</p>
 * <pre>
 *     InputStream shielded = new CloseShieldInputStream(System.in);
 *     new BZip2InputStream(shielded);  // closing BZip2InputStream won't close System.in
 * </pre>
 *
 * @author Stef
 * @since 1.0
 */
public class CloseShieldInputStream extends InputStream {

    private final InputStream in;

    /**
     * Wraps {@code in} so that {@link #close()} becomes a no-op.
     *
     * @param in the underlying stream to protect, must not be null
     */
    public CloseShieldInputStream(InputStream in) {
        if (in == null) throw new IllegalArgumentException("in must not be null");
        this.in = in;
    }

    @Override
    public int read() throws IOException {
        return in.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return in.read(b, off, len);
    }

    @Override
    public long skip(long n) throws IOException {
        return in.skip(n);
    }

    @Override
    public int available() throws IOException {
        return in.available();
    }

    /**
     * Does <em>not</em> close the underlying stream.
     */
    @Override
    public void close() {
        // intentionally empty - shields the underlying stream from being closed
    }
}
