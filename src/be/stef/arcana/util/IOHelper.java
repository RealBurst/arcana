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

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Stream and file I/O utilities shared across all JUnpack decompressors.
 *
 * <p>This class provides stateless static helpers and intentionally avoids any
 * dependency on external libraries.  All methods operate on standard
 * {@code java.io} types.</p>
 *
 * @author Stef
 * @since 1.0
 */
public final class IOHelper {

    /** Default buffer size used for copy operations. */
    public static final int BUFFER_SIZE = 65536;

    private IOHelper() {}

    // =========================================================================
    // Stream copy
    // =========================================================================

    /**
     * Copies all bytes from {@code in} to {@code out} until EOF.
     *
     * @param in  source stream
     * @param out destination stream
     * @return total number of bytes copied
     * @throws IOException on read or write error
     */
    public static long copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        long total = 0;
        int read;
        while ((read = in.read(buf)) != -1) {
            out.write(buf, 0, read);
            total += read;
        }
        return total;
    }

    /**
     * Copies exactly {@code length} bytes from {@code in} to {@code out}.
     *
     * @param in     source stream
     * @param out    destination stream
     * @param length number of bytes to copy
     * @throws EOFException if the stream ends before {@code length} bytes are read
     * @throws IOException  on read or write error
     */
    public static void copyExactly(InputStream in, OutputStream out, long length) throws IOException {
        byte[] buf = new byte[(int) Math.min(BUFFER_SIZE, length)];
        long remaining = length;
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int read = in.read(buf, 0, toRead);
            if (read == -1) throw new EOFException("Unexpected end of stream: expected " + remaining + " more bytes");
            out.write(buf, 0, read);
            remaining -= read;
        }
    }

    // =========================================================================
    // Fully reading
    // =========================================================================

    /**
     * Reads all bytes from {@code in} until EOF and returns them as a
     * {@code byte[]}.  Uses a doubling-buffer strategy to avoid over-allocation.
     *
     * @param in source stream
     * @return all bytes read from the stream
     * @throws IOException on read error
     */
    public static byte[] readFully(InputStream in) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        int total = 0;
        int read;
        while ((read = in.read(buf, total, buf.length - total)) != -1) {
            total += read;
            if (total == buf.length) {
                byte[] larger = new byte[buf.length * 2];
                System.arraycopy(buf, 0, larger, 0, total);
                buf = larger;
            }
        }
        if (total == buf.length) return buf;
        byte[] result = new byte[total];
        System.arraycopy(buf, 0, result, 0, total);
        return result;
    }

    /**
     * Reads exactly {@code length} bytes from {@code in} into a new array.
     *
     * @param in     source stream
     * @param length exact number of bytes to read
     * @return byte array of exactly {@code length} bytes
     * @throws EOFException if the stream ends prematurely
     * @throws IOException  on read error
     */
    public static byte[] readExactly(InputStream in, int length) throws IOException {
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(result, offset, length - offset);
            if (read == -1) throw new EOFException("Expected " + length + " bytes but got " + offset);
            offset += read;
        }
        return result;
    }

    /**
     * Reads exactly {@code length} bytes from {@code in} into {@code dest}
     * starting at {@code destOffset}.
     *
     * @param in         source stream
     * @param dest       destination array
     * @param destOffset start offset in {@code dest}
     * @param length     number of bytes to read
     * @throws EOFException if the stream ends prematurely
     * @throws IOException  on read error
     */
    public static void readExactly(InputStream in, byte[] dest, int destOffset, int length) throws IOException {
        int offset = destOffset;
        int end = destOffset + length;
        while (offset < end) {
            int read = in.read(dest, offset, end - offset);
            if (read == -1) throw new EOFException("Expected " + length + " bytes but got " + (offset - destOffset));
            offset += read;
        }
    }

    // =========================================================================
    // Drain / skip
    // =========================================================================

    /**
     * Drains (discards) all remaining bytes from {@code in} until EOF.
     *
     * @param in stream to drain
     * @throws IOException on read error
     */
    public static void drain(InputStream in) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        while (in.read(buf) != -1) {}
    }

    /**
     * Skips exactly {@code n} bytes from {@code in}.
     *
     * <p>Unlike {@link InputStream#skip(long)}, this method retries until all
     * bytes are skipped or EOF is reached.</p>
     *
     * @param in stream to skip in
     * @param n  number of bytes to skip
     * @throws EOFException if the stream ends before {@code n} bytes are skipped
     * @throws IOException  on read error
     */
    public static void skipExactly(InputStream in, long n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                // skip() may return 0 on some streams - fall back to read
                int b = in.read();
                if (b == -1) throw new EOFException("Unexpected EOF while skipping " + n + " bytes");
                remaining--;
            } else {
                remaining -= skipped;
            }
        }
    }

    // =========================================================================
    // Directory utilities
    // =========================================================================

    /**
     * Creates the directory {@code dir} and all missing parents.
     *
     * @param dir directory to create
     * @throws IOException if the directory could not be created
     */
    public static void mkdirs(File dir) throws IOException {
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Could not create directory: " + dir.getAbsolutePath());
        }
    }
}
