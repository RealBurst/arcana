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
/*
 * The decompression engine used by this class is derived from the aircompressor
 * library (v0.27, Apache License 2.0) by Airlift contributors:
 *   https://github.com/airlift/aircompressor
 * Ported to package be.stef.arcana.formats.zstd to remove all external dependencies.
 * The engine formerly used sun.misc.Unsafe for performance; it now uses
 * {@link MemoryAccess} which selects Unsafe automatically when available and
 * falls back to pure-Java array reads on JDKs where Unsafe is inaccessible.
 */
package be.stef.arcana.formats.zstd;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


/**
 * Facade for Zstandard decompression of a whole stream.
 *
 * <h3>Usage</h3>
 * <pre>
 *     ZstdHelper.decompress(inputStream, outputStream, unpackedSize);
 * </pre>
 *
 * <h3>Internals</h3>
 * <p>The data is decoded by {@link ZstdInputStream}, block by block, and copied
 * to the output as it is produced: memory is bounded by the window size of
 * the frames, not by the size of the file. Several frames and skippable
 * frames (anywhere in the stream) are accepted, like the zstd tool does.</p>
 *
 * @author Stef
 * @since 2.0
 */
public final class ZstdHelper
{
    /** Copy buffer size. */
    private static final int COPY_BUFFER_SIZE = 65536;

    private ZstdHelper() {}

    /**
     * Decompresses a Zstandard stream (one or more frames) and writes the result to {@code out}.
     *
     * <p>The method reads {@code in} until its end. The caller is responsible for
     * bounding {@code in} when the Zstandard data is followed by other data.</p>
     *
     * @param in             input stream positioned at the first frame
     * @param out            output stream receiving the decompressed bytes
     * @param unpackedSize   expected decompressed size in bytes, or -1 when unknown
     * @return the number of bytes written
     * @throws IOException   if reading, decompressing, or writing fails
     * @throws ZstdMalformedInputException if a Zstd frame is corrupt or malformed
     */
    public static long decompress(InputStream in, OutputStream out, long unpackedSize) throws IOException
    {
        ZstdInputStream zin = new ZstdInputStream(in);
        byte[] buf = new byte[COPY_BUFFER_SIZE];
        long total = 0;
        int n;
        while ((n = zin.read(buf, 0, buf.length)) > 0) {
            out.write(buf, 0, n);
            total += n;
        }
        if (unpackedSize >= 0 && total != unpackedSize) {
            throw new IOException("Zstd decompression size mismatch: expected " + unpackedSize + " bytes, got " + total);
        }
        return total;
    }
}
