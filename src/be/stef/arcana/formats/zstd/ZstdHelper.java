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
import static be.stef.arcana.formats.zstd.MemoryAccess.BASE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


/**
 * Facade for Zstandard decompression within the unrar5j pipeline.
 *
 * <p>This is the <strong>only class</strong> that {@code Rar5Extractor} should reference
 * in the {@code be.stef.arcana.formats.zstd} package. All other classes in this package are
 * implementation details of the ported aircompressor engine and may be replaced
 * at any time without affecting callers.</p>
 *
 * <h3>Usage</h3>
 * <pre>
 *     ZstdHelper.decompress(inputStream, outputStream, unpackedSize);
 * </pre>
 *
 * <h3>Internals</h3>
 * <p>The engine works by reading the entire compressed payload into a {@code byte[]}
 * buffer, then decompressing it in one shot into a second buffer, and finally
 * streaming the result to the output. This is consistent with how RAR7 stores
 * Zstd-compressed data: each file entry is an independent, self-contained Zstd
 * frame - there is no cross-file streaming state to maintain (unlike the LZ decoder).</p>
 *
 * <p>The internal {@link ZstdFrameDecompressor} instance is not thread-safe and
 * must not be shared across threads. Since {@code Rar5Extractor} is single-threaded
 * per extraction session, one instance per call is sufficient.</p>
 *
 * @author Stef
 * @since 2.0
 */
public final class ZstdHelper
{
    /** Read buffer size for streaming input into the compressed byte array. */
    private static final int READ_BUFFER_SIZE = 65536;

    private ZstdHelper() {}

    /**
     * Decompresses a Zstandard-compressed stream and writes the result to {@code out}.
     *
     * <p>The method reads exactly {@code compressedSize} bytes from {@code in} (the
     * entire packed data area of a RAR7 file entry), decompresses them, and writes
     * the result to {@code out}. The caller is responsible for bounding {@code in}
     * (e.g. via {@code BoundedInputStream}) so that only the packed data is consumed.</p>
     *
     * @param in             bounded input stream containing the compressed Zstd frame
     * @param out            output stream receiving the decompressed bytes
     * @param unpackedSize   expected decompressed size in bytes (from the RAR file header)
     * @throws IOException   if reading, decompressing, or writing fails
     * @throws ZstdMalformedInputException if the Zstd frame is corrupt or malformed
     */
    public static void decompress(InputStream in, OutputStream out, long unpackedSize) throws IOException
    {
        // --- Step 1: read the entire compressed payload into memory ---
        // RAR7 Zstd entries are independent frames; we need the full frame before decompressing.
        byte[] compressed = readFully(in);

        // --- Step 2: allocate output buffer ---
        // unpackedSize comes from the RAR file header; it is trusted at this point
        // (Rar5Extractor already validated it against the compression ratio guard).
        if (unpackedSize > Integer.MAX_VALUE) {
            throw new IOException("Zstd unpacked size too large for a single-pass decompress: " + unpackedSize);
        }
        int outSize = (int) unpackedSize;
        byte[] decompressed = new byte[outSize];

        // --- Step 3: decompress ---
        // Address arithmetic matches the convention used throughout ZstdFrameDecompressor:
        //   address = BASE + array_index
        long inputAddress  = BASE;
        long inputLimit    = BASE + compressed.length;
        long outputAddress = BASE;
        long outputLimit   = BASE + outSize;

        ZstdFrameDecompressor decompressor = new ZstdFrameDecompressor();
        int written = decompressor.decompress(
                compressed,  inputAddress,  inputLimit,
                decompressed, outputAddress, outputLimit);

        if (written != outSize) {
            throw new IOException("Zstd decompression size mismatch: expected " + outSize + " bytes, got " + written);
        }

        // --- Step 4: write to output stream ---
        out.write(decompressed, 0, written);
    }

    /**
     * Reads all bytes from {@code in} until EOF and returns them as a {@code byte[]}.
     *
     * <p>Uses a growing buffer strategy to avoid over-allocating when the compressed
     * size is not known in advance. In practice the caller uses a {@code BoundedInputStream},
     * so the total is bounded by the packed data size from the RAR header.</p>
     *
     * @param in source stream
     * @return all bytes read
     * @throws IOException on read error
     */
    private static byte[] readFully(InputStream in) throws IOException
    {
        byte[] buf = new byte[READ_BUFFER_SIZE];
        int totalRead = 0;
        int read;
        while ((read = in.read(buf, totalRead, buf.length - totalRead)) != -1) {
            totalRead += read;
            if (totalRead == buf.length) {
                // Grow buffer
                byte[] newBuf = new byte[buf.length * 2];
                System.arraycopy(buf, 0, newBuf, 0, totalRead);
                buf = newBuf;
            }
        }
        // Trim to actual size
        if (totalRead == buf.length) {
            return buf;
        }
        byte[] result = new byte[totalRead];
        System.arraycopy(buf, 0, result, 0, totalRead);
        return result;
    }
}
