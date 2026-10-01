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
package be.stef.arcana.extractor;

import be.stef.arcana.util.ExtractionGuard;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.formats.zstd.ZstdHelper;
import be.stef.arcana.formats.zstd.ZstdMalformedInputException;
import be.stef.arcana.util.IOHelper;
import be.stef.arcana.util.NullOutputStream;
import be.stef.arcana.util.SafePathBuilder;

/**
 * Extractor for Zstandard-compressed single files (.zst, .zstd).
 *
 * <p>Delegates to {@link ZstdHelper}, the pure-Java Zstandard decompressor
 * ported from the aircompressor library (v0.27, Apache License 2.0) - no
 * external dependency, no JNI.</p>
 *
 * <h3>Important</h3>
 * <p>Zstandard is a single-file compressor, not a container format.  Like
 * GZIP and BZIP2, a {@code .zst} file always holds exactly one compressed
 * stream; the output file name is derived by stripping the {@code .zst} or
 * {@code .zstd} extension.</p>
 *
 * <p>The decompressor requires the full compressed payload before it can
 * start producing output (single-shot decompression).  Very large files may
 * therefore require significant heap space.  If memory is constrained, stream
 * the archive in chunks using the underlying {@link ZstdHelper} API directly.</p>
 *
 * @author Stef
 * @since 1.0
 */
public class ZstdExtractor implements ArchiveExtractor {

    @Override
    public boolean supportsStream() {
        return true;
    }

    // =========================================================================
    // extract(File, File)
    // =========================================================================

    @Override
    public void extract(File archive, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        String outputName = deriveOutputName(archive.getName());
        File target = SafePathBuilder.buildSafePath(destination, outputName);

        long unpackedSize = estimateUnpackedSize(archive);

        try (InputStream in = new BufferedInputStream(new FileInputStream(archive), 65536);
             BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            decompress(in, out, unpackedSize);
        }
    }

    // =========================================================================
    // extract(InputStream, File)
    // =========================================================================

    @Override
    public void extract(InputStream in, File destination) throws IOException {
        IOHelper.mkdirs(destination);
        File target = SafePathBuilder.buildSafePath(destination, "output");

        try (BufferedOutputStream out = new BufferedOutputStream(ExtractionGuard.open(target), 65536)) {
            // Unknown uncompressed size from stream - read fully to determine
            byte[] compressed = IOHelper.readFully(in);
            long unpackedSize = peekUnpackedSize(compressed);
            decompress(new java.io.ByteArrayInputStream(compressed), out, unpackedSize);
        }
    }

    /**
     * Returns a streaming Zstd decompressor over the given input stream.
     *
     * <p>Used internally by {@link TarZstdExtractor}. Unlike the single-shot
     * {@link #extract} methods, this decompresses frame by frame so that
     * archives of arbitrary size (including multi-gigabyte .tar.zst files)
     * can be processed without buffering the entire stream in memory.</p>
     *
     * @param in stream positioned at the start of a Zstd frame
     * @return streaming decompressed InputStream
     */
    public java.io.InputStream openDecompressedStream(java.io.InputStream in) {
        return new be.stef.arcana.formats.zstd.ZstdInputStream(in);
    }

    // =========================================================================
    // list(File)
    // =========================================================================

    /**
     * Returns a single synthetic entry.  The uncompressed size requires
     * decompressing the stream and is therefore returned as {@code -1}.
     */
    @Override
    public List<ArcanaEntry> list(File archive) throws IOException {
        List<ArcanaEntry> result = new ArrayList<>();
        result.add(new ArcanaEntry.Builder(deriveOutputName(archive.getName()))
                .compressedSize(archive.length())
                .uncompressedSize(-1L)
                .lastModifiedTime(archive.lastModified() / 1000L)
                .directory(false)
                .format(ArcanaFormat.ZSTD)
                .build());
        return result;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private void decompress(InputStream in, java.io.OutputStream out, long unpackedSize) throws IOException {
        try {
            ZstdHelper.decompress(in, out, unpackedSize);
        } catch (ZstdMalformedInputException e) {
            throw new ArcanaCorruptedException("Corrupted Zstandard stream: " + e.getMessage(), e);
        }
    }

    /**
     * Reads the Zstd frame header to obtain the Frame Content Size when available.
     * Returns a conservative default when the size is not present in the header.
     *
     * <p>Zstd frame header layout (simplified):</p>
     * <pre>
     *   [4] magic  0xFD2FB528 LE
     *   [1] FHD    bits 5 = single_segment, bits 6-7 = fcs_flag
     *   [?] FCS    1/2/4/8 bytes based on fcs_flag
     * </pre>
     */
    private long estimateUnpackedSize(File archive) throws IOException {
        byte[] header = new byte[18]; // magic(4) + FHD(1) + window(1) + FCS(8) max
        int read;
        try (InputStream in = new FileInputStream(archive)) {
            read = in.read(header);
        }
        return peekUnpackedSize(header);
    }

    private long peekUnpackedSize(byte[] data) {
        if (data == null || data.length < 6) return -1L;
        // Check magic
        long magic = (data[0] & 0xFFL) | ((data[1] & 0xFFL) << 8) | ((data[2] & 0xFFL) << 16) | ((data[3] & 0xFFL) << 24);
        if (magic != 0xFD2FB528L) return -1L;

        int fhd = data[4] & 0xFF;
        boolean singleSegment = (fhd & 0x20) != 0;
        int fcsFlag = (fhd >> 6) & 0x03;

        int offset = 5;
        if (!singleSegment) offset++; // skip window descriptor byte

        if (offset >= data.length) return -1L;

        switch (fcsFlag) {
            case 0:
                return singleSegment && offset < data.length ? (data[offset] & 0xFFL) : -1L;
            case 1:
                if (offset + 1 >= data.length) return -1L;
                return 256L + ((data[offset] & 0xFFL) | ((data[offset + 1] & 0xFFL) << 8));
            case 2:
                if (offset + 3 >= data.length) return -1L;
                return (data[offset] & 0xFFL) | ((data[offset + 1] & 0xFFL) << 8) | ((data[offset + 2] & 0xFFL) << 16) | ((data[offset + 3] & 0xFFL) << 24);
            case 3:
                if (offset + 7 >= data.length) return -1L;
                long lo = (data[offset] & 0xFFL) | ((data[offset + 1] & 0xFFL) << 8) | ((data[offset + 2] & 0xFFL) << 16) | ((data[offset + 3] & 0xFFL) << 24);
                long hi = (data[offset + 4] & 0xFFL) | ((data[offset + 5] & 0xFFL) << 8) | ((data[offset + 6] & 0xFFL) << 16) | ((data[offset + 7] & 0xFFL) << 24);
                return lo | (hi << 32);
            default:
                return -1L;
        }
    }

    /**
     * Derives the output file name by stripping the Zstandard extension.
     */
    static String deriveOutputName(String archiveName) {
        String lower = archiveName.toLowerCase();
        if (lower.endsWith(".zst"))  return archiveName.substring(0, archiveName.length() - 4);
        if (lower.endsWith(".zstd")) return archiveName.substring(0, archiveName.length() - 5);
        return "output";
    }
}
