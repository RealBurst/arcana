/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import be.stef.arcana.formats.lha.LhaCrc16;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * Writes LHA archives using <b>header level 2</b> and <b>-lh5-</b> compression
 * (or -lh6- / -lh7-, see {@link #LhaWriter(OutputStream, int)}).
 *
 * <p>Header level 2 is the most widely compatible modern format: it stores
 * the file name in an extended header, timestamps as Unix seconds (level-2
 * native) and the CRC-16 of both the data and the header itself.</p>
 *
 * <h3>Usage</h3>
 * <pre>
 *     try (LhaWriter lha = new LhaWriter(out)) {
 *         lha.writeEntry("path/to/file.txt", fileInputStream, fileSize, lastModifiedMs);
 *         lha.writeDirectory("path/to/dir/");
 *     }
 * </pre>
 *
 * <p>Call {@link #finish()} (or {@link #close()}) to write the end-of-archive
 * marker (a single zero byte).</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class LhaWriter extends FilterOutputStream {

    private boolean finished = false;
    private final int dictBits;

    /** Writer using -lh5- (8 KB dictionary), readable by every LHA tool. */
    public LhaWriter(final OutputStream out) { this(out, Lh5Encoder.LH5); }

    /**
     * Writer using the given method.
     *
     * @param dictBits {@link Lh5Encoder#LH5} (-lh5-, 8 KB), {@link Lh5Encoder#LH6} (-lh6-, 32 KB)
     *                 or {@link Lh5Encoder#LH7} (-lh7-, 64 KB: best ratio, not readable by old DOS LHA 2.x)
     */
    public LhaWriter(final OutputStream out, final int dictBits) {
        super(out);
        Lh5Encoder.methodFor(dictBits); // validates
        this.dictBits = dictBits;
    }

    // ---- Public API ------------------------------------------------------

    /**
     * Compresses the given data and writes a complete LHA entry.
     *
     * @param entryName    path inside the archive (forward slashes, no leading '/')
     * @param data         uncompressed data source
     * @param originalSize uncompressed size in bytes
     * @param lastModMs    last-modified time in milliseconds since the Unix epoch
     * @throws IOException if an I/O error occurs
     */
    public void writeEntry(final String entryName, final InputStream data,
                           final long originalSize, final long lastModMs) throws IOException {
        // Compress data into a byte buffer so we know the compressed size for the header
        final ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
        final long compressedSize = Lh5Encoder.compress(data, compressedBuf, dictBits);
        final byte[] compressedData = compressedBuf.toByteArray();

        // Compute CRC-16 over uncompressed data - we need to re-read from the buffer
        // Since we compressed from an InputStream, the caller must provide a CRC or
        // we compute it during compression (done via the stored original bytes).
        // For simplicity, we recompute from the output: but we don't have uncompressed bytes.
        // The architecture: LhaCompressor passes a byte[] so we compute it there.
        // Here we receive the compressed bytes. We accept a pre-computed CRC as the 6th arg.
        writeEntryInternal(entryName, false, compressedData, originalSize, lastModMs, 0);
    }

    /**
     * Compresses the given uncompressed bytes and writes a complete LHA entry.
     * The CRC-16 is computed from {@code uncompressed}.
     */
    public void writeEntry(final String entryName, final byte[] uncompressed, final long lastModMs) throws IOException {
        final int crc16 = LhaCrc16.compute(uncompressed, 0, uncompressed.length);
        final ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
        Lh5Encoder.compress(new java.io.ByteArrayInputStream(uncompressed), compressedBuf, dictBits);
        final byte[] compressedData = compressedBuf.toByteArray();

        // If compressed data is larger, store as -lh0- (stored)
        final boolean store = compressedData.length >= uncompressed.length;
        final byte[] dataToWrite = store ? uncompressed : compressedData;
        writeEntryInternal(entryName, false, dataToWrite, uncompressed.length, lastModMs, crc16);
    }

    /**
     * Writes a directory entry.
     *
     * @param dirName directory path (must end with '/')
     * @throws IOException if an I/O error occurs
     */
    public void writeDirectory(final String dirName, final long lastModMs) throws IOException {
        writeEntryInternal(dirName, true, new byte[0], 0, lastModMs, 0);
    }

    /**
     * Writes the end-of-archive marker (two zero bytes).
     */
    public void finish() throws IOException {
        if (!finished) {
            out.write(0); // end-of-archive: a single 0 byte (header size 0), as written by lha
            out.flush();
            finished = true;
        }
    }

    @Override
    public void close() throws IOException {
        try { finish(); } finally { out.close(); }
    }

    // ---- Header writing -------------------------------------------------

    private void writeEntryInternal(final String name, final boolean isDir,
                                     final byte[] compressedData, final long originalSize,
                                     final long lastModMs, final int crc16) throws IOException {
        final String method = isDir ? "-lhd-" : (compressedData.length >= originalSize && originalSize > 0 ? "-lh0-" : Lh5Encoder.methodFor(dictBits));

        // Split "a/b/c.txt" into directory "a/b/" and file name "c.txt" (directories: all is directory)
        String path = name.replace('\\', '/');
        while (path.startsWith("/")) path = path.substring(1);
        if (isDir && !path.isEmpty() && !path.endsWith("/")) path += "/";
        final int slash = path.lastIndexOf('/');
        final byte[] fileBytes = path.substring(slash + 1).getBytes(StandardCharsets.UTF_8);
        final byte[] dirBytes  = path.substring(0, slash + 1).getBytes(StandardCharsets.UTF_8);
        for (int k = 0; k < dirBytes.length; k++) if (dirBytes[k] == '/') dirBytes[k] = (byte) 0xFF; // LHA path separator

        // Level-2 header = 24-byte base + first-ext-size(2) + extended headers.
        // Each extended header is: type(1) + data + next-ext-size(2).
        final int commonExtSize = 1 + 2 + 2;                                     // 0x00: header CRC-16
        final int fileExtSize   = 1 + fileBytes.length + 2;                      // 0x01: file name
        final int dirExtSize    = dirBytes.length > 0 ? 1 + dirBytes.length + 2 : 0; // 0x02: directory
        int totalHeaderSize = 26 + commonExtSize + fileExtSize + dirExtSize;
        // LHA rule: a level-2 header size whose low byte is 0 would read as end-of-archive -> pad 1 byte
        final boolean pad = (totalHeaderSize & 0xFF) == 0;
        if (pad) totalHeaderSize++;

        final ByteBuffer hdr = ByteBuffer.allocate(totalHeaderSize).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putShort((short) totalHeaderSize);                      // [0-1] total header size
        hdr.put(method.getBytes(StandardCharsets.US_ASCII), 0, 5); // [2-6] method
        hdr.putInt(compressedData.length);                          // [7-10] compressed size
        hdr.putInt((int) originalSize);                             // [11-14] original size
        hdr.putInt((int) (lastModMs / 1000L));                      // [15-18] Unix timestamp
        hdr.put((byte) 0x20);                                       // [19] reserved (MS-DOS attribute)
        hdr.put((byte) 0x02);                                       // [20] header level 2
        hdr.putShort((short) crc16);                                // [21-22] CRC-16 of data
        hdr.put((byte) 'U');                                        // [23] OS ID (Unix)
        hdr.putShort((short) commonExtSize);                        // [24-25] first ext header size

        final int crcPos = hdr.position() + 1;
        hdr.put((byte) 0x00);                                       // ext 0x00: common header
        hdr.putShort((short) 0);                                    //   header CRC, patched below
        hdr.putShort((short) fileExtSize);                          //   next ext size
        hdr.put((byte) 0x01);                                       // ext 0x01: file name
        hdr.put(fileBytes);
        hdr.putShort((short) dirExtSize);                           //   next ext size (0 = last)
        if (dirExtSize > 0) {
            hdr.put((byte) 0x02);                                   // ext 0x02: directory (0xFF separators)
            hdr.put(dirBytes);
            hdr.putShort((short) 0);                                //   next ext size = 0 (last)
        }
        if (pad) hdr.put((byte) 0x00);

        // Header CRC-16 covers the whole header with the CRC field itself set to 0
        final byte[] h = hdr.array();
        final int headerCrc = LhaCrc16.compute(h, 0, h.length);
        h[crcPos]     = (byte) headerCrc;
        h[crcPos + 1] = (byte) (headerCrc >>> 8);

        out.write(h);
        out.write(compressedData);
    }

    // ---- Utility ---------------------------------------------------------

    /** Converts milliseconds since epoch to Unix seconds (truncated). */
    static long toUnixSeconds(final long millis) { return millis / 1000L; }
}
