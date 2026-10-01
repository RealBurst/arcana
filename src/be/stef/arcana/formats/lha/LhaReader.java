/*
 * Copyright 2025 Stephane Bury - Derived from Apache Commons Compress
 * (LhaArchiveInputStream.java, Apache License 2.0).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

/**
 * Reads entries from an LHA/LZH archive stream.
 *
 * <p>Supports header levels 0, 1 and 2.  Decompresses -lh0- (stored),
 * -lz4- (stored), -lh4- through -lh7- (LZH adaptive Huffman).  Entries with
 * unknown compression methods can be listed but not extracted.</p>
 *
 * <h3>Usage</h3>
 * <pre>
 *     try (LhaReader lha = new LhaReader(in)) {
 *         LhaEntry entry;
 *         while ((entry = lha.nextEntry()) != null) {
 *             if (!entry.isDirectory()) {
 *                 // read from lha until -1 to get the decompressed bytes
 *             }
 *         }
 *     }
 * </pre>
 *
 * <p>Derived from {@code org.apache.commons.compress.archivers.lha
 * .LhaArchiveInputStream} (Apache License 2.0).  Dependencies replaced:
 * {@code Crc16} -> {@link LhaCrc16}, {@code ZipUtil.dosToJavaTime} -> inline,
 * {@code IOUtils}/{@code BoundedInputStream}/{@code ChecksumInputStream} -> inner
 * classes, {@code LhStaticHuffman...} -> {@link LhaDecoder}.</p>
 */
public final class LhaReader extends FilterInputStream {

    // ---- Header format constants -----------------------------------------
    private static final int HEADER_MIN_LEN                   = 22;
    private static final int OFFSET_COMPRESSION_METHOD        = 2;
    private static final int OFFSET_HEADER_LEVEL              = 20;

    // Level 0
    private static final int L0_OFFSET_HEADER_SIZE            = 0;
    private static final int L0_OFFSET_HEADER_CHECKSUM        = 1;
    private static final int L0_OFFSET_COMPRESSED_SIZE        = 7;
    private static final int L0_OFFSET_ORIGINAL_SIZE          = 11;
    private static final int L0_OFFSET_MSDOS_TIME             = 15;
    private static final int L0_OFFSET_FILENAME_LENGTH        = 21;
    private static final int L0_OFFSET_FILENAME               = 22;

    // Level 1
    private static final int L1_OFFSET_HEADER_SIZE            = 0;
    private static final int L1_OFFSET_HEADER_CHECKSUM        = 1;
    private static final int L1_OFFSET_SKIP_SIZE              = 7;
    private static final int L1_OFFSET_ORIGINAL_SIZE          = 11;
    private static final int L1_OFFSET_MSDOS_TIME             = 15;
    private static final int L1_OFFSET_FILENAME_LENGTH        = 21;
    private static final int L1_OFFSET_FILENAME               = 22;

    // Level 2
    private static final int L2_MIN_LEN                       = 26;
    private static final int L2_OFFSET_HEADER_SIZE            = 0;
    private static final int L2_OFFSET_COMPRESSED_SIZE        = 7;
    private static final int L2_OFFSET_ORIGINAL_SIZE          = 11;
    private static final int L2_OFFSET_UNIX_TIME              = 15;
    private static final int L2_OFFSET_CRC                    = 21;
    private static final int L2_OFFSET_OS_ID                  = 23;
    private static final int L2_OFFSET_FIRST_EXT_HDR_SIZE     = 24;

    // Extended header types
    private static final int EXT_COMMON                       = 0x00;
    private static final int EXT_FILENAME                     = 0x01;
    private static final int EXT_DIRECTORY                    = 0x02;
    private static final int EXT_UNIX_TIMESTAMP               = 0x54;

    private static final int EXT_HDR_NEXT_SIZE_LEN            = 2;
    private static final int EXT_HDR_MIN_LEN                  = 3;

    // Compression methods
    private static final String METHOD_DIR  = "-lhd-";
    private static final String METHOD_LH0  = "-lh0-";
    private static final String METHOD_LZ4  = "-lz4-";
    private static final String METHOD_LH4  = "-lh4-";
    private static final String METHOD_LH5  = "-lh5-";
    private static final String METHOD_LH6  = "-lh6-";
    private static final String METHOD_LH7  = "-lh7-";

    private static final int    MAX_PATH_LEN = 4096;

    // ---- Runtime state --------------------------------------------------
    private final Charset charset;

    /** Bounded view of the compressed data for the current entry. */
    private BoundedStream  boundedCompressed;
    /** Decompressed (and CRC-verified) stream for the current entry; null for unsupported methods. */
    private CrcStream      decompressedStream;
    /** Most recently returned entry. */
    private LhaEntry       currentEntry;

    // ---- Constructors ---------------------------------------------------

    /** Creates a LhaReader using UTF-8 for path names. */
    public LhaReader(final InputStream in) { this(in, StandardCharsets.UTF_8); }

    /**
     * Creates a LhaReader using the given charset for path names.
     *
     * @param in      raw archive input stream
     * @param charset charset used to decode path names in level-0 and level-1 headers
     */
    public LhaReader(final InputStream in, final Charset charset) {
        super(in);
        this.charset = charset;
    }

    // ---- Public API -----------------------------------------------------

    /**
     * Advances to the next archive entry and returns its metadata.
     *
     * @return the next entry, or {@code null} at the end of the archive
     * @throws IOException if the archive is malformed or an I/O error occurs
     */
    public LhaEntry nextEntry() throws IOException {
        // Drain the current compressed stream so we are positioned at the next header
        if (boundedCompressed != null) { boundedCompressed.drain(); boundedCompressed = null; }
        decompressedStream = null;
        currentEntry = readHeader();
        return currentEntry;
    }

    /**
     * Returns {@code true} if the current entry's decompressed data can be read.
     * Returns {@code false} for unsupported compression methods.
     */
    public boolean canReadEntryData() { return decompressedStream != null; }

    // ---- InputStream (delegates to the decompressed stream) -------------

    @Override
    public int read() throws IOException {
        if (decompressedStream == null) throw new IOException("LHA: unsupported compression method or no current entry");
        return decompressedStream.read();
    }

    @Override
    public int read(final byte[] buf, final int off, final int len) throws IOException {
        if (decompressedStream == null) throw new IOException("LHA: unsupported compression method or no current entry");
        return decompressedStream.read(buf, off, len);
    }

    // ---- Header parsing -------------------------------------------------

    private LhaEntry readHeader() throws IOException {
        final byte[] buf = new byte[HEADER_MIN_LEN];
        final int got = readFully(in, buf, 0, HEADER_MIN_LEN, false);
        // End-of-archive: a 0 header-size byte (level 2 writers pad headers so their size never ends in 0x00).
        // Any trailing bytes after it (some writers emit two zeros) are ignored.
        if (got == 0 || buf[0] == 0) return null;
        if (got < HEADER_MIN_LEN) throw new IOException("LHA: truncated header (" + got + " bytes)");

        final ByteBuffer hdr = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        switch (hdr.get(OFFSET_HEADER_LEVEL)) {
            case 0:  return readLevel0(hdr);
            case 1:  return readLevel1(hdr);
            case 2:  return readLevel2(hdr);
            default: throw new IOException("LHA: unknown header level " + (hdr.get(OFFSET_HEADER_LEVEL) & 0xFF));
        }
    }

    // ---- Level 0 --------------------------------------------------------

    private LhaEntry readLevel0(ByteBuffer hdr) throws IOException {
        final int hdrSize = (hdr.get(L0_OFFSET_HEADER_SIZE) & 0xFF) + 2;
        if (hdrSize < HEADER_MIN_LEN) throw new IOException("LHA: level-0 header too short: " + hdrSize);
        hdr = readComplete(hdr, hdrSize);

        final int checksum = hdr.get(L0_OFFSET_HEADER_CHECKSUM) & 0xFF;
        final String method = readMethod(hdr);
        final LhaEntry.Builder b = new LhaEntry.Builder();
        b.compressionMethod = method;
        b.compressedSize    = getUInt32(hdr, L0_OFFSET_COMPRESSED_SIZE);
        b.originalSize      = getUInt32(hdr, L0_OFFSET_ORIGINAL_SIZE);
        b.lastModified      = dosToUnixMs(getUInt32(hdr, L0_OFFSET_MSDOS_TIME));
        b.directory         = METHOD_DIR.equals(method);

        final int nameLen = hdr.get(L0_OFFSET_FILENAME_LENGTH) & 0xFF;
        if (nameLen > hdrSize - L0_OFFSET_FILENAME - 2) throw new IOException("LHA: level-0 filename too long");
        hdr.position(L0_OFFSET_FILENAME);
        b.name = getPathName(hdr, nameLen);
        b.crc16 = hdr.getShort() & 0xFFFF;

        if (checksumLevel01(hdr) != checksum) throw new IOException("LHA: level-0 header checksum mismatch");
        return openEntry(b.build());
    }

    // ---- Level 1 --------------------------------------------------------

    private LhaEntry readLevel1(ByteBuffer hdr) throws IOException {
        final int baseSize = (hdr.get(L1_OFFSET_HEADER_SIZE) & 0xFF) + 2;
        if (baseSize < HEADER_MIN_LEN) throw new IOException("LHA: level-1 header too short: " + baseSize);
        hdr = readComplete(hdr, baseSize);

        final int checksum = hdr.get(L1_OFFSET_HEADER_CHECKSUM) & 0xFF;
        final String method = readMethod(hdr);
        long skipSize = getUInt32(hdr, L1_OFFSET_SKIP_SIZE);

        final LhaEntry.Builder b = new LhaEntry.Builder();
        b.compressionMethod = method;
        b.originalSize      = getUInt32(hdr, L1_OFFSET_ORIGINAL_SIZE);
        b.lastModified      = dosToUnixMs(getUInt32(hdr, L1_OFFSET_MSDOS_TIME));
        b.directory         = METHOD_DIR.equals(method);

        final int nameLen = hdr.get(L1_OFFSET_FILENAME_LENGTH) & 0xFF;
        if (nameLen > baseSize - L1_OFFSET_FILENAME - 5) throw new IOException("LHA: level-1 filename too long");
        hdr.position(L1_OFFSET_FILENAME);
        b.name  = getPathName(hdr, nameLen);
        b.crc16 = hdr.getShort() & 0xFFFF;
        // skip OS ID byte
        hdr.get();

        if (checksumLevel01(hdr) != checksum) throw new IOException("LHA: level-1 header checksum mismatch");

        // Extended headers
        int extSize = hdr.getShort() & 0xFFFF; // at end of base header
        while (extSize > 0) {
            final byte[] extBuf = new byte[extSize];
            readFully(in, extBuf, 0, extSize, true);
            final ByteBuffer ext = ByteBuffer.wrap(extBuf).order(ByteOrder.LITTLE_ENDIAN);
            skipSize -= extSize;
            applyExtHeader(ext, b);
            extSize = (extBuf[extBuf.length - 2] & 0xFF) | ((extBuf[extBuf.length - 1] & 0xFF) << 8);
        }
        if (skipSize < 0) throw new IOException("LHA: level-1 compressed size underflow");
        b.compressedSize = skipSize;
        return openEntry(b.build());
    }

    // ---- Level 2 --------------------------------------------------------

    private LhaEntry readLevel2(ByteBuffer hdr) throws IOException {
        final int hdrSize = (hdr.get(L2_OFFSET_HEADER_SIZE) & 0xFF) | ((hdr.get(L2_OFFSET_HEADER_SIZE + 1) & 0xFF) << 8);
        if (hdrSize < L2_MIN_LEN) throw new IOException("LHA: level-2 header too short: " + hdrSize);
        hdr = readComplete(hdr, hdrSize);

        final String method = readMethod(hdr);
        final LhaEntry.Builder b = new LhaEntry.Builder();
        b.compressionMethod = method;
        b.compressedSize    = getUInt32(hdr, L2_OFFSET_COMPRESSED_SIZE);
        b.originalSize      = getUInt32(hdr, L2_OFFSET_ORIGINAL_SIZE);
        b.lastModified      = getUInt32(hdr, L2_OFFSET_UNIX_TIME) * 1000L; // Unix seconds
        b.crc16             = (hdr.get(L2_OFFSET_CRC) & 0xFF) | ((hdr.get(L2_OFFSET_CRC + 1) & 0xFF) << 8);
        b.directory         = METHOD_DIR.equals(method);
        // OS ID at L2_OFFSET_OS_ID (ignored for our purposes)

        // Process embedded extended headers
        int extSize = (hdr.get(L2_OFFSET_FIRST_EXT_HDR_SIZE) & 0xFF) | ((hdr.get(L2_OFFSET_FIRST_EXT_HDR_SIZE + 1) & 0xFF) << 8);
        int extOffset = L2_OFFSET_FIRST_EXT_HDR_SIZE + 2;
        while (extSize > 0) {
            if (extOffset + extSize > hdr.limit()) throw new IOException("LHA: level-2 extended header overflows buffer");
            // slice(): relative view, so ext.get(0) / arrayOffset() refer to THIS extended header
            final ByteBuffer ext = ByteBuffer.wrap(hdr.array(), extOffset, extSize).slice().order(ByteOrder.LITTLE_ENDIAN);
            extOffset += extSize;
            applyExtHeader(ext, b);
            extSize = (ext.array()[extOffset - 2] & 0xFF) | ((ext.array()[extOffset - 1] & 0xFF) << 8);
            if (extOffset >= hdr.limit()) extSize = 0;
        }
        return openEntry(b.build());
    }

    // ---- Extended header processing -------------------------------------

    private void applyExtHeader(final ByteBuffer ext, final LhaEntry.Builder b) {
        if (ext.limit() < EXT_HDR_MIN_LEN) return;
        final int type = ext.get(0) & 0xFF;
        final int payloadEnd = ext.limit() - EXT_HDR_NEXT_SIZE_LEN;
        switch (type) {
            case EXT_FILENAME: {
                final int len = payloadEnd - 1;
                if (len > 0) {
                    final byte[] nameBuf = new byte[len];
                    System.arraycopy(ext.array(), ext.arrayOffset() + 1, nameBuf, 0, len);
                    b.name = sanitizePath(new String(nameBuf, charset));
                }
                break;
            }
            case EXT_DIRECTORY: {
                final int len = payloadEnd - 1;
                if (len > 0) {
                    final byte[] dirBuf = new byte[len];
                    System.arraycopy(ext.array(), ext.arrayOffset() + 1, dirBuf, 0, len);
                    for (int i = 0; i < len; i++) if (dirBuf[i] == (byte) 0xFF) dirBuf[i] = '/'; // LHA path separator
                    String dir = sanitizePath(new String(dirBuf, charset));
                    if (!dir.isEmpty() && dir.charAt(dir.length() - 1) != '/') dir += "/";
                    b.name = dir + b.name; // prepend directory to filename
                }
                break;
            }
            case EXT_UNIX_TIMESTAMP: {
                if (payloadEnd - 1 >= 4) {
                    final long unixSec = ext.getInt(1) & 0xFFFFFFFFL;
                    b.lastModified = unixSec * 1000L;
                }
                break;
            }
            default: break; // silently ignore unknown extended headers
        }
    }

    // ---- Entry stream setup ---------------------------------------------

    private LhaEntry openEntry(final LhaEntry entry) throws IOException {
        boundedCompressed = new BoundedStream(in, entry.getCompressedSize());

        if (entry.isDirectory()) {
            // Directory entries have no data
            decompressedStream = new CrcStream(new ByteArrayInputStream(new byte[0]), 0);
            return entry;
        }

        final InputStream inner;
        final String method = entry.getCompressionMethod();
        if (METHOD_LH0.equals(method) || METHOD_LZ4.equals(method)) {
            inner = boundedCompressed; // stored
        } else if (METHOD_LH4.equals(method)) {
            inner = LhaDecoder.lh4(boundedCompressed);
        } else if (METHOD_LH5.equals(method)) {
            inner = LhaDecoder.lh5(boundedCompressed);
        } else if (METHOD_LH6.equals(method)) {
            inner = LhaDecoder.lh6(boundedCompressed);
        } else if (METHOD_LH7.equals(method)) {
            inner = LhaDecoder.lh7(boundedCompressed);
        } else {
            decompressedStream = null; // unsupported
            return entry;
        }
        decompressedStream = new CrcStream(inner, entry.getCrc16());
        return entry;
    }

    // ---- Parsing helpers ------------------------------------------------

    private ByteBuffer readComplete(final ByteBuffer initial, final int totalSize) throws IOException {
        final int remaining = totalSize - initial.capacity();
        final byte[] extra = new byte[remaining];
        readFully(in, extra, 0, remaining, true);
        final ByteBuffer full = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);
        full.put(initial.array(), 0, initial.capacity());
        full.put(extra);
        full.position(0);
        return full;
    }

    private String readMethod(final ByteBuffer hdr) throws IOException {
        final byte[] mb = new byte[5];
        System.arraycopy(hdr.array(), OFFSET_COMPRESSION_METHOD, mb, 0, 5);
        if (mb[0] == '-' && mb[4] == '-') return new String(mb, StandardCharsets.US_ASCII);
        throw new IOException("LHA: invalid compression method in header");
    }

    private String getPathName(final ByteBuffer buf, final int len) throws IOException {
        if (len > MAX_PATH_LEN) throw new IOException("LHA: path name too long: " + len);
        final int base = buf.position();
        final byte[] raw = new byte[len];
        System.arraycopy(buf.array(), base, raw, 0, len);
        buf.position(base + len);
        // 0xFF bytes are directory separators in LHA
        final StringBuilder sb = new StringBuilder();
        int start = 0;
        for (int i = 0; i < len; i++) {
            if ((raw[i] & 0xFF) == 0xFF) {
                if (i > start) sb.append(new String(raw, start, i - start, charset)).append('/');
                start = i + 1;
            }
        }
        if (start < len) sb.append(new String(raw, start, len - start, charset));
        return sanitizePath(sb.toString());
    }

    private static String sanitizePath(String p) {
        p = p.replace('\\', '/');
        while (p.startsWith("/")) p = p.substring(1); // strip leading slashes
        return p;
    }

    /** Reads bytes [2..limit) of the header and returns their sum mod 256. */
    private static int checksumLevel01(final ByteBuffer hdr) {
        int sum = 0;
        for (int i = 2; i < hdr.limit(); i++) sum += hdr.get(i) & 0xFF;
        return sum & 0xFF;
    }

    /** Returns an unsigned 32-bit value as {@code long}. */
    private static long getUInt32(final ByteBuffer buf, final int offset) {
        return buf.getInt(offset) & 0xFFFFFFFFL;
    }

    /**
     * Converts an MS-DOS date+time field to milliseconds since the Unix epoch.
     *
     * <p>The 32-bit MS-DOS datetime is packed as:
     * {@code (date << 16) | time} where time uses bits 15-11=hours, 10-5=minutes,
     * 4-0=seconds/2; and date uses bits 15-9=year-1980, 8-5=month, 4-0=day.</p>
     */
    private static long dosToUnixMs(final long dosDateTime) {
        final int time = (int) (dosDateTime & 0xFFFF);
        final int date = (int) (dosDateTime >>> 16);
        final int year    = 1980 + ((date >>> 9) & 0x7F);
        final int month   = (date >>> 5) & 0x0F;   // 1-12
        final int day     = date & 0x1F;            // 1-31
        final int hour    = (time >>> 11) & 0x1F;
        final int minute  = (time >>> 5)  & 0x3F;
        final int second  = (time & 0x1F) * 2;
        if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
        final Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.set(year, month - 1, day, hour, minute, second);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }

    /** Reads exactly {@code len} bytes into {@code buf}. */
    private static int readFully(final InputStream in, final byte[] buf, final int off, final int len, final boolean required) throws IOException {
        int total = 0;
        while (total < len) {
            final int n = in.read(buf, off + total, len - total);
            if (n < 0) {
                if (required) throw new IOException("LHA: unexpected end of stream (needed " + len + " bytes, got " + total + ")");
                return total;
            }
            total += n;
        }
        return total;
    }

    // ---- Inner classes --------------------------------------------------

    /**
     * An input stream that reads at most {@code limit} bytes from the delegate
     * and exposes a {@link #drain()} method to consume any remaining bytes.
     */
    private static final class BoundedStream extends FilterInputStream {
        private long remaining;
        BoundedStream(final InputStream in, final long limit) { super(in); this.remaining = limit; }

        @Override public int read() throws IOException {
            if (remaining <= 0) return -1;
            final int b = in.read(); if (b >= 0) remaining--; return b;
        }
        @Override public int read(final byte[] b, final int off, final int len) throws IOException {
            if (remaining <= 0) return -1;
            final int n = in.read(b, off, (int) Math.min(len, remaining));
            if (n > 0) remaining -= n;
            return n;
        }
        @Override public long skip(final long n) throws IOException {
            final long s = in.skip(Math.min(n, remaining));
            remaining -= s; return s;
        }

        /** Consumes and discards all remaining bytes up to the limit. */
        void drain() throws IOException {
            final byte[] buf = new byte[4096];
            while (remaining > 0) {
                final int n = read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n < 0) break;
            }
        }
    }

    /**
     * An input stream that computes CRC-16 over all bytes read and optionally
     * verifies it when the stream is exhausted.
     */
    private static final class CrcStream extends FilterInputStream {
        private int  crc;
        private final int expectedCrc;
        private boolean verified = false;

        CrcStream(final InputStream in, final int expectedCrc) {
            super(in); this.crc = 0; this.expectedCrc = expectedCrc;
        }

        @Override public int read() throws IOException {
            final int b = in.read();
            if (b >= 0) crc = LhaCrc16.update(crc, b); else verify();
            return b;
        }
        @Override public int read(final byte[] b, final int off, final int len) throws IOException {
            final int n = in.read(b, off, len);
            if (n > 0) crc = LhaCrc16.update(crc, b, off, n); else if (n < 0) verify();
            return n;
        }

        private void verify() throws IOException {
            if (!verified && expectedCrc != 0 && (crc & 0xFFFF) != (expectedCrc & 0xFFFF)) {
                verified = true;
                throw new IOException("LHA: CRC-16 mismatch (expected 0x"
                        + Integer.toHexString(expectedCrc & 0xFFFF) + ", got 0x"
                        + Integer.toHexString(crc & 0xFFFF) + ")");
            }
            verified = true;
        }
    }
}
