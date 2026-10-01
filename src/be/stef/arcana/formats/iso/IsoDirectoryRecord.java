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
package be.stef.arcana.formats.iso;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * A single ISO 9660 Directory Record.
 *
 * <p>Layout (variable length, minimum 34 bytes):</p>
 * <pre>
 *   0      length of record (byte)
 *   1      extended attribute record length (byte)
 *   2-9    extent location (LBA) - both-endian uint32
 *   10-17  data length          - both-endian uint32
 *   18-24  recording date/time  - 7 bytes
 *   25     file flags           - byte
 *   26     file unit size       - byte (interleaved mode)
 *   27     interleave gap       - byte
 *   28-31  volume sequence number - both-endian uint16
 *   32     file identifier length (byte)
 *   33..   file identifier      - variable
 *   ..     padding (1 byte if id length is even)
 *   ..     system use area (SUSP / Rock Ridge)
 * </pre>
 *
 * @author Stef
 * @since 1.1
 */
final class IsoDirectoryRecord {

    /** Total record length in bytes (0 means end of directory sector). */
    final int recordLength;
    /** Logical block address (sector) where the file/dir data starts. */
    final long extentLba;
    /** Data length in bytes. */
    final long dataLength;
    /** File flags (see IsoConstants.FILE_FLAG_*). */
    final int flags;
    /** Raw file identifier bytes (before Joliet/Rock Ridge decoding). */
    final byte[] rawIdentifier;
    /** Recording date as Unix epoch seconds, or -1 if unavailable. */
    final long recordingEpochSeconds;
    /** Offset of the system-use area within the record (0 if none). */
    final int systemUseOffset;
    /** Length of the system-use area. */
    final int systemUseLength;
    /** Backing buffer holding this record (for system-use parsing). */
    final byte[] buffer;
    /** Absolute offset of this record within {@link #buffer}. */
    final int bufferOffset;

    private IsoDirectoryRecord(int recordLength, long extentLba, long dataLength, int flags,
                               byte[] rawIdentifier, long recordingEpochSeconds,
                               int systemUseOffset, int systemUseLength,
                               byte[] buffer, int bufferOffset) {
        this.recordLength = recordLength;
        this.extentLba = extentLba;
        this.dataLength = dataLength;
        this.flags = flags;
        this.rawIdentifier = rawIdentifier;
        this.recordingEpochSeconds = recordingEpochSeconds;
        this.systemUseOffset = systemUseOffset;
        this.systemUseLength = systemUseLength;
        this.buffer = buffer;
        this.bufferOffset = bufferOffset;
    }

    /**
     * Parses a directory record starting at {@code offset} within {@code buf}.
     *
     * @param buf    buffer containing directory data
     * @param offset start offset of the record
     * @return the parsed record, or {@code null} if the record length is 0
     *         (which marks the end of records in the current sector)
     */
    static IsoDirectoryRecord parse(byte[] buf, int offset) {
        int len = buf[offset] & 0xff;
        if (len == 0) {
            return null; // end of records in this sector
        }
        int earLen = buf[offset + 1] & 0xff;
        long lba = readUint32LE(buf, offset + 2);   // both-endian: LE part first
        long size = readUint32LE(buf, offset + 10);
        long epoch = parseDirDateTime(buf, offset + 18);
        int flags = buf[offset + 25] & 0xff;
        int idLen = buf[offset + 32] & 0xff;

        byte[] id = new byte[idLen];
        System.arraycopy(buf, offset + 33, id, 0, idLen);

        // System use area starts after the identifier (+ optional pad byte)
        int idEnd = 33 + idLen;
        if ((idLen & 1) == 0) {
            idEnd++; // pad to even boundary
        }
        int suOffset = 0;
        int suLength = 0;
        if (idEnd < len) {
            suOffset = offset + idEnd;
            suLength = len - idEnd;
        }
        // earLen is skipped extended attributes at the start of file data; kept for completeness
        return new IsoDirectoryRecord(len, lba + earLen, size, flags, id, epoch, suOffset, suLength, buf, offset);
    }

    boolean isDirectory() {
        return (flags & IsoConstants.FILE_FLAG_DIRECTORY) != 0;
    }

    boolean isMultiExtent() {
        return (flags & IsoConstants.FILE_FLAG_MULTI_EXTENT) != 0;
    }

    /**
     * Decodes the file identifier as an ISO 9660 name (ASCII, strips the
     * {@code ;version} suffix and a trailing dot).
     */
    String getIso9660Name() {
        // Special entries: 0x00 = ".", 0x01 = ".."
        if (rawIdentifier.length == 1) {
            if (rawIdentifier[0] == 0x00) return ".";
            if (rawIdentifier[0] == 0x01) return "..";
        }
        String name;
        try {
            name = new String(rawIdentifier, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
            name = new String(rawIdentifier);
        }
        // Strip version suffix ";1"
        int semi = name.indexOf(';');
        if (semi >= 0) {
            name = name.substring(0, semi);
        }
        // Strip trailing dot (files with no extension are stored as "NAME.")
        if (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }
        return name;
    }

    /**
     * Decodes the file identifier as a Joliet name (UTF-16BE / UCS-2),
     * stripping the {@code ;version} suffix.
     */
    String getJolietName() {
        if (rawIdentifier.length == 1) {
            if (rawIdentifier[0] == 0x00) return ".";
            if (rawIdentifier[0] == 0x01) return "..";
        }
        String name;
        try {
            name = new String(rawIdentifier, "UTF-16BE");
        } catch (UnsupportedEncodingException e) {
            name = new String(rawIdentifier);
        }
        int semi = name.indexOf(';');
        if (semi >= 0) {
            name = name.substring(0, semi);
        }
        return name;
    }

    // =========================================================================
    // Endianness helpers
    // =========================================================================

    /** Reads a little-endian uint32 (the LE half of a both-endian field). */
    static long readUint32LE(byte[] buf, int off) {
        return  (buf[off]     & 0xffL)
             | ((buf[off + 1] & 0xffL) << 8)
             | ((buf[off + 2] & 0xffL) << 16)
             | ((buf[off + 3] & 0xffL) << 24);
    }

    /** Reads a little-endian uint16 (the LE half of a both-endian field). */
    static int readUint16LE(byte[] buf, int off) {
        return (buf[off] & 0xff) | ((buf[off + 1] & 0xff) << 8);
    }

    /**
     * Parses the 7-byte directory record date/time into Unix epoch seconds.
     * Layout: year-1900, month, day, hour, minute, second, gmt offset (15-min units).
     */
    private static long parseDirDateTime(byte[] buf, int off) {
        int year = (buf[off] & 0xff) + 1900;
        int month = buf[off + 1] & 0xff;
        int day = buf[off + 2] & 0xff;
        int hour = buf[off + 3] & 0xff;
        int minute = buf[off + 4] & 0xff;
        int second = buf[off + 5] & 0xff;
        int gmtOffset = buf[off + 6]; // signed, in 15-minute intervals
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return -1L;
        }
        try {
            java.util.Calendar cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
            cal.clear();
            cal.set(year, month - 1, day, hour, minute, second);
            long millis = cal.getTimeInMillis();
            millis -= gmtOffset * 15L * 60L * 1000L; // convert to UTC
            return millis / 1000L;
        } catch (Exception e) {
            return -1L;
        }
    }
}
