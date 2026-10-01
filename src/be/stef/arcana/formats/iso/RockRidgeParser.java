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

/**
 * Parses SUSP / Rock Ridge System Use entries attached to a directory record.
 *
 * <p>This implementation extracts the alternate name (NM entry), which is the
 * feature that matters most for extraction: it gives the real Unix file name
 * that would otherwise be mangled by the ISO 9660 8.3 convention. Continuation
 * areas (CE entries) are followed by reading additional sectors through the
 * supplied {@link SectorReader}.</p>
 *
 * @author Stef
 * @since 1.1
 */
final class RockRidgeParser {

    /** Callback used to read a continuation area sector from the image. */
    interface SectorReader {
        byte[] readBytes(long lba, long offset, int length) throws IOException;
    }

    private RockRidgeParser() {}

    /**
     * Extracts the Rock Ridge alternate name (NM) from the system-use area of a
     * directory record, following CE continuation areas if present.
     *
     * @param record the directory record to inspect
     * @param reader  reader for continuation areas
     * @return the alternate name, or {@code null} if no NM entry is present
     */
    static String extractAlternateName(IsoDirectoryRecord record, SectorReader reader) throws IOException {
        if (record.systemUseLength <= 0) {
            return null;
        }
        StringBuilder name = new StringBuilder();
        boolean found = parseArea(record.buffer, record.bufferOffset + (record.systemUseOffset - record.bufferOffset),
                record.systemUseLength, name, reader, 0);
        return found ? name.toString() : null;
    }

    /**
     * Parses a system-use area, appending NM fragments to {@code name}.
     * Returns true if at least one NM entry was found.
     */
    private static boolean parseArea(byte[] buf, int offset, int length, StringBuilder name,
                                     SectorReader reader, int depth) throws IOException {
        if (depth > 8) {
            return name.length() > 0; // guard against pathological CE chains
        }
        boolean found = false;
        int pos = offset;
        int end = offset + length;
        while (pos + 4 <= end) {
            int sig0 = buf[pos] & 0xff;
            int sig1 = buf[pos + 1] & 0xff;
            int entryLen = buf[pos + 2] & 0xff;
            if (entryLen < 4) {
                break; // malformed or padding
            }

            if (sig0 == 'N' && sig1 == 'M') {
                // NM: offset+3 version, offset+4 flags, offset+5.. name bytes
                int flags = buf[pos + 4] & 0xff;
                int nameLen = entryLen - 5;
                if (nameLen > 0 && (flags & (IsoConstants.NM_FLAG_CURRENT | IsoConstants.NM_FLAG_PARENT)) == 0) {
                    name.append(new String(buf, pos + 5, nameLen, java.nio.charset.StandardCharsets.UTF_8));
                    found = true;
                }
                // If NM_FLAG_CONTINUE is set, the next NM entry appends more of the name
            } else if (sig0 == 'C' && sig1 == 'E') {
                // CE: continuation area. Follow it.
                // offset+4  block location (both-endian uint32) -> LE part at +4
                // offset+12 offset within block (both-endian uint32) -> LE at +12
                // offset+20 length of continuation (both-endian uint32) -> LE at +20
                long ceLba = IsoDirectoryRecord.readUint32LE(buf, pos + 4);
                long ceOffset = IsoDirectoryRecord.readUint32LE(buf, pos + 12);
                long ceLength = IsoDirectoryRecord.readUint32LE(buf, pos + 20);
                if (reader != null && ceLength > 0 && ceLength < 8192) {
                    byte[] cont = reader.readBytes(ceLba, ceOffset, (int) ceLength);
                    boolean sub = parseArea(cont, 0, cont.length, name, reader, depth + 1);
                    found = found || sub;
                }
            } else if (sig0 == 'S' && sig1 == 'T') {
                break; // ST: terminator
            }

            pos += entryLen;
        }
        return found;
    }

    /**
     * Returns a copy of the first System Use entry with signature {@code c0 c1}
     * (header included), following CE continuation areas, or {@code null}.
     */
    static byte[] findEntry(IsoDirectoryRecord record, SectorReader reader, char c0, char c1) throws IOException {
        if (record.systemUseLength <= 0) return null;
        return findInArea(record.buffer, record.systemUseOffset, record.systemUseLength, reader, c0, c1, 0);
    }

    private static byte[] findInArea(byte[] buf, int offset, int length, SectorReader reader, char c0, char c1, int depth) throws IOException {
        if (depth > 8) return null;
        int pos = offset;
        int end = Math.min(offset + length, buf.length);
        while (pos + 4 <= end) {
            int sig0 = buf[pos] & 0xff;
            int sig1 = buf[pos + 1] & 0xff;
            int entryLen = buf[pos + 2] & 0xff;
            if (entryLen < 4 || pos + entryLen > end) break;
            if (sig0 == c0 && sig1 == c1) return java.util.Arrays.copyOfRange(buf, pos, pos + entryLen);
            if (sig0 == 'C' && sig1 == 'E' && entryLen >= 28) {
                long ceLba = IsoDirectoryRecord.readUint32LE(buf, pos + 4);
                long ceOffset = IsoDirectoryRecord.readUint32LE(buf, pos + 12);
                long ceLength = IsoDirectoryRecord.readUint32LE(buf, pos + 20);
                if (reader != null && ceLength > 0 && ceLength < 8192) {
                    byte[] cont = reader.readBytes(ceLba, ceOffset, (int) ceLength);
                    byte[] found = findInArea(cont, 0, cont.length, reader, c0, c1, depth + 1);
                    if (found != null) return found;
                }
            } else if (sig0 == 'S' && sig1 == 'T') {
                break;
            }
            pos += entryLen;
        }
        return null;
    }
}
