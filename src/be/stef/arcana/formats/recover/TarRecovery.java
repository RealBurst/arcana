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
package be.stef.arcana.formats.recover;

import be.stef.arcana.formats.carve.ByteSource;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Recovery of a damaged TAR (or of the partial TAR decoded from a damaged
 * tar.gz / tar.bz2 / tar.xz...). Every header carries its own checksum: a
 * damaged header is skipped and the next valid one is searched, block by block
 * and also at any byte offset ("ustar" magic), because data lost in the middle
 * (a destroyed bzip2 block for example) shifts everything that follows.
 *
 * <p>TAR stores no checksum of the file contents: complete files are reported
 * UNVERIFIED, or OK when the TAR came out of a compressed stream whose checksums
 * were all verified. When the input is known to have holes ({@code holes = true}), a
 * valid header found inside the data of a file means that data is missing: the
 * file is cut there (PARTIAL) and the recovery continues from that header.</p>
 *
 * @author Stef
 * @since 1.3
 */
final class TarRecovery {

    private static final byte[] USTAR = {'u', 's', 't', 'a', 'r'};

    private TarRecovery() {}

    static void recover(final File tar, final Outputs out, final RecoveryReport report, final boolean holes) throws IOException {
        recover(tar, out, report, holes, false);
    }

    /**
     * @param verified the TAR was decoded completely from a compressed stream whose
     *                 checksums were all correct (gzip CRC, bzip2 block CRCs, xz checks):
     *                 complete files are then reported OK instead of UNVERIFIED
     */
    static void recover(final File tar, final Outputs out, final RecoveryReport report, final boolean holes, final boolean verified) throws IOException {
        int headers = 0, skipped = 0;
        try (ByteSource s = new ByteSource(tar)) {
            final long len = s.length();
            long pos = 0;
            String longName = null;
            int lastFile = -1; // report index of the last regular file, while its end is not confirmed
            String paxPath = null;
            long paxSize = -1;
            while (pos + 512 <= len) {
                if (isZeroBlock(s, pos)) { pos += 512; lastFile = -1; continue; }
                if (!validHeader(s, pos)) {
                    if (lastFile >= 0) {
                        // no header where the previous file ends: its data (or its size) is damaged
                        report.downgrade(lastFile, RecoveryReport.Status.PARTIAL, "no valid header after this file: its data is probably damaged");
                        lastFile = -1;
                    }
                    final long next = resync(s, pos + 1);
                    if (next < 0) break;
                    skipped++;
                    pos = next;
                    continue;
                }
                headers++;
                lastFile = -1;
                final int type = s.u8(pos + 156);
                String name = longName != null ? longName : paxPath != null ? paxPath : headerName(s, pos);
                long size = paxSize >= 0 ? paxSize : parseSize(s, pos + 124);
                longName = null;
                paxPath = null;
                paxSize = -1;
                final long data = pos + 512;
                if (size < 0) { pos = data; continue; }
                final long blocks = (size + 511) / 512 * 512;
                if (type == 'L' || type == 'x' || type == 'K' || type == 'g') {
                    // meta-data entries: GNU long name, PAX attributes
                    final byte[] meta = s.bytes(data, (int) Math.min(size, 1 << 20));
                    if (meta != null && type == 'L') longName = cString(meta);
                    if (meta != null && type == 'x') {
                        final String[] pax = parsePax(meta);
                        paxPath = pax[0];
                        if (pax[1] != null) try { paxSize = Long.parseLong(pax[1]); } catch (final NumberFormatException ignored) { /* keep header size */ }
                    }
                    pos = data + blocks;
                    continue;
                }
                if (type == '5' || name.endsWith("/")) {
                    out.directory(name);
                    pos = data + (type == '5' ? 0 : blocks);
                    continue;
                }
                if (type == '1' || type == '2') {
                    report.add(name, RecoveryReport.Status.UNVERIFIED, 0, 0, (type == '1' ? "hard" : "symbolic") + " link not recreated in forced mode");
                    pos = data;
                    continue;
                }
                if (type != '0' && type != 0 && type != '7') {
                    pos = data + blocks; // devices, FIFOs...: nothing to write
                    continue;
                }
                // Regular file
                long end = data + size;
                String message = null;
                boolean partial = false;
                if (holes) {
                    final long inner = firstHeaderIn(s, data, Math.min(end, len));
                    if (inner >= 0) {
                        end = inner;
                        partial = true;
                        message = "data missing (a header was found inside the file data)";
                    }
                }
                if (end > len) {
                    end = len;
                    partial = true;
                    message = "archive ends inside the file";
                }
                final long written = copy(s, data, end, out, name);
                report.add(name, partial ? RecoveryReport.Status.PARTIAL : verified ? RecoveryReport.Status.OK : RecoveryReport.Status.UNVERIFIED, written, size, message);
                if (!partial) lastFile = report.lastIndex();
                pos = partial ? end : data + blocks;
            }
        }
        if (headers == 0) report.note("No valid TAR header found.");
        if (skipped > 0) report.note(skipped + " damaged zone(s) skipped while searching TAR headers.");
    }

    private static long copy(final ByteSource s, final long from, final long to, final Outputs out, final String name) throws IOException {
        final byte[] buf = new byte[65536];
        long p = from;
        try (OutputStream o = out.file(name)) {
            while (p < to) {
                final int n = s.read(p, buf, 0, (int) Math.min(buf.length, to - p));
                if (n <= 0) break;
                o.write(buf, 0, n);
                p += n;
            }
        }
        return p - from;
    }

    /** Next valid header after {@code from}: "ustar" magic at any offset, else a 512-aligned block with a valid checksum. */
    private static long resync(final ByteSource s, final long from) throws IOException {
        long q = from + 257;
        while (true) {
            final long m = s.indexOf(USTAR, q, s.length());
            if (m < 0) break;
            final long h = m - 257;
            if (h >= from && validHeader(s, h)) return h;
            q = m + 1;
        }
        for (long h = (from + 511) / 512 * 512; h + 512 <= s.length(); h += 512) {
            if (validHeader(s, h)) return h;
        }
        return -1;
    }

    /** First valid ustar header strictly inside [from, to), or -1. */
    private static long firstHeaderIn(final ByteSource s, final long from, final long to) throws IOException {
        long q = from + 257;
        while (q < to + 257) {
            final long m = s.indexOf(USTAR, q, Math.min(s.length(), to + 257 + 5));
            if (m < 0) return -1;
            final long h = m - 257;
            if (h >= from && h < to && validHeader(s, h)) return h;
            q = m + 1;
        }
        return -1;
    }

    private static boolean isZeroBlock(final ByteSource s, final long pos) throws IOException {
        for (int i = 0; i < 512; i++) if (s.u8(pos + i) != 0) return false;
        return true;
    }

    static boolean validHeader(final ByteSource s, final long pos) throws IOException {
        final byte[] h = s.bytes(pos, 512);
        if (h == null || h[0] == 0) return false;
        long stored = 0;
        int digits = 0;
        for (int i = 148; i < 156; i++) {
            final int c = h[i] & 0xFF;
            if (c == 0 || c == ' ') { if (digits > 0) break; continue; }
            if (c < '0' || c > '7') return false;
            stored = stored * 8 + (c - '0');
            digits++;
        }
        if (digits == 0) return false;
        long sum = 0, signed = 0;
        for (int i = 0; i < 512; i++) {
            final int v = (i >= 148 && i < 156) ? ' ' : h[i];
            sum += v & 0xFF;
            signed += (byte) v;
        }
        return sum == stored || signed == stored;
    }

    private static String headerName(final ByteSource s, final long pos) throws IOException {
        final String name = cString(s.bytes(pos, 100));
        if (s.matches(pos + 257, USTAR)) {
            final String prefix = cString(s.bytes(pos + 345, 155));
            if (!prefix.isEmpty()) return prefix + "/" + name;
        }
        return name;
    }

    /** Octal or base-256 size, -1 if invalid. */
    private static long parseSize(final ByteSource s, final long pos) throws IOException {
        final byte[] f = s.bytes(pos, 12);
        if ((f[0] & 0x80) != 0) {
            long v = f[0] & 0x7F;
            for (int i = 1; i < 12; i++) v = (v << 8) | (f[i] & 0xFF);
            return v;
        }
        long v = 0;
        boolean any = false;
        for (final byte b : f) {
            final int c = b & 0xFF;
            if (c == 0 || c == ' ') { if (any) break; continue; }
            if (c < '0' || c > '7') return -1;
            v = v * 8 + (c - '0');
            any = true;
        }
        return v;
    }

    private static String cString(final byte[] b) {
        int n = 0;
        while (n < b.length && b[n] != 0) n++;
        return new String(b, 0, n, StandardCharsets.UTF_8);
    }

    /** {path, size} from PAX extended records ("len key=value\n"). */
    private static String[] parsePax(final byte[] b) {
        final String[] r = new String[2];
        final String text = new String(b, StandardCharsets.UTF_8);
        for (final String line : text.split("\n")) {
            final int sp = line.indexOf(' ');
            final int eq = line.indexOf('=');
            if (sp < 0 || eq < sp) continue;
            final String key = line.substring(sp + 1, eq);
            final String value = line.substring(eq + 1);
            if (key.equals("path")) r[0] = value;
            else if (key.equals("size")) r[1] = value;
        }
        return r;
    }
}
