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
import be.stef.arcana.formats.xz.LZMA2InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Finds the part of a damaged LZMA2 stream that can still be decoded after the
 * damaged zone.
 *
 * <p>Multithreaded encoders (Arcana, 7-Zip -mmt) cut the stream into segments
 * that start with a chunk resetting the dictionary and the properties (control
 * byte 0xE0-0xFF): such a segment can be decoded without anything before it.
 * After a damaged zone, the chunk headers are searched again: a position is
 * accepted only if the chain of chunk headers that starts there leads exactly to
 * the end marker of the stream (a very strong check). The segments of that
 * "tail" are then decoded; their position in the uncompressed data is known
 * from the end (total size minus the sizes of the tail segments).</p>
 *
 * @author Stef
 * @since 1.3
 */
final class Lzma2SegmentRecovery {

    /** Tail found after the damage. */
    static final class Tail {
        /** Position of the tail in the uncompressed data. */
        long unpackStart;
        final List<long[]> segments = new ArrayList<long[]>(); // {packed offset, packed size, unpacked size}
    }

    private Lzma2SegmentRecovery() {}

    /**
     * @param start      absolute offset of the packed LZMA2 stream
     * @param packSize   packed size (end marker included)
     * @param unpackSize total uncompressed size
     * @return the decodable tail, or null if none
     */
    static Tail findTail(final ByteSource s, final long start, final long packSize, final long unpackSize) throws IOException {
        final long end = Math.min(start + packSize, s.length());
        final Map<Long, Boolean> memo = new HashMap<Long, Boolean>();
        for (long p = start + 1; p < end; p++) {
            final int c = s.u8(p);
            if (c < 0xE0) continue;
            if (!reachesEnd(s, p, end, memo)) continue;
            // p starts a valid chain up to the end marker: the tail
            final Tail t = new Tail();
            long q = p;
            long segStart = p, segUnpacked = 0, total = 0;
            while (true) {
                final int ctrl = s.u8(q);
                if (ctrl == 0) break;
                final long[] chunk = chunk(s, q);
                if (ctrl >= 0xE0 && q != segStart) {
                    t.segments.add(new long[] {segStart, q - segStart, segUnpacked});
                    segStart = q;
                    segUnpacked = 0;
                }
                segUnpacked += chunk[1];
                total += chunk[1];
                q += chunk[0];
            }
            t.segments.add(new long[] {segStart, q - segStart, segUnpacked});
            t.unpackStart = unpackSize - total;
            if (t.unpackStart >= 0) return t;
            // more data than the folder holds: a false start (random bytes looking like a chunk header), keep searching
        }
        return null;
    }

    /** Decodes one segment (its chunks followed by an end marker). */
    static byte[] decode(final ByteSource s, final long[] seg, final int dictSize) throws IOException {
        final byte[] packed = new byte[(int) seg[1] + 1];
        if (s.read(seg[0], packed, 0, (int) seg[1]) != seg[1]) throw new IOException("segment truncated");
        final byte[] out = new byte[(int) seg[2]];
        final LZMA2InputStream in = new LZMA2InputStream(new ByteArrayInputStream(packed), (int) Math.max(4096, Math.min(dictSize, seg[2])));
        try {
            int n = 0;
            while (n < out.length) {
                final int k = in.read(out, n, out.length - n);
                if (k < 0) throw new IOException("segment shorter than announced");
                n += k;
            }
        } finally {
            in.close();
        }
        return out;
    }

    /** True if the chain of chunk headers starting at {@code p} ends exactly with the end marker at {@code end - 1}. */
    private static boolean reachesEnd(final ByteSource s, final long p, final long end, final Map<Long, Boolean> memo) throws IOException {
        final List<Long> path = new ArrayList<Long>();
        long q = p;
        Boolean result = null;
        while (result == null) {
            final Boolean known = memo.get(q);
            if (known != null) { result = known; break; }
            path.add(q);
            final int ctrl = s.u8(q);
            if (ctrl == 0) { result = q == end - 1; break; }
            final long[] c = chunk(s, q);
            if (c == null || q + c[0] >= end) { result = false; break; }
            q += c[0];
            if (path.size() > 10_000_000) { result = false; break; }
        }
        for (final Long x : path) memo.put(x, result);
        return result;
    }

    /** {chunk size (header included), unpacked size} of the chunk at {@code q}, or null if invalid. */
    private static long[] chunk(final ByteSource s, final long q) throws IOException {
        final int ctrl = s.u8(q);
        if (ctrl == 0x01 || ctrl == 0x02) {
            final int a = s.u8(q + 1), b = s.u8(q + 2);
            if (a < 0 || b < 0) return null;
            final long un = ((a << 8) | b) + 1;
            return new long[] {3 + un, un};
        }
        if (ctrl >= 0x80) {
            final int a = s.u8(q + 1), b = s.u8(q + 2), c = s.u8(q + 3), d = s.u8(q + 4);
            if (a < 0 || b < 0 || c < 0 || d < 0) return null;
            final long un = (((ctrl & 0x1F) << 16) | (a << 8) | b) + 1;
            final long pk = ((c << 8) | d) + 1;
            if (ctrl >= 0xC0) {
                final int props = s.u8(q + 5);
                if (props < 0 || props > (4 * 5 + 4) * 9 + 8) return null; // (pb * 5 + lp) * 9 + lc, lc + lp <= 4
            }
            return new long[] {(ctrl >= 0xC0 ? 6 : 5) + pk, un};
        }
        return null;
    }
}
