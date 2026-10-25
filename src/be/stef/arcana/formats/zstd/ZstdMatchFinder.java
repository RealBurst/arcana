/*
 * Copyright 2026 Stephane Bury
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
package be.stef.arcana.formats.zstd;

import java.util.Arrays;

/**
 * Finds the matches of a block in the window (the bytes before it in the
 * buffer). Two strategies:
 * <ul>
 *   <li>level 1, "fast": one hash table of positions (hash of the next 5 bytes);
 *       the position one byte ahead is first tried with the last offset;</li>
 *   <li>level 2, "double fast": a second table hashed on 8 bytes is tried
 *       first, for longer matches.</li>
 * </ul>
 * Positions are stored as buffer index + 1 (0 = empty) and shifted when the
 * buffer slides. The repeated offsets follow the rules of RFC 8878 section
 * 3.1.2.5 (a repeated offset is only used after at least one literal, so
 * the offset value 1 always means the last offset).
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdMatchFinder {

    private static final long PRIME_5 = 0xCF1BBCDCBBL;
    private static final long PRIME_6 = 0xCF1BBCDCBF9BL;
    private static final long PRIME_8 = 0xCF1BBCDCB7A56463L;

    private final int level;
    private final int windowSize;
    private final int[] shortTable;
    private final int shortLog;
    private final int[] longTable;
    private final int longLog;

    /** Repeated offsets, as the decoder keeps them. */
    final int[] rep = {1, 4, 8};

    ZstdMatchFinder(final int level, final int windowSize) {
        this.level = level;
        this.windowSize = windowSize;
        if (level <= 1) {
            shortLog = 15;
            longLog = 0;
            longTable = null;
        } else {
            shortLog = 16;
            longLog = 17;
            longTable = new int[1 << longLog];
        }
        shortTable = new int[1 << shortLog];
    }

    /** The buffer moved {@code shift} bytes to the left. */
    void slide(final int shift) {
        shiftTable(shortTable, shift);
        if (longTable != null) shiftTable(longTable, shift);
    }

    private static void shiftTable(final int[] t, final int shift) {
        for (int i = 0; i < t.length; i++) {
            final int v = t[i] - shift;
            t[i] = v > 0 ? v : 0;
        }
    }

    void reset() {
        Arrays.fill(shortTable, 0);
        if (longTable != null) Arrays.fill(longTable, 0);
        rep[0] = 1;
        rep[1] = 4;
        rep[2] = 8;
    }

    /**
     * Finds the sequences of {@code buf[start..end)}; the window is
     * {@code buf[lowest..start)}.
     */
    void find(final byte[] buf, final int lowest, final int start, final int end, final ZstdSequenceStore store) {
        store.reset();
        if (level <= 1) fast(buf, lowest, start, end, store);
        else doubleFast(buf, lowest, start, end, store);
    }

    private void fast(final byte[] buf, final int lowest, final int start, final int end, final ZstdSequenceStore store) {
        final int[] table = shortTable;
        final int hlog = shortLog;
        final int ilimit = end - 16;
        int anchor = start;
        int ip = start;
        if (ip == lowest) ip++;
        while (ip < ilimit) {
            final int h = hash6(buf, ip, hlog);
            final int cand = table[h] - 1;
            table[h] = ip + 1;
            final int r = rep[0];
            if (ip + 1 - r >= lowest && read32(buf, ip + 1) == read32(buf, ip + 1 - r)) {
                final int len = 4 + count(buf, ip + 5, ip + 5 - r, end);
                store.add(buf, anchor, ip + 1 - anchor, 1, len);
                ip += 1 + len;
                anchor = ip;
            } else if (cand >= lowest && ip - cand <= windowSize && read32(buf, cand) == read32(buf, ip)) {
                int c = cand;
                int len = 4 + count(buf, ip + 4, c + 4, end);
                while (ip > anchor && c > lowest && buf[ip - 1] == buf[c - 1]) {
                    ip--;
                    c--;
                    len++;
                }
                newOffset(ip - c);
                store.add(buf, anchor, ip - anchor, ip - c + 3, len);
                ip += len;
                anchor = ip;
            } else {
                ip += ((ip - anchor) >> 8) + 1;
                continue;
            }
            if (ip < ilimit) {
                table[hash6(buf, ip - 2, hlog)] = ip - 2 + 1;
            }
        }
        store.addLastLiterals(buf, anchor, end - anchor);
    }

    private void doubleFast(final byte[] buf, final int lowest, final int start, final int end, final ZstdSequenceStore store) {
        final int[] st = shortTable;
        final int[] lt = longTable;
        final int slog = shortLog;
        final int llog = longLog;
        final int ilimit = end - 16;
        int anchor = start;
        int ip = start;
        if (ip == lowest) ip++;
        while (ip < ilimit) {
            final int hl = hash8(buf, ip, llog);
            final int hs = hash5(buf, ip, slog);
            final int candL = lt[hl] - 1;
            final int candS = st[hs] - 1;
            lt[hl] = ip + 1;
            st[hs] = ip + 1;
            final int matchStart;
            final int r = rep[0];
            if (ip + 1 - r >= lowest && read32(buf, ip + 1) == read32(buf, ip + 1 - r)) {
                final int len = 4 + count(buf, ip + 5, ip + 5 - r, end);
                store.add(buf, anchor, ip + 1 - anchor, 1, len);
                matchStart = ip + 1;
                ip += 1 + len;
                anchor = ip;
            } else {
                int c = -1;
                int len = 0;
                if (candL >= lowest && ip - candL <= windowSize && read64(buf, candL) == read64(buf, ip)) {
                    c = candL;
                    len = 8 + count(buf, ip + 8, c + 8, end);
                } else if (candS >= lowest && ip - candS <= windowSize && read32(buf, candS) == read32(buf, ip)) {
                    final int hl1 = hash8(buf, ip + 1, llog);
                    final int candL1 = lt[hl1] - 1;
                    lt[hl1] = ip + 2;
                    if (candL1 >= lowest && ip + 1 - candL1 <= windowSize && read64(buf, candL1) == read64(buf, ip + 1)) {
                        ip++;
                        c = candL1;
                        len = 8 + count(buf, ip + 8, c + 8, end);
                    } else {
                        c = candS;
                        len = 4 + count(buf, ip + 4, c + 4, end);
                    }
                }
                if (c < 0) {
                    ip += ((ip - anchor) >> 8) + 1;
                    continue;
                }
                while (ip > anchor && c > lowest && buf[ip - 1] == buf[c - 1]) {
                    ip--;
                    c--;
                    len++;
                }
                newOffset(ip - c);
                store.add(buf, anchor, ip - anchor, ip - c + 3, len);
                matchStart = ip;
                ip += len;
                anchor = ip;
            }
            if (ip < ilimit) {
                final int p = matchStart + 2;
                lt[hash8(buf, p, llog)] = p + 1;
                st[hash5(buf, p, slog)] = p + 1;
                lt[hash8(buf, ip - 2, llog)] = ip - 2 + 1;
                st[hash5(buf, ip - 1, slog)] = ip - 1 + 1;
            }
        }
        store.addLastLiterals(buf, anchor, end - anchor);
    }

    private void newOffset(final int offset) {
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = offset;
    }

    /** Number of equal bytes from {@code a} and {@code b}, {@code a} staying below {@code end}. */
    private static int count(final byte[] buf, int a, int b, final int end) {
        final int start = a;
        while (a + 8 <= end && read64(buf, a) == read64(buf, b)) {
            a += 8;
            b += 8;
        }
        if (a + 8 <= end) {
            final long diff = read64(buf, a) ^ read64(buf, b);
            return a - start + (Long.numberOfTrailingZeros(diff) >>> 3);
        }
        while (a < end && buf[a] == buf[b]) {
            a++;
            b++;
        }
        return a - start;
    }

    private static int read32(final byte[] buf, final int i) {
        return MemoryAccess.getInt(buf, MemoryAccess.BASE + i);
    }

    private static long read64(final byte[] buf, final int i) {
        return MemoryAccess.getLong(buf, MemoryAccess.BASE + i);
    }

    private static int hash5(final byte[] buf, final int i, final int log) {
        return (int) (((read64(buf, i) << 24) * PRIME_5) >>> (64 - log));
    }

    private static int hash6(final byte[] buf, final int i, final int log) {
        return (int) (((read64(buf, i) << 16) * PRIME_6) >>> (64 - log));
    }

    private static int hash8(final byte[] buf, final int i, final int log) {
        return (int) ((read64(buf, i) * PRIME_8) >>> (64 - log));
    }
}
