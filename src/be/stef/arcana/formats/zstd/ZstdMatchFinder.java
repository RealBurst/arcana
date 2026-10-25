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
 * buffer). Strategies, by level (see {@link #forLevel}):
 * <ul>
 *   <li>"fast" (level 1): one hash table of positions (hash of the next 6
 *       bytes); the position one byte ahead is first tried with the last
 *       offset;</li>
 *   <li>"double fast" (levels 2 to 4): a second table hashed on 8 bytes is
 *       tried first, for longer matches;</li>
 *   <li>"greedy", "lazy", "lazy2" (levels 5 to 12): hash chains (every
 *       position is linked to the previous one with the same hash, up to
 *       2^searchLog candidates are compared). Greedy takes the longest match
 *       found; lazy also searches one position further, lazy2 two, and keeps
 *       the later match when it is worth more (length against the cost of
 *       its offset).</li>
 * </ul>
 * The fast tables store buffer index + 1 (0 = empty) and are shifted when the
 * buffer slides; the hash chains store absolute positions + 1 (index in the
 * buffer + {@code hcBase}), so that the chain slot of a position
 * (position &amp; chainMask) does not change when the buffer slides. The
 * repeated offsets follow RFC 8878 section 3.1.2.5 (a repeated offset is only
 * used after at least one literal, so the offset value 1 always means the
 * last offset).
 *
 * @author Stef
 * @since 1.2.0
 */
final class ZstdMatchFinder {

    private static final long PRIME_5 = 0xCF1BBCDCBBL;
    private static final long PRIME_6 = 0xCF1BBCDCBF9BL;
    private static final long PRIME_8 = 0xCF1BBCDCB7A56463L;

    static final int FAST = 1;
    static final int DOUBLE_FAST = 2;
    static final int GREEDY = 3;
    static final int LAZY = 4;
    static final int LAZY2 = 5;

    /** Parameters of a level. For "double fast", hashLog is the short table and chainLog the long one. */
    static final class Params {
        final int strategy;
        final int windowLog;
        final int hashLog;
        final int chainLog;
        final int searchLog;
        /** A match this long is taken without looking further (chain search and lazy evaluation). */
        final int targetLength;

        Params(final int strategy, final int windowLog, final int hashLog, final int chainLog, final int searchLog, final int targetLength) {
            this.strategy = strategy;
            this.windowLog = windowLog;
            this.hashLog = hashLog;
            this.chainLog = chainLog;
            this.searchLog = searchLog;
            this.targetLength = targetLength;
        }
    }

    /** Levels 1 to 12 (index = level). */
    private static final Params[] LEVELS = {
        null,
        new Params(FAST, 19, 15, 0, 0, 0),
        new Params(DOUBLE_FAST, 20, 16, 17, 0, 0),
        new Params(DOUBLE_FAST, 21, 17, 18, 0, 0),
        new Params(DOUBLE_FAST, 21, 18, 19, 0, 0),
        new Params(GREEDY, 21, 18, 21, 3, 64),
        new Params(LAZY, 21, 18, 21, 3, 64),
        new Params(LAZY, 21, 19, 21, 4, 128),
        new Params(LAZY2, 21, 19, 21, 4, 128),
        new Params(LAZY2, 22, 20, 22, 4, 128),
        new Params(LAZY2, 22, 20, 22, 5, 256),
        new Params(LAZY2, 22, 21, 22, 6, 256),
        new Params(LAZY2, 22, 22, 22, 7, 512),
    };

    /** Highest level with parameters. */
    static final int MAX_LEVEL = LEVELS.length - 1;

    /** Parameters of {@code level} (1 to {@link #MAX_LEVEL}). */
    static Params forLevel(final int level) {
        return LEVELS[Math.max(1, Math.min(MAX_LEVEL, level))];
    }

    private final Params params;
    private final int windowSize;
    private final int[] shortTable;
    private final int shortLog;
    private final int[] longTable;
    private final int longLog;

    // hash chains
    private final int[] hcHead;
    private final int[] hcChain;
    private final int hcMask;
    /** Absolute position of buf[0]. */
    private int hcBase;
    /** Next absolute position to insert in the chains. */
    private int nextToUpdate;
    /** Offset of the last match found by {@link #searchChain}. */
    private int bestOffset;

    /** Repeated offsets, as the decoder keeps them. */
    final int[] rep = {1, 4, 8};

    /**
     * @param params     parameters of the level
     * @param windowSize largest offset (may be below 1 &lt;&lt; params.windowLog for small inputs)
     */
    ZstdMatchFinder(final Params params, final int windowSize) {
        this.params = params;
        this.windowSize = windowSize;
        if (params.strategy == FAST) {
            shortLog = params.hashLog;
            shortTable = new int[1 << shortLog];
            longLog = 0;
            longTable = null;
            hcHead = null;
            hcChain = null;
            hcMask = 0;
        } else if (params.strategy == DOUBLE_FAST) {
            shortLog = params.hashLog;
            shortTable = new int[1 << shortLog];
            longLog = params.chainLog;
            longTable = new int[1 << longLog];
            hcHead = null;
            hcChain = null;
            hcMask = 0;
        } else {
            shortLog = params.hashLog;
            shortTable = null;
            longLog = 0;
            longTable = null;
            hcHead = new int[1 << params.hashLog];
            hcChain = new int[1 << params.chainLog];
            hcMask = (1 << params.chainLog) - 1;
        }
    }

    /** The buffer moved {@code shift} bytes to the left. */
    void slide(final int shift) {
        if (shortTable != null) shiftTable(shortTable, shift);
        if (longTable != null) shiftTable(longTable, shift);
        if (hcHead != null) {
            hcBase += shift;
            if (hcBase > (1 << 30)) {
                // keep the absolute positions far from overflow; a multiple of the chain size keeps the chain slots
                final int r = hcBase & ~hcMask;
                shiftTable(hcHead, r);
                shiftTable(hcChain, r);
                hcBase -= r;
                nextToUpdate = Math.max(0, nextToUpdate - r);
            }
        }
    }

    private static void shiftTable(final int[] t, final int shift) {
        for (int i = 0; i < t.length; i++) {
            final int v = t[i] - shift;
            t[i] = v > 0 ? v : 0;
        }
    }

    void reset() {
        if (shortTable != null) Arrays.fill(shortTable, 0);
        if (longTable != null) Arrays.fill(longTable, 0);
        if (hcHead != null) {
            Arrays.fill(hcHead, 0);
            Arrays.fill(hcChain, 0);
        }
        hcBase = 0;
        nextToUpdate = 0;
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
        if (params.strategy == FAST) fast(buf, lowest, start, end, store);
        else if (params.strategy == DOUBLE_FAST) doubleFast(buf, lowest, start, end, store);
        else lazy(buf, lowest, start, end, params.strategy - GREEDY, store);
    }

    /**
     * Greedy (depth 0), lazy (1) and lazy2 (2) parsing over the hash chains.
     * A match found at ip is compared with the best match one (and two)
     * positions further: gain = 4 * length - bits of the offset value, with a
     * bonus for the match already found.
     */
    private void lazy(final byte[] buf, final int lowest, final int start, final int end, final int depth, final ZstdSequenceStore store) {
        final int ilimit = end - 16;
        int anchor = start;
        int ip = start;
        if (ip == lowest) ip++;
        if (nextToUpdate < lowest + hcBase) nextToUpdate = lowest + hcBase;
        while (ip < ilimit) {
            int matchLen = 0;
            int offVal = 0;
            int mstart = ip;
            final int r0 = rep[0];
            if (ip + 1 - r0 >= lowest && read32(buf, ip + 1) == read32(buf, ip + 1 - r0)) {
                matchLen = 4 + count(buf, ip + 5, ip + 5 - r0, end);
                offVal = 1;
                mstart = ip + 1;
            }
            if (depth > 0 || matchLen == 0) {
                final int ml = searchChain(buf, ip, lowest, end);
                if (ml > matchLen) {
                    matchLen = ml;
                    offVal = bestOffset + 3;
                    mstart = ip;
                }
            }
            if (matchLen < 4) {
                ip += ((ip - anchor) >> 8) + 1;
                continue;
            }
            if (depth > 0 && matchLen < params.targetLength) {
                while (ip < ilimit) {
                    ip++;
                    if (ip >= ilimit) break;
                    final int r = rep[0];
                    if (ip - r >= lowest && read32(buf, ip) == read32(buf, ip - r)) {
                        final int mlRep = 4 + count(buf, ip + 4, ip + 4 - r, end);
                        final int gain2 = mlRep * 3;
                        final int gain1 = matchLen * 3 - Util.highestBit(offVal) + 1;
                        if (gain2 > gain1) {
                            matchLen = mlRep;
                            offVal = 1;
                            mstart = ip;
                        }
                    }
                    final int ml2 = searchChain(buf, ip, lowest, end);
                    if (ml2 >= 4) {
                        final int gain2 = ml2 * 4 - Util.highestBit(bestOffset + 3);
                        final int gain1 = matchLen * 4 - Util.highestBit(offVal) + 4;
                        if (gain2 > gain1) {
                            matchLen = ml2;
                            offVal = bestOffset + 3;
                            mstart = ip;
                            continue;
                        }
                    }
                    if (depth == 2 && ip + 1 < ilimit) {
                        ip++;
                        final int rr = rep[0];
                        if (ip - rr >= lowest && read32(buf, ip) == read32(buf, ip - rr)) {
                            final int mlRep = 4 + count(buf, ip + 4, ip + 4 - rr, end);
                            final int gain2 = mlRep * 4;
                            final int gain1 = matchLen * 4 - Util.highestBit(offVal) + 1;
                            if (gain2 > gain1) {
                                matchLen = mlRep;
                                offVal = 1;
                                mstart = ip;
                            }
                        }
                        final int ml3 = searchChain(buf, ip, lowest, end);
                        if (ml3 >= 4) {
                            final int gain2 = ml3 * 4 - Util.highestBit(bestOffset + 3);
                            final int gain1 = matchLen * 4 - Util.highestBit(offVal) + 7;
                            if (gain2 > gain1) {
                                matchLen = ml3;
                                offVal = bestOffset + 3;
                                mstart = ip;
                                continue;
                            }
                        }
                    }
                    break;
                }
            }
            if (offVal > 3) {
                final int off = offVal - 3;
                while (mstart > anchor && mstart - off > lowest && buf[mstart - 1] == buf[mstart - 1 - off]) {
                    mstart--;
                    matchLen++;
                }
                newOffset(off);
            }
            store.add(buf, anchor, mstart - anchor, offVal, matchLen);
            ip = mstart + matchLen;
            anchor = ip;
        }
        store.addLastLiterals(buf, anchor, end - anchor);
    }

    /**
     * Longest match for {@code buf[ip..]} among the chained positions;
     * returns its length (0 if below 4) and sets {@link #bestOffset}.
     */
    private int searchChain(final byte[] buf, final int ip, final int lowest, final int end) {
        final int[] head = hcHead;
        final int[] chain = hcChain;
        final int mask = hcMask;
        final int base = hcBase;
        final int hlog = shortLog;
        final int abs = ip + base;
        // link the positions not inserted yet, up to ip excluded
        for (int p = nextToUpdate; p < abs; p++) {
            final int h = hash5(buf, p - base, hlog);
            chain[p & mask] = head[h];
            head[h] = p + 1;
        }
        if (nextToUpdate < abs) nextToUpdate = abs;
        final int minAbs = Math.max(lowest + base, Math.max(abs - windowSize, abs - mask));
        int cand = head[hash5(buf, ip, hlog)] - 1;
        int attempts = 1 << params.searchLog;
        int best = 3;
        final int maxLen = end - ip;
        while (cand >= minAbs && attempts-- > 0) {
            final int ci = cand - base;
            if (buf[ci + best] == buf[ip + best] && read32(buf, ci) == read32(buf, ip)) {
                final int len = 4 + count(buf, ip + 4, ci + 4, end);
                if (len > best) {
                    best = len;
                    bestOffset = ip - ci;
                    if (len >= maxLen || len >= params.targetLength) break;
                }
            }
            cand = chain[cand & mask] - 1;
        }
        return best >= 4 ? best : 0;
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
