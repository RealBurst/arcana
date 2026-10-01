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
package be.stef.arcana.formats.bzip2;

import java.util.Arrays;

/**
 * Burrows-Wheeler block sort for the bzip2 encoder, in linear time.
 *
 * <p>bzip2 sorts the n cyclic rotations of a block. Since 1.3 they are obtained
 * from the suffix array of a single copy of the block (instead of the block
 * doubled), which halves the work:</p>
 * <ol>
 *   <li>the primitive root {@code u} of the block is found ({@code block = u^m},
 *       m = 1 for almost every real block), with the KMP failure function;</li>
 *   <li>{@code u} is rotated to its smallest rotation, which is a Lyndon word
 *       (u is primitive);</li>
 *   <li>for a Lyndon word, the order of the rotations is the order of the
 *       suffixes (with a smallest sentinel appended): one SA-IS pass on
 *       {@code |u| + 1} symbols gives it;</li>
 *   <li>indexes are shifted back, and each rotation of {@code u} stands for its
 *       m equal rotations of the block.</li>
 * </ol>
 * <p>The suffix array is built with SA-IS (Nong, Zhang, Chan 2009), O(n) whatever
 * the data.</p>
 *
 * <p>Working arrays are kept between blocks to avoid reallocating them per block.</p>
 *
 * @author Stef
 * @since 1.3
 */
final class BZip2BlockSort {

    private int[] text = new int[0];
    private int[] sa = new int[0];

    /**
     * Sorts the rotations of {@code block[0..n)} (values 0..255).
     *
     * @param fmap receives the start index of each rotation in sorted order
     * @return origPtr, the rank of the rotation starting at 0
     */
    int sort(final int[] block, final int n, final int[] fmap) {
        if (n == 1) {
            fmap[0] = 0;
            return 0;
        }
        if (text.length < n + 1) {
            text = new int[n + 1];
            sa = new int[n + 1];
        }
        // 1. primitive root length p (block = u^(n/p)); text[] is used as the KMP table
        final int p = primitiveRootLength(block, n, text);
        // 2. start of the smallest rotation of u (a Lyndon word)
        final int k = leastRotation(block, p);
        // 3. suffix array of the rotated root + sentinel
        for (int i = 0, j = k; i < p; i++) {
            text[i] = (block[j] & 0xFF) + 1;
            if (++j == p) j = 0;
        }
        text[p] = 0; // unique smallest sentinel
        sais(text, sa, p + 1, 257);
        // 4. back to block indexes; sa[0] is the sentinel
        final int m = n / p;
        int out = 0;
        int origPtr = -1;
        for (int i = 1; i <= p; i++) {
            int r = sa[i] + k;
            if (r >= p) r -= p;
            for (int c = 0; c < m; c++) {
                final int pos = r + c * p;
                if (pos == 0) origPtr = out;
                fmap[out++] = pos;
            }
        }
        return origPtr;
    }

    /** Smallest p such that block = u^(n/p) with |u| = p (n itself if the block is primitive). */
    static int primitiveRootLength(final int[] s, final int n, final int[] fail) {
        fail[0] = 0;
        int k = 0;
        for (int i = 1; i < n; i++) {
            while (k > 0 && (s[i] & 0xFF) != (s[k] & 0xFF)) k = fail[k - 1];
            if ((s[i] & 0xFF) == (s[k] & 0xFF)) k++;
            fail[i] = k;
        }
        final int p = n - fail[n - 1];
        return n % p == 0 ? p : n;
    }

    /** Start index of the lexicographically smallest rotation of s[0..p) (minimum expression, O(p)). */
    static int leastRotation(final int[] s, final int p) {
        int i = 0, j = 1, k = 0;
        while (i < p && j < p && k < p) {
            int x = i + k;
            if (x >= p) x -= p;
            int y = j + k;
            if (y >= p) y -= p;
            final int a = s[x] & 0xFF;
            final int b = s[y] & 0xFF;
            if (a == b) {
                k++;
            } else {
                if (a > b) i += k + 1;
                else j += k + 1;
                if (i == j) j++;
                k = 0;
            }
        }
        return Math.min(i, j);
    }

    // ---- SA-IS -----------------------------------------------------------

    private static void getBuckets(final int[] s, final int n, final int[] bkt, final int k, final boolean end) {
        Arrays.fill(bkt, 0, k, 0);
        for (int i = 0; i < n; i++) bkt[s[i]]++;
        int sum = 0;
        for (int i = 0; i < k; i++) {
            sum += bkt[i];
            bkt[i] = end ? sum : sum - bkt[i];
        }
    }

    private static boolean isLms(final boolean[] t, final int i) {
        return i > 0 && t[i] && !t[i - 1];
    }

    private static void induceL(final boolean[] t, final int[] sa, final int[] s, final int n, final int[] bkt, final int k) {
        getBuckets(s, n, bkt, k, false);
        for (int i = 0; i < n; i++) {
            final int j = sa[i] - 1;
            if (j >= 0 && !t[j]) sa[bkt[s[j]]++] = j;
        }
    }

    private static void induceS(final boolean[] t, final int[] sa, final int[] s, final int n, final int[] bkt, final int k) {
        getBuckets(s, n, bkt, k, true);
        for (int i = n - 1; i >= 0; i--) {
            final int j = sa[i] - 1;
            if (j >= 0 && t[j]) sa[--bkt[s[j]]] = j;
        }
    }

    /**
     * Suffix array of {@code s[0..n)} over alphabet [0, k); {@code s[n-1]} must be
     * the unique smallest symbol (sentinel).
     */
    static void sais(final int[] s, final int[] sa, final int n, final int k) {
        final boolean[] t = new boolean[n]; // true = S-type
        t[n - 1] = true;
        for (int i = n - 2; i >= 0; i--) t[i] = s[i] < s[i + 1] || (s[i] == s[i + 1] && t[i + 1]);

        final int[] bkt = new int[k];

        // Stage 1: sort the LMS substrings
        getBuckets(s, n, bkt, k, true);
        Arrays.fill(sa, 0, n, -1);
        for (int i = 1; i < n; i++) if (isLms(t, i)) sa[--bkt[s[i]]] = i;
        induceL(t, sa, s, n, bkt, k);
        induceS(t, sa, s, n, bkt, k);

        // Compact the sorted LMS substrings into the first n1 slots
        int n1 = 0;
        for (int i = 0; i < n; i++) if (isLms(t, sa[i])) sa[n1++] = sa[i];

        // Name the LMS substrings
        Arrays.fill(sa, n1, n, -1);
        int name = 0;
        int prev = -1;
        for (int i = 0; i < n1; i++) {
            final int pos = sa[i];
            boolean diff = false;
            for (int d = 0; d < n; d++) {
                if (prev == -1 || s[pos + d] != s[prev + d] || t[pos + d] != t[prev + d]) {
                    diff = true;
                    break;
                } else if (d > 0 && (isLms(t, pos + d) || isLms(t, prev + d))) {
                    break;
                }
            }
            if (diff) {
                name++;
                prev = pos;
            }
            sa[n1 + (pos >> 1)] = name - 1;
        }
        for (int i = n - 1, j = n - 1; i >= n1; i--) if (sa[i] >= 0) sa[j--] = sa[i];

        // Stage 2: sort the reduced problem (recursively if names are not unique)
        final int[] s1 = new int[n1];
        System.arraycopy(sa, n - n1, s1, 0, n1);
        final int[] sa1 = new int[n1];
        if (name < n1) {
            sais(s1, sa1, n1, name);
        } else {
            for (int i = 0; i < n1; i++) sa1[s1[i]] = i;
        }

        // Stage 3: induce the final suffix array from the sorted LMS suffixes
        getBuckets(s, n, bkt, k, true);
        for (int i = 1, j = 0; i < n; i++) if (isLms(t, i)) s1[j++] = i; // s1 = LMS positions
        for (int i = 0; i < n1; i++) sa1[i] = s1[sa1[i]];
        Arrays.fill(sa, 0, n, -1);
        for (int i = n1 - 1; i >= 0; i--) {
            final int j = sa1[i];
            sa[--bkt[s[j]]] = j;
        }
        induceL(t, sa, s, n, bkt, k);
        induceS(t, sa, s, n, bkt, k);
    }
}
