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
package be.stef.arcana.formats.rar.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Pure Java implementation of BLAKE2sp (BLAKE2s parallel, 8 leaves).
 *
 * <p>BLAKE2sp hashes input with 8 independent BLAKE2s leaf instances, then
 * combines their digests with a single BLAKE2s root node. Output: 32 bytes.
 * This mirrors the reference C implementation: data is consumed in 512-byte
 * super-blocks (8 leaves x 64-byte blocks); the trailing remainder is
 * distributed to the leaves at finalisation.</p>
 *
 * <p>Two usage modes are available:</p>
 * <ul>
 *   <li>One-shot: {@link #hash(File)} / {@link #verify(File, byte[])} - reads the whole file.</li>
 *   <li>Incremental: {@link Digest} - fed as bytes are produced, so no second
 *       pass over the data is needed.</li>
 * </ul>
 *
 * <p>Memory use is bounded and independent of input size in both modes.</p>
 *
 * @author Stef
 * @since 2.0.1
 */
public final class Blake2sp {

    private static final int DEGREE      = 8;
    private static final int DIGEST_LEN  = 32;
    private static final int BLOCK_SIZE  = 64;
    private static final int SUPER_BLOCK = DEGREE * BLOCK_SIZE; // 512

    private static final int[] IV = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final byte[][] SIGMA = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
        {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
        {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
        { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
        { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
        { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
        {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
        {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
        { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    };

    // -- Incremental digest -------------------------------------------------

    /**
     * Incremental BLAKE2sp accumulator.
     *
     * <p>Feed bytes with {@link #update(byte[], int, int)} as they are produced,
     * then read the result once with {@link #digest()}. This avoids re-reading
     * the data a second time, which matters for multi-gigabyte files.</p>
     *
     * <p>Not thread-safe: a single instance must be fed by one thread only.</p>
     */
    public static final class Digest {

        private final Blake2s[] leaf = new Blake2s[DEGREE];
        private final byte[] sb = new byte[SUPER_BLOCK];
        private int sbLen = 0;
        private byte[] result;

        /**
         * Creates a new empty accumulator.
         */
        public Digest() {
            for (int i = 0; i < DEGREE; i++) {
                leaf[i] = new Blake2s();
                initLeaf(leaf[i], i);
            }
            leaf[DEGREE - 1].lastNode = true;
        }

        /**
         * Feeds bytes into the accumulator.
         *
         * @param in  source buffer
         * @param off start offset in the buffer
         * @param len number of bytes to consume
         * @throws IllegalStateException if {@link #digest()} was already called
         */
        public void update(byte[] in, int off, int len) {
            if (result != null) {
                throw new IllegalStateException("digest() already called on this Digest");
            }
            while (len > 0) {
                int take = Math.min(SUPER_BLOCK - sbLen, len);
                System.arraycopy(in, off, sb, sbLen, take);
                sbLen += take;
                off   += take;
                len   -= take;
                if (sbLen == SUPER_BLOCK) {
                    for (int i = 0; i < DEGREE; i++) {
                        leaf[i].update(sb, i * BLOCK_SIZE, BLOCK_SIZE);
                    }
                    sbLen = 0;
                }
            }
        }

        /**
         * Finalises and returns the 32-byte digest. Subsequent calls return the
         * same value; no further {@link #update} is allowed after this.
         *
         * @return the 32-byte BLAKE2sp digest
         */
        public byte[] digest() {
            if (result == null) {
                // Distribute the trailing remainder across leaves, exactly as
                // the reference blake2sp_final does: leaf i gets up to 64 bytes
                // starting at i*64.
                for (int i = 0; i < DEGREE; i++) {
                    int start = i * BLOCK_SIZE;
                    if (sbLen > start) {
                        leaf[i].update(sb, start, Math.min(sbLen - start, BLOCK_SIZE));
                    }
                }
                byte[] leafDigests = new byte[DEGREE * DIGEST_LEN];
                for (int i = 0; i < DEGREE; i++) {
                    leaf[i].doFinal(leafDigests, i * DIGEST_LEN);
                }
                Blake2s root = new Blake2s();
                initRoot(root);
                root.lastNode = true;
                root.update(leafDigests, 0, leafDigests.length);
                result = new byte[DIGEST_LEN];
                root.doFinal(result, 0);
            }
            return result.clone();
        }

        /**
         * Compares the computed digest with an expected value.
         *
         * @param expected the expected 32-byte digest (may be null)
         * @return true if the digests match
         */
        public boolean matches(byte[] expected) {
            if (expected == null || expected.length != DIGEST_LEN) return false;
            return Arrays.equals(digest(), expected);
        }
    }

    // -- One-shot API -------------------------------------------------------

    /**
     * Computes the BLAKE2sp digest of a file.
     *
     * @param file the file to hash
     * @return the 32-byte digest
     * @throws IOException if the file cannot be read
     */
    public static byte[] hash(File file) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(file), 65536)) {
            return hash(in);
        }
    }

    /**
     * Computes the BLAKE2sp digest of a stream, consuming it to the end.
     *
     * @param in the stream to hash
     * @return the 32-byte digest
     * @throws IOException if the stream cannot be read
     */
    public static byte[] hash(InputStream in) throws IOException {
        Digest d = new Digest();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (n > 0) d.update(buf, 0, n);
        }
        return d.digest();
    }

    /**
     * Verifies a file against an expected BLAKE2sp digest.
     *
     * @param file         the file to verify
     * @param expectedHash the expected 32-byte digest
     * @return true if the digests match
     * @throws IOException if the file cannot be read
     */
    public static boolean verify(File file, byte[] expectedHash) throws IOException {
        if (expectedHash == null || expectedHash.length != DIGEST_LEN) return false;
        return Arrays.equals(hash(file), expectedHash);
    }

    // -- BLAKE2s single-instance state (leaf or root) -----------------------

    /**
     * A single BLAKE2s hashing state, mirroring the reference implementation's
     * update/final buffering semantics.
     */
    private static final class Blake2s {
        final int[]  h   = new int[8];
        final long[] t   = new long[2];   // 64-bit byte counter (t[0] low, t[1] high)
        final byte[] buf = new byte[BLOCK_SIZE];
        int     buflen   = 0;
        boolean lastNode = false;

        void incrementCounter(long inc) {
            t[0] += inc;
            if (t[0] < inc) t[1]++; // carry on unsigned overflow (rare)
        }

        /** Mirror of blake2s_update: note the strict {@code > BLOCK_SIZE} test. */
        void update(byte[] in, int off, int inlen) {
            if (inlen <= 0) return;
            int left = buflen;
            int fill = BLOCK_SIZE - left;
            if (inlen > fill) {
                buflen = 0;
                System.arraycopy(in, off, buf, left, fill);
                incrementCounter(BLOCK_SIZE);
                compress(this, buf, 0, false);
                off += fill; inlen -= fill;
                while (inlen > BLOCK_SIZE) {
                    incrementCounter(BLOCK_SIZE);
                    compress(this, in, off, false);
                    off += BLOCK_SIZE; inlen -= BLOCK_SIZE;
                }
            }
            System.arraycopy(in, off, buf, buflen, inlen);
            buflen += inlen;
        }

        /** Mirror of blake2s_final: pad the buffered remainder, compress as last block. */
        void doFinal(byte[] out, int outOff) {
            incrementCounter(buflen);
            Arrays.fill(buf, buflen, BLOCK_SIZE, (byte) 0);
            compress(this, buf, 0, true);
            for (int i = 0; i < 8; i++) {
                int word = h[i];
                out[outOff + i * 4]     = (byte)  word;
                out[outOff + i * 4 + 1] = (byte) (word >>> 8);
                out[outOff + i * 4 + 2] = (byte) (word >>> 16);
                out[outOff + i * 4 + 3] = (byte) (word >>> 24);
            }
        }
    }

    // -- Initialisation -----------------------------------------------------

    private static void initLeaf(Blake2s s, int leafIndex) {
        int p0 = 0x02080020; // depth=2 | fanout=8 | key_len=0 | digest_len=32
        int p1 = 0;
        int p2 = leafIndex;   // node_offset low
        int p3 = 0x20000000;  // inner_length=32 | node_depth=0
        xorIV(s.h, new int[]{ p0, p1, p2, p3, 0, 0, 0, 0 });
    }

    private static void initRoot(Blake2s s) {
        int p0 = 0x02080020;
        int p1 = 0;
        int p2 = 0;
        int p3 = 0x20010000;  // inner_length=32 | node_depth=1
        xorIV(s.h, new int[]{ p0, p1, p2, p3, 0, 0, 0, 0 });
    }

    private static void xorIV(int[] h, int[] param) {
        for (int i = 0; i < 8; i++) h[i] = IV[i] ^ param[i];
    }

    // -- BLAKE2s compression -------------------------------------------------

    private static void compress(Blake2s s, byte[] block, int off, boolean last) {
        int[] m = new int[16];
        for (int i = 0; i < 16; i++) {
            int base = off + i * 4;
            m[i] = (block[base]     & 0xFF)
                 | ((block[base+1] & 0xFF) <<  8)
                 | ((block[base+2] & 0xFF) << 16)
                 | ((block[base+3] & 0xFF) << 24);
        }

        int[] h = s.h;
        int v0=h[0], v1=h[1], v2=h[2],  v3=h[3];
        int v4=h[4], v5=h[5], v6=h[6],  v7=h[7];
        int v8=IV[0], v9=IV[1], v10=IV[2], v11=IV[3];
        int v12 = IV[4] ^ (int)  s.t[0];
        int v13 = IV[5] ^ (int)  s.t[1];
        int v14 = last                 ? ~IV[6] : IV[6];
        int v15 = (last && s.lastNode) ? ~IV[7] : IV[7];

        for (int round = 0; round < 10; round++) {
            byte[] sg = SIGMA[round];
            int x, y;
            x=m[sg[0]];  y=m[sg[1]];
            v0+=v4+x;  v12=Integer.rotateRight(v12^v0,16); v8+=v12;  v4=Integer.rotateRight(v4^v8,12);
            v0+=v4+y;  v12=Integer.rotateRight(v12^v0, 8); v8+=v12;  v4=Integer.rotateRight(v4^v8, 7);
            x=m[sg[2]];  y=m[sg[3]];
            v1+=v5+x;  v13=Integer.rotateRight(v13^v1,16); v9+=v13;  v5=Integer.rotateRight(v5^v9,12);
            v1+=v5+y;  v13=Integer.rotateRight(v13^v1, 8); v9+=v13;  v5=Integer.rotateRight(v5^v9, 7);
            x=m[sg[4]];  y=m[sg[5]];
            v2+=v6+x;  v14=Integer.rotateRight(v14^v2,16); v10+=v14; v6=Integer.rotateRight(v6^v10,12);
            v2+=v6+y;  v14=Integer.rotateRight(v14^v2, 8); v10+=v14; v6=Integer.rotateRight(v6^v10, 7);
            x=m[sg[6]];  y=m[sg[7]];
            v3+=v7+x;  v15=Integer.rotateRight(v15^v3,16); v11+=v15; v7=Integer.rotateRight(v7^v11,12);
            v3+=v7+y;  v15=Integer.rotateRight(v15^v3, 8); v11+=v15; v7=Integer.rotateRight(v7^v11, 7);
            x=m[sg[8]];  y=m[sg[9]];
            v0+=v5+x;  v15=Integer.rotateRight(v15^v0,16); v10+=v15; v5=Integer.rotateRight(v5^v10,12);
            v0+=v5+y;  v15=Integer.rotateRight(v15^v0, 8); v10+=v15; v5=Integer.rotateRight(v5^v10, 7);
            x=m[sg[10]]; y=m[sg[11]];
            v1+=v6+x;  v12=Integer.rotateRight(v12^v1,16); v11+=v12; v6=Integer.rotateRight(v6^v11,12);
            v1+=v6+y;  v12=Integer.rotateRight(v12^v1, 8); v11+=v12; v6=Integer.rotateRight(v6^v11, 7);
            x=m[sg[12]]; y=m[sg[13]];
            v2+=v7+x;  v13=Integer.rotateRight(v13^v2,16); v8+=v13;  v7=Integer.rotateRight(v7^v8,12);
            v2+=v7+y;  v13=Integer.rotateRight(v13^v2, 8); v8+=v13;  v7=Integer.rotateRight(v7^v8, 7);
            x=m[sg[14]]; y=m[sg[15]];
            v3+=v4+x;  v14=Integer.rotateRight(v14^v3,16); v9+=v14;  v4=Integer.rotateRight(v4^v9,12);
            v3+=v4+y;  v14=Integer.rotateRight(v14^v3, 8); v9+=v14;  v4=Integer.rotateRight(v4^v9, 7);
        }

        h[0]^=v0^v8;  h[1]^=v1^v9;  h[2]^=v2^v10; h[3]^=v3^v11;
        h[4]^=v4^v12; h[5]^=v5^v13; h[6]^=v6^v14; h[7]^=v7^v15;
    }

    private Blake2sp() {}
}