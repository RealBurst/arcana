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
package be.stef.arcana.formats.squashfs;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;

/**
 * LZO1X block decompressor (the format written by lzo1x_1 and lzo1x_999),
 * written from the description of the bitstream in the Linux kernel
 * documentation (Documentation/staging/lzo.rst).
 *
 * <p>Instructions, depending on the "state" (number of literals copied by
 * the previous instruction, 4 meaning "4 or more"):</p>
 * <ul>
 * <li>0000LLLL, state 0: literal run of 3 + L bytes (L = 0: extended length);</li>
 * <li>0000DDSS, state 1-3: copy 2 bytes, distance (H &lt;&lt; 2) + D + 1;</li>
 * <li>0000DDSS, state 4: copy 3 bytes, distance (H &lt;&lt; 2) + D + 2049;</li>
 * <li>0001HLLL: copy 2 + L bytes, distance 16384 + (H &lt;&lt; 14) + D (end of stream when 16384);</li>
 * <li>001LLLLL: copy 2 + L bytes, distance D + 1;</li>
 * <li>01LDDDSS: copy 3 + L bytes, distance (H &lt;&lt; 3) + D + 1;</li>
 * <li>1LLDDDSS: copy 5 + L bytes, distance (H &lt;&lt; 3) + D + 1.</li>
 * </ul>
 * <p>SS gives the number of literals that follow the instruction.</p>
 *
 * @author Stef
 * @since 1.0.3
 */
public final class Lzo1xDecompressor {

    private Lzo1xDecompressor() {
    }

    /**
     * Decompresses src[srcOff, srcOff + srcLen) into dst.
     *
     * @return the number of bytes written to dst
     */
    public static int decompress(final byte[] src, final int srcOff, final int srcLen, final byte[] dst) throws IOException {
        final int end = srcOff + srcLen;
        int ip = srcOff;
        int op = 0;
        int state = 0;
        try {
            if (ip < end && (src[ip] & 0xff) > 17) {
                final int first = (src[ip++] & 0xff) - 17;
                op = literals(src, ip, dst, op, first);
                ip += first;
                state = first < 4 ? first : 4;
            }
            while (true) {
                if (ip >= end) throw new ArcanaCorruptedException("LZO stream truncated");
                final int t = src[ip++] & 0xff;
                int length;
                int distance;
                int next;
                if (t < 16) {
                    if (state == 0) {
                        // literal run
                        length = t;
                        if (length == 0) {
                            length = 15;
                            while (src[ip] == 0) {
                                length += 255;
                                ip++;
                            }
                            length += src[ip++] & 0xff;
                        }
                        length += 3;
                        op = literals(src, ip, dst, op, length);
                        ip += length;
                        state = 4;
                        continue;
                    }
                    final int h = src[ip++] & 0xff;
                    next = t & 3;
                    if (state == 4) {
                        length = 3;
                        distance = (h << 2) + ((t >> 2) & 3) + 2049;
                    } else {
                        length = 2;
                        distance = (h << 2) + ((t >> 2) & 3) + 1;
                    }
                } else if (t < 32) {
                    length = t & 7;
                    if (length == 0) {
                        length = 7;
                        while (src[ip] == 0) {
                            length += 255;
                            ip++;
                        }
                        length += src[ip++] & 0xff;
                    }
                    length += 2;
                    final int le16 = (src[ip] & 0xff) | (src[ip + 1] & 0xff) << 8;
                    ip += 2;
                    distance = 16384 + ((t & 8) << 11) + (le16 >> 2);
                    next = le16 & 3;
                    if (distance == 16384) return op; // end of stream
                } else if (t < 64) {
                    length = t & 31;
                    if (length == 0) {
                        length = 31;
                        while (src[ip] == 0) {
                            length += 255;
                            ip++;
                        }
                        length += src[ip++] & 0xff;
                    }
                    length += 2;
                    final int le16 = (src[ip] & 0xff) | (src[ip + 1] & 0xff) << 8;
                    ip += 2;
                    distance = (le16 >> 2) + 1;
                    next = le16 & 3;
                } else if (t < 128) {
                    length = 3 + ((t >> 5) & 1);
                    distance = ((src[ip++] & 0xff) << 3) + ((t >> 2) & 7) + 1;
                    next = t & 3;
                } else {
                    length = 5 + ((t >> 5) & 3);
                    distance = ((src[ip++] & 0xff) << 3) + ((t >> 2) & 7) + 1;
                    next = t & 3;
                }
                if (distance > op) throw new ArcanaCorruptedException("LZO match before the start of the output");
                if (op + length > dst.length) throw new ArcanaCorruptedException("LZO output overflow");
                for (int i = 0; i < length; i++, op++) dst[op] = dst[op - distance];
                op = literals(src, ip, dst, op, next);
                ip += next;
                state = next;
            }
        } catch (final ArrayIndexOutOfBoundsException e) {
            throw new ArcanaCorruptedException("LZO stream corrupted", e);
        }
    }

    private static int literals(final byte[] src, final int ip, final byte[] dst, final int op, final int n) throws IOException {
        if (n == 0) return op;
        if (op + n > dst.length) throw new ArcanaCorruptedException("LZO output overflow");
        System.arraycopy(src, ip, dst, op, n);
        return op + n;
    }
}
