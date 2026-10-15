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
package be.stef.arcana.formats.dmg;

import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * Decoder of Apple Data Compression (ADC), the LZ77 variant of the old "UDCO"
 * disk images (chunk type 0x80000004), written from its public description.
 *
 * <p>Each instruction starts with one byte:</p>
 * <ul>
 * <li>1LLLLLLL: L + 1 literal bytes follow;</li>
 * <li>01LLLLLL DDDDDDDD DDDDDDDD: copy L + 4 bytes from D + 1 bytes back
 *     (16-bit big-endian distance);</li>
 * <li>00LLLLDD DDDDDDDD: copy L + 3 bytes from D + 1 bytes back (10-bit distance).</li>
 * </ul>
 *
 * @author Stef
 * @since 1.5
 */
public final class AdcDecoder {

    private AdcDecoder() {
    }

    /**
     * Decodes src[srcOff, srcOff + srcLen) into dst[0, dstLen).
     *
     * @return the number of bytes written (stops when the input or the output ends)
     */
    public static int decode(final byte[] src, final int srcOff, final int srcLen, final byte[] dst, final int dstLen) throws ArcanaCorruptedException {
        final int end = srcOff + srcLen;
        int sp = srcOff;
        int dp = 0;
        while (sp < end && dp < dstLen) {
            final int b = src[sp++] & 0xff;
            if ((b & 0x80) != 0) {
                final int n = (b & 0x7f) + 1;
                if (n > end - sp || n > dstLen - dp) throw new ArcanaCorruptedException("ADC literal run out of range");
                System.arraycopy(src, sp, dst, dp, n);
                sp += n;
                dp += n;
                continue;
            }
            final int n;
            final int dist;
            if ((b & 0x40) != 0) {
                if (end - sp < 2) throw new ArcanaCorruptedException("ADC data truncated");
                n = (b & 0x3f) + 4;
                dist = ((src[sp] & 0xff) << 8 | (src[sp + 1] & 0xff)) + 1;
                sp += 2;
            } else {
                if (end - sp < 1) throw new ArcanaCorruptedException("ADC data truncated");
                n = ((b >>> 2) & 0x0f) + 3;
                dist = ((b & 3) << 8 | (src[sp] & 0xff)) + 1;
                sp++;
            }
            if (dist > dp || n > dstLen - dp) throw new ArcanaCorruptedException("ADC match out of range");
            for (int i = 0; i < n; i++) dst[dp + i] = dst[dp + i - dist];
            dp += n;
        }
        return dp;
    }
}
