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
package be.stef.arcana.formats.lzfse;

import be.stef.arcana.exceptions.ArcanaCorruptedException;

/**
 * LZVN decoder (Apple's fast LZ77 codec, used inside LZFSE streams for small
 * blocks and by HFS+ / APFS transparent compression), written from the
 * description of the opcodes in Apple's reference LZFSE implementation
 * (github.com/lzfse/lzfse, BSD-3-Clause; no code copied).
 *
 * <p>The stream is a list of byte-aligned instructions. Each one may copy L
 * literal bytes (stored right after the opcode) then M bytes from D bytes back
 * in the output (D is kept from one instruction to the next):</p>
 * <ul>
 * <li>sml_d LLMMMDDD DDDDDDDD: L, M + 3, D (11 bits);</li>
 * <li>med_d 101LLMMM DDDDDDDD DDDDDDMM: L, M + 3 (5 bits), D (14 bits);</li>
 * <li>lrg_d LLMMM111 DDDDDDDD DDDDDDDD: L, M + 3, D (16 bits, little-endian);</li>
 * <li>pre_d LLMMM110: L, M + 3, previous D;</li>
 * <li>sml_l 1110LLLL / lrg_l 11100000 LLLLLLLL: L (lrg: L + 16) literals only;</li>
 * <li>sml_m 1111MMMM / lrg_m 11110000 MMMMMMMM: M (lrg: M + 16), previous D;</li>
 * <li>0x06: end of stream (followed by 7 zero bytes); 0x0E, 0x16: no-op;
 *     the other opcodes are undefined.</li>
 * </ul>
 *
 * @author Stef
 * @since 1.5
 */
public final class LzvnDecoder {

    private static final byte SML_D = 1;
    private static final byte MED_D = 2;
    private static final byte LRG_D = 3;
    private static final byte PRE_D = 4;
    private static final byte SML_L = 5;
    private static final byte LRG_L = 6;
    private static final byte SML_M = 7;
    private static final byte LRG_M = 8;
    private static final byte NOP = 9;
    private static final byte EOS = 10;
    private static final byte UDEF = 0;

    /** Instruction kind of every opcode byte. */
    private static final byte[] KIND = new byte[256];

    static {
        for (int opc = 0; opc < 256; opc++) {
            byte k;
            if (opc >= 0xF0) k = opc == 0xF0 ? LRG_M : SML_M;
            else if (opc >= 0xE0) k = opc == 0xE0 ? LRG_L : SML_L;
            else if (opc >= 0xD0) k = UDEF;
            else if (opc >= 0xA0 && opc < 0xC0) k = MED_D;
            else if (opc >= 0x70 && opc < 0x80) k = UDEF;
            else if ((opc & 7) == 7) k = LRG_D;
            else if ((opc & 7) == 6) k = opc == 0x06 ? EOS : opc == 0x0E || opc == 0x16 ? NOP : opc < 0x40 ? UDEF : PRE_D;
            else k = SML_D;
            KIND[opc] = k;
        }
    }

    private LzvnDecoder() {
    }

    /**
     * Decodes the LZVN stream src[srcPos, srcEnd) into dst[dstPos, dstEnd).
     * Matches may reach back to {@code dstBegin} (output of the previous
     * blocks of an LZFSE stream). Decoding stops at the end-of-stream opcode,
     * or when the output is full and the input is exhausted.
     *
     * @return the position in dst after the last byte written
     * @throws ArcanaCorruptedException on an invalid instruction, a distance
     *         out of range, a truncated stream or an output larger than dstEnd
     */
    public static int decode(final byte[] src, final int srcPos, final int srcEnd, final byte[] dst, final int dstBegin, final int dstPos, final int dstEnd) throws ArcanaCorruptedException {
        int sp = srcPos;
        int dp = dstPos;
        int d = 0;
        while (true) {
            if (sp >= srcEnd) {
                if (dp == dstEnd) return dp; // some writers end exactly at the output size, without opcode 0x06
                throw new ArcanaCorruptedException("LZVN stream truncated");
            }
            final int opc = src[sp] & 0xff;
            int l = 0;
            int m = 0;
            switch (KIND[opc]) {
                case SML_D:
                    need(sp + 2, srcEnd);
                    l = opc >>> 6;
                    m = ((opc >>> 3) & 7) + 3;
                    d = (opc & 7) << 8 | (src[sp + 1] & 0xff);
                    sp += 2;
                    break;
                case MED_D: {
                    need(sp + 3, srcEnd);
                    final int w = (src[sp + 1] & 0xff) | (src[sp + 2] & 0xff) << 8;
                    l = (opc >>> 3) & 3;
                    m = ((opc & 7) << 2 | (w & 3)) + 3;
                    d = w >>> 2;
                    sp += 3;
                    break;
                }
                case LRG_D:
                    need(sp + 3, srcEnd);
                    l = opc >>> 6;
                    m = ((opc >>> 3) & 7) + 3;
                    d = (src[sp + 1] & 0xff) | (src[sp + 2] & 0xff) << 8;
                    sp += 3;
                    break;
                case PRE_D:
                    l = opc >>> 6;
                    m = ((opc >>> 3) & 7) + 3;
                    sp++;
                    break;
                case SML_L:
                    l = opc & 15;
                    sp++;
                    break;
                case LRG_L:
                    need(sp + 2, srcEnd);
                    l = (src[sp + 1] & 0xff) + 16;
                    sp += 2;
                    break;
                case SML_M:
                    m = opc & 15;
                    sp++;
                    break;
                case LRG_M:
                    need(sp + 2, srcEnd);
                    m = (src[sp + 1] & 0xff) + 16;
                    sp += 2;
                    break;
                case NOP:
                    sp++;
                    continue;
                case EOS:
                    return dp;
                default:
                    throw new ArcanaCorruptedException("Invalid LZVN opcode 0x" + Integer.toHexString(opc));
            }
            if (l > 0) {
                need(sp + l, srcEnd);
                if (l > dstEnd - dp) throw new ArcanaCorruptedException("LZVN output larger than expected");
                System.arraycopy(src, sp, dst, dp, l);
                sp += l;
                dp += l;
            }
            if (m > 0) {
                if (d <= 0 || d > dp - dstBegin) throw new ArcanaCorruptedException("Invalid LZVN match distance " + d);
                if (m > dstEnd - dp) throw new ArcanaCorruptedException("LZVN output larger than expected");
                for (int i = 0; i < m; i++) dst[dp + i] = dst[dp + i - d];
                dp += m;
            }
        }
    }

    private static void need(final int pos, final int end) throws ArcanaCorruptedException {
        if (pos > end) throw new ArcanaCorruptedException("LZVN stream truncated");
    }
}
