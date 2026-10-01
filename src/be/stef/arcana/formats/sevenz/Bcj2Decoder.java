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
/* Ported from the LZMA SDK's Bcj2.c (BCJ2 Decoder, Converter for x86 code),
 * Igor Pavlov, public domain. Reimplemented in a clear, non-optimized form
 * (the original C source uses branchless bit-twiddling for speed) by
 * Stephane Bury (2025), and validated against real archives produced by the
 * reference 7-Zip encoder (7z 23.01) before being ported here. */
package be.stef.arcana.formats.sevenz;

import be.stef.arcana.util.IOHelper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Decoder for the BCJ2 filter (7z method id 03 03 01 1B), the 4-stream
 * branch converter for 32-bit x86 executables used by 7-Zip.
 *
 * <p>Unlike the simple, single-stream BCJ x86 filter ({@link BCJDecoder} via
 * {@code X86Options}), BCJ2 splits its input into four separate streams:</p>
 * <ul>
 *   <li><b>MAIN</b>  -- the bulk of the code, with CALL/JMP/Jcc operands
 *       stripped out, opcode byte(s) left in place</li>
 *   <li><b>CALL</b>  -- the absolute target addresses for {@code E8} (CALL)
 *       instructions, as 4-byte big-endian values</li>
 *   <li><b>JUMP</b>  -- the absolute target addresses for {@code E9} (JMP)
 *       and {@code 0F 8x} (Jcc near) instructions, as 4-byte big-endian
 *       values</li>
 *   <li><b>RC</b>    -- a range-coded control bit per CALL/JMP/Jcc opcode
 *       candidate found in MAIN, saying whether that occurrence was really
 *       converted (and so has an entry in CALL/JUMP) or left as a literal
 *       false positive</li>
 * </ul>
 *
 * <p>This implementation buffers all four input streams and the decoded
 * output fully in memory, which is simple and safe given that BCJ2 is only
 * ever applied to individual folder entries (typically an executable of at
 * most a few hundred MB) -- never to an entire archive.</p>
 *
 * @author Stef
 * @since 1.1
 */
final class Bcj2Decoder {

    private static final int K_TOP_VALUE = 1 << 24;
    private static final int K_NUM_MODEL_BITS = 11;
    private static final int K_BIT_MODEL_TOTAL = 1 << K_NUM_MODEL_BITS;
    private static final int K_NUM_MOVE_BITS = 5;

    /** 258 probability contexts: 0 = Jcc (0F 8x), 1 = JMP (E9), 2..257 = CALL (E8) keyed by preceding byte. */
    private static final int NUM_PROBS = 258;

    private Bcj2Decoder() {
    }

    /**
     * Decodes a BCJ2-filtered stream given its four component input streams.
     *
     * @param main       the MAIN stream (streams[0] of the coder)
     * @param call       the CALL stream (streams[1] of the coder)
     * @param jump       the JUMP stream (streams[2] of the coder)
     * @param rc         the RC (range coder control) stream (streams[3] of the coder)
     * @param outputSize the exact number of decoded bytes to produce
     * @return an InputStream over the fully decoded output
     * @throws IOException if any input stream ends prematurely or the RC stream is malformed
     */
    static InputStream decode(final InputStream main, final InputStream call, final InputStream jump, final InputStream rc, final long outputSize)
            throws IOException {
        final byte[] mainBytes = IOHelper.readFully(main);
        final byte[] callBytes = IOHelper.readFully(call);
        final byte[] jumpBytes = IOHelper.readFully(jump);
        final byte[] rcBytes = IOHelper.readFully(rc);
        final byte[] out = decode(mainBytes, callBytes, jumpBytes, rcBytes, outputSize);
        return new ByteArrayInputStream(out);
    }

    /**
     * Core BCJ2 decode algorithm, operating on fully-buffered byte arrays.
     */
    static byte[] decode(final byte[] main, final byte[] call, final byte[] jump, final byte[] rc, final long outputSize) throws IOException {
        if (outputSize < 0 || outputSize > Integer.MAX_VALUE) {
            throw new IOException("Invalid BCJ2 output size: " + outputSize);
        }
        final int outSize = (int) outputSize;
        final int[] probs = new int[NUM_PROBS];
        for (int i = 0; i < NUM_PROBS; i++) {
            probs[i] = K_BIT_MODEL_TOTAL >> 1;
        }

        int mp = 0; // position in main
        int cp = 0; // position in call
        int jp = 0; // position in jump
        int rp = 0; // position in rc

        // --- Range decoder init: read 5 bytes; the first must effectively be 0 ---
        if (rc.length < 5) {
            throw new IOException("BCJ2 RC stream too short (expected at least 5 bytes)");
        }
        long code = 0;
        for (int i = 0; i < 5; i++) {
            code = ((code << 8) | (rc[rp++] & 0xffL)) & 0xffffffffL;
        }
        long range = 0xffffffffL;

        final byte[] out = new byte[outSize];
        int outPos = 0;
        long ip = 0; // number of bytes emitted so far, used for relative<->absolute conversion
        int prevByte = 0;

        while (outPos < outSize) {
            if (mp >= main.length) {
                throw new IOException("BCJ2 MAIN stream exhausted before producing the expected output size");
            }
            final int b = main[mp++] & 0xff;
            out[outPos++] = (byte) b;
            ip++;

            final boolean isTriggerSingle = (b == 0xE8 || b == 0xE9);
            final boolean isTriggerJcc = (prevByte == 0x0F && b >= 0x80 && b <= 0x8F);
            if (!(isTriggerSingle || isTriggerJcc)) {
                prevByte = b;
                continue;
            }
            if (outPos >= outSize) {
                // Trigger byte was the very last byte of output: no room for an
                // operand even if one were coded. Nothing more to do.
                break;
            }

            final int probIndex;
            if (b == 0xE8) {
                probIndex = 2 + prevByte;
            } else if (isTriggerJcc) {
                probIndex = 0;
            } else {
                probIndex = 1;
            }

            // --- range-decode one bit using probs[probIndex] ---
            if (range < K_TOP_VALUE) {
                if (rp >= rc.length) {
                    throw new IOException("BCJ2 RC stream exhausted");
                }
                range = (range << 8) & 0xffffffffL;
                code = ((code << 8) | (rc[rp++] & 0xffL)) & 0xffffffffL;
            }
            final int ttt = probs[probIndex];
            final long bound = (range >>> K_NUM_MODEL_BITS) * ttt;
            final int bit;
            if (code < bound) {
                range = bound;
                probs[probIndex] = ttt + ((K_BIT_MODEL_TOTAL - ttt) >>> K_NUM_MOVE_BITS);
                bit = 0;
            } else {
                range = (range - bound) & 0xffffffffL;
                code = (code - bound) & 0xffffffffL;
                probs[probIndex] = ttt - (ttt >>> K_NUM_MOVE_BITS);
                bit = 1;
            }

            if (bit == 0) {
                // False positive: leave as literal, byte already copied.
                prevByte = b;
                continue;
            }

            // Converted: read 4 bytes (big-endian absolute address) from CALL or JUMP.
            final long absolute;
            if (b == 0xE8) {
                if (cp + 4 > call.length) {
                    throw new IOException("BCJ2 CALL stream exhausted");
                }
                absolute = readBe32(call, cp);
                cp += 4;
            } else {
                if (jp + 4 > jump.length) {
                    throw new IOException("BCJ2 JUMP stream exhausted");
                }
                absolute = readBe32(jump, jp);
                jp += 4;
            }

            final long destIp = ip + 4;
            final long relative = (absolute - destIp) & 0xffffffffL;
            ip = destIp;

            // Write 4 bytes little-endian, truncating at outSize if necessary.
            long v = relative;
            for (int k = 0; k < 4 && outPos < outSize; k++) {
                out[outPos++] = (byte) (v & 0xff);
                v >>>= 8;
            }
            prevByte = (int) ((relative >>> 24) & 0xff);
        }

        return out;
    }

    private static long readBe32(final byte[] buf, final int off) {
        return ((buf[off] & 0xffL) << 24) | ((buf[off + 1] & 0xffL) << 16) | ((buf[off + 2] & 0xffL) << 8) | (buf[off + 3] & 0xffL);
    }
}
