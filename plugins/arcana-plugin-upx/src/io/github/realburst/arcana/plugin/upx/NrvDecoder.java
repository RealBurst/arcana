/*
 * NRV2B/NRV2D/NRV2E decoder adapted from the UCL 1.03 algorithms used by UPX.
 * Copyright (C) 1996-2004 Markus Franz Xaver Johannes Oberhumer.
 * Copyright 2026 Stephane Bury (Java adaptation).
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Reference: UPX v5.2.1 vendor/ucl/src/n2{b,d,e}_d.c, getbit.h.
 */
package io.github.realburst.arcana.plugin.upx;

import java.io.IOException;

final class NrvDecoder {
    private final byte[] src;
    private int pos, bits, count, b8;
    private final int width;

    private NrvDecoder(byte[] src, int width) { this.src = src; this.width = width; }

    static byte[] decode(byte[] src, int size, int method) throws IOException {
        int kind = (method - 2) / 3;
        int variant = (method - 2) % 3;
        if (kind < 0 || kind > 2 || variant < 0) throw new IOException("Unsupported NRV method: " + method);
        NrvDecoder r = new NrvDecoder(src, variant == 0 ? 32 : variant == 1 ? 8 : 16);
        byte[] dst = new byte[size];
        int out = 0, last = 1;
        long steps = 0, maxSteps = Math.max(10000L, 32L * size + src.length * 16L);
        while (true) {
            if (++steps > maxSteps) throw new IOException("NRV stream exceeded the step limit");
            while (r.bit() != 0) {
                if (out >= size) throw new IOException("NRV: output exceeds expected size");
                dst[out++] = (byte) r.read();
            }
            long off = 1;
            if (kind == 0) {
                do {
                    off = off * 2 + r.bit();
                    if (off > 0x1000002L) throw new IOException("NRV: invalid match distance");
                } while (r.bit() == 0);
            } else {
                while (true) {
                    off = off * 2 + r.bit();
                    if (off > 0x1000002L) throw new IOException("NRV: invalid match distance");
                    if (r.bit() != 0) break;
                    off = (off - 1) * 2 + r.bit();
                }
            }
            long len;
            if (off == 2) {
                off = last;
                len = kind == 0 ? 0 : r.bit();
            } else {
                off = (off - 3) * 256 + r.read();
                if (off == 0xffffffffL) break;
                if (kind == 0) {
                    off++;
                    len = 0;
                } else {
                    len = (~off) & 1;
                    off = (off >>> 1) + 1;
                }
                last = (int) off;
            }
            if (kind == 0) {
                len = r.bit() * 2 + r.bit();
                if (len == 0) len = r.longLength(1, 2, size);
                len += off > 0xd00 ? 1 : 0;
            } else if (kind == 1) {
                len = len * 2 + r.bit();
                if (len == 0) len = r.longLength(1, 2, size);
                len += off > 0x500 ? 1 : 0;
            } else {
                if (len != 0) len = 1 + r.bit();
                else if (r.bit() != 0) len = 3 + r.bit();
                else len = r.longLength(1, 3, size);
                len += off > 0x500 ? 1 : 0;
            }
            long copies = len + 1;
            if (off <= 0 || off > out || copies > size - out)
                throw new IOException("NRV: invalid match offset or length");
            for (int i = 0; i < copies; ++i) { dst[out] = dst[out - (int)off]; ++out; }
        }
        if (out != size || r.pos != src.length)
            throw new IOException("NRV: incorrect output size or input consumption");
        return dst;
    }

    private long longLength(long initial, int extra, int limit) throws IOException {
        long n = initial;
        do {
            n = n * 2 + bit();
            if (n > limit) throw new IOException("NRV: match length exceeds limit");
        } while (bit() == 0);
        return n + extra;
    }

    private int read() throws IOException {
        if (pos >= src.length) throw new IOException("NRV: truncated input");
        return src[pos++] & 255;
    }

    private int bit() throws IOException {
        if (width == 8) {
            if ((b8 & 0x7f) != 0) b8 *= 2;
            else b8 = read() * 2 + 1;
            return (b8 >>> 8) & 1;
        }
        if (width == 16) {
            bits *= 2;
            if ((bits & 0xffff) == 0) bits = (read() | read() << 8) * 2 + 1;
            return (bits >>> 16) & 1;
        }
        if (count == 0) {
            bits = read() | read() << 8 | read() << 16 | read() << 24;
            count = 32;
        }
        return (bits >>> --count) & 1;
    }
}
