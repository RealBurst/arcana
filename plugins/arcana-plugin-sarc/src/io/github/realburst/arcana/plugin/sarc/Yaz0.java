/*
 * Arcana plugin: Nintendo SARC archives (.sarc, .pack, .szs...).
 * Licensed under the Apache License, Version 2.0.
 */
package io.github.realburst.arcana.plugin.sarc;

import java.io.IOException;

/**
 * Yaz0 decompression (Nintendo, .szs and other Yaz0 files): "Yaz0",
 * decompressed size (32 bits big-endian), 8 reserved bytes, then groups of a
 * flag byte (bits from the highest: 1 = one literal byte, 0 = a copy) and
 * their items. A copy is 2 bytes "NR RR": distance = 0xRRR + 1, length = N + 2,
 * or, when N is 0, a third byte gives length = byte + 0x12.
 */
public final class Yaz0 {

    /** Largest decompressed size accepted (the data is decoded in memory). */
    public static final int MAX_SIZE = Integer.MAX_VALUE - 64;

    private Yaz0() {}

    /** True if {@code b} starts with the Yaz0 magic. */
    public static boolean is(final byte[] b) {
        return b.length >= 16 && b[0] == 'Y' && b[1] == 'a' && b[2] == 'z' && b[3] == '0';
    }

    /** Decompressed size given by the header. */
    public static long size(final byte[] b) {
        return ((b[4] & 0xFFL) << 24) | ((b[5] & 0xFF) << 16) | ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
    }

    /** Decompresses a whole Yaz0 file. */
    public static byte[] decompress(final byte[] in) throws IOException {
        if (!is(in)) throw new IOException("Not a Yaz0 file");
        final long size = size(in);
        if (size > MAX_SIZE) throw new IOException("Yaz0 data too large: " + size + " bytes");
        final byte[] out = new byte[(int) size];
        int ip = 16;
        int op = 0;
        while (op < out.length) {
            if (ip >= in.length) throw new IOException("Yaz0 data truncated");
            final int flags = in[ip++] & 0xFF;
            for (int bit = 0x80; bit != 0 && op < out.length; bit >>>= 1) {
                if ((flags & bit) != 0) {
                    if (ip >= in.length) throw new IOException("Yaz0 data truncated");
                    out[op++] = in[ip++];
                    continue;
                }
                if (ip + 2 > in.length) throw new IOException("Yaz0 data truncated");
                final int b1 = in[ip++] & 0xFF;
                final int b2 = in[ip++] & 0xFF;
                final int dist = (((b1 & 0x0F) << 8) | b2) + 1;
                int len = b1 >>> 4;
                if (len == 0) {
                    if (ip >= in.length) throw new IOException("Yaz0 data truncated");
                    len = (in[ip++] & 0xFF) + 0x12;
                } else {
                    len += 2;
                }
                if (dist > op) throw new IOException("Corrupted Yaz0 data (copy before the start at " + op + ")");
                if (len > out.length - op) len = out.length - op;
                for (int k = 0; k < len; k++, op++) out[op] = out[op - dist];
            }
        }
        return out;
    }
}
