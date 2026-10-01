/*
 * Copyright 2026 Stephane Bury and contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * UPX framing reference: UPX 5.2.1 src/compress/compress_lzma.cpp.
 */
package io.github.realburst.arcana.plugin.upx;

import be.stef.arcana.formats.xz.LZMAInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/** Adapts UPX's two-byte LZMA properties to Arcana's raw LZMA decoder. */
final class UpxLzmaDecoder {
    private UpxLzmaDecoder() { }

    static byte[] decode(byte[] compressed, int size) throws IOException {
        if (compressed.length < 3 || size <= 0) {
            throw new IOException("Truncated UPX LZMA block");
        }
        int first = compressed[0] & 255, second = compressed[1] & 255;
        int pb = first & 7, lp = second >>> 4, lc = second & 15;
        if (pb > 4 || lp > 4 || lc > 8 || (first >>> 3) != lc + lp) {
            throw new IOException("Invalid UPX LZMA properties");
        }
        // UPX does not store the encoder's dictionary size. An output-sized
        // dictionary can represent every backward reference in this block.
        ByteArrayInputStream raw = new ByteArrayInputStream(compressed, 2, compressed.length - 2);
        byte[] decoded = new byte[size];
        try (LZMAInputStream stream = new LZMAInputStream(raw, size, lc, lp, pb, size, null)) {
            int pos = 0;
            while (pos < decoded.length) {
                int n = stream.read(decoded, pos, decoded.length - pos);
                if (n < 0) throw new IOException("Truncated UPX LZMA output");
                pos += n;
            }
            if (stream.read() != -1 || raw.available() != 0) {
                throw new IOException("UPX LZMA block has trailing data");
            }
        }
        return decoded;
    }
}
