/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.cab;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Decompresses a CFDATA block compressed with MSZIP (Cabinet compression type 0x0001).
 *
 * <p>MSZIP block format: bytes 0-1 are the signature "CK" (0x43 0x4B),
 * followed by raw DEFLATE data ({@code nowrap=true}). Each block is
 * decompressed independently.</p>
 *
 * @author Stef
 * @since 1.3
 */
final class MszipDecoder {

    private MszipDecoder() {}

    /**
     * Decompresses one MSZIP-encoded CFDATA block.
     *
     * @param compressed    the compressed bytes including the "CK" signature
     * @param compressedLen number of valid bytes in {@code compressed}
     * @param output        destination buffer
     * @param uncompLen     expected number of decompressed bytes
     * @param history       uncompressed output of the previous block of the same folder, or null for
     *                      the first block. MS-ZIP keeps the deflate history across blocks, so a block
     *                      may reference up to 32 KB of the previous one (makecab relies on this).
     * @throws IOException if the data is not valid MSZIP
     */
    static void decompress(byte[] compressed, int compressedLen, byte[] output, int uncompLen, byte[] history) throws IOException {
        if (compressedLen < 2 || (compressed[0] & 0xFF) != 0x43 || (compressed[1] & 0xFF) != 0x4B) {
            throw new IOException("CAB: missing MSZIP 'CK' signature in CFDATA block");
        }
        Inflater inf = new Inflater(true);
        try {
            if (history != null && history.length > 0) inf.setDictionary(history);
            inf.setInput(compressed, 2, compressedLen - 2);
            int n = inf.inflate(output, 0, uncompLen);
            if (n != uncompLen) throw new IOException("CAB: MSZIP decompressed " + n + " bytes, expected " + uncompLen);
        } catch (DataFormatException e) {
            throw new IOException("CAB: MSZIP decompression error: " + e.getMessage(), e);
        } finally {
            inf.end();
        }
    }
}
