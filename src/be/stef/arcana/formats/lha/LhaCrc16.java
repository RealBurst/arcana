/*
 * Copyright 2025 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 */
package be.stef.arcana.formats.lha;

/**
 * CRC-16 implementation using the LHA/LZH polynomial (0xA001, i.e. reversed 0x8005).
 *
 * <p>Provides both a stateless API (static methods that take the running CRC as first
 * argument and return the updated value) and a stateful API (instance methods).</p>
 *
 * <p>Used by {@code LhaReader} (extractor) and {@code LhaWriter} (compressor).</p>
 *
 * @author Stef
 * @since 1.2
 */
public final class LhaCrc16 {

    private static final int[] TABLE = new int[256];

    static {
        for (int i = 0; i < 256; i++) {
            int crc = i;
            for (int j = 0; j < 8; j++) crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xA001 : crc >>> 1;
            TABLE[i] = crc;
        }
    }

    // =========================================================================
    // Stateless API (used by LhaReader)
    // =========================================================================

    /**
     * Updates a running CRC-16 with a single byte and returns the new CRC.
     *
     * @param crc current CRC value (0 to start)
     * @param b   byte value (only the low 8 bits are used)
     * @return updated CRC-16
     */
    public static int update(int crc, int b) {
        return TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8);
    }

    /**
     * Updates a running CRC-16 with a range of bytes and returns the new CRC.
     *
     * @param crc current CRC value (0 to start)
     * @param buf byte array
     * @param off start offset
     * @param len number of bytes
     * @return updated CRC-16
     */
    public static int update(int crc, byte[] buf, int off, int len) {
        for (int i = 0; i < len; i++) crc = TABLE[(crc ^ buf[off + i]) & 0xFF] ^ (crc >>> 8);
        return crc;
    }

    // =========================================================================
    // Stateful API (used by LhaWriter)
    // =========================================================================

    private int crc = 0;

    /** Creates a new CRC-16 accumulator with initial value 0. */
    public LhaCrc16() {}

    /** Updates the CRC with a single byte. */
    public void update(int b) { crc = TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8); }

    /** Updates the CRC with {@code len} bytes starting at {@code off}. */
    public void update(byte[] buf, int off, int len) { crc = update(crc, buf, off, len); }

    /** Returns the current 16-bit CRC value. */
    public int getValue() { return crc; }

    /** Resets the accumulator to 0. */
    public void reset() { crc = 0; }

    /** Computes the CRC-16 of the given byte range in a single call. */
    public static int compute(byte[] data, int off, int len) { return update(0, data, off, len); }
}