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
package be.stef.arcana.util;

/**
 * Low-level byte-manipulation utilities shared across all JUnpack decompressors.
 *
 * <p>All methods treat byte arrays as raw memory and perform no bounds checking
 * beyond what the JVM already enforces via {@link ArrayIndexOutOfBoundsException}.
 * Callers are responsible for ensuring that {@code offset + width <= data.length}.</p>
 *
 * <p>The "unsigned" read methods return the value as a wider signed Java type so
 * that the full unsigned range is preserved:</p>
 * <ul>
 *   <li>uint8  -> int   (0..255)</li>
 *   <li>uint16 -> int   (0..65535)</li>
 *   <li>uint32 -> long  (0..4294967295)</li>
 *   <li>uint64 -> long  (may overflow for values > Long.MAX_VALUE; use with care)</li>
 * </ul>
 *
 * @author Stef
 * @since 1.0
 */
public final class ByteUtils {

    private ByteUtils() {}

    // =========================================================================
    // Little-endian readers
    // =========================================================================

    /**
     * Reads an unsigned 8-bit integer (0..255).
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return unsigned value as int
     */
    public static int readUInt8(byte[] data, int offset) {
        return data[offset] & 0xFF;
    }

    /**
     * Reads an unsigned 16-bit little-endian integer (0..65535).
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return unsigned value as int
     */
    public static int readUInt16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    /**
     * Reads an unsigned 32-bit little-endian integer (0..4294967295).
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return unsigned value as long
     */
    public static long readUInt32LE(byte[] data, int offset) {
        return (data[offset]     & 0xFFL)
             | ((data[offset + 1] & 0xFFL) << 8)
             | ((data[offset + 2] & 0xFFL) << 16)
             | ((data[offset + 3] & 0xFFL) << 24);
    }

    /**
     * Reads a signed 32-bit little-endian integer.
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return signed value as int
     */
    public static int readInt32LE(byte[] data, int offset) {
        return (data[offset]     & 0xFF)
             | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16)
             | (data[offset + 3]          << 24);
    }

    /**
     * Reads an unsigned 64-bit little-endian integer.
     *
     * <p>Note: Java {@code long} is signed; values above {@code Long.MAX_VALUE}
     * will appear negative.  Use {@code Long.compareUnsigned()} for comparisons
     * involving the full uint64 range.</p>
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return value as long (may be negative for uint64 > Long.MAX_VALUE)
     */
    public static long readUInt64LE(byte[] data, int offset) {
        return (data[offset]     & 0xFFL)
             | ((data[offset + 1] & 0xFFL) << 8)
             | ((data[offset + 2] & 0xFFL) << 16)
             | ((data[offset + 3] & 0xFFL) << 24)
             | ((data[offset + 4] & 0xFFL) << 32)
             | ((data[offset + 5] & 0xFFL) << 40)
             | ((data[offset + 6] & 0xFFL) << 48)
             | ((data[offset + 7] & 0xFFL) << 56);
    }

    // =========================================================================
    // Big-endian readers
    // =========================================================================

    /**
     * Reads an unsigned 16-bit big-endian integer (0..65535).
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return unsigned value as int
     */
    public static int readUInt16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /**
     * Reads an unsigned 32-bit big-endian integer (0..4294967295).
     *
     * @param data   source array
     * @param offset byte offset in {@code data}
     * @return unsigned value as long
     */
    public static long readUInt32BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFFL) << 24)
             | ((data[offset + 1] & 0xFFL) << 16)
             | ((data[offset + 2] & 0xFFL) << 8)
             |  (data[offset + 3] & 0xFFL);
    }

    // =========================================================================
    // Little-endian writers
    // =========================================================================

    /**
     * Writes a 32-bit value as little-endian into {@code data} at {@code offset}.
     *
     * @param data   target array
     * @param offset byte offset in {@code data}
     * @param value  value to write (upper 32 bits ignored)
     */
    public static void writeUInt32LE(byte[] data, int offset, int value) {
        data[offset]     = (byte)  (value         & 0xFF);
        data[offset + 1] = (byte) ((value >> 8)   & 0xFF);
        data[offset + 2] = (byte) ((value >> 16)  & 0xFF);
        data[offset + 3] = (byte) ((value >> 24)  & 0xFF);
    }

    // =========================================================================
    // Misc
    // =========================================================================

    /**
     * Converts a byte array to its hexadecimal string representation,
     * with each byte separated by a space (e.g. {@code "1F 8B 08"}).
     *
     * @param bytes source array, must not be null
     * @return hex string
     */
    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }
    // =========================================================================
    // Methods ported from be.stef.arcana.formats.rar.util.Utils
    // (kept in ByteUtils for unified access across all JUnpack decompressors)
    // =========================================================================

    /**
     * Aligns a size value to a 16-byte AES block boundary.
     *
     * @param size the size to align
     * @return the aligned size (smallest multiple of 16 >= size)
     */
    public static long alignToAesBlock(long size) {
        return ((size + 15) / 16) * 16;
    }

    /**
     * Copies {@code length} bytes from {@code source} starting at {@code offset}
     * into a new array.
     *
     * @param source source array
     * @param offset start offset in {@code source}
     * @param length number of bytes to copy
     * @return new array containing the copied bytes
     */
    public static byte[] copyBytes(byte[] source, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, offset, result, 0, length);
        return result;
    }

    /**
     * Fills a portion of {@code array} with zero bytes.
     *
     * @param array  target array
     * @param offset start offset
     * @param length number of bytes to zero
     */
    public static void zeroMemory(byte[] array, int offset, int length) {
        java.util.Arrays.fill(array, offset, offset + length, (byte) 0);
    }

    /**
     * Fills the entire {@code array} with zero bytes.
     *
     * @param array target array
     */
    public static void zeroMemory(byte[] array) {
        java.util.Arrays.fill(array, (byte) 0);
    }

    /**
     * Converts a byte array to a compact lowercase hexadecimal string (no spaces).
     * Returns {@code "null"} if {@code bytes} is null.
     *
     * @param bytes source array, may be null
     * @return compact hex string
     */
    public static String toBytesToHexCompact(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

}
