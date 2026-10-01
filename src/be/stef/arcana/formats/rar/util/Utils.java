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
package be.stef.arcana.formats.rar.util;

import be.stef.arcana.util.ByteUtils;

/**
 * Compatibility facade delegating all byte-manipulation operations to
 * {@link ByteUtils} - the unified utility class shared across all JUnpack
 * decompressors.
 *
 * <p>Within JUnpack, all RAR processing classes continue to import this class
 * ({@code be.stef.arcana.formats.rar.util.Utils}) unchanged.  The actual implementation now
 * lives in {@code be.stef.arcana.util.ByteUtils}, which is also used by the
 * TAR, BZIP2, and Zstandard engines.</p>
 *
 * @author Stef
 * @since 2.0
 */
public final class Utils {

    private Utils() {}

    public static String bytesToHex(byte[] bytes)                          { return ByteUtils.toHexString(bytes); }
    public static String bytesToHexCompact(byte[] bytes)                   { return ByteUtils.toBytesToHexCompact(bytes); }
    public static long   readUInt32LE(byte[] data, int offset)             { return ByteUtils.readUInt32LE(data, offset); }
    public static long   readUInt64LE(byte[] data, int offset)             { return ByteUtils.readUInt64LE(data, offset); }
    public static int    readUInt16LE(byte[] data, int offset)             { return ByteUtils.readUInt16LE(data, offset); }
    public static void   writeUInt32LE(byte[] data, int offset, int value) { ByteUtils.writeUInt32LE(data, offset, value); }
    public static long   alignToAesBlock(long size)                        { return ByteUtils.alignToAesBlock(size); }
    public static byte[] copyBytes(byte[] source, int offset, int length)  { return ByteUtils.copyBytes(source, offset, length); }
    public static void   zeroMemory(byte[] array, int offset, int length)  { ByteUtils.zeroMemory(array, offset, length); }
    public static void   zeroMemory(byte[] array)                          { ByteUtils.zeroMemory(array); }
}
