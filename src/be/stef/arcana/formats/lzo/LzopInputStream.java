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
package be.stef.arcana.formats.lzo;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * Decompresses an lzop file (.lzo). Written from public descriptions of the
 * lzop container; no lzop code is used.
 *
 * <p>Header (integers big-endian): 9-byte magic {@code 89 4C 5A 4F 00 0D 0A 1A 0A},
 * version (2), library version (2), version needed to extract (2, from
 * version 0x0940 on), method (1), level (1, from 0x0940 on), flags (4),
 * filter (4, only with flag F_H_FILTER), mode (4), mtime low (4), mtime high
 * (4, from 0x0940 on), name length (1), name, header checksum (4: Adler-32 of
 * the fields from the version to the name, or CRC32 with flag F_H_CRC32),
 * then an optional extra field (length, data, checksum) with flag
 * F_H_EXTRA_FIELD.</p>
 *
 * <p>Blocks: uncompressed size (4, 0 ends the file), compressed size (4),
 * Adler-32 and/or CRC32 of the uncompressed data (flags F_ADLER32_D,
 * F_CRC32_D), Adler-32 and/or CRC32 of the compressed data (flags
 * F_ADLER32_C, F_CRC32_C, only when the block is compressed), then the data.
 * A block whose compressed size equals its uncompressed size is stored.
 * Methods 1 (LZO1X-1), 2 (LZO1X-1(15)) and 3 (LZO1X-999) all produce LZO1X
 * blocks, decoded by {@link Lzo1xDecompressor}. Every checksum the flags
 * announce is verified.</p>
 *
 * <p>Several lzop files concatenated are decoded one after the other (as
 * {@code lzop -dc} does); other data after the end block is ignored.</p>
 *
 * @author Stef
 * @since 1.4
 */
public final class LzopInputStream extends InputStream {

    private static final byte[] MAGIC = {(byte) 0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A};

    private static final int F_ADLER32_D     = 0x00000001;
    private static final int F_ADLER32_C     = 0x00000002;
    private static final int F_H_EXTRA_FIELD = 0x00000040;
    private static final int F_CRC32_D       = 0x00000100;
    private static final int F_CRC32_C       = 0x00000200;
    private static final int F_MULTIPART     = 0x00000400;
    private static final int F_H_FILTER      = 0x00000800;
    private static final int F_H_CRC32       = 0x00001000;

    /** Highest "version needed to extract" accepted (lzop 1.04). */
    private static final int MAX_VERSION_NEEDED = 0x1040;
    /** Largest block lzop writes (64 MiB). */
    private static final int MAX_BLOCK_SIZE = 64 * 1024 * 1024;

    private final InputStream in;
    private final byte[] one = new byte[1];
    private String name;
    private long mtime;
    private int method;
    private int level;
    private int flags;
    private int members;
    private byte[] block = new byte[0];
    private int blockPos;
    private int blockLen;
    private boolean finished;

    /**
     * Reads the header of the first member.
     *
     * @param in lzop file content, read from its first byte
     * @throws IOException if the header is not valid or uses an unsupported feature
     */
    public LzopInputStream(final InputStream in) throws IOException {
        this.in = new BufferedInputStream(in, 65536);
        final byte[] m = new byte[MAGIC.length];
        if (readUpTo(m) < MAGIC.length || !java.util.Arrays.equals(m, MAGIC)) throw new ArcanaCorruptedException("Not an lzop file (bad signature)");
        readHeader();
    }

    /** File name stored in the header of the first member (may be empty). */
    public String getName() {
        return name;
    }

    /** Modification time stored in the header of the first member, in seconds since 1970. */
    public long getModificationTime() {
        return mtime;
    }

    /** Method of the first member: 1 LZO1X-1, 2 LZO1X-1(15), 3 LZO1X-999. */
    public int getMethod() {
        return method;
    }

    /** Compression level stored in the header of the first member (0 when absent). */
    public int getLevel() {
        return level;
    }

    @Override
    public int read() throws IOException {
        return read(one, 0, 1) < 0 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        if (len == 0) return 0;
        while (blockPos == blockLen) {
            if (finished || !nextBlock()) {
                finished = true;
                return -1;
            }
        }
        final int n = Math.min(len, blockLen - blockPos);
        System.arraycopy(block, blockPos, b, off, n);
        blockPos += n;
        return n;
    }

    // -------------------------------------------------------------------------
    // Header
    // -------------------------------------------------------------------------

    private void readHeader() throws IOException {
        final Checksum hc = new Adler32();
        final Checksum alt = new CRC32();
        final HeaderReader h = new HeaderReader(hc, alt);
        final int version = h.u16();
        h.u16(); // library version
        if (version < 0x0900) throw new ArcanaUnsupportedFormatException("lzop: header version " + hex(version) + " not supported");
        if (version >= 0x0940) {
            final int needed = h.u16();
            if (needed > MAX_VERSION_NEEDED) throw new ArcanaUnsupportedFormatException("lzop: this file needs lzop version " + hex(needed));
            if (needed < 0x0900) throw new ArcanaCorruptedException("lzop: invalid version needed to extract " + hex(needed));
        }
        final int meth = h.u8();
        if (meth < 1 || meth > 3) throw new ArcanaUnsupportedFormatException("lzop: compression method " + meth + " not supported (only LZO1X: 1, 2, 3)");
        final int lvl = version >= 0x0940 ? h.u8() : 0;
        final int fl = (int) h.u32();
        if ((fl & F_H_FILTER) != 0) throw new ArcanaUnsupportedFormatException("lzop: filters are not supported");
        if ((fl & F_MULTIPART) != 0) throw new ArcanaUnsupportedFormatException("lzop: multipart files are not supported");
        h.u32(); // mode
        long time = h.u32();
        if (version >= 0x0940) time |= h.u32() << 32;
        final byte[] nameBytes = new byte[h.u8()];
        h.bytes(nameBytes);
        final long computed = ((fl & F_H_CRC32) != 0 ? alt : hc).getValue();
        if (u32() != computed) throw new ArcanaCorruptedException("lzop: header checksum error");
        if ((fl & F_H_EXTRA_FIELD) != 0) {
            final HeaderReader x = new HeaderReader(new Adler32(), new CRC32());
            final long len = x.u32();
            if (len > MAX_BLOCK_SIZE) throw new ArcanaCorruptedException("lzop: extra field too large");
            x.bytes(new byte[(int) len]);
            if (u32() != ((fl & F_H_CRC32) != 0 ? x.alt : x.main).getValue()) throw new ArcanaCorruptedException("lzop: extra field checksum error");
        }
        members++;
        flags = fl;
        if (members == 1) {
            method = meth;
            level = lvl;
            mtime = time;
            name = decodeName(nameBytes);
        }
    }

    /** Reads header fields and feeds both checksums with their bytes. */
    private final class HeaderReader {
        final Checksum main;
        final Checksum alt;

        HeaderReader(final Checksum main, final Checksum alt) {
            this.main = main;
            this.alt = alt;
        }

        void bytes(final byte[] b) throws IOException {
            if (readUpTo(b) < b.length) throw new ArcanaCorruptedException("lzop: truncated header");
            main.update(b, 0, b.length);
            alt.update(b, 0, b.length);
        }

        int u8() throws IOException {
            final byte[] b = new byte[1];
            bytes(b);
            return b[0] & 0xFF;
        }

        int u16() throws IOException {
            final byte[] b = new byte[2];
            bytes(b);
            return (b[0] & 0xFF) << 8 | (b[1] & 0xFF);
        }

        long u32() throws IOException {
            final byte[] b = new byte[4];
            bytes(b);
            return be32(b);
        }
    }

    // -------------------------------------------------------------------------
    // Blocks
    // -------------------------------------------------------------------------

    /** Decodes the next block; false at the end of the last member. */
    private boolean nextBlock() throws IOException {
        long dstLen = u32();
        while (dstLen == 0) {
            if (!nextMemberHeader()) return false;
            dstLen = u32();
        }
        if (dstLen > MAX_BLOCK_SIZE) throw new ArcanaCorruptedException("lzop: block size " + dstLen + " too large");
        final long srcLen = u32();
        if (srcLen == 0 || srcLen > dstLen) throw new ArcanaCorruptedException("lzop: invalid compressed block size " + srcLen);
        final long adlerD = (flags & F_ADLER32_D) != 0 ? u32() : -1;
        final long crcD   = (flags & F_CRC32_D) != 0 ? u32() : -1;
        final boolean compressed = srcLen < dstLen;
        final long adlerC = compressed && (flags & F_ADLER32_C) != 0 ? u32() : -1;
        final long crcC   = compressed && (flags & F_CRC32_C) != 0 ? u32() : -1;
        final byte[] src = new byte[(int) srcLen];
        if (readUpTo(src) < src.length) throw new ArcanaCorruptedException("lzop: unexpected end of file in a block");
        check(src, src.length, adlerC, crcC, "compressed");
        if (block.length < dstLen) block = new byte[(int) dstLen];
        if (compressed) {
            final int n = Lzo1xDecompressor.decompress(src, 0, src.length, block);
            if (n != dstLen) throw new ArcanaCorruptedException("lzop: block decoded to " + n + " bytes instead of " + dstLen);
        } else {
            System.arraycopy(src, 0, block, 0, src.length);
        }
        check(block, (int) dstLen, adlerD, crcD, "uncompressed");
        blockPos = 0;
        blockLen = (int) dstLen;
        return true;
    }

    /** After an end block: true if another lzop file follows (its header is read), false at EOF or before other trailing data. */
    private boolean nextMemberHeader() throws IOException {
        in.mark(MAGIC.length);
        final byte[] m = new byte[MAGIC.length];
        final int n = readUpTo(m);
        if (n == MAGIC.length && java.util.Arrays.equals(m, MAGIC)) {
            readHeader();
            return true;
        }
        in.reset();
        return false;
    }

    private static void check(final byte[] data, final int len, final long adler, final long crc, final String what) throws IOException {
        if (adler >= 0) {
            final Adler32 a = new Adler32();
            a.update(data, 0, len);
            if (a.getValue() != adler) throw new ArcanaCorruptedException("lzop: Adler-32 error on the " + what + " data of a block");
        }
        if (crc >= 0) {
            final CRC32 c = new CRC32();
            c.update(data, 0, len);
            if (c.getValue() != crc) throw new ArcanaCorruptedException("lzop: CRC32 error on the " + what + " data of a block");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private long u32() throws IOException {
        final byte[] b = new byte[4];
        if (readUpTo(b) < 4) throw new ArcanaCorruptedException("lzop: unexpected end of file");
        return be32(b);
    }

    private static long be32(final byte[] b) {
        return ((long) (b[0] & 0xFF) << 24) | (b[1] & 0xFF) << 16 | (b[2] & 0xFF) << 8 | (b[3] & 0xFF);
    }

    private int readUpTo(final byte[] b) throws IOException {
        int n = 0;
        while (n < b.length) {
            final int r = in.read(b, n, b.length - n);
            if (r < 0) break;
            n += r;
        }
        return n;
    }

    /** The name is stored as raw bytes: UTF-8 when valid, else ISO-8859-1. */
    private static String decodeName(final byte[] b) {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b)).toString();
        } catch (final java.nio.charset.CharacterCodingException e) {
            return new String(b, StandardCharsets.ISO_8859_1);
        }
    }

    private static String hex(final int v) {
        return String.format("0x%04X", v);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
