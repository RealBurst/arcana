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
package be.stef.arcana.formats.carve;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Random-access reader over a file, with a small page cache, used to parse
 * structures at arbitrary offsets (PE headers, archive trailers...).
 *
 * <p>Reads past the end of the file return 0 bytes / -1 values instead of
 * throwing: the parsers check the file length themselves.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class ByteSource implements Closeable {

    private static final int PAGE_BITS = 16;
    private static final int PAGE_SIZE = 1 << PAGE_BITS;
    private static final int PAGES = 8;

    private final RandomAccessFile raf;
    private final long length;
    private final long[] pageIndex = new long[PAGES];
    private final byte[][] pageData = new byte[PAGES][];
    private final int[] pageLen = new int[PAGES];
    private int nextVictim;

    public ByteSource(final File file) throws IOException {
        this.raf = new RandomAccessFile(file, "r");
        this.length = raf.length();
        for (int i = 0; i < PAGES; i++) pageIndex[i] = -1;
    }

    public long length() {
        return length;
    }

    private int page(final long p) throws IOException {
        for (int i = 0; i < PAGES; i++) if (pageIndex[i] == p) return i;
        final int slot = nextVictim;
        nextVictim = (nextVictim + 1) % PAGES;
        if (pageData[slot] == null) pageData[slot] = new byte[PAGE_SIZE];
        final long start = p << PAGE_BITS;
        final int n = (int) Math.max(0, Math.min(PAGE_SIZE, length - start));
        raf.seek(start);
        raf.readFully(pageData[slot], 0, n);
        pageIndex[slot] = p;
        pageLen[slot] = n;
        return slot;
    }

    /** Byte at {@code pos} (0-255), or -1 outside the file. */
    public int u8(final long pos) throws IOException {
        if (pos < 0 || pos >= length) return -1;
        final int slot = page(pos >>> PAGE_BITS);
        return pageData[slot][(int) (pos & (PAGE_SIZE - 1))] & 0xFF;
    }

    /**
     * Copies up to {@code len} bytes from {@code pos}.
     *
     * @return number of bytes copied (less than len at the end of the file)
     */
    public int read(final long pos, final byte[] b, final int off, final int len) throws IOException {
        if (pos < 0 || pos >= length) return 0;
        final int n = (int) Math.min(len, length - pos);
        int done = 0;
        while (done < n) {
            final long p = pos + done;
            final int slot = page(p >>> PAGE_BITS);
            final int inPage = (int) (p & (PAGE_SIZE - 1));
            final int k = Math.min(n - done, pageLen[slot] - inPage);
            if (k <= 0) break;
            System.arraycopy(pageData[slot], inPage, b, off + done, k);
            done += k;
        }
        return done;
    }

    /** {@code len} bytes from {@code pos}, or null if the file is shorter. */
    public byte[] bytes(final long pos, final int len) throws IOException {
        final byte[] b = new byte[len];
        return read(pos, b, 0, len) == len ? b : null;
    }

    public int u16le(final long pos) throws IOException {
        if (pos < 0 || pos + 2 > length) return -1;
        return u8(pos) | (u8(pos + 1) << 8);
    }

    public long u32le(final long pos) throws IOException {
        if (pos < 0 || pos + 4 > length) return -1;
        return (u8(pos) | (u8(pos + 1) << 8) | (u8(pos + 2) << 16) | ((long) u8(pos + 3) << 24)) & 0xFFFFFFFFL;
    }

    public long u64le(final long pos) throws IOException {
        if (pos < 0 || pos + 8 > length) return -1;
        return u32le(pos) | (u32le(pos + 4) << 32);
    }

    public int u16be(final long pos) throws IOException {
        if (pos < 0 || pos + 2 > length) return -1;
        return (u8(pos) << 8) | u8(pos + 1);
    }

    public long u32be(final long pos) throws IOException {
        if (pos < 0 || pos + 4 > length) return -1;
        return (((long) u8(pos) << 24) | (u8(pos + 1) << 16) | (u8(pos + 2) << 8) | u8(pos + 3)) & 0xFFFFFFFFL;
    }

    /** True if the bytes at {@code pos} equal {@code sig}. */
    public boolean matches(final long pos, final byte[] sig) throws IOException {
        if (pos < 0 || pos + sig.length > length) return false;
        for (int i = 0; i < sig.length; i++) if (u8(pos + i) != (sig[i] & 0xFF)) return false;
        return true;
    }

    /**
     * Position of the first occurrence of {@code sig} in {@code [from, to)}, or -1.
     */
    public long indexOf(final byte[] sig, final long from, final long to) throws IOException {
        final long end = Math.min(to, length) - sig.length;
        final int first = sig[0] & 0xFF;
        for (long p = Math.max(0, from); p <= end; p++) {
            if (u8(p) == first && matches(p, sig)) return p;
        }
        return -1;
    }

    /**
     * Position of the last occurrence of {@code sig} in {@code [from, to)}, or -1.
     */
    public long lastIndexOf(final byte[] sig, final long from, final long to) throws IOException {
        final int first = sig[0] & 0xFF;
        for (long p = Math.min(to, length) - sig.length; p >= Math.max(0, from); p--) {
            if (u8(p) == first && matches(p, sig)) return p;
        }
        return -1;
    }

    @Override
    public void close() throws IOException {
        raf.close();
    }
}
