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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * .NET single-file bundle ({@code dotnet publish -p:PublishSingleFile=true}): the
 * application host (apphost.exe) followed by the files of the application (DLL,
 * .deps.json, .runtimeconfig.json, native libraries...) and a manifest giving the
 * path, offset and size of each file.
 *
 * <p>The manifest is found through the bundle signature stored in the apphost
 * (the apphost holds the offset of the manifest). When the apphost is missing
 * (bundle cut out of its executable), the manifest is searched at the end of
 * the file and validated entry by entry; the offsets are then shifted by the
 * number of bytes missing at the start.</p>
 *
 * <p>Manifest layout (little-endian): major (4), minor (4), file count (4),
 * bundle id (string); from version 2: deps.json offset/size, runtimeconfig.json
 * offset/size (8 each), flags (8); then per file: offset (8), size (8),
 * compressed size (8, version 6 and later, 0 = stored), type (1), path (string).
 * Strings are prefixed by their UTF-8 length (7-bit encoded). Compressed files
 * are raw deflate.</p>
 *
 * @author Stef
 * @since 1.3
 */
public final class DotNetBundle {

    /** SHA-256 of ".net core bundle", written after the manifest offset in the apphost. */
    private static final byte[] SIGNATURE = {(byte) 0x8b, 0x12, 0x02, (byte) 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, (byte) 0x93, 0x02, 0x14, (byte) 0xd7, (byte) 0xa0, 0x32, 0x13, (byte) 0xf5, (byte) 0xb9, (byte) 0xe6, (byte) 0xef, (byte) 0xae, 0x33, 0x18, (byte) 0xee, 0x3b, 0x2d, (byte) 0xce, 0x24, (byte) 0xb3, 0x6a, (byte) 0xae};

    /** Size of the end of the file searched for the manifest when the apphost is missing. */
    private static final long SEARCH_WINDOW = 16L << 20;

    /** One file of the bundle. */
    public static final class Entry {
        /** Absolute position in the scanned file (shift applied). */
        public final long offset;
        /** Uncompressed size. */
        public final long size;
        /** Compressed size, 0 if stored. */
        public final long compressedSize;
        /** 1 assembly, 2 native library, 3 deps.json, 4 runtimeconfig.json, 5 symbols, 0 other. */
        public final int type;
        /** Relative path in the application directory ("en/App.resources.dll"). */
        public final String path;

        Entry(final long offset, final long size, final long compressedSize, final int type, final String path) {
            this.offset = offset;
            this.size = size;
            this.compressedSize = compressedSize;
            this.type = type;
            this.path = path;
        }

        /** Bytes used in the file. */
        public long storedSize() {
            return compressedSize > 0 ? compressedSize : size;
        }
    }

    /** Parsed manifest. */
    public static final class Manifest {
        public final int major;
        public final String bundleId;
        public final List<Entry> entries;
        /** Absolute position of the manifest and its end. */
        public final long start, end;
        /** Bytes missing at the start of the file (apphost cut off), 0 for a complete executable. */
        public final long missing;

        Manifest(final int major, final String bundleId, final List<Entry> entries, final long start, final long end, final long missing) {
            this.major = major;
            this.bundleId = bundleId;
            this.entries = entries;
            this.start = start;
            this.end = end;
            this.missing = missing;
        }
    }

    private DotNetBundle() {}

    /** Finds and parses the bundle manifest of {@code s}, or returns null if {@code s} is not a .NET bundle. */
    public static Manifest find(final ByteSource s) throws IOException {
        final Manifest m = findInExecutable(s);
        return m != null ? m : findWithoutHost(s);
    }

    /** Manifest of a complete executable (apphost present), or null. */
    public static Manifest findInExecutable(final ByteSource s) throws IOException {
        final long len = s.length();
        // The apphost holds the manifest offset just before the signature
        final long sig = s.indexOf(SIGNATURE, 8, Math.min(len, 16L << 20));
        if (sig >= 8) {
            final long header = s.u64le(sig - 8);
            if (header > 0 && header < len) return parse(s, header, false);
        }
        return null;
    }

    /** Opens the content of an entry (inflated if compressed); the stream reads {@code s}, which must stay open. */
    public static InputStream open(final ByteSource s, final Entry e) {
        final InputStream raw = new FileCarver.SourceStream(s, e.offset, e.storedSize());
        return e.compressedSize > 0 ? new InflaterInputStream(raw, new Inflater(true), 65536) : raw;
    }

    /** Bundle without its apphost: the manifest is searched backwards from the end. */
    private static Manifest findWithoutHost(final ByteSource s) throws IOException {
        final long len = s.length();
        final long from = Math.max(0, len - SEARCH_WINDOW);
        for (long p = len - 17; p >= from; p--) {
            if (s.u8(p + 3) != 0 || s.u8(p + 7) != 0) continue; // major / minor are small numbers
            final long major = s.u32le(p);
            if (major < 1 || major > 20 || s.u32le(p + 4) > 20) continue;
            final Manifest m = parse(s, p, true);
            if (m != null) return m;
        }
        return null;
    }

    /**
     * Parses the manifest at {@code p}.
     *
     * @param shifted true if the offsets may be shifted (apphost missing): the shift is deduced from the
     *                position of the manifest, written right after the last file
     */
    private static Manifest parse(final ByteSource s, final long p, final boolean shifted) throws IOException {
        final long len = s.length();
        final int major = (int) s.u32le(p);
        final long count = s.u32le(p + 8);
        if (major < 1 || major > 20 || count <= 0 || count > 1_000_000) return null;
        final long[] q = {p + 12};
        final String id = string(s, q, 64);
        if (id == null || id.isEmpty()) return null;
        if (major >= 2) q[0] += 40;
        final List<Entry> raw = new ArrayList<Entry>();
        long lastEnd = 0;
        for (long i = 0; i < count; i++) {
            if (q[0] + 25 > len) return null;
            final long off = s.u64le(q[0]);
            final long size = s.u64le(q[0] + 8);
            q[0] += 16;
            long csize = 0;
            if (major >= 6) {
                csize = s.u64le(q[0]);
                q[0] += 8;
            }
            final int type = s.u8(q[0]++);
            final String path = string(s, q, 4096);
            if (off < 0 || size < 0 || csize < 0 || type > 10 || path == null || path.isEmpty()) return null;
            raw.add(new Entry(off, size, csize, type, path));
            lastEnd = Math.max(lastEnd, off + (csize > 0 ? csize : size));
        }
        if (q[0] > len) return null;
        long shift = shifted ? p - lastEnd : 0;
        if (shift > 0) shift = 0; // gap before the manifest: the offsets are not shifted
        final List<Entry> entries = new ArrayList<Entry>(raw.size());
        int assemblies = 0;
        for (final Entry e : raw) {
            final long off = e.offset + shift;
            if (off < 0 || off + e.storedSize() > p) return null;
            // Stored assemblies and native libraries start with "MZ" (or "\177ELF" on Linux)
            if (e.compressedSize == 0 && e.size >= 2 && (e.type == 1 || e.type == 2) && assemblies < 8) {
                final int a = s.u8(off), b = s.u8(off + 1);
                if (!(a == 'M' && b == 'Z') && !(a == 0x7F && b == 'E')) return null;
                assemblies++;
            }
            entries.add(new Entry(off, e.size, e.compressedSize, e.type, e.path));
        }
        if (shifted && assemblies == 0) return null; // no way to check the shift
        return new Manifest(major, id, entries, p, q[0], -shift);
    }

    /** Length-prefixed UTF-8 string (7-bit encoded length), null if implausible. */
    private static String string(final ByteSource s, final long[] q, final int max) throws IOException {
        int n = 0, shift = 0, b;
        do {
            b = s.u8(q[0]++);
            if (b < 0 || shift > 28) return null;
            n |= (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (n < 0 || n > max) return null;
        final byte[] bytes = s.bytes(q[0], n);
        if (bytes == null) return null;
        for (final byte c : bytes) if ((c & 0xFF) < 0x20 || c == 0x7F) return null;
        q[0] += n;
        return new String(bytes, StandardCharsets.UTF_8);
    }
}