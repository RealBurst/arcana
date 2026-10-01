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
/* 7z format: data compressed with LZMA2, header also compressed with LZMA2
 * as required by the specification. Uses the XZ-Java LZMA2 encoder already
 * ported as part of the Arcana 7z extraction layer (0BSD license). */
package be.stef.arcana.compressor;

import be.stef.arcana.formats.sevenz.SevenZAesOutputStream;
import be.stef.arcana.util.ProgressInputStream;
import be.stef.arcana.formats.xz.ArrayCache;
import be.stef.arcana.formats.xz.BasicArrayCache;
import be.stef.arcana.formats.xz.LZMA2Options;
import be.stef.arcana.formats.xz.FinishableOutputStream;
import be.stef.arcana.formats.xz.FinishableWrapperOutputStream;
import be.stef.arcana.formats.xz.ParallelLZMA2OutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

/**
 * Compressor for 7-Zip archives (.7z) using LZMA2 compression.
 *
 * <p>Produces archives fully compatible with 7-Zip and any other tool that reads
 * the 7z format. The compression engine is the pure-Java LZMA2 encoder from the
 * XZ-Java library (0BSD license), already ported as part of the Arcana 7z
 * extraction layer. No external dependency, no JNI.</p>
 *
 * <p>All files are compressed together in a single LZMA2 solid stream for
 * maximum compression ratio. Since 1.3 the stream is encoded by several threads
 * (independent LZMA2 blocks, like 7-Zip -mmt, see {@link ParallelLZMA2OutputStream})
 * and written directly to the target: memory use no longer grows with the archive. The header is also compressed with LZMA2 as
 * required by the 7z specification.</p>
 *
 * @author Stef
 * @since 1.1
 */
public class SevenZCompressor implements ArchiveCompressor {

    // ---- 7z format constants ----
    private static final byte[] SIGNATURE = {0x37, 0x7A, (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C};
    private static final byte[] VERSION   = {0x00, 0x04};

    // ---- NID constants ----
    private static final int NID_END                = 0x00;
    private static final int NID_HEADER             = 0x01;
    private static final int NID_MAIN_STREAMS_INFO  = 0x04;
    private static final int NID_FILES_INFO         = 0x05;
    private static final int NID_PACK_INFO          = 0x06;
    private static final int NID_UNPACK_INFO        = 0x07;
    private static final int NID_SUB_STREAMS_INFO   = 0x08;
    private static final int NID_SIZE               = 0x09;
    private static final int NID_CRC                = 0x0A;
    private static final int NID_FOLDER             = 0x0B;
    private static final int NID_CODERS_UNPACK_SIZE = 0x0C;
    private static final int NID_NUM_UNPACK_STREAM  = 0x0D;
    private static final int NID_EMPTY_STREAM       = 0x0E;
    private static final int NID_NAME               = 0x11;
    private static final int NID_MTIME              = 0x14;
    private static final int NID_WIN_ATTRIBUTES     = 0x15;
    private static final int NID_ENCODED_HEADER     = 0x17;

    /** LZMA2 method ID in 7z folder coder: single byte 0x21. */
    private static final byte[] LZMA2_METHOD_ID = {0x21};

    private static final int BUFFER_SIZE = 65536;
    private static final int START_HEADER_SIZE = 32;

    private final int    preset;
    private final byte[] password; // null = no encryption
    private final ArrayCache arrayCache = BasicArrayCache.getInstance();

    /** Creates a SevenZCompressor with default compression level (6). */
    public SevenZCompressor() {
        this(LZMA2Options.PRESET_DEFAULT, null);
    }

    /**
     * Creates a SevenZCompressor with the given LZMA2 preset.
     *
     * @param preset 0 (fastest) to 9 (best compression)
     */
    public SevenZCompressor(final int preset) {
        this(preset, null);
    }

    /** Creates a SevenZCompressor with default compression level and AES-256 encryption. */
    public SevenZCompressor(final byte[] password) {
        this(LZMA2Options.PRESET_DEFAULT, password);
    }

    /**
     * Creates a SevenZCompressor with the given LZMA2 preset and AES-256 encryption.
     *
     * @param preset   0 (fastest) to 9 (best compression)
     * @param password archive password; null disables encryption
     */
    public SevenZCompressor(final int preset, final byte[] password) {
        if (preset < LZMA2Options.PRESET_MIN || preset > LZMA2Options.PRESET_MAX) throw new IllegalArgumentException("preset must be 0..9");
        this.preset   = preset;
        this.password = password;
    }

    @Override
    public boolean supportsDirectories() { return true; }

    // =========================================================================
    // Public compress methods
    // =========================================================================

    /**
     * Writes the archive directly into {@code target}: the packed data is streamed
     * (nothing is kept in memory whatever the archive size) and the 32-byte start
     * header, which depends on the data size, is patched at the end.
     */
    @Override
    public void compress(final File source, final File target) throws IOException {
        final byte[] startHeader;
        try (OutputStream fos = new BufferedOutputStream(new FileOutputStream(target), BUFFER_SIZE)) {
            fos.write(new byte[START_HEADER_SIZE]); // placeholder
            startHeader = writeBody(source, fos);
        }
        try (RandomAccessFile raf = new RandomAccessFile(target, "rw")) {
            raf.write(startHeader);
        }
    }

    /**
     * The start header precedes the data and depends on its size: the archive is
     * built in a temporary file, then copied to {@code out}.
     */
    @Override
    public void compress(final File source, final OutputStream out) throws IOException {
        final File tmp = File.createTempFile("arcana-7z-", ".tmp");
        try {
            compress(source, tmp);
            Files.copy(tmp.toPath(), out);
            out.flush();
        } finally {
            if (!tmp.delete()) tmp.deleteOnExit();
        }
    }

    /**
     * Writes packed streams + headers (everything after the start header) and
     * returns the 32-byte start header.
     */
    private byte[] writeBody(final File source, final OutputStream out) throws IOException {
        final List<Entry> entries = new ArrayList<Entry>();
        // Paths inside the archive are relative to the PARENT of the source, so that
        // compressing a directory "_Files" yields "_Files", "_Files/a.txt", ... and not
        // "_Files" next to a flat "a.txt".
        final File abs = source.getAbsoluteFile();
        final File base = abs.getParentFile() != null ? abs.getParentFile() : abs;
        collectEntries(abs, base, entries);

        final List<Entry> nonEmpty = new ArrayList<Entry>();
        for (final Entry e : entries) { if (!e.isDirectory) nonEmpty.add(e); }

        // Packed data: files -> LZMA2 (multithreaded when possible) -> [AES] -> out
        final CountingOutputStream packed = new CountingOutputStream(out);
        long lzma2Size = 0;
        long totalUnpack = 0;
        byte[] aesProperties = null;
        if (!nonEmpty.isEmpty()) {
            final SevenZAesOutputStream aes = password != null ? new SevenZAesOutputStream(packed, password) : null;
            final CountingOutputStream lzma2 = new CountingOutputStream(aes != null ? aes : packed);
            totalUnpack = compressSolid(nonEmpty, lzma2);
            lzma2Size = lzma2.count;
            if (aes != null) {
                aes.finish();
                aesProperties = aes.getAesProperties();
            }
        }
        final long packSize = packed.count;

        // Build kHeader, then compress it
        final byte[] kHeader = buildKHeader(entries, nonEmpty, packSize, lzma2Size, totalUnpack, aesProperties);
        final byte[] lzma2Header = compressBytes(kHeader);
        final byte[] encodedHeader = buildEncodedHeader(packSize, lzma2Header.length, kHeader.length);
        out.write(lzma2Header);
        out.write(encodedHeader);
        out.flush();

        // Start header
        final long nhCrc = crc32bytes(encodedHeader);
        final long nhOffset = packSize + lzma2Header.length;
        final byte[] startHdrContent = new byte[20];
        writeLong(startHdrContent, 0, nhOffset);
        writeLong(startHdrContent, 8, encodedHeader.length);
        writeInt(startHdrContent, 16, (int) nhCrc);
        final long sigCrc = crc32bytes(startHdrContent);

        final byte[] start = new byte[START_HEADER_SIZE];
        System.arraycopy(SIGNATURE, 0, start, 0, 6);
        System.arraycopy(VERSION, 0, start, 6, 2);
        writeInt(start, 8, (int) sigCrc);
        System.arraycopy(startHdrContent, 0, start, 12, 20);
        return start;
    }

    /** Counts the bytes written through it. */
    private static final class CountingOutputStream extends FilterOutputStream {
        long count;

        CountingOutputStream(final OutputStream out) {
            super(out);
        }

        @Override
        public void write(final int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override
        public void write(final byte[] b, final int off, final int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }

    // =========================================================================
    // File collection
    // =========================================================================

    private static void collectEntries(final File source, final File root, final List<Entry> result) {
        // Collect files first, directories second (required by 7z spec: empty streams
        // come after non-empty ones so the kEmptyStream bitset aligns correctly).
        final List<Entry> files = new java.util.ArrayList<Entry>();
        final List<Entry> dirs  = new java.util.ArrayList<Entry>();
        collectRecursive(source, root, files, dirs);
        result.addAll(files);
        result.addAll(dirs);
    }

    private static void collectRecursive(final File file, final File root, final List<Entry> files, final List<Entry> dirs) {
        final String path = relativePath(root, file);
        if (file.isDirectory()) {
            dirs.add(new Entry(path, file, true));
            final File[] children = file.listFiles();
            if (children != null) { for (final File c : children) collectRecursive(c, root, files, dirs); }
        } else {
            files.add(new Entry(path, file, false));
        }
    }

    private static String relativePath(final File root, final File file) {
        final String rp = root.getAbsolutePath();
        final String fp = file.getAbsolutePath();
        if (fp.equals(rp)) return file.getName();
        String rel = fp.substring(rp.length());
        if (rel.startsWith(File.separator)) rel = rel.substring(1);
        return rel.replace(File.separatorChar, '/');
    }

    // =========================================================================
    // LZMA2 compression
    // =========================================================================

    /**
     * Compresses all files as one solid LZMA2 stream into {@code out}. The CRC32 and
     * the size of each file are computed while reading (files are read only once).
     *
     * @return total uncompressed size
     */
    private long compressSolid(final List<Entry> files, final OutputStream out) throws IOException {
        final LZMA2Options opts = new LZMA2Options(preset);
        long expected = 0;
        for (final Entry e : files) expected += e.size;
        final FinishableOutputStream lz2 = ParallelLZMA2OutputStream.create(out, opts, expected); // multithreaded when possible
        final byte[] buf = new byte[BUFFER_SIZE];
        final CRC32 crc = new CRC32();
        long total = 0;
        for (final Entry e : files) {
            crc.reset();
            long size = 0;
            try (ProgressInputStream in = new ProgressInputStream(
                    new BufferedInputStream(new FileInputStream(e.file), BUFFER_SIZE), e.size, e.name)) {
                int n;
                while ((n = in.read(buf)) >= 0) {
                    lz2.write(buf, 0, n);
                    crc.update(buf, 0, n);
                    size += n;
                }
                in.finish();
            }
            e.size = size;
            e.crc32 = crc.getValue();
            total += size;
        }
        lz2.finish();
        return total;
    }

    private byte[] compressBytes(final byte[] data) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final LZMA2Options opts = new LZMA2Options(preset);
        final FinishableOutputStream lz2 = opts.getOutputStream(new FinishableWrapperOutputStream(baos), arrayCache);
        lz2.write(data);
        lz2.finish();
        return baos.toByteArray();
    }

    // =========================================================================
    // Header construction
    // =========================================================================

    private byte[] buildKHeader(final List<Entry> entries, final List<Entry> nonEmpty, final long packSize, final long lzma2Size, final long totalUnpack, final byte[] aesProperties) throws IOException {
        final ByteArrayOutputStream h = new ByteArrayOutputStream();
        h.write(NID_HEADER);

        if (!nonEmpty.isEmpty()) {
            h.write(NID_MAIN_STREAMS_INFO);
            // kPackInfo
            h.write(NID_PACK_INFO);
            writeU64(h, 0);
            writeU64(h, 1);
            h.write(NID_SIZE);
            writeU64(h, packSize);
            h.write(NID_END);
            // kUnpackInfo
            h.write(NID_UNPACK_INFO);
            h.write(NID_FOLDER);
            writeU64(h, 1);
            h.write(0x00);
            if (aesProperties != null) {
                // Two coders: AES256SHA256 (outer) + LZMA2 (inner)
                // Decoding order: packed -> AES_decode -> LZMA2_decode -> data
                writeU64(h, 2);
                // Coder 0: AES256SHA256 -- flags: id_len=4 | has_attributes = 4|0x20 = 0x24
                h.write(0x24);
                h.write(SevenZAesOutputStream.METHOD_ID); // {0x06, 0xF1, 0x07, 0x01}
                writeU64(h, 34);        // propSize = 34
                h.write(aesProperties); // [0xD3, 0xFF, salt(16), iv(16)]
                // Coder 1: LZMA2 -- flags: id_len=1 | has_attributes = 1|0x20 = 0x21
                h.write(0x21);
                h.write(LZMA2_METHOD_ID);
                h.write(0x01);  // propSize = 1
                h.write(getLzma2PropByte());
                // Bind pairs: count is implicit (numOutStreams - 1 = 2 - 1 = 1)
                // A bind pair is (inIndex, outIndex): the IN stream inIndex is fed by the OUT stream outIndex.
                // LZMA2 input (in stream 1) <- AES output (out stream 0)
                writeU64(h, 1); // inIndex  = 1 (LZMA2 input)
                writeU64(h, 0); // outIndex = 0 (AES output)
                // numPackStreams = numInStreams - numBindPairs = 2 - 1 = 1 (implicit): the unbound AES input (in 0)
                // Final folder output = the unbound out stream = LZMA2 output (out 1)
            } else {
                // One coder: LZMA2 only -- coder props: idSize=1 (0x01) | hasAttr=1 (0x20) = 0x21
                // followed by propSize=1 and the LZMA2 dict-size property byte
                writeU64(h, 1);
                h.write(0x21);
                h.write(LZMA2_METHOD_ID);
                h.write(0x01);  // propSize = 1
                h.write(getLzma2PropByte());
            }
            h.write(NID_CODERS_UNPACK_SIZE);
            if (aesProperties != null) {
                writeU64(h, lzma2Size);   // AES output (out 0) = decrypted LZMA2 stream WITHOUT the 16-byte padding
                writeU64(h, totalUnpack); // LZMA2 output (out 1) = total uncompressed data
            } else {
                writeU64(h, totalUnpack); // LZMA2 output only
            }
            h.write(NID_END);
            // kSubStreamsInfo
            h.write(NID_SUB_STREAMS_INFO);
            // kNumUnpackStream is only written when > 1 (1 is the implicit default)
            if (nonEmpty.size() > 1) {
                h.write(NID_NUM_UNPACK_STREAM);
                writeU64(h, nonEmpty.size());
                h.write(NID_SIZE);
                for (int i = 0; i < nonEmpty.size() - 1; i++) writeU64(h, nonEmpty.get(i).size);
            }
            h.write(NID_CRC);
            h.write(0x01);
            for (final Entry e : nonEmpty) h.write(int32LE((int) e.crc32));
            h.write(NID_END);
            h.write(NID_END);
        }

        // kFilesInfo
        h.write(NID_FILES_INFO);
        writeU64(h, entries.size());

        // kEmptyStream
        boolean hasEmpty = false;
        for (final Entry e : entries) { if (e.isDirectory) { hasEmpty = true; break; } }
        if (hasEmpty) {
            final int nbytes = (entries.size() + 7) / 8;
            final byte[] bits = new byte[nbytes];
            for (int i = 0; i < entries.size(); i++) { if (entries.get(i).isDirectory) bits[i / 8] |= (byte) (0x80 >>> (i % 8)); }
            // kEmptyStream is a raw BitVector, unlike kName/kMTime/kWinAttributes
            // it has NO leading "external" byte -- size is exactly nbytes.
            h.write(NID_EMPTY_STREAM);
            writeU64(h, nbytes);
            h.write(bits);
        }

        // kName
        final ByteArrayOutputStream names = new ByteArrayOutputStream();
        for (final Entry e : entries) { names.write(e.name.getBytes("UTF-16LE")); names.write(0); names.write(0); }
        h.write(NID_NAME);
        writeU64(h, 1 + names.size());
        h.write(0x00);
        h.write(names.toByteArray());

        // kMTime
        final ByteArrayOutputStream mtimes = new ByteArrayOutputStream();
        for (final Entry e : entries) mtimes.write(toWindowsTime(e.file.lastModified()));
        // Order is allDefined (0x01) THEN external (0x00) -- not the other way round.
        h.write(NID_MTIME);
        writeU64(h, 1 + 1 + mtimes.size());
        h.write(0x01);  // allDefined = true
        h.write(0x00);  // external = 0 (inline)
        h.write(mtimes.toByteArray());

        // kWinAttributes
        final ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        for (final Entry e : entries) attrs.write(int32LE(e.isDirectory ? 0x10 : 0x20));
        h.write(NID_WIN_ATTRIBUTES);
        writeU64(h, 1 + 1 + attrs.size());
        h.write(0x01);  // allDefined = true
        h.write(0x00);  // external = 0 (inline)
        h.write(attrs.toByteArray());

        h.write(NID_END);
        h.write(NID_END);
        return h.toByteArray();
    }

    private byte[] buildEncodedHeader(final long dataSize, final long hdrSize, final long unpackSize) throws IOException {
        final ByteArrayOutputStream eh = new ByteArrayOutputStream();
        eh.write(NID_ENCODED_HEADER);
        eh.write(NID_PACK_INFO);
        writeU64(eh, dataSize);
        writeU64(eh, 1);
        eh.write(NID_SIZE);
        writeU64(eh, hdrSize);
        eh.write(NID_END);
        eh.write(NID_UNPACK_INFO);
        eh.write(NID_FOLDER);
        writeU64(eh, 1);
        eh.write(0x00);
        writeU64(eh, 1);
        eh.write(0x21);
        eh.write(LZMA2_METHOD_ID);
        eh.write(0x01);  // propSize = 1
        eh.write(getLzma2PropByte());
        eh.write(NID_CODERS_UNPACK_SIZE);
        writeU64(eh, unpackSize);
        eh.write(NID_END);
        eh.write(NID_END);
        return eh.toByteArray();
    }

    // =========================================================================
    // LZMA2 property byte
    // =========================================================================

    /**
     * Returns the 1-byte LZMA2 property that encodes the dictionary size,
     * as required by the 7z folder coder description (spec: getDistSlot(d-1)-23).
     * Dict sizes match XZ-Java LZMA2Options.presetToDictSize[].
     * Pre-computed to avoid depending on LZMA2Options.getDictSize() returning
     * the right value before the object is fully initialised.
     */
    private byte getLzma2PropByte() {
        // presetToDictSize = {1<<18,1<<20,1<<21,1<<22,1<<22,1<<23,1<<23,1<<24,1<<25,1<<26}
        // prop = getDistSlot(dictSize-1) - 23
        // Pre-computed for each preset 0..9:
        final int[] propByPreset = {12, 16, 18, 20, 20, 22, 22, 24, 26, 28};
        return (byte) propByPreset[preset];
    }

    // =========================================================================
    // Binary I/O helpers
    // =========================================================================

    /**
     * Encodes a uint64 value using the 7z SDK variable-length integer format
     * (IgorPavlov WriteNumber, LZMA SDK public domain).
     *
     * The first byte contains a unary-encoded length prefix (high bits) plus
     * the most-significant bits of the value. The remaining bytes contain the
     * least-significant bits of the value in little-endian order.
     *
     * Examples: 0=00, 127=7F, 128=80 80, 16384=C0 00 40, 2097152=E0 00 00 20.
     */
    static void writeU64(final OutputStream out, final long v) throws IOException {
        int first = 0;
        int mask = 0x80;
        int nExtra = 0;
        for (int i = 0; i < 8; i++) {
            if (v < (1L << (7 * (i + 1)))) {
                first |= (int) ((v >>> (8 * i)) & 0xFF);
                nExtra = i;
                break;
            }
            first |= mask;
            mask >>>= 1;
            if (i == 7) { first = 0xFF; nExtra = 8; }
        }
        out.write(first);
        long temp = v;
        for (int k = 0; k < nExtra; k++) {
            out.write((int) (temp & 0xFF));
            temp >>>= 8;
        }
    }

    private static byte[] int32LE(final int v) { return new byte[]{(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)}; }
    private static void writeLong(final byte[] b, final int o, final long v) { for (int i = 0; i < 8; i++) b[o + i] = (byte) (v >>> (8 * i)); }
    private static void writeInt(final byte[] b, final int o, final int v) { for (int i = 0; i < 4; i++) b[o + i] = (byte) (v >>> (8 * i)); }
    private static byte[] toWindowsTime(final long ms) { final long t = (ms + 11644473600000L) * 10000L; final byte[] r = new byte[8]; for (int i = 0; i < 8; i++) r[i] = (byte) (t >>> (8 * i)); return r; }
    private static long crc32bytes(final byte[] d) { final CRC32 c = new CRC32(); c.update(d); return c.getValue(); }

    // =========================================================================
    // Entry record
    // =========================================================================

    private static final class Entry {
        final String name;
        final File file;
        final boolean isDirectory;
        long size;   // expected size, then the number of bytes actually compressed
        long crc32;  // computed while compressing

        Entry(final String name, final File file, final boolean isDirectory) {
            this.name = name;
            this.file = file;
            this.isDirectory = isDirectory;
            this.size = isDirectory ? 0L : file.length();
        }
    }
}
