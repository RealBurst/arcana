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
package be.stef.arcana.formats.dmg;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.hfs.HfsPlusReader;
import be.stef.arcana.formats.lzfse.LzfseDecoder;
import be.stef.arcana.formats.xz.LZMAInputStream;
import be.stef.arcana.formats.xz.XZInputStream;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Reader of Apple disk images in the UDIF format (.dmg), written from the
 * public descriptions of the format (koly trailer, "mish" block tables).
 *
 * <p>Layout: the data fork (the compressed chunks), an XML property list, then
 * a 512-byte big-endian trailer starting with "koly" in the last 512 bytes of
 * the file (version 4: data fork offset and length, XML offset and length,
 * segment information, data fork and master checksums, image variant, sector
 * count). The property list holds a "resource-fork" dictionary whose "blkx"
 * array describes the partitions of the image: a name such as
 * "disk image (Apple_HFS : 4)", and a base64 "mish" table: first sector and
 * sector count of the partition, base offset of its data, its checksum, then
 * 40-byte chunk entries (type, sector, sector count, offset and length in the
 * data fork; 512-byte sectors).</p>
 *
 * <p>Chunk types: 0 zero-fill, 1 raw, 2 ignored (read as zeros), 0x80000004
 * ADC, 0x80000005 zlib, 0x80000006 bzip2, 0x80000007 LZFSE, 0x80000008 LZMA
 * (xz stream), 0x7FFFFFFE comment, 0xFFFFFFFF end of table.</p>
 *
 * <p>Each partition is exposed as a random-access view
 * ({@link PartitionReader}): chunks are decoded on demand and a few of them
 * are kept in a small cache, so a file system reader can work without
 * decompressing the whole image in memory. The data fork CRC32 (koly) and the
 * partition CRC32 (blkx, over the decoded partition) are verified when they
 * are present.</p>
 *
 * <p>A .dmg without trailer is read as a raw disk image (read/write "UDRW"
 * images, plain HFS+ volumes): Apple partition map, GUID partition table or a
 * single volume. Encrypted images (encrcdsa / cdsaencr), sparse images (sprs)
 * and segmented images are recognized and reported as not supported.</p>
 *
 * @author Stef
 * @since 1.5
 */
public final class UdifImage implements Closeable {

    /** Size of a UDIF sector. */
    public static final int SECTOR = 512;

    public static final int CHUNK_ZERO = 0x00000000;
    public static final int CHUNK_RAW = 0x00000001;
    public static final int CHUNK_IGNORE = 0x00000002;
    public static final int CHUNK_ADC = 0x80000004;
    public static final int CHUNK_ZLIB = 0x80000005;
    public static final int CHUNK_BZIP2 = 0x80000006;
    public static final int CHUNK_LZFSE = 0x80000007;
    public static final int CHUNK_LZMA = 0x80000008;
    public static final int CHUNK_COMMENT = 0x7FFFFFFE;
    public static final int CHUNK_END = 0xFFFFFFFF;

    /** Checksum type of a CRC32 (koly and mish). */
    public static final int CHECKSUM_CRC32 = 2;

    /** Largest decoded chunk and largest compressed chunk accepted (hdiutil writes at most a few MiB). */
    private static final long MAX_CHUNK = 64L << 20;
    private static final long MAX_XML = 64L << 20;
    /** Memory used by the decoded chunk cache of one partition. */
    private static final long CACHE_BYTES = 32L << 20;

    /** Positional input (a file, or the page cache of an analyzer). */
    public interface Input extends Closeable {
        long length() throws IOException;

        /** Reads up to len bytes at pos; returns the number of bytes read (less at the end of the input). */
        int read(long pos, byte[] b, int off, int len) throws IOException;
    }

    /** One partition (one "blkx" entry). */
    public static final class Partition {
        /** Number of the entry ("ID" of the property list, else its position). */
        public final int id;
        /** Full name, e.g. "disk image (Apple_HFS : 4)". */
        public final String name;
        /** Partition type, e.g. "Apple_HFS", "Apple_APFS", "Apple_Free", "MBR". */
        public final String type;
        /** First sector of the partition in the image, and its sector count. */
        public final long firstSector;
        public final long sectorCount;
        /** Checksum of the decoded partition: type (2 = CRC32, 0 = none) and value. */
        public final int checksumType;
        public final int checksum;
        final int[] types;
        final long[] sector;
        final long[] count;
        final long[] offset;
        final long[] length;

        Partition(final int id, final String name, final long firstSector, final long sectorCount, final int checksumType, final int checksum, final List<long[]> chunks) {
            this.id = id;
            this.name = name;
            this.type = typeOf(name);
            this.firstSector = firstSector;
            this.sectorCount = sectorCount;
            this.checksumType = checksumType;
            this.checksum = checksum;
            final int n = chunks.size();
            types = new int[n];
            sector = new long[n];
            count = new long[n];
            offset = new long[n];
            length = new long[n];
            for (int i = 0; i < n; i++) {
                final long[] c = chunks.get(i);
                types[i] = (int) c[0];
                sector[i] = c[1];
                count[i] = c[2];
                offset[i] = c[3];
                length[i] = c[4];
            }
        }

        /** Size of the partition in bytes. */
        public long size() {
            return sectorCount * SECTOR;
        }

        /** Name without the "(type : n)" suffix, e.g. "disk image"; may be empty. */
        public String shortName() {
            final int p = name.lastIndexOf(" (");
            return (p >= 0 && name.endsWith(")") ? name.substring(0, p) : name).trim();
        }

        /** Number of chunks (comments and end markers excluded). */
        public int chunkCount() {
            return types.length;
        }

        /** True if every chunk is zero-fill or ignored: nothing to extract. */
        public boolean isEmpty() {
            for (final int t : types) if (t != CHUNK_ZERO && t != CHUNK_IGNORE) return false;
            return true;
        }

        /** True for the entries that only describe the partition scheme (maps, free space, boot records). */
        public boolean isPartitionScheme() {
            final String t = type.toLowerCase();
            return t.equals("ddm") || t.equals("mbr") || t.contains("gpt") || t.equals("apple_partition_map") || t.equals("apple_free") || t.startsWith("apple_driver") || t.equals("apple_patches") || t.equals("apple_void") || t.equals("apple_scratch") || t.contains("driver descriptor");
        }

        private static String typeOf(final String name) {
            final int open = name.lastIndexOf('(');
            final int colon = name.lastIndexOf(" : ");
            if (open >= 0 && colon > open) return name.substring(open + 1, colon).trim();
            return name.trim();
        }
    }

    private final Input in;
    private final long fileLength;
    private final boolean raw;
    private int version;
    private long dataForkOffset;
    private long dataForkLength;
        private int dataForkChecksumType;
    private int dataForkChecksum;
    private int imageVariant;
    private long sectorCount;
    private final List<Partition> partitions = new ArrayList<Partition>();

    /** Opens a disk image file. */
    public static UdifImage open(final File file) throws IOException {
        final RandomAccessFile raf = new RandomAccessFile(file, "r");
        return new UdifImage(new Input() {
            @Override
            public long length() throws IOException {
                return raf.length();
            }

            @Override
            public int read(final long pos, final byte[] b, final int off, final int len) throws IOException {
                raf.seek(pos);
                int done = 0;
                while (done < len) {
                    final int n = raf.read(b, off + done, len - done);
                    if (n < 0) break;
                    done += n;
                }
                return done;
            }

            @Override
            public void close() throws IOException {
                raf.close();
            }
        });
    }

    /** Reads the trailer and the partition tables; the input is closed with this image. */
    public UdifImage(final Input input) throws IOException {
        this.in = input;
        boolean ok = false;
        try {
            fileLength = in.length();
            final String kind = probe(in);
            if ("encrypted".equals(kind)) throw new ArcanaUnsupportedFormatException("Encrypted disk image (AES, encrcdsa / cdsaencr header): not supported");
            if ("sparse".equals(kind)) throw new ArcanaUnsupportedFormatException("Sparse disk image (.sparseimage, \"sprs\" header): not supported - convert it with hdiutil convert -format UDZO");
            raw = !"udif".equals(kind);
            if (raw) readRawImage();
            else readTrailer();
            ok = true;
        } finally {
            if (!ok) in.close();
        }
    }

    /**
     * Kind of disk image: "udif" (koly trailer), "encrypted", "sparse", or null
     * when none of these signatures is present.
     */
    public static String probe(final Input in) throws IOException {
        final long len = in.length();
        final byte[] head = new byte[8];
        if (in.read(0, head, 0, 8) == 8) {
            final String h = new String(head, StandardCharsets.ISO_8859_1);
            if (h.equals("encrcdsa")) return "encrypted";
            if (h.startsWith("sprs")) return "sparse";
        }
        if (len >= SECTOR) {
            final byte[] t = new byte[SECTOR];
            if (in.read(len - SECTOR, t, 0, SECTOR) == SECTOR) {
                if (t[0] == 'k' && t[1] == 'o' && t[2] == 'l' && t[3] == 'y' && be32(t, 8) == SECTOR) return "udif";
                // FileVault 1 style ("cdsaencr" v1 header at the end of the file)
                if (new String(t, SECTOR - 8, 8, StandardCharsets.ISO_8859_1).equals("cdsaencr")) return "encrypted";
            }
        }
        return null;
    }

    /** True if this image had no UDIF trailer and is read as a raw disk image. */
    public boolean isRaw() {
        return raw;
    }

    public int getVersion() {
        return version;
    }

    public int getImageVariant() {
        return imageVariant;
    }

    public long getSectorCount() {
        return sectorCount;
    }

    public int getDataForkChecksumType() {
        return dataForkChecksumType;
    }

    public int getDataForkChecksum() {
        return dataForkChecksum;
    }

    public List<Partition> getPartitions() {
        return Collections.unmodifiableList(partitions);
    }

    /** Image format deduced from the chunk types: "UDZO (zlib)", "UDBZ (bzip2)", "ULFO (LZFSE)"... */
    public String getFormatName() {
        if (raw) return "raw disk image (no UDIF trailer)";
        boolean adc = false;
        boolean zlib = false;
        boolean bzip2 = false;
        boolean lzfse = false;
        boolean lzma = false;
        for (final Partition p : partitions) {
            for (final int t : p.types) {
                adc |= t == CHUNK_ADC;
                zlib |= t == CHUNK_ZLIB;
                bzip2 |= t == CHUNK_BZIP2;
                lzfse |= t == CHUNK_LZFSE;
                lzma |= t == CHUNK_LZMA;
            }
        }
        final StringBuilder sb = new StringBuilder();
        if (zlib) sb.append(" + UDZO (zlib)");
        if (bzip2) sb.append(" + UDBZ (bzip2)");
        if (lzfse) sb.append(" + ULFO (LZFSE)");
        if (lzma) sb.append(" + ULMO (LZMA)");
        if (adc) sb.append(" + UDCO (ADC)");
        return sb.length() == 0 ? "UDRO (uncompressed)" : sb.substring(3);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }

    // =========================================================================
    // Trailer and property list
    // =========================================================================

    private void readTrailer() throws IOException {
        final byte[] k = readAt(fileLength - SECTOR, SECTOR);
        version = be32(k, 4);
        dataForkOffset = be64(k, 24);
        dataForkLength = be64(k, 32);
        final long rsrcLength = be64(k, 48);
        final int segmentNumber = be32(k, 56);
        final int segmentCount = be32(k, 60);
        dataForkChecksumType = be32(k, 80);
        dataForkChecksum = be32(k, 88);
        final long xmlOffset = be64(k, 216);
        final long xmlLength = be64(k, 224);
        imageVariant = be32(k, 488);
        sectorCount = be64(k, 492);
        if (version != 4) throw new ArcanaUnsupportedFormatException("UDIF version " + version + " is not supported (4 only)");
        if (segmentCount > 1) throw new ArcanaUnsupportedFormatException("Segmented disk image (segment " + segmentNumber + " of " + segmentCount + "): not supported");
        if (dataForkOffset < 0 || dataForkLength < 0 || dataForkOffset + dataForkLength > fileLength - SECTOR) throw new ArcanaCorruptedException("Invalid UDIF data fork position (truncated image?)");
        if (xmlLength == 0) {
            if (rsrcLength > 0) throw new ArcanaUnsupportedFormatException("Disk image without XML property list (resource fork only, very old UDIF): not supported");
            throw new ArcanaCorruptedException("Disk image without partition table");
        }
        if (xmlOffset < 0 || xmlLength < 0 || xmlLength > MAX_XML || xmlOffset + xmlLength > fileLength) throw new ArcanaCorruptedException("Invalid UDIF property list position (truncated image?)");
        final byte[] xml = readAt(xmlOffset, (int) xmlLength);
        final Object root = PlistParser.parse(new String(xml, StandardCharsets.UTF_8));
        final Object fork = root instanceof Map ? ((Map<?, ?>) root).get("resource-fork") : null;
        final Object blkx = fork instanceof Map ? ((Map<?, ?>) fork).get("blkx") : null;
        if (!(blkx instanceof List)) throw new ArcanaCorruptedException("Disk image property list without \"blkx\" partition list");
        int index = 0;
        for (final Object o : (List<?>) blkx) {
            if (!(o instanceof Map)) continue;
            final Map<?, ?> m = (Map<?, ?>) o;
            final Object data = m.get("Data");
            if (!(data instanceof byte[])) throw new ArcanaCorruptedException("Disk image partition without block table");
            String name = m.get("Name") instanceof String ? (String) m.get("Name") : m.get("CFName") instanceof String ? (String) m.get("CFName") : "";
            int id = index;
            if (m.get("ID") instanceof String) {
                try {
                    id = Integer.parseInt(((String) m.get("ID")).trim());
                } catch (final NumberFormatException ignored) {
                    // keep the position
                }
            }
            partitions.add(parseMish((byte[]) data, id, name));
            index++;
        }
    }

    private Partition parseMish(final byte[] d, final int id, final String name) throws IOException {
        if (d.length < 204 || be32(d, 0) != 0x6D697368) throw new ArcanaCorruptedException("Invalid block table (no \"mish\" signature) for partition " + name);
        final long first = be64(d, 8);
        final long sectors = be64(d, 16);
        final long dataStart = be64(d, 24);
        final int sumType = be32(d, 64);
        final int sum = be32(d, 72);
        final long n = be32(d, 200) & 0xffffffffL;
        if (n > (d.length - 204) / 40) throw new ArcanaCorruptedException("Invalid block table for partition " + name);
        if (first < 0 || sectors < 0 || sectors > Long.MAX_VALUE / SECTOR || dataStart < 0) throw new ArcanaCorruptedException("Invalid block table for partition " + name);
        final List<long[]> chunks = new ArrayList<long[]>();
        long next = 0;
        for (int i = 0; i < n; i++) {
            final int p = 204 + 40 * i;
            final int type = be32(d, p);
            if (type == CHUNK_END) break;
            if (type == CHUNK_COMMENT) continue;
            final long sec = be64(d, p + 8);
            final long cnt = be64(d, p + 16);
            final long off = be64(d, p + 24);
            final long len = be64(d, p + 32);
            if (cnt == 0) continue;
            if (type != CHUNK_ZERO && type != CHUNK_RAW && type != CHUNK_IGNORE && type != CHUNK_ADC && type != CHUNK_ZLIB && type != CHUNK_BZIP2 && type != CHUNK_LZFSE && type != CHUNK_LZMA) {
                throw new ArcanaUnsupportedFormatException("Unknown disk image chunk type 0x" + Integer.toHexString(type) + " in partition " + name);
            }
            if (sec < next || cnt < 0 || sec + cnt > sectors || off < 0 || len < 0) throw new ArcanaCorruptedException("Invalid chunk " + i + " in the block table of partition " + name);
            next = sec + cnt;
            chunks.add(new long[] {type, sec, cnt, dataForkOffset + dataStart + off, len});
        }
        return new Partition(id, name, first, sectors, sumType, sum, chunks);
    }

    // =========================================================================
    // Raw images (no trailer)
    // =========================================================================

    private void readRawImage() throws IOException {
        final long sectors = fileLength / SECTOR;
        sectorCount = sectors;
        if (sectors < 3) throw new ArcanaCorruptedException("Not a disk image (no UDIF trailer, too short)");
        final byte[] b = readAt(0, (int) Math.min(fileLength, 4096));
        if (be16(b, 1024) == 0x482B || be16(b, 1024) == 0x4858 || be16(b, 1024) == 0x4244) {
            addRaw(0, "HFS+ volume (Apple_HFS : 0)", 0, sectors);
            return;
        }
        if (b.length >= 1024 && b[512] == 'E' && b[513] == 'F' && b[514] == 'I' && b[515] == ' ' && b[516] == 'P' && b[517] == 'A' && b[518] == 'R' && b[519] == 'T') {
            readGpt(b);
            return;
        }
        if (b[0] == 'E' && b[1] == 'R') {
            final int blk = be16(b, 2) == 0 ? SECTOR : be16(b, 2);
            final byte[] e0 = readAt(blk, SECTOR);
            if (e0[0] == 'P' && e0[1] == 'M') {
                final long n = be32(e0, 4) & 0xffffffffL;
                for (int i = 0; i < Math.min(n, 256); i++) {
                    final byte[] e = readAt((long) blk * (i + 1), SECTOR);
                    if (e[0] != 'P' || e[1] != 'M') break;
                    final long start = (be32(e, 8) & 0xffffffffL) * blk / SECTOR;
                    final long count = (be32(e, 12) & 0xffffffffL) * blk / SECTOR;
                    final String pname = cString(e, 16, 32);
                    final String ptype = cString(e, 48, 32);
                    if (start + count <= sectors) addRaw(i, pname + " (" + ptype + " : " + i + ")", start, count);
                }
                if (!partitions.isEmpty()) return;
            }
        }
        throw new ArcanaUnsupportedFormatException("No UDIF \"koly\" trailer (truncated or not a disk image) and no HFS+ volume or partition map found");
    }

    private void readGpt(final byte[] b) throws IOException {
        final long entriesLba = le64(b, 512 + 72);
        final long n = le32(b, 512 + 80) & 0xffffffffL;
        final int size = le32(b, 512 + 84);
        if (size < 128 || size > 4096 || n > 1024 || entriesLba < 2) throw new ArcanaCorruptedException("Invalid GUID partition table");
        for (int i = 0; i < n; i++) {
            final long pos = entriesLba * SECTOR + (long) i * size;
            if (pos + 128 > fileLength) break;
            final byte[] e = readAt(pos, 128);
            boolean used = false;
            for (int j = 0; j < 16; j++) used |= e[j] != 0;
            if (!used) continue;
            final long first = le64(e, 32);
            final long last = le64(e, 40);
            if (first < 0 || last < first || last >= sectorCount) continue;
            final String pname = new String(e, 56, 72, StandardCharsets.UTF_16LE).replace("\u0000", "").trim();
            addRaw(i, pname + " (" + gptType(e) + " : " + i + ")", first, last - first + 1);
        }
        if (partitions.isEmpty()) throw new ArcanaCorruptedException("Empty GUID partition table");
    }

    private static String gptType(final byte[] e) {
        final String g = String.format("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", le32(e, 0), le16(e, 4), le16(e, 6), e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]);
        if (g.equals("48465300-0000-11AA-AA11-00306543ECAC")) return "Apple_HFS";
        if (g.equals("7C3457EF-0000-11AA-AA11-00306543ECAC")) return "Apple_APFS";
        if (g.equals("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")) return "EFI";
        if (g.equals("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")) return "Microsoft Basic Data";
        return g;
    }

    private void addRaw(final int id, final String name, final long first, final long count) {
        final List<long[]> chunks = new ArrayList<long[]>();
        chunks.add(new long[] {CHUNK_RAW, 0, count, first * SECTOR, count * SECTOR});
        partitions.add(new Partition(id, name, first, count, 0, 0, chunks));
    }

    // =========================================================================
    // Checksums
    // =========================================================================

    /**
     * Checks the CRC32 of the data fork (koly), when the image has one.
     *
     * @throws ArcanaCorruptedException if it does not match
     */
    public void verifyDataFork() throws IOException {
        if (raw || dataForkChecksumType != CHECKSUM_CRC32) return;
        final CRC32 crc = new CRC32();
        final byte[] buf = new byte[1 << 20];
        long pos = dataForkOffset;
        long left = dataForkLength;
        while (left > 0) {
            final int n = (int) Math.min(buf.length, left);
            if (in.read(pos, buf, 0, n) != n) throw new ArcanaCorruptedException("Disk image truncated (data fork)");
            crc.update(buf, 0, n);
            pos += n;
            left -= n;
        }
        if ((int) crc.getValue() != dataForkChecksum) throw new ArcanaCorruptedException(String.format("Disk image data fork CRC32 mismatch (stored %08x, computed %08x)", dataForkChecksum, (int) crc.getValue()));
    }

    // =========================================================================
    // Partition access
    // =========================================================================

    /** Random-access view of a partition (chunks decoded on demand). */
    public PartitionReader openPartition(final Partition p) {
        return new PartitionReader(p);
    }

    /** Decoded content of one partition, read by sector-aligned or arbitrary ranges. */
    public final class PartitionReader implements HfsPlusReader.Source {
        private final Partition p;
        private final int[] chunkCrc;
        private final boolean[] crcKnown;
        private long cachedBytes;
        private final Map<Integer, byte[]> cache = new LinkedHashMap<Integer, byte[]>(16, 0.75f, true);

        PartitionReader(final Partition p) {
            this.p = p;
            chunkCrc = new int[p.types.length];
            crcKnown = new boolean[p.types.length];
        }

        public Partition getPartition() {
            return p;
        }

        @Override
        public long length() {
            return p.size();
        }

        @Override
        public void readFully(long pos, final byte[] b, int off, int len) throws IOException {
            if (pos < 0 || len < 0 || pos > p.size() - len) throw new ArcanaCorruptedException("Read beyond the end of partition " + p.name);
            while (len > 0) {
                final int ci = chunkAt(pos / SECTOR);
                final long start = ci >= 0 ? p.sector[ci] * SECTOR : 0;
                final long end = ci >= 0 ? start + p.count[ci] * SECTOR : nextChunkStart(pos);
                final int n = (int) Math.min(len, end - pos);
                if (ci < 0 || p.types[ci] == CHUNK_ZERO || p.types[ci] == CHUNK_IGNORE) {
                    java.util.Arrays.fill(b, off, off + n, (byte) 0);
                } else if (p.types[ci] == CHUNK_RAW) {
                    if (pos - start + n > p.length[ci]) throw new ArcanaCorruptedException("Raw chunk " + ci + " of partition " + p.name + " shorter than its sectors");
                    if (in.read(p.offset[ci] + pos - start, b, off, n) != n) throw new ArcanaCorruptedException("Disk image truncated (chunk " + ci + " of partition " + p.name + ")");
                } else {
                    System.arraycopy(chunk(ci), (int) (pos - start), b, off, n);
                }
                pos += n;
                off += n;
                len -= n;
            }
        }

        /** Index of the chunk holding a sector, or -1 in a gap. */
        private int chunkAt(final long sec) {
            int lo = 0;
            int hi = p.sector.length - 1;
            while (lo <= hi) {
                final int mid = (lo + hi) >>> 1;
                if (p.sector[mid] > sec) hi = mid - 1;
                else if (p.sector[mid] + p.count[mid] <= sec) lo = mid + 1;
                else return mid;
            }
            return -1;
        }

        private long nextChunkStart(final long pos) {
            final long sec = pos / SECTOR;
            for (int i = 0; i < p.sector.length; i++) if (p.sector[i] > sec) return p.sector[i] * SECTOR;
            return p.size();
        }

        private byte[] chunk(final int ci) throws IOException {
            byte[] d = cache.get(ci);
            if (d != null) return d;
            d = decode(ci);
            chunkCrc[ci] = crc(d, d.length);
            crcKnown[ci] = true;
            cache.put(ci, d);
            cachedBytes += d.length;
            while (cachedBytes > CACHE_BYTES && cache.size() > 1) {
                final Map.Entry<Integer, byte[]> eldest = cache.entrySet().iterator().next();
                cachedBytes -= eldest.getValue().length;
                cache.remove(eldest.getKey());
            }
            return d;
        }

        private byte[] decode(final int ci) throws IOException {
            final long outLen = p.count[ci] * SECTOR;
            final long inLen = p.length[ci];
            if (outLen > MAX_CHUNK || inLen > MAX_CHUNK) throw new ArcanaCorruptedException("Chunk " + ci + " of partition " + p.name + " too large");
            if (p.offset[ci] + inLen > fileLength) throw new ArcanaCorruptedException("Disk image truncated (chunk " + ci + " of partition " + p.name + ")");
            final byte[] src = readAt(p.offset[ci], (int) inLen);
            final byte[] out = new byte[(int) outLen];
            final int type = p.types[ci];
            int n;
            try {
                switch (type) {
                    case CHUNK_ZLIB: {
                        final Inflater inf = new Inflater();
                        try {
                            inf.setInput(src);
                            n = 0;
                            while (n < out.length && !inf.finished()) {
                                final int k = inf.inflate(out, n, out.length - n);
                                if (k == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                                n += k;
                            }
                        } finally {
                            inf.end();
                        }
                        break;
                    }
                    case CHUNK_BZIP2:
                        n = readAll(new BZip2InputStream(new ByteArrayInputStream(src)), out);
                        break;
                    case CHUNK_LZMA:
                        n = readAll(src.length >= 6 && (src[0] & 0xff) == 0xFD && src[1] == '7' && src[2] == 'z' && src[3] == 'X' && src[4] == 'Z' ? new XZInputStream(new ByteArrayInputStream(src)) : new LZMAInputStream(new ByteArrayInputStream(src)), out);
                        break;
                    case CHUNK_LZFSE:
                        n = LzfseDecoder.decode(src, 0, src.length, out, 0, out.length);
                        break;
                    case CHUNK_ADC:
                        n = AdcDecoder.decode(src, 0, src.length, out, out.length);
                        break;
                    default:
                        throw new ArcanaUnsupportedFormatException("Unknown chunk type 0x" + Integer.toHexString(type));
                }
            } catch (final DataFormatException e) {
                throw new ArcanaCorruptedException("Chunk " + ci + " of partition " + p.name + " (" + chunkName(type) + "): " + e.getMessage(), e);
            } catch (final ArcanaCorruptedException | ArcanaUnsupportedFormatException e) {
                throw e;
            } catch (final IOException | RuntimeException e) {
                throw new ArcanaCorruptedException("Chunk " + ci + " of partition " + p.name + " (" + chunkName(type) + "): " + e, e);
            }
            if (n != out.length) throw new ArcanaCorruptedException("Chunk " + ci + " of partition " + p.name + " (" + chunkName(type) + ") decoded to " + n + " bytes instead of " + out.length);
            return out;
        }

        /**
         * Checks the CRC32 of the decoded partition (blkx checksum), when the
         * partition has one: CRC32 of its chunks in order, the "ignore" chunks
         * left out. Chunks already decoded are not decoded again.
         *
         * @throws ArcanaCorruptedException if it does not match
         */
        public void verifyChecksum() throws IOException {
            if (p.checksumType != CHECKSUM_CRC32) return;
            long crc = 0;
            final byte[] buf = new byte[1 << 16];
            for (int ci = 0; ci < p.types.length; ci++) {
                final long start = p.sector[ci] * SECTOR;
                final long len = p.count[ci] * SECTOR;
                final int t = p.types[ci];
                long c;
                if (t == CHUNK_IGNORE) {
                    continue; // hdiutil leaves the ignored ranges out of the checksum
                } else if (t == CHUNK_ZERO) {
                    c = crcOfZeros(len);
                } else if (t == CHUNK_RAW) {
                    final CRC32 r = new CRC32();
                    long done = 0;
                    while (done < len) {
                        final int n = (int) Math.min(buf.length, len - done);
                        readFully(start + done, buf, 0, n);
                        r.update(buf, 0, n);
                        done += n;
                    }
                    c = r.getValue();
                } else {
                    if (!crcKnown[ci]) {
                        final byte[] d = decode(ci);
                        chunkCrc[ci] = crc(d, d.length);
                        crcKnown[ci] = true;
                    }
                    c = chunkCrc[ci] & 0xffffffffL;
                }
                crc = crc32Combine(crc, c, len);
            }
            if ((int) crc != p.checksum) throw new ArcanaCorruptedException(String.format("Checksum mismatch in partition %s (stored CRC32 %08x, computed %08x)", p.name, p.checksum, (int) crc));
        }

        /** Writes the whole decoded partition to out, then checks its CRC32. */
        public void copyTo(final OutputStream out) throws IOException {
            final byte[] buf = new byte[1 << 16];
            long pos = 0;
            while (pos < p.size()) {
                final int n = (int) Math.min(buf.length, p.size() - pos);
                readFully(pos, buf, 0, n);
                out.write(buf, 0, n);
                pos += n;
            }
            verifyChecksum();
        }
    }

    /** Name of a chunk type ("zlib", "raw"...). */
    private static String chunkName(final int type) {
        switch (type) {
            case CHUNK_ZERO: return "zero";
            case CHUNK_RAW: return "raw";
            case CHUNK_IGNORE: return "ignore";
            case CHUNK_ADC: return "ADC";
            case CHUNK_ZLIB: return "zlib";
            case CHUNK_BZIP2: return "bzip2";
            case CHUNK_LZFSE: return "LZFSE";
            case CHUNK_LZMA: return "LZMA";
            default: return "0x" + Integer.toHexString(type);
        }
    }

    private static int readAll(final InputStream s, final byte[] out) throws IOException {
        int n = 0;
        try {
            while (n < out.length) {
                final int k = s.read(out, n, out.length - n);
                if (k < 0) break;
                n += k;
            }
        } finally {
            s.close();
        }
        return n;
    }

    // =========================================================================
    // CRC32 of concatenated pieces (GF(2) matrix method, as in zlib's crc32_combine)
    // =========================================================================

    private static int crc(final byte[] b, final int len) {
        final CRC32 c = new CRC32();
        c.update(b, 0, len);
        return (int) c.getValue();
    }

    private static final long CRC_ZERO_BYTE;

    static {
        final CRC32 c = new CRC32();
        c.update(0);
        CRC_ZERO_BYTE = c.getValue();
    }

    /** CRC32 of n zero bytes. */
    static long crcOfZeros(long n) {
        long result = 0;
        long piece = CRC_ZERO_BYTE;
        long pieceLen = 1;
        while (n > 0) {
            if ((n & 1) != 0) result = crc32Combine(result, piece, pieceLen);
            n >>>= 1;
            if (n > 0) {
                piece = crc32Combine(piece, piece, pieceLen);
                pieceLen <<= 1;
            }
        }
        return result;
    }

    /** CRC32 of A followed by B, from crc(A), crc(B) and the length of B. */
    static long crc32Combine(long crc1, final long crc2, long len2) {
        if (len2 <= 0) return crc1;
        final long[] even = new long[32];
        final long[] odd = new long[32];
        odd[0] = 0xEDB88320L; // operator for one zero bit
        long row = 1;
        for (int n = 1; n < 32; n++) {
            odd[n] = row;
            row <<= 1;
        }
        gf2Square(even, odd); // two zero bits
        gf2Square(odd, even); // four zero bits
        do {
            gf2Square(even, odd); // apply len2 zero bytes to crc1
            if ((len2 & 1) != 0) crc1 = gf2Times(even, crc1);
            len2 >>>= 1;
            if (len2 == 0) break;
            gf2Square(odd, even);
            if ((len2 & 1) != 0) crc1 = gf2Times(odd, crc1);
            len2 >>>= 1;
        } while (len2 != 0);
        return (crc1 ^ crc2) & 0xffffffffL;
    }

    private static long gf2Times(final long[] mat, long vec) {
        long sum = 0;
        int i = 0;
        while (vec != 0) {
            if ((vec & 1) != 0) sum ^= mat[i];
            vec >>>= 1;
            i++;
        }
        return sum;
    }

    private static void gf2Square(final long[] square, final long[] mat) {
        for (int n = 0; n < 32; n++) square[n] = gf2Times(mat, mat[n]);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private byte[] readAt(final long pos, final int len) throws IOException {
        final byte[] b = new byte[len];
        if (pos < 0 || in.read(pos, b, 0, len) != len) throw new ArcanaCorruptedException("Disk image truncated");
        return b;
    }

    private static String cString(final byte[] b, final int off, final int max) {
        int n = 0;
        while (n < max && b[off + n] != 0) n++;
        return new String(b, off, n, StandardCharsets.ISO_8859_1).trim();
    }

    static int be16(final byte[] b, final int off) {
        return (b[off] & 0xff) << 8 | (b[off + 1] & 0xff);
    }

    static int be32(final byte[] b, final int off) {
        return (b[off] & 0xff) << 24 | (b[off + 1] & 0xff) << 16 | (b[off + 2] & 0xff) << 8 | (b[off + 3] & 0xff);
    }

    static long be64(final byte[] b, final int off) {
        return (long) be32(b, off) << 32 | (be32(b, off + 4) & 0xffffffffL);
    }

    private static int le16(final byte[] b, final int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8;
    }

    private static int le32(final byte[] b, final int off) {
        return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8 | (b[off + 2] & 0xff) << 16 | (b[off + 3] & 0xff) << 24;
    }

    private static long le64(final byte[] b, final int off) {
        return (le32(b, off) & 0xffffffffL) | (long) le32(b, off + 4) << 32;
    }
}
