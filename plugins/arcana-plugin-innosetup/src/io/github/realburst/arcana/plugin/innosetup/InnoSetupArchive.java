/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.innosetup;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import be.stef.arcana.exceptions.ArcanaEncryptedException;
import be.stef.arcana.exceptions.ArcanaUnsupportedFormatException;
import be.stef.arcana.formats.bzip2.BZip2InputStream;
import be.stef.arcana.formats.xz.LZMA2InputStream;
import be.stef.arcana.formats.xz.LZMAInputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Reader of Inno Setup installers (5.4.2 to 7.x), written from the record
 * declarations of the Inno Setup sources.
 *
 * <p>Layout: the loader keeps an offset table ("rDlPtS" + version) in its
 * resources. At Offset0: the 64-byte SetupID, (6.5+) the encryption header,
 * then two compressed blocks (4-byte CRC, stored size, compressed flag, then
 * 4 KiB pieces each preceded by their CRC, LZMA1 inside): the first holds the
 * setup header and the entries (languages, messages, ..., files, ...), the
 * second the file locations. File data starts at Offset1 in the installer, or
 * in setup-1.bin, setup-2.bin... ("disk spanning"); each chunk starts with
 * "zlb" 0x1A and holds one file or, in solid mode, many.</p>
 */
final class InnoSetupArchive implements Closeable {

    static final byte[] LDR_MAGIC = {'r', 'D', 'l', 'P', 't', 'S', (byte) 0xCD, (byte) 0xE6, (byte) 0xD7, 0x7B, 0x0B, 0x2A};
    private static final byte[] CHUNK_ID = {'z', 'l', 'b', 0x1A};
    private static final int LDR_SEARCH = 16 << 20;
    private static final int MAX_STRING = 64 << 20;
    private static final long FILETIME_EPOCH = 11644473600000L;
    private static final Charset ANSI = Charset.isSupported("windows-1252") ? Charset.forName("windows-1252") : StandardCharsets.ISO_8859_1;

    /** Random access to the installer. */
    interface Source extends Closeable {
        long length() throws IOException;

        /** Reads exactly len bytes at pos. */
        void readFully(long pos, byte[] b, int off, int len) throws IOException;
    }

    /** A file as a source. */
    static Source fileSource(final RandomAccessFile raf) {
        return new Source() {
            @Override
            public long length() throws IOException {
                return raf.length();
            }

            @Override
            public void readFully(final long pos, final byte[] b, final int off, final int len) throws IOException {
                raf.seek(pos);
                raf.readFully(b, off, len);
            }

            @Override
            public void close() throws IOException {
                raf.close();
            }
        };
    }

    /** Encryption schemes. */
    enum Crypt {
        NONE("none"), RC4("RC4"), XCHACHA("XChaCha20");

        final String label;

        Crypt(final String label) {
            this.label = label;
        }
    }

    /** A file to install: destination path and index of its data. */
    static final class Item {
        final String path;
        final int location;

        Item(final String path, final int location) {
            this.path = path;
            this.location = location;
        }
    }

    /** Where and how the data of a file is stored. */
    static final class Location {
        int firstSlice;
        int lastSlice;
        long startOffset;
        long chunkSuboffset;
        long size;
        long chunkPackedSize;
        byte[] hash;
        long time;
        boolean compressed;
        boolean encrypted;
        boolean callOptimized;
    }

    final File file;
    private String name;
    private final Source src;
    final String setupId;
    private final Map<String, String> lay;
    final boolean unicode;
    private long offset0;
    private long offset1;
    String appName = "";
    String appVersion = "";
    String method;
    int slicesPerDisk = 1;
    Crypt crypt = Crypt.NONE;
    boolean fullEncryption;
    boolean passwordProtected;
    final List<Item> items = new ArrayList<Item>();
    Location[] locations = new Location[0];
    private String hashName;

    // encryption material
    private byte[] password;
    private byte[] rc4Salt;
    private byte[] rc4Check;
    private byte[] kdfSalt;
    private int kdfIterations;
    private byte[] baseNonce;
    private int passwordTest;
    private byte[] key;
    private boolean rc4Checked;

    private InnoSetupArchive(final File file, final Source src, final String setupId, final Map<String, String> lay) {
        this.file = file;
        this.src = src;
        this.setupId = setupId;
        this.lay = lay;
        this.unicode = "1".equals(lay.get("u"));
    }

    // =========================================================================
    // Opening
    // =========================================================================

    /** Position of the loader offset table, or -1. */
    static long findOffsetTable(final Source src) throws IOException {
        final long len = Math.min(src.length(), LDR_SEARCH);
        final byte[] buf = new byte[1 << 20];
        long base = 0;
        while (base < len) {
            final int n = (int) Math.min(buf.length, len - base);
            src.readFully(base, buf, 0, n);
            for (int i = 0; i + LDR_MAGIC.length <= n; i++) {
                if (buf[i] == 'r' && matches(buf, i, LDR_MAGIC)) return base + i;
            }
            if (base + n >= len) break;
            base += n - LDR_MAGIC.length;
        }
        return -1;
    }

    /**
     * Opens an installer.
     *
     * @param password password given by the user (UTF-8), or null
     */
    static InnoSetupArchive open(final File file, final byte[] password) throws IOException {
        final Source src = fileSource(new RandomAccessFile(file, "r"));
        boolean ok = false;
        try {
            final InnoSetupArchive a = open(src, file, file.getName(), password);
            ok = true;
            return a;
        } finally {
            if (!ok) src.close();
        }
    }

    /**
     * Reads the setup data of an installer.
     *
     * @param file the installer file, to find the setup-N.bin data files (null: data not read)
     * @param name name of the installer file (gives the names of the data files)
     */
    static InnoSetupArchive open(final Source src, final File file, final String name, final byte[] password) throws IOException {
        final long table = findOffsetTable(src);
        if (table < 0) throw new ArcanaUnsupportedFormatException("Not an Inno Setup installer (or one older than 5.1.5)");
        final byte[] t = new byte[64];
        src.readFully(table, t, 0, (int) Math.min(64, src.length() - table));
        final int version = le32(t, 12);
        final long off0;
        final long off1;
        final long total;
        if (version == 1) {
            checkCrc(t, 40, le32(t, 40), "loader offset table");
            total = u32(t, 16);
            off0 = u32(t, 32);
            off1 = u32(t, 36);
        } else if (version == 2) {
            checkCrc(t, 60, le32(t, 60), "loader offset table");
            total = le64(t, 16);
            off0 = le64(t, 40);
            off1 = le64(t, 48);
        } else {
            throw new ArcanaUnsupportedFormatException("Unsupported Inno Setup loader table version " + version);
        }
        if (src.length() < total) throw new ArcanaCorruptedException("Inno Setup installer truncated (" + src.length() + " of " + total + " bytes)");
        if (off0 <= 0 || off0 + 64 > src.length()) throw new ArcanaCorruptedException("Invalid Inno Setup data offset");
        final String id = setupIdAt(src, off0);
        final Map<String, String> lay = InnoLayouts.get(id);
        if (lay == null) throw new ArcanaUnsupportedFormatException("Unsupported Inno Setup version: \"" + id + "\" (supported: " + InnoLayouts.range() + ")");
        final InnoSetupArchive a = new InnoSetupArchive(file, src, id, lay);
        a.name = name;
        a.offset0 = off0;
        a.offset1 = off1;
        a.password = password;
        a.readSetupData();
        return a;
    }

    private static String setupIdAt(final Source src, final long off0) throws IOException {
        final byte[] idb = new byte[64];
        src.readFully(off0, idb, 0, 64);
        int idLen = 0;
        while (idLen < 64 && idb[idLen] != 0) idLen++;
        final String id = new String(idb, 0, idLen, StandardCharsets.ISO_8859_1);
        if (!id.startsWith("Inno Setup Setup Data")) throw new ArcanaCorruptedException("Inno Setup data not found");
        return id;
    }

    /** "6.4.3", "5.5.7 (u)"... from the SetupID. */
    String formatVersion() {
        return formatVersion(setupId);
    }

    /** "Inno Setup Setup Data (5.5.7) (u)" gives "5.5.7 Unicode"; old ANSI builds give "5.5.7 ANSI". */
    static String formatVersion(final String setupId) {
        final int a = setupId.indexOf('(');
        final int b = setupId.indexOf(')', a + 1);
        if (a < 0 || b < 0) return setupId;
        final String v = setupId.substring(a + 1, b);
        if (setupId.endsWith("(u)")) return v + " Unicode";
        return v.startsWith("5.") ? v + " ANSI" : v;
    }

    /** The SetupID of an installer (format version), or null if it cannot be read. */
    static String readSetupId(final Source src) {
        try {
            final long table = findOffsetTable(src);
            if (table < 0) return null;
            final byte[] t = new byte[64];
            src.readFully(table, t, 0, (int) Math.min(64, src.length() - table));
            final int version = le32(t, 12);
            final long off0 = version == 1 ? u32(t, 32) : version == 2 ? le64(t, 40) : -1;
            return off0 > 0 && off0 + 64 <= src.length() ? setupIdAt(src, off0) : null;
        } catch (final IOException | RuntimeException e) {
            return null;
        }
    }

    private int num(final String k) {
        final String v = lay.get(k);
        return v == null ? -1 : Integer.parseInt(v);
    }

    private void readSetupData() throws IOException {
        long pos = offset0 + 64;
        final int encHdr = num("enchdr");
        if (encHdr > 0) {
            final byte[] h = new byte[4 + encHdr];
            src.readFully(pos, h, 0, h.length);
            final CRC32 crc = new CRC32();
            crc.update(h, 4, encHdr);
            if ((int) crc.getValue() != le32(h, 0)) throw new ArcanaCorruptedException("Inno Setup encryption header CRC error");
            final int use = h[4] & 0xff; // 0 none, 1 files, 2 everything
            kdfSalt = copy(h, 5, 16);
            kdfIterations = le32(h, 21);
            baseNonce = copy(h, 25, 24);
            passwordTest = le32(h, 49);
            if (use != 0) crypt = Crypt.XCHACHA;
            fullEncryption = use == 2;
            pos += h.length;
        }
        if (fullEncryption) needKey();

        // ---- block 1: header and entries ----
        final long[] next = new long[1];
        final Records r = new Records(block(pos, next, fullEncryption ? InnoCrypto.xchacha(key, baseNonce, 0, -2) : null), unicode);
        final String[] hs = r.strings(lay.get("H"));
        r.ansiStrings(lay.get("H"));
        final byte[] h = r.binary(lay.get("H"));
        appName = hs[num("H.AppName")];
        appVersion = hs[num("H.AppVersion")];
        final String[] methods = lay.get("cm").split("\\.");
        final int cm = h[num("H.CompressMethod")] & 0xff;
        if (cm >= methods.length) throw new ArcanaCorruptedException("Unknown Inno Setup compression method " + cm);
        method = methods[cm];
        slicesPerDisk = Math.max(1, le32(h, num("H.SlicesPerDisk")));
        final int opt = num("H.Options");
        passwordProtected = bit(h, opt, num("H.bit.Password"));
        if (lay.containsKey("H.PasswordHash")) {
            if (bit(h, opt, num("H.bit.EncryptionUsed"))) crypt = Crypt.RC4;
            rc4Check = copy(h, num("H.PasswordHash"), 20);
            rc4Salt = copy(h, num("H.PasswordSalt"), 8);
        } else if (lay.containsKey("H.EncryptionKDFSalt")) {
            if (bit(h, opt, num("H.bit.EncryptionUsed"))) crypt = Crypt.XCHACHA;
            kdfSalt = copy(h, num("H.EncryptionKDFSalt"), 16);
            kdfIterations = le32(h, num("H.EncryptionKDFIterations"));
            baseNonce = copy(h, num("H.EncryptionBaseNonce"), 24);
            passwordTest = le32(h, num("H.PasswordTest"));
        }
        // entries before the files: skipped
        for (final String e : new String[] {"Language", "CustomMessage", "Permission", "Type", "Component", "Task", "Dir", "ISSigKey"}) {
            if (!lay.containsKey(e)) continue;
            final int count = le32(h, num("H.Num" + e + "Entries"));
            for (int i = 0; i < count; i++) r.skip(lay.get(e));
        }
        final int fileCount = le32(h, num("H.NumFileEntries"));
        final int locCount = le32(h, num("H.NumFileLocationEntries"));
        if (fileCount < 0 || locCount < 0) throw new ArcanaCorruptedException("Invalid Inno Setup entry counts");
        final String fileLayout = lay.get("File");
        final int src = num("F.SourceFilename");
        final int dst = num("F.DestName");
        final List<String> rawPaths = new ArrayList<String>();
        final List<Integer> rawLocs = new ArrayList<Integer>();
        for (int i = 0; i < fileCount; i++) {
            final String[] s = r.strings(fileLayout);
            r.ansiStrings(fileLayout);
            final byte[] b = r.binary(fileLayout);
            final int loc = le32(b, num("F.LocationEntry"));
            final int type = b[num("F.FileType")] & 0xff;
            if (type != 0 || loc < 0) continue; // uninstaller, or external file read at install time
            String dest = s[dst];
            if (dest.endsWith("\\") || dest.isEmpty()) dest = dest + baseName(s[src]);
            rawPaths.add(dest);
            rawLocs.add(loc);
        }

        // ---- block 2: file locations ----
        final InputStream in2 = block(next[0], null, fullEncryption ? InnoCrypto.xchacha(key, baseNonce, 0, -3) : null);
        final int locSize = num("Location");
        final byte[] lb = new byte[locSize];
        locations = new Location[locCount];
        final int flagsOff = num("L.Flags");
        final int startSize = num("L.StartOffset#");
        hashName = lay.get("L.hash");
        final int hashLen = "SHA256Sum".equals(hashName) ? 32 : "SHA1Sum".equals(hashName) ? 20 : "MD5Sum".equals(hashName) ? 16 : 4;
        final long tz = TimeZone.getDefault().getRawOffset();
        for (int i = 0; i < locCount; i++) {
            readFully(in2, lb, 0, locSize);
            final Location l = new Location();
            l.firstSlice = le32(lb, num("L.FirstSlice"));
            l.lastSlice = le32(lb, num("L.LastSlice"));
            l.startOffset = startSize == 8 ? le64(lb, num("L.StartOffset")) : u32(lb, num("L.StartOffset"));
            l.chunkSuboffset = le64(lb, num("L.ChunkSuboffset"));
            l.size = le64(lb, num("L.OriginalSize"));
            l.chunkPackedSize = le64(lb, num("L.ChunkCompressedSize"));
            l.hash = copy(lb, num("L.hashOff"), hashLen);
            l.compressed = bit(lb, flagsOff, num("L.bit.ChunkCompressed"));
            l.encrypted = bit(lb, flagsOff, num("L.bit.ChunkEncrypted"));
            l.callOptimized = bit(lb, flagsOff, num("L.bit.CallInstructionOptimized"));
            final long ft = le64(lb, num("L.TimeStamp"));
            if (ft > 0) {
                l.time = ft / 10000 - FILETIME_EPOCH;
                if (!bit(lb, flagsOff, num("L.bit.TimeStampInUTC"))) l.time -= tz;
            }
            if (l.size < 0 || l.chunkSuboffset < 0 || l.chunkPackedSize < 0 || l.firstSlice < 0 || l.lastSlice < l.firstSlice) throw new ArcanaCorruptedException("Invalid Inno Setup file location " + i);
            locations[i] = l;
        }

        // ---- names ----
        final Set<String> used = new HashSet<String>();
        final Set<String> seen = new HashSet<String>();
        for (int i = 0; i < rawPaths.size(); i++) {
            final int loc = rawLocs.get(i);
            if (loc >= locCount) throw new ArcanaCorruptedException("Invalid Inno Setup file location index " + loc);
            final String path = outputPath(rawPaths.get(i));
            if (!seen.add(path.toLowerCase() + '\0' + loc)) continue; // same file, same data: listed twice in the script
            items.add(new Item(unique(path, used), loc));
        }
    }

    // =========================================================================
    // Names
    // =========================================================================

    /**
     * Destination path to archive path: "{app}\x\y" gives "x/y"; the other
     * constants become a first directory: "{sys}\a.dll" gives "sys/a.dll",
     * "{code:GetDir|x}\b" gives "code_GetDir_x/b".
     */
    static String outputPath(final String dest) {
        String s = dest.replace('/', '\\');
        if (s.regionMatches(true, 0, "{app}", 0, 5)) s = s.substring(5);
        final StringBuilder sb = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c == '{') {
                depth++;
                continue;
            }
            if (c == '}' && depth > 0) {
                depth--;
                continue;
            }
            if (depth > 0) {
                sb.append(c == ':' || c == '|' || c == '\\' || c == ',' || c == '"' ? '_' : c);
            } else {
                sb.append(c == '\\' ? '/' : c);
            }
        }
        final StringBuilder out = new StringBuilder();
        for (final String part : sb.toString().split("/")) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) continue;
            if (out.length() > 0) out.append('/');
            out.append(part);
        }
        return out.length() == 0 ? "_" : out.toString();
    }

    /** The second file with the same path (other language or architecture) is named "name (2).ext". */
    private static String unique(final String path, final Set<String> used) {
        if (used.add(path.toLowerCase())) return path;
        final int slash = path.lastIndexOf('/');
        final int dot = path.lastIndexOf('.');
        final String stem = dot > slash + 1 ? path.substring(0, dot) : path;
        final String ext = dot > slash + 1 ? path.substring(dot) : "";
        for (int n = 2;; n++) {
            final String p = stem + " (" + n + ")" + ext;
            if (used.add(p.toLowerCase())) return p;
        }
    }

    private static String baseName(final String p) {
        final int i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
        return i < 0 ? p : p.substring(i + 1);
    }

    // =========================================================================
    // Encryption
    // =========================================================================

    /** The password encoded like Inno Setup hashes it. */
    private byte[] passwordBytes() {
        final String p = new String(password, StandardCharsets.UTF_8);
        return p.getBytes(unicode ? StandardCharsets.UTF_16LE : ANSI);
    }

    /** Derives and checks the XChaCha20 key (6.4 and later). */
    private void needKey() throws IOException {
        if (key != null) return;
        if (password == null) throw new ArcanaEncryptedException("This Inno Setup installer is encrypted: a password is required");
        final byte[] k = InnoCrypto.deriveKey(passwordBytes(), kdfSalt, kdfIterations);
        if (!InnoCrypto.xchachaPasswordOk(k, baseNonce, passwordTest)) throw new ArcanaEncryptedException("Wrong password for this Inno Setup installer");
        key = k;
    }

    /** Checks the password of the RC4 era (up to 6.3). */
    private void needRc4Password() throws IOException {
        if (rc4Checked) return;
        if (password == null) throw new ArcanaEncryptedException("The files of this Inno Setup installer are encrypted: a password is required");
        if (!InnoCrypto.rc4PasswordOk(rc4Salt, rc4Check, passwordBytes())) throw new ArcanaEncryptedException("Wrong password for this Inno Setup installer");
        rc4Checked = true;
    }

    // =========================================================================
    // Compressed blocks of the setup data
    // =========================================================================

    /** Decompressed content of the block at pos; next[0] receives the position after it. */
    private InputStream block(final long pos, final long[] next, final InnoCrypto.Cipher cipher) throws IOException {
        final int sizeLen = num("stored");
        final byte[] h = new byte[4 + sizeLen + 1];
        src.readFully(pos, h, 0, h.length);
        final CRC32 crc = new CRC32();
        crc.update(h, 4, sizeLen + 1);
        if ((int) crc.getValue() != le32(h, 0)) throw new ArcanaCorruptedException("Inno Setup header block CRC error");
        final long stored = sizeLen == 8 ? le64(h, 4) : u32(h, 4);
        final boolean compressed = h[4 + sizeLen] != 0;
        final long start = pos + h.length;
        if (stored < 0 || start + stored > src.length()) throw new ArcanaCorruptedException("Inno Setup header block truncated");
        if (next != null) next[0] = start + stored;
        InputStream in = new PieceStream(start, stored);
        if (cipher != null) in = InnoCrypto.decrypting(in, cipher);
        if (!compressed) return in;
        final byte[] props = new byte[5];
        readFully(in, props, 0, 5);
        return new LZMAInputStream(in, -1, props[0], dictSize(le32(props, 1), 1L << 28));
    }

    /** The data of a block without the CRC that precedes every 4 KiB piece (checked). */
    private final class PieceStream extends InputStream {
        private final byte[] piece = new byte[4096];
        private long pos;
        private long left;
        private int avail;
        private int next;

        PieceStream(final long pos, final long length) {
            this.pos = pos;
            this.left = length;
        }

        @Override
        public int read() throws IOException {
            final byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            if (next == avail) {
                if (left == 0) return -1;
                if (left < 5) throw new ArcanaCorruptedException("Inno Setup header block damaged");
                final byte[] c = new byte[4];
                src.readFully(pos, c, 0, 4);
                final int n = (int) Math.min(4096, left - 4);
                src.readFully(pos + 4, piece, 0, n);
                pos += 4 + n;
                left -= 4 + n;
                final CRC32 crc = new CRC32();
                crc.update(piece, 0, n);
                if ((int) crc.getValue() != le32(c, 0)) throw new ArcanaCorruptedException("Inno Setup header block CRC error");
                avail = n;
                next = 0;
            }
            final int n = Math.min(len, avail - next);
            System.arraycopy(piece, next, b, off, n);
            next += n;
            return n;
        }
    }

    /** Reads the records of a block: strings (32-bit byte length + data) then a binary part. */
    private static final class Records {
        private final InputStream in;
        private final boolean unicode;

        Records(final InputStream in, final boolean unicode) {
            this.in = in;
            this.unicode = unicode;
        }

        String[] strings(final String layout) throws IOException {
            final int n = Integer.parseInt(layout.substring(0, layout.indexOf('.')));
            final String[] s = new String[n];
            for (int i = 0; i < n; i++) {
                final byte[] b = string();
                s[i] = new String(b, unicode ? StandardCharsets.UTF_16LE : ANSI);
            }
            return s;
        }

        void ansiStrings(final String layout) throws IOException {
            final String[] p = layout.split("\\.");
            for (int i = 0, n = Integer.parseInt(p[1]); i < n; i++) string();
        }

        byte[] binary(final String layout) throws IOException {
            final String[] p = layout.split("\\.");
            final byte[] b = new byte[Integer.parseInt(p[2])];
            readFully(in, b, 0, b.length);
            return b;
        }

        void skip(final String layout) throws IOException {
            final String[] p = layout.split("\\.");
            for (int i = 0, n = Integer.parseInt(p[0]) + Integer.parseInt(p[1]); i < n; i++) string();
            readFully(in, new byte[Integer.parseInt(p[2])], 0, Integer.parseInt(p[2]));
        }

        private byte[] string() throws IOException {
            final byte[] l = new byte[4];
            readFully(in, l, 0, 4);
            final int len = le32(l, 0);
            if (len < 0 || len > MAX_STRING) throw new ArcanaCorruptedException("Invalid Inno Setup string length " + len);
            final byte[] b = new byte[len];
            readFully(in, b, 0, len);
            return b;
        }
    }

    // =========================================================================
    // File data
    // =========================================================================

    /** Total uncompressed size of the chunk holding a location (end of its last file). */
    long chunkSize(final Location l) {
        long end = 0;
        for (final Location o : locations) {
            if (o.firstSlice == l.firstSlice && o.startOffset == l.startOffset) end = Math.max(end, o.chunkSuboffset + o.size);
        }
        return end;
    }

    /** Decompressed data of the chunk holding l, positioned at the start of the chunk. */
    InputStream openChunk(final Location l) throws IOException {
        InputStream in = new SliceStream(l);
        if (l.encrypted) {
            if (crypt == Crypt.RC4) {
                needRc4Password();
                final byte[] salt = new byte[8];
                readFully(in, salt, 0, 8);
                in = InnoCrypto.decrypting(in, InnoCrypto.rc4(salt, passwordBytes()));
            } else {
                needKey();
                in = InnoCrypto.decrypting(in, InnoCrypto.xchacha(key, baseNonce, l.startOffset, l.firstSlice));
            }
        }
        if (!l.compressed) return in;
        final long total = chunkSize(l);
        if ("Zip".equals(method)) return new InflaterInputStream(in, new Inflater(false), 65536);
        if ("Bzip".equals(method)) return new BZip2InputStream(in, false);
        if ("LZMA".equals(method)) {
            final byte[] props = new byte[5];
            readFully(in, props, 0, 5);
            return new LZMAInputStream(in, -1, props[0], dictSize(le32(props, 1), total));
        }
        if ("LZMA2".equals(method)) {
            final int p = readByte(in);
            if (p > 40) throw new ArcanaCorruptedException("Invalid LZMA2 dictionary size in Inno Setup data");
            final long dict = p == 40 ? 0xffffffffL : (2L | (p & 1)) << (p / 2 + 11);
            return new LZMA2InputStream(in, dictSize(dict, total));
        }
        if ("Stored".equals(method)) return in;
        throw new ArcanaUnsupportedFormatException("Inno Setup compression method " + method + " is not supported");
    }

    /** The dictionary never needs to be larger than the data (saves memory with large dictionaries). */
    private static int dictSize(final long declared, final long dataSize) {
        long d = declared & 0xffffffffL;
        if (dataSize > 0) d = Math.min(d, Math.max(4096, dataSize));
        return (int) Math.min(d, Integer.MAX_VALUE - 64);
    }

    /** The compressed bytes of a chunk, after its "zlb" id, over as many slices as needed. */
    private final class SliceStream extends InputStream {
        private final Location loc;
        private Source in;
        private boolean own;
        private int slice;
        private long pos;
        private long sliceEnd;
        private long left;

        SliceStream(final Location loc) throws IOException {
            this.loc = loc;
            this.left = loc.chunkPackedSize + (loc.encrypted && crypt == Crypt.RC4 ? 8 : 0);
            openSlice(loc.firstSlice);
            pos = offset1 + loc.startOffset;
            if (pos + 4 > sliceEnd) throw new ArcanaCorruptedException("Inno Setup chunk outside its slice");
            final byte[] id = new byte[4];
            in.readFully(pos, id, 0, 4);
            if (!matches(id, 0, CHUNK_ID)) throw new ArcanaCorruptedException("Inno Setup data chunk not found (bad offset or damaged installer)");
            pos += 4;
        }

        private void openSlice(final int s) throws IOException {
            closeSlice();
            slice = s;
            if (offset1 != 0) {
                in = src;
                own = false;
                sliceEnd = src.length();
                return;
            }
            if (file == null) throw new ArcanaUnsupportedFormatException("Inno Setup data files cannot be read here");
            final File f = sliceFile(s);
            if (!f.isFile()) throw new ArcanaCorruptedException("Missing Inno Setup data file " + f.getName() + " (it must be next to the installer)");
            in = fileSource(new RandomAccessFile(f, "r"));
            own = true;
            final int idLen = 8;
            final int sizeLen = num("slice");
            final byte[] h = new byte[idLen + sizeLen];
            in.readFully(0, h, 0, h.length);
            final String want = lay.get("sliceid");
            for (int i = 0; i < 7; i++) {
                if (h[i] != want.charAt(i)) throw new ArcanaCorruptedException("Invalid Inno Setup slice header in " + f.getName());
            }
            final long total = sizeLen == 8 ? le64(h, idLen) : u32(h, idLen);
            if (total != in.length()) throw new ArcanaCorruptedException("Inno Setup slice " + f.getName() + " truncated");
            sliceEnd = total;
            pos = h.length;
        }

        private void closeSlice() throws IOException {
            if (own && in != null) in.close();
            in = null;
        }

        @Override
        public int read() throws IOException {
            final byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(final byte[] b, final int off, final int len) throws IOException {
            if (len == 0) return 0;
            if (left <= 0) return -1;
            if (pos >= sliceEnd) {
                if (slice >= loc.lastSlice) throw new ArcanaCorruptedException("Inno Setup data truncated");
                openSlice(slice + 1);
            }
            final int n = (int) Math.min(Math.min(len, left), sliceEnd - pos);
            in.readFully(pos, b, off, n);
            pos += n;
            left -= n;
            return n;
        }

        @Override
        public void close() throws IOException {
            closeSlice();
        }
    }

    /** setup-1.bin, or setup-1a.bin, setup-1b.bin... when a disk holds several slices. */
    File sliceFile(final int s) {
        return new File(file.getAbsoluteFile().getParentFile(), sliceName(s));
    }

    /** Name of the data file holding slice s. */
    String sliceName(final int s) {
        String base = name == null ? "setup.exe" : name;
        final int dot = base.lastIndexOf('.');
        if (dot > 0) base = base.substring(0, dot);
        final int major = s / slicesPerDisk + 1;
        return slicesPerDisk == 1 ? base + "-" + major + ".bin" : base + "-" + major + (char) ('a' + s % slicesPerDisk) + ".bin";
    }

    /** Data files needed next to the installer, null when the data is inside it. */
    boolean externalData() {
        return offset1 == 0;
    }

    /** Name of the checksum of the files (SHA256Sum, SHA1Sum...). */
    String hashName() {
        return hashName;
    }

    /**
     * Undoes the x86 CALL/JMP address conversion of one 64 KiB buffer
     * ("CallInstructionOptimized" files): Inno converts each buffer separately.
     */
    static void untransformCalls(final byte[] b, final int size, final int addrOffset) {
        if (size < 5) return;
        final int end = size - 4;
        int i = 0;
        while (i < end) {
            final int op = b[i] & 0xff;
            if (op == 0xE8 || op == 0xE9) {
                i++;
                final int hi = b[i + 3] & 0xff;
                if (hi == 0x00 || hi == 0xFF) {
                    final int addr = (addrOffset + i + 4) & 0xFFFFFF;
                    int rel = (b[i] & 0xff) | (b[i + 1] & 0xff) << 8 | (b[i + 2] & 0xff) << 16;
                    rel -= addr;
                    if ((rel & 0x800000) != 0) b[i + 3] = (byte) ~b[i + 3];
                    b[i] = (byte) rel;
                    b[i + 1] = (byte) (rel >> 8);
                    b[i + 2] = (byte) (rel >> 16);
                }
                i += 4;
            } else {
                i++;
            }
        }
    }

    @Override
    public void close() throws IOException {
        src.close();
    }

    // =========================================================================
    // Low level
    // =========================================================================

    static boolean matches(final byte[] b, final int off, final byte[] m) {
        if (off + m.length > b.length) return false;
        for (int i = 0; i < m.length; i++) {
            if (b[off + i] != m[i]) return false;
        }
        return true;
    }

    private static void checkCrc(final byte[] b, final int len, final int expected, final String what) throws IOException {
        final CRC32 crc = new CRC32();
        crc.update(b, 0, len);
        if ((int) crc.getValue() != expected) throw new ArcanaCorruptedException("Inno Setup " + what + " CRC error");
    }

    private static boolean bit(final byte[] b, final int off, final int bit) {
        return bit >= 0 && (b[off + bit / 8] >> (bit % 8) & 1) != 0;
    }

    static void readFully(final InputStream in, final byte[] b, final int off, final int len) throws IOException {
        int n = 0;
        while (n < len) {
            final int r = in.read(b, off + n, len - n);
            if (r < 0) throw new EOFException("Inno Setup data truncated");
            n += r;
        }
    }

    private static int readByte(final InputStream in) throws IOException {
        final int b = in.read();
        if (b < 0) throw new EOFException("Inno Setup data truncated");
        return b;
    }

    private static byte[] copy(final byte[] b, final int off, final int len) {
        final byte[] r = new byte[len];
        System.arraycopy(b, off, r, 0, len);
        return r;
    }

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    static long u32(final byte[] b, final int p) {
        return le32(b, p) & 0xffffffffL;
    }

    static long le64(final byte[] b, final int p) {
        return u32(b, p) | (long) le32(b, p + 4) << 32;
    }
}
