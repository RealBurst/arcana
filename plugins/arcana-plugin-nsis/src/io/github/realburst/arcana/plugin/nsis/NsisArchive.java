/*
 * Copyright 2026 Stephane Bury
 * SPDX-License-Identifier: Apache-2.0
 */
package io.github.realburst.arcana.plugin.nsis;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the structure of an NSIS installer: first header, compression mode,
 * installer header and the list of files written by the "File" instructions.
 *
 * <p>Layout (NSIS 2.x and 3.x, see Source/exehead/fileform.h):</p>
 * <ul>
 * <li>the "first header" (28 bytes) sits at a 512-byte aligned offset after
 *     the executable stub: flags, 0xDEADBEEF, "NullsoftInst", header length,
 *     length of all the following data;</li>
 * <li>non-solid installers: [int len][header block][int len][file 1][int len][file 2]...,
 *     bit 31 of each length tells whether the block is compressed, and each
 *     compressed block is an independent stream;</li>
 * <li>solid installers ("SetCompressor /SOLID"): everything after the first
 *     header is one compressed stream holding the same sequence, without the
 *     compression bit;</li>
 * <li>the header holds 8 block descriptors (pages, sections, entries, strings,
 *     language tables, ...). The entries are the compiled script; the files are
 *     found in the EW_EXTRACTFILE instructions.</li>
 * </ul>
 */
final class NsisArchive {

    /** One file of the installer. */
    static final class Item {
        /** Path relative to $INSTDIR, '/' separated ("$PLUGINSDIR/x.dll" for other roots). */
        String name;
        /** Offset of the data block, relative to the start of the data. */
        final long offset;
        /** Unix time in seconds, or -1. */
        final long time;
        /** Size of the stored block (non-solid only), or -1. */
        long packedSize = -1;
        /** Size of the file, or -1 while unknown. */
        long size = -1;

        Item(final String name, final long offset, final long time) {
            this.name = name;
            this.offset = offset;
            this.time = time;
        }
    }

    static final int FIRST_HEADER_SIZE = 28;
    private static final int FH_FLAGS_UNINSTALL = 1;
    private static final int ENTRY_SIZE = 28;
    private static final int EW_CREATEDIR = 11;
    private static final int EW_EXTRACTFILE = 20;
    private static final int NB_ENTRIES = 2;
    private static final int NB_STRINGS = 3;
    private static final int NB_LANGTABLES = 4;

    final NsisStreams.Source src;
    /** Position of the first header in the file. */
    final long firstHeader;
    final int flags;
    final int headerLength;
    /** End of the installer data in the file. */
    final long end;
    final boolean solid;
    final NsisStreams.Method method;
    /** Non-solid: position of the data in the file. */
    final long dataStart;
    final boolean unicode;
    /** 2 for NSIS 2.x (including "Unicode NSIS" by Jim Park), 3 for NSIS 3.x. */
    final int major;
    final boolean pointer64;
    final List<Item> items = new ArrayList<Item>();

    private final byte[] header;
    private int stringsStart;
    private int stringsEnd;
    private final boolean parkCodes;
    private static final char[] ANSI = ansiTable();

    private NsisArchive(final NsisStreams.Source src, final long fh) throws IOException {
        this.src = src;
        this.firstHeader = fh;
        final byte[] b = new byte[FIRST_HEADER_SIZE];
        NsisStreams.readFully(src, fh, b);
        flags = le32(b, 0);
        headerLength = le32(b, 20);
        final long following = le32(b, 24) & 0xffffffffL;
        if (headerLength <= 0 || following < FIRST_HEADER_SIZE + 4) throw new IOException("Invalid NSIS first header");
        end = Math.min(src.length(), fh + following);

        final long start = fh + FIRST_HEADER_SIZE;
        final byte[] head = new byte[16];
        NsisStreams.readFully(src, start, head);
        byte[] hdr = null;
        NsisStreams.Method m = null;
        long data = -1;
        // non-solid: [int length | 0x80000000][compressed header], or [int length][stored header]
        final long first = le32(head, 0) & 0xffffffffL;
        final long blockLen = first & 0x7fffffffL;
        if (blockLen >= 1 && start + 4 + blockLen <= end) {
            final boolean compressed = (first & 0x80000000L) != 0;
            if (!compressed && blockLen == headerLength) {
                hdr = new byte[headerLength];
                NsisStreams.readFully(src, start + 4, hdr);
                m = NsisStreams.Method.STORED;
            } else if (compressed) {
                m = NsisStreams.detect(head, 4);
                hdr = tryDecode(NsisStreams.range(src, start + 4, blockLen), m, false);
            }
            if (hdr != null && validBlocks(hdr, false) == null && validBlocks(hdr, true) == null) hdr = null;
            if (hdr != null) data = start + 4 + blockLen;
        }
        if (hdr == null) {
            // solid: one stream "[int header length][header][int len][file]..."
            m = NsisStreams.detect(head, 0);
            hdr = tryDecode(NsisStreams.range(src, start, end - start), m, true);
            if (hdr == null) throw new IOException("Unsupported or damaged NSIS installer (header not readable)");
            solid = true;
        } else {
            solid = false;
        }
        header = hdr;
        method = m;
        dataStart = data;

        int[] blocks = validBlocks(header, false);
        boolean p64 = false;
        if (blocks == null) {
            blocks = validBlocks(header, true);
            p64 = true;
        }
        if (blocks == null) throw new IOException("Unsupported NSIS header layout");
        pointer64 = p64;
        stringsStart = blocks[NB_STRINGS * 2];
        stringsEnd = blocks[NB_LANGTABLES * 2];
        unicode = looksUnicode();
        parkCodes = unicode && countParkCodes() > 0;
        major = unicode ? (parkCodes ? 2 : 3) : ansiMajor();
        readEntries(blocks[NB_ENTRIES * 2], blocks[NB_ENTRIES * 2 + 1]);
    }

    /** Opens the installer, or throws an IOException if the file is not a supported NSIS installer. */
    static NsisArchive open(final NsisStreams.Source src) throws IOException {
        final long fh = findFirstHeader(src);
        if (fh < 0) throw new IOException("Not an NSIS installer");
        return new NsisArchive(src, fh);
    }

    /** True for an uninstaller produced by "WriteUninstaller". */
    boolean isUninstaller() {
        return (flags & FH_FLAGS_UNINSTALL) != 0;
    }

    // =========================================================================
    // First header
    // =========================================================================

    /** True if b[off..off+28) is an NSIS first header. */
    static boolean isFirstHeader(final byte[] b, final int off) {
        return off + FIRST_HEADER_SIZE <= b.length
                && (le32(b, off) & ~15) == 0
                && le32(b, off + 4) == 0xDEADBEEF
                && le32(b, off + 8) == 0x6C6C754E   // "Null"
                && le32(b, off + 12) == 0x74666F73  // "soft"
                && le32(b, off + 16) == 0x74736E49  // "Inst"
                && le32(b, off + 20) > 0
                && le32(b, off + 24) != 0;
    }

    /** Position of the first header (512-byte aligned, like the NSIS stub searches it), or -1. */
    static long findFirstHeader(final NsisStreams.Source src) throws IOException {
        final long len = src.length();
        final byte[] buf = new byte[1 << 20];
        for (long base = 512; base + FIRST_HEADER_SIZE <= len; base += buf.length) {
            final int n = (int) Math.min(buf.length, len - base);
            int got = 0;
            while (got < n) {
                final int k = src.read(base + got, buf, got, n - got);
                if (k < 0) break;
                got += k;
            }
            for (int off = 0; off + FIRST_HEADER_SIZE <= got; off += 512) {
                if (isFirstHeader(buf, off)) return base + off;
            }
            // a header that straddles two buffers starts at an aligned offset of the next round anyway
            if (got < n) break;
        }
        return -1;
    }

    // =========================================================================
    // Header decoding
    // =========================================================================

    /** Decodes the header from a non-solid block (exactly headerLength bytes) or from the start of the solid stream. */
    private byte[] tryDecode(final InputStream raw, final NsisStreams.Method m, final boolean solidStream) {
        try (InputStream in = NsisStreams.decoder(raw, m)) {
            if (solidStream && NsisStreams.readInt(in) != headerLength) return null;
            final byte[] h = new byte[headerLength];
            NsisStreams.readFully(in, h, headerLength);
            return h;
        } catch (final IOException | RuntimeException e) {
            return null; // wrong guess: the caller tries the other layout
        }
    }

    /** Offsets and counts of the 8 header blocks, or null if they do not make sense. */
    private int[] validBlocks(final byte[] h, final boolean p64) {
        final int stride = p64 ? 16 : 8;
        if (4 + 8 * stride > h.length) return null;
        final int[] r = new int[16];
        for (int i = 0; i < 8; i++) {
            final int p = 4 + i * stride;
            r[i * 2] = le32(h, p);
            if (p64 && le32(h, p + 4) != 0) return null;
            r[i * 2 + 1] = le32(h, p + (p64 ? 8 : 4));
        }
        final int entries = r[NB_ENTRIES * 2];
        final int count = r[NB_ENTRIES * 2 + 1];
        final int strings = r[NB_STRINGS * 2];
        final int lang = r[NB_LANGTABLES * 2];
        if (entries < 4 + 8 * stride || count < 0 || count > (h.length - entries) / ENTRY_SIZE) return null;
        if (strings < entries + (long) count * ENTRY_SIZE || lang <= strings || lang > h.length) return null;
        return r;
    }

    // =========================================================================
    // Strings
    // =========================================================================

    private boolean looksUnicode() {
        final int n = Math.min(stringsEnd - stringsStart, 8192) & ~1;
        if (n < 2) return false;
        int zeroOdd = 0;
        for (int i = 1; i < n; i += 2) {
            if (header[stringsStart + i] == 0) zeroOdd++;
        }
        return header[stringsStart] == 0 && header[stringsStart + 1] == 0 && zeroOdd * 2 > n / 2;
    }

    /** NSIS 2 codes variables with bytes 252..255, NSIS 3 with 1..4: counts which ones are followed by a coded short. */
    private int ansiMajor() {
        int v2 = 0;
        int v3 = 0;
        for (int i = stringsStart; i + 2 < stringsEnd; i++) {
            final int c = header[i] & 0xff;
            if ((header[i + 1] & 0x80) == 0 || (header[i + 2] & 0x80) == 0) continue;
            if (c >= 1 && c <= 3) v3++;
            else if (c >= 253) v2++;
        }
        return v2 > v3 ? 2 : 3;
    }

    private int countParkCodes() {
        int n = 0;
        for (int i = stringsStart; i + 3 < stringsEnd; i += 2) {
            final int c = (header[i] & 0xff) | (header[i + 1] & 0xff) << 8;
            if (c >= 0xE001 && c <= 0xE003) n++;
        }
        return n;
    }

    /** Code kinds after normalization. */
    private static final int LANG = 1;
    private static final int SHELL = 2;
    private static final int VAR = 3;
    private static final int SKIP = 4;

    /**
     * Expands string number idx: variables become "$NAME" ("$OUTDIR" is
     * replaced by outDir when given), shell folders "$PROGRAMFILES" etc.,
     * language strings "$(LSTR_n)".
     */
    String string(final int idx, final String outDir) {
        if (idx < 0) return "$(LSTR_" + (-idx - 1) + ")";
        final StringBuilder sb = new StringBuilder();
        int p = stringsStart + (unicode ? idx * 2 : idx);
        while (p < stringsEnd) {
            int c;
            if (unicode) {
                if (p + 1 >= stringsEnd) break;
                c = (header[p] & 0xff) | (header[p + 1] & 0xff) << 8;
                p += 2;
            } else {
                c = header[p++] & 0xff;
            }
            if (c == 0) break;
            final int code = codeOf(c);
            if (code == 0) {
                sb.append(unicode ? (char) c : ANSI[c]);
                continue;
            }
            if (code == SKIP) {
                if (unicode) {
                    if (p + 1 >= stringsEnd) break;
                    sb.append((char) ((header[p] & 0xff) | (header[p + 1] & 0xff) << 8));
                    p += 2;
                } else {
                    if (p >= stringsEnd) break;
                    sb.append(ANSI[header[p++] & 0xff]);
                }
                continue;
            }
            // 2 bytes of data: one wchar (Unicode) or two chars (ANSI)
            if (p + 1 >= stringsEnd) break;
            final int b0 = header[p] & 0xff;
            final int b1 = header[p + 1] & 0xff;
            p += 2;
            final int data = parkCodes ? ((b1 << 8 | b0) & 0x7FFF) : ((b1 & 0x7F) << 7 | (b0 & 0x7F));
            if (code == VAR) {
                if (data == 22 && outDir != null) sb.append(outDir);
                else sb.append(varName(data));
            } else if (code == SHELL) {
                sb.append(shellName(b0, b1));
            } else {
                sb.append("$(LSTR_").append(data).append(')');
            }
        }
        return sb.toString();
    }

    /** True if string idx starts with a variable, a shell folder or a language string (absolute path for NSIS). */
    private boolean startsWithCode(final int idx) {
        if (idx < 0) return true;
        final int p = stringsStart + (unicode ? idx * 2 : idx);
        if (p >= stringsEnd || (unicode && p + 1 >= stringsEnd)) return false;
        final int c = unicode ? (header[p] & 0xff) | (header[p + 1] & 0xff) << 8 : header[p] & 0xff;
        final int code = codeOf(c);
        return code != 0 && code != SKIP;
    }

    private int codeOf(final int c) {
        if (unicode) {
            if (parkCodes) {
                switch (c) {
                    case 0xE000: return SKIP;
                    case 0xE001: return VAR;
                    case 0xE002: return SHELL;
                    case 0xE003: return LANG;
                    default: return 0;
                }
            }
            return c >= 1 && c <= 4 ? c : 0;
        }
        if (major >= 3) return c >= 1 && c <= 4 ? c : 0;
        switch (c) {
            case 252: return SKIP;
            case 253: return VAR;
            case 254: return SHELL;
            case 255: return LANG;
            default: return 0;
        }
    }

    private static final String[] VARS = {
        "CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP", "PLUGINSDIR",
        "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK", "_OUTDIR"
    };

    private static String varName(final int v) {
        if (v < 10) return "$" + v;
        if (v < 20) return "$R" + (v - 10);
        if (v < 20 + VARS.length) return "$" + VARS[v - 20];
        return "$_" + (v - 20 - VARS.length) + "_";
    }

    private String shellName(final int user, final int common) {
        if ((user & 0x80) != 0) {
            // folder read from HKLM\Software\Microsoft\Windows\CurrentVersion, value = string (user & 0x3F)
            final String value = string(user & 0x3F, null);
            final String bits = (user & 0x40) != 0 ? "64" : "";
            if ("ProgramFilesDir".equalsIgnoreCase(value)) return "$PROGRAMFILES" + bits;
            if ("CommonFilesDir".equalsIgnoreCase(value)) return "$COMMONFILES" + bits;
            return "$(REG:" + value + ")";
        }
        if (user == 0x1A && common == 0x1A) return "$QUICKLAUNCH";
        final String n = csidl(user);
        if (n != null) return "$" + n;
        final String c = csidl(common);
        return c != null ? "$" + c : "$SHELL_" + user;
    }

    private static String csidl(final int id) {
        switch (id) {
            case 0x00: return "DESKTOP";
            case 0x02: return "SMPROGRAMS";
            case 0x05: return "DOCUMENTS";
            case 0x06: return "FAVORITES";
            case 0x07: return "SMSTARTUP";
            case 0x08: return "RECENT";
            case 0x09: return "SENDTO";
            case 0x0B: return "STARTMENU";
            case 0x0D: return "MUSIC";
            case 0x0E: return "VIDEOS";
            case 0x13: return "NETHOOD";
            case 0x14: return "FONTS";
            case 0x15: return "TEMPLATES";
            case 0x16: return "STARTMENU";
            case 0x17: return "SMPROGRAMS";
            case 0x18: return "SMSTARTUP";
            case 0x19: return "DESKTOP";
            case 0x1A: return "APPDATA";
            case 0x1B: return "PRINTHOOD";
            case 0x1C: return "LOCALAPPDATA";
            case 0x20: return "INTERNET_CACHE";
            case 0x21: return "COOKIES";
            case 0x22: return "HISTORY";
            case 0x23: return "APPDATA";
            case 0x24: return "WINDIR";
            case 0x25: return "SYSDIR";
            case 0x26: return "PROGRAMFILES";
            case 0x27: return "PICTURES";
            case 0x28: return "PROFILE";
            case 0x2B: return "COMMONFILES";
            case 0x2D: return "TEMPLATES";
            case 0x2E: return "DOCUMENTS";
            case 0x2F: return "ADMINTOOLS";
            case 0x30: return "ADMINTOOLS";
            case 0x35: return "MUSIC";
            case 0x36: return "PICTURES";
            case 0x37: return "VIDEOS";
            case 0x38: return "RESOURCES";
            case 0x39: return "RESOURCES_LOCALIZED";
            case 0x3B: return "CDBURN_AREA";
            default: return null;
        }
    }

    // =========================================================================
    // Entries (compiled script)
    // =========================================================================

    private void readEntries(final int offset, final int count) {
        String outDir = "$INSTDIR";
        final Map<String, Item> byName = new HashMap<String, Item>();
        for (int i = 0; i < count; i++) {
            final int p = offset + i * ENTRY_SIZE;
            final int which = le32(header, p);
            if (which == EW_CREATEDIR) {
                // SetOutPath = CreateDirectory with parm1 != 0 (updates $OUTDIR)
                if (le32(header, p + 8) != 0) outDir = string(le32(header, p + 4), outDir);
            } else if (which == EW_EXTRACTFILE) {
                final int nameIdx = le32(header, p + 8);
                final long dataOffset = le32(header, p + 12) & 0xffffffffL;
                final long ft = (le32(header, p + 16) & 0xffffffffL) | (long) le32(header, p + 20) << 32;
                String name = string(nameIdx, outDir);
                if (!startsWithCode(nameIdx) && !isAbsolute(name)) name = outDir + "\\" + name;
                name = entryName(name);
                if (name.isEmpty()) continue;
                final Item same = byName.get(name.toLowerCase());
                if (same != null) {
                    if (same.offset == dataOffset) continue; // same file extracted again (other section)
                    name = uniqueName(name, byName);
                }
                final long time = ft == 0 || ft == -1L ? -1 : ft / 10000000L - 11644473600L;
                final Item item = new Item(name, dataOffset, time);
                byName.put(name.toLowerCase(), item);
                items.add(item);
            }
        }
    }

    private static boolean isAbsolute(final String s) {
        return s.length() >= 2 && (s.charAt(1) == ':' || s.startsWith("\\\\"));
    }

    /** "$INSTDIR\bin\x.dll" gives "bin/x.dll"; other roots keep their name ("$PLUGINSDIR/x.dll"). */
    static String entryName(final String path) {
        String s = path.replace('\\', '/');
        if (s.equalsIgnoreCase("$INSTDIR")) return "";
        if (s.regionMatches(true, 0, "$INSTDIR/", 0, 9)) s = s.substring(9);
        final StringBuilder sb = new StringBuilder();
        for (final String part : s.split("/")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(part);
        }
        return sb.toString();
    }

    private static String uniqueName(final String name, final Map<String, Item> used) {
        final int slash = name.lastIndexOf('/');
        final int dot = name.lastIndexOf('.');
        final int cut = dot > slash + 1 ? dot : name.length();
        for (int n = 2;; n++) {
            final String candidate = name.substring(0, cut) + " (" + n + ")" + name.substring(cut);
            if (!used.containsKey(candidate.toLowerCase())) return candidate;
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    static int le32(final byte[] b, final int p) {
        return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8 | (b[p + 2] & 0xff) << 16 | (b[p + 3] & 0xff) << 24;
    }

    /** NSIS ANSI strings use the system code page: windows-1252 is the usual one. */
    private static char[] ansiTable() {
        final char[] t = new char[256];
        final byte[] all = new byte[256];
        for (int i = 0; i < 256; i++) all[i] = (byte) i;
        String s;
        try {
            s = new String(all, Charset.forName("windows-1252"));
        } catch (final RuntimeException e) {
            s = new String(all, Charset.forName("ISO-8859-1"));
        }
        for (int i = 0; i < 256; i++) t[i] = i < s.length() && s.charAt(i) != '\uFFFD' ? s.charAt(i) : (char) i;
        return t;
    }
}
