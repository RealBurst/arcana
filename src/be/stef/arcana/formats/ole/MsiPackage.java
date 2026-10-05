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
package be.stef.arcana.formats.ole;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Windows Installer package (.msi) read from its compound file: stream names,
 * string pool and the tables needed to place the installed files (File,
 * Component, Directory, Media), as documented in the Windows Installer SDK.
 *
 * <p>Stream names are packed: characters 0x3800-0x47FF hold two characters of
 * the set [0-9A-Za-z._], 0x4800-0x483F one, and 0x4840 marks a table. A table
 * stream stores its rows column by column; strings are indexes into the string
 * pool (_StringPool: length and reference count of each string, _StringData:
 * the characters), integers are stored with their sign bit flipped.</p>
 *
 * <p>The files of the package are in cabinets stored as streams (Media table,
 * Cabinet "#name"); inside a cabinet, a file is named after its key in the
 * File table. Files in external cabinets give the cabinet name
 * ({@link InstalledFile#externalCabinet}) so that the caller can find it;
 * uncompressed files next to the package are reported but not extracted.</p>
 *
 * @author Stef
 * @since 1.0.4
 */
public final class MsiPackage {

    /** CLSID of the root storage of an installation package, a patch and a transform. */
    public static final String CLSID_PACKAGE = "{000C1084-0000-0000-C000-000000000046}";
    public static final String CLSID_PATCH = "{000C1086-0000-0000-C000-000000000046}";

    private static final String CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

    /** A file installed by the package. */
    public static final class InstalledFile {
        /** Target path ("ProgramFiles/App/app.exe"). */
        public final String path;
        public final long size;
        /** Key of the file in the File table = its name inside the cabinet. */
        public final String key;
        /** Cabinet stream holding the file, or null when it is outside the package. */
        public final CompoundFile.Node cabinet;
        /** Name of the external cabinet holding the file (Media table), or null. */
        public final String externalCabinet;

        InstalledFile(final String path, final long size, final String key, final CompoundFile.Node cabinet, final String externalCabinet) {
            this.path = path;
            this.size = size;
            this.key = key;
            this.cabinet = cabinet;
            this.externalCabinet = externalCabinet;
        }
    }

    private final CompoundFile cf;
    /** Root streams by decoded name. */
    private final Map<String, CompoundFile.Node> streams = new LinkedHashMap<String, CompoundFile.Node>();
    private String[] strings;
    private int refSize = 2;
    private final List<InstalledFile> files = new ArrayList<InstalledFile>();
    private final Set<CompoundFile.Node> cabinets = new HashSet<CompoundFile.Node>();

    public MsiPackage(final CompoundFile cf) throws IOException {
        this.cf = cf;
        for (final CompoundFile.Node n : cf.getRoot().children) {
            if (!n.storage) streams.put(decodeName(n.name), n);
        }
        readStringPool();
        readFiles();
    }

    /** Decodes a packed MSI stream name. */
    public static String decodeName(final String name) {
        final StringBuilder sb = new StringBuilder(name.length() * 2);
        for (int i = 0; i < name.length(); i++) {
            int c = name.charAt(i);
            if (c >= 0x3800 && c < 0x4800) {
                c -= 0x3800;
                sb.append(CHARSET.charAt(c & 0x3F));
                sb.append(CHARSET.charAt((c >> 6) & 0x3F));
            } else if (c >= 0x4800 && c < 0x4840) {
                sb.append(CHARSET.charAt(c - 0x4800));
            } else if (c == 0x4840) {
                sb.append('!');
            } else {
                sb.append((char) c);
            }
        }
        return sb.toString();
    }

    /** Files installed by the package, with their target paths. */
    public List<InstalledFile> getFiles() {
        return files;
    }

    /** Streams that are neither tables nor cabinets holding installed files (Binary, Icon, custom actions...). */
    public Map<String, CompoundFile.Node> getOtherStreams() {
        final Map<String, CompoundFile.Node> m = new LinkedHashMap<String, CompoundFile.Node>();
        for (final Map.Entry<String, CompoundFile.Node> e : streams.entrySet()) {
            if (e.getKey().startsWith("!") || e.getKey().startsWith("\u0005") || cabinets.contains(e.getValue())) continue;
            m.put(e.getKey(), e.getValue());
        }
        return m;
    }

    // =========================================================================
    // String pool
    // =========================================================================

    private void readStringPool() throws IOException {
        final CompoundFile.Node poolNode = streams.get("!_StringPool");
        final CompoundFile.Node dataNode = streams.get("!_StringData");
        if (poolNode == null || dataNode == null) throw new ArcanaCorruptedException("MSI string pool missing");
        final byte[] pool = cf.read(poolNode);
        final byte[] data = cf.read(dataNode);
        if (pool.length < 4) throw new ArcanaCorruptedException("MSI string pool too short");
        final int codepage = CompoundFile.le16(pool, 0);
        if ((CompoundFile.le16(pool, 2) & 0x8000) != 0) refSize = 3;
        final Charset cs = charset(codepage);
        final int entries = pool.length / 4;
        final List<String> list = new ArrayList<String>();
        list.add(""); // id 0 = null
        int offset = 0;
        for (int i = 1; i < entries; i++) {
            long len = CompoundFile.le16(pool, 4 * i);
            final int refs = CompoundFile.le16(pool, 4 * i + 2);
            if (len == 0 && refs != 0) {
                // long string: the length is in the next entry
                if (i + 1 >= entries) break;
                len = (CompoundFile.le16(pool, 4 * (i + 1)) & 0xffffL) | (long) CompoundFile.le16(pool, 4 * (i + 1) + 2) << 16;
                i++;
            }
            if (offset + len > data.length) throw new ArcanaCorruptedException("MSI string data truncated");
            list.add(new String(data, offset, (int) len, cs));
            offset += len;
        }
        strings = list.toArray(new String[0]);
    }

    private static Charset charset(final int codepage) {
        if (codepage == 0) return Charset.forName("windows-1252");
        if (codepage == 65001) return StandardCharsets.UTF_8;
        try {
            return Charset.forName("windows-" + codepage);
        } catch (final RuntimeException e) {
            try {
                return Charset.forName("Cp" + codepage);
            } catch (final RuntimeException e2) {
                return StandardCharsets.ISO_8859_1;
            }
        }
    }

    private String str(final long id) {
        return id >= 0 && id < strings.length ? strings[(int) id] : null;
    }

    // =========================================================================
    // Tables
    // =========================================================================

    /** Column definitions of every table, from _Columns (Table, Number, Name, Type). */
    private Map<String, List<int[]>> columns;
    private Map<String, List<String>> columnNames;

    private void readColumns() throws IOException {
        columns = new HashMap<String, List<int[]>>();
        columnNames = new HashMap<String, List<String>>();
        final CompoundFile.Node node = streams.get("!_Columns");
        if (node == null) throw new ArcanaCorruptedException("MSI _Columns table missing");
        // fixed schema: Table (string), Number (i2), Name (string), Type (i2)
        final int[] types = {0x0800 | refSize, 2, 0x0800 | refSize, 2};
        final List<long[]> rows = readTable(cf.read(node), types);
        final Map<String, Map<Integer, Object[]>> byTable = new HashMap<String, Map<Integer, Object[]>>();
        for (final long[] r : rows) {
            final String table = str(r[0]);
            if (table == null) continue;
            Map<Integer, Object[]> m = byTable.get(table);
            if (m == null) byTable.put(table, m = new HashMap<Integer, Object[]>());
            m.put((int) r[1], new Object[] {str(r[2]), (int) r[3]});
        }
        for (final Map.Entry<String, Map<Integer, Object[]>> e : byTable.entrySet()) {
            final List<int[]> t = new ArrayList<int[]>();
            final List<String> names = new ArrayList<String>();
            for (int i = 1; i <= e.getValue().size(); i++) {
                final Object[] c = e.getValue().get(i);
                if (c == null) throw new ArcanaCorruptedException("MSI column numbering broken in " + e.getKey());
                t.add(new int[] {(Integer) c[1]});
                names.add((String) c[0]);
            }
            columns.put(e.getKey(), t);
            columnNames.put(e.getKey(), names);
        }
    }

    /** Width in bytes of a column (Windows Installer column type). */
    private int width(final int type) throws IOException {
        if ((type & 0x0800) != 0 || (type & 0xff) == 0) return refSize; // strings, binary objects (stream names)
        final int size = type & 0xff;
        if (size <= 2) return 2;
        if (size == 4) return 4;
        throw new ArcanaCorruptedException("Unsupported MSI column type 0x" + Integer.toHexString(type));
    }

    /**
     * Reads a table stored column by column. Strings and objects give a string
     * id, integers their value (null = Long.MIN_VALUE).
     */
    private List<long[]> readTable(final byte[] data, final int[] types) throws IOException {
        int rowSize = 0;
        final int[] widths = new int[types.length];
        for (int i = 0; i < types.length; i++) rowSize += widths[i] = width(types[i] == 2 ? 2 : types[i]);
        final List<long[]> rows = new ArrayList<long[]>();
        if (rowSize == 0) return rows;
        final int count = data.length / rowSize;
        for (int r = 0; r < count; r++) rows.add(new long[types.length]);
        int p = 0;
        for (int c = 0; c < types.length; c++) {
            final boolean string = (types[c] & 0x0800) != 0 || (types[c] & 0xff) == 0;
            for (int r = 0; r < count; r++) {
                long v;
                if (widths[c] == 2) v = CompoundFile.le16(data, p);
                else if (widths[c] == 3) v = CompoundFile.le16(data, p) | (data[p + 2] & 0xffL) << 16;
                else v = CompoundFile.le32(data, p) & 0xffffffffL;
                p += widths[c];
                if (!string) {
                    if (v == 0) v = Long.MIN_VALUE;
                    else if (widths[c] == 2) v = (short) (v ^ 0x8000);
                    else v = (int) (v ^ 0x80000000L);
                }
                rows.get(r)[c] = v;
            }
        }
        return rows;
    }

    /** Rows of a table as maps column name -> value (strings resolved). */
    private List<Map<String, Object>> table(final String name) throws IOException {
        final List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        final CompoundFile.Node node = streams.get("!" + name);
        final List<int[]> cols = columns.get(name);
        if (node == null || cols == null) return out;
        final int[] types = new int[cols.size()];
        for (int i = 0; i < types.length; i++) types[i] = cols.get(i)[0];
        final List<String> names = columnNames.get(name);
        for (final long[] r : readTable(cf.read(node), types)) {
            final Map<String, Object> m = new HashMap<String, Object>();
            for (int i = 0; i < types.length; i++) {
                final boolean string = (types[i] & 0x0800) != 0 || (types[i] & 0xff) == 0;
                m.put(names.get(i), string ? str(r[i]) : (r[i] == Long.MIN_VALUE ? null : Long.valueOf(r[i])));
            }
            out.add(m);
        }
        return out;
    }

    // =========================================================================
    // Installed files
    // =========================================================================

    private void readFiles() throws IOException {
        readColumns();
        // directories: key -> {parent, default dir}
        final Map<String, String[]> dirs = new HashMap<String, String[]>();
        for (final Map<String, Object> r : table("Directory")) {
            dirs.put((String) r.get("Directory"), new String[] {(String) r.get("Directory_Parent"), (String) r.get("DefaultDir")});
        }
        final Map<String, String> componentDir = new HashMap<String, String>();
        for (final Map<String, Object> r : table("Component")) componentDir.put((String) r.get("Component"), (String) r.get("Directory_"));
        // media: last sequence -> embedded cabinet
        final List<long[]> media = new ArrayList<long[]>();
        final List<CompoundFile.Node> mediaCab = new ArrayList<CompoundFile.Node>();
        final List<String> mediaExternal = new ArrayList<String>();
        for (final Map<String, Object> r : table("Media")) {
            final Object last = r.get("LastSequence");
            final String cab = (String) r.get("Cabinet");
            CompoundFile.Node node = null;
            if (cab != null && cab.startsWith("#")) node = streams.get(cab.substring(1));
            media.add(new long[] {last == null ? 0 : (Long) last, media.size()});
            mediaCab.add(node);
            mediaExternal.add(cab != null && !cab.isEmpty() && !cab.startsWith("#") ? cab : null);
            if (node != null) cabinets.add(node);
        }
        media.sort((a, b) -> Long.compare(a[0], b[0]));
        final Map<String, String> pathCache = new HashMap<String, String>();
        final Set<String> used = new HashSet<String>();
        for (final Map<String, Object> r : table("File")) {
            final String key = (String) r.get("File");
            final String fileName = longName((String) r.get("FileName"));
            if (key == null || fileName == null || fileName.isEmpty()) continue;
            final Object sizeObj = r.get("FileSize");
            final Object seqObj = r.get("Sequence");
            final String dir = dirPath(componentDir.get((String) r.get("Component_")), dirs, pathCache, 0);
            String path = dir.isEmpty() ? fileName : dir + "/" + fileName;
            if (!used.add(path.toLowerCase())) path = unique(path, used);
            CompoundFile.Node cab = null;
            String external = null;
            if (seqObj != null) {
                final long seq = (Long) seqObj;
                for (final long[] m : media) {
                    if (seq <= m[0]) {
                        cab = mediaCab.get((int) m[1]);
                        external = mediaExternal.get((int) m[1]);
                        break;
                    }
                }
            }
            files.add(new InstalledFile(path, sizeObj == null ? -1 : (Long) sizeObj, key, cab, cab == null ? external : null));
        }
    }

    /** System folders, resolved by Windows Installer at install time: shown with their usual names. */
    private static final Map<String, String> SYSTEM_FOLDERS = new HashMap<String, String>();

    static {
        final String[] pairs = {
            "ProgramFilesFolder", "Program Files", "ProgramFiles64Folder", "Program Files", "ProgramFiles6432Folder", "Program Files",
            "CommonFilesFolder", "Program Files/Common Files", "CommonFiles64Folder", "Program Files/Common Files", "CommonFiles6432Folder", "Program Files/Common Files",
            "WindowsFolder", "Windows", "SystemFolder", "Windows/System32", "System64Folder", "Windows/System32", "System6432Folder", "Windows/System32",
            "System16Folder", "Windows/System", "FontsFolder", "Windows/Fonts", "WindowsVolume", "",
            "AppDataFolder", "AppData/Roaming", "LocalAppDataFolder", "AppData/Local", "CommonAppDataFolder", "ProgramData",
            "DesktopFolder", "Desktop", "PersonalFolder", "Documents", "MyPicturesFolder", "Pictures", "FavoritesFolder", "Favorites",
            "StartMenuFolder", "Start Menu", "ProgramMenuFolder", "Start Menu/Programs", "StartupFolder", "Start Menu/Programs/Startup",
            "AdminToolsFolder", "Start Menu/Programs/Administrative Tools", "SendToFolder", "SendTo", "TemplateFolder", "Templates",
            "RecentFolder", "Recent", "NetHoodFolder", "NetHood", "PrintHoodFolder", "PrintHood", "TempFolder", "Temp"
        };
        for (int i = 0; i < pairs.length; i += 2) SYSTEM_FOLDERS.put(pairs[i], pairs[i + 1]);
    }

    /** Target path of a directory; the root (TARGETDIR / SourceDir) is "". */
    private String dirPath(final String key, final Map<String, String[]> dirs, final Map<String, String> cache, final int depth) {
        if (key == null) return "";
        final String cached = cache.get(key);
        if (cached != null) return cached;
        final String system = SYSTEM_FOLDERS.get(key);
        if (system != null) {
            cache.put(key, system);
            return system;
        }
        final String[] d = dirs.get(key);
        if (d == null || depth > 64) return "";
        final String parentKey = d[0];
        String name = d[1];
        String result;
        if (parentKey == null || parentKey.isEmpty() || parentKey.equals(key)) {
            result = "";
        } else {
            // DefaultDir: "target:source", each "short|long"; "." = the parent directory itself
            if (name != null) {
                final int colon = name.indexOf(':');
                if (colon >= 0) name = name.substring(0, colon);
                name = longName(name);
            }
            final String parent = dirPath(parentKey, dirs, cache, depth + 1);
            if (name == null || name.isEmpty() || name.equals(".")) result = parent;
            else result = parent.isEmpty() ? name : parent + "/" + name;
        }
        cache.put(key, result);
        return result;
    }

    private static String longName(final String s) {
        if (s == null) return null;
        final int bar = s.indexOf('|');
        return bar >= 0 ? s.substring(bar + 1) : s;
    }

    private static String unique(final String path, final Set<String> used) {
        final int slash = path.lastIndexOf('/');
        final int dot = path.lastIndexOf('.');
        final int cut = dot > slash + 1 ? dot : path.length();
        for (int n = 2;; n++) {
            final String p = path.substring(0, cut) + " (" + n + ")" + path.substring(cut);
            if (used.add(p.toLowerCase())) return p;
        }
    }
}
