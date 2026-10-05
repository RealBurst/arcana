# OLE compound files and Windows Installer packages (MSI)

| | |
|---|---|
| Extensions | `.msi`, `.msp`, `.doc`, `.xls`, `.ppt`, `.msg` (format name `ole`) |
| Signature | `D0 CF 11 E0 A1 B1 1A E1` at offset 0 |
| Arcana support | list, extract (MSI packages: installed file tree; other compound files: storages and streams) |
| Main classes | `be.stef.arcana.formats.ole.CompoundFile`, `be.stef.arcana.formats.ole.MsiPackage`, `be.stef.arcana.extractor.OleExtractor`, `be.stef.arcana.formats.cab.CabReader` |
| Test samples | `test/samples/msi/package.msi` (made by `wixl`, embedded MSZIP cabinet); corpus references `test/corpus/msi/7z2501-x64.msi.txt`, `test/corpus/msi/PowerShell-7.4.6-win-x64.msi.txt`, `test/corpus/msi/jinstall-unpacked.exe.txt` |

## Overview

The Compound File Binary format (also called OLE2 structured storage) is a
small FAT file system inside a file, defined by Microsoft in the early 1990s
for OLE. It holds *storages* (folders) and *streams* (files). It is the
container of Office 97-2003 documents (`.doc`, `.xls`, `.ppt`), Outlook
messages (`.msg`), and Windows Installer packages (`.msi`), patches (`.msp`)
and transforms (`.mst`).

A Windows Installer package is a relational database stored in a compound
file: each table is a stream, strings are shared in a string pool, and the
files to install are usually in cabinets, either stored as streams of the
package (embedded) or next to it (external). Arcana extracts an `.msi` as the
tree of the files it installs, with their target names and folders, as an
administrative install would.

For packages stored inside executables (installers carrying an `.msi` and its
cabinets as PE resources), see [sfx-executables.md](sfx-executables.md).

## Detection

`ArchiveDetector.detectByMagic` returns `OLE` when the file starts with the 8
signature bytes; the extension fallback maps `.msi` and `.msp` to `OLE`.

`OleExtractor` then chooses the view from the CLSID of the root storage
(`CompoundFile.getRootClsid`):

| Root CLSID | Kind | View |
|---|---|---|
| `{000C1084-0000-0000-C000-000000000046}` (`MsiPackage.CLSID_PACKAGE`) | installation package | installed files + `[streams]/` |
| `{000C1086-0000-0000-C000-000000000046}` (`MsiPackage.CLSID_PATCH`) | patch | raw streams, MSI names decoded |
| `{000C1082-0000-0000-C000-000000000046}` | transform | raw streams, MSI names decoded |
| anything else | other compound file | raw storages and streams |

A package whose tables cannot be read (any `IOException` or runtime exception
in `MsiPackage`) falls back to the raw view with decoded names.

`arcana i` uses `DataAnalyzer.ole`, which only looks at the extension: "MSI -
Windows Installer package (OLE2)" for `.msi`, DOC, XLS, PPT, MSG for the
Office and Outlook extensions, "OLE2" otherwise.

## Structure

### Compound file header (`CompoundFile` constructor)

The header is the first 512 bytes; sector n starts at `(n + 1) * sector size`.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | signature | `D0 CF 11 E0 A1 B1 1A E1` |
| 8 | 16 | CLSID | not read |
| 24 | 2 | minor version | not read |
| 26 | 2 | major version | not read (3 or 4) |
| 28 | 2 | byte order | not read |
| 30 | 2 | sector shift | 9 (512 bytes) or 12 (4096 bytes), else "Invalid OLE sector size" |
| 32 | 2 | mini sector shift | must be 6 (64 bytes) |
| 44 | 4 | number of FAT sectors | at most the number of sectors of the file |
| 48 | 4 | first directory sector | |
| 56 | 4 | mini stream cutoff | streams smaller than this are in the mini stream (4096) |
| 60 | 4 | first MiniFAT sector | ENDOFCHAIN or FREESECT = no MiniFAT |
| 64 | 4 | number of MiniFAT sectors | not read (the chain is followed) |
| 68 | 4 | first DIFAT sector | |
| 72 | 4 | number of DIFAT sectors | not read |
| 76 | 436 | DIFAT | the first 109 FAT sector numbers |

Special sector numbers: `0xFFFFFFFE` ENDOFCHAIN, `0xFFFFFFFF` FREESECT.

The FAT sector list comes from the 109 header entries, then from the DIFAT
chain: each DIFAT sector holds `sector size / 4 - 1` entries and the number of
the next DIFAT sector in its last 4 bytes. The FAT is the concatenation of
those sectors; it gives, for every sector, the next sector of its chain.

### Directory entries (`entry`, `walkTree`)

The directory is the FAT chain starting at offset 48, cut into 128-byte
entries. Entry 0 is the root storage.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 64 | name | UTF-16LE |
| 64 | 2 | name length | in bytes, terminating zero included; at most 64 and even |
| 66 | 1 | type | 1 storage, 2 stream, 5 root; other types are skipped |
| 67 | 1 | color | red-black tree; not read |
| 68 | 4 | left sibling | |
| 72 | 4 | right sibling | |
| 76 | 4 | child | root of the tree of the children of a storage |
| 80 | 16 | CLSID | read for the root entry only |
| 96 | 4 | state bits | not read |
| 100 | 8 | creation time | not read |
| 108 | 8 | modification time | FILETIME; converted to Unix seconds, -1 when 0 |
| 116 | 4 | starting sector | in the FAT, or in the MiniFAT for small streams |
| 120 | 8 | stream size | only the low 32 bits with 512-byte sectors |

The children of a storage are the nodes of a red-black tree; `walkTree` visits
it in order (left, node, right), which is the sort order of the tree.

### Streams (`copy`, `chain`)

- A stream of at least the cutoff size is read by following its FAT chain.
- A smaller stream is read from the *mini stream*: the content of the root
  entry (its FAT chain, size from the root entry), cut into 64-byte mini
  sectors chained by the MiniFAT (the FAT chain starting at offset 60, read as
  32-bit entries).

### MSI stream names (`MsiPackage.decodeName`)

Windows Installer packs stream names to fit the 31-character limit of compound
file names. With the 64-character alphabet `0-9 A-Z a-z . _`:

| UTF-16 code unit | Decoded as |
|---|---|
| 0x3800-0x47FF | two characters: alphabet[(c - 0x3800) & 0x3F], then alphabet[((c - 0x3800) >> 6) & 0x3F] |
| 0x4800-0x483F | one character: alphabet[c - 0x4800] |
| 0x4840 | "!" (prefix of table streams) |
| other | itself |

Examples from `package.msi`: `!_StringPool`, `!File`, `data.cab`; streams of
the Binary table are named `Binary.<key>`.

### String pool (`readStringPool`)

`!_StringPool` holds 4-byte entries, `!_StringData` the characters of all
strings, concatenated without separators.

| Entry | Field | Notes |
|---|---|---|
| 0 | code page (2 bytes), flags (2 bytes) | flag 0x8000: string references are 3 bytes wide instead of 2 |
| n >= 1 | length (2 bytes), reference count (2 bytes) | string id n |

Length 0 with a non-zero reference count marks a long string: its length is
the next entry read as a 32-bit value (low part first), and that next entry
does not take an id. Code page 0 is read as windows-1252, 65001 as UTF-8,
others as `windows-<n>` or `Cp<n>`, ISO-8859-1 when Java does not know them.

### Tables (`readColumns`, `readTable`)

`!_Columns` (fixed schema: Table, Number, Name, Type) gives the columns of
every table. A table stream stores its rows column by column: all values of
column 1, then all values of column 2, and so on; the number of rows is the
stream size divided by the row size.

| Column type | Width | Value |
|---|---|---|
| string (0x0800) or binary (size 0) | 2 or 3 bytes (string pool flag) | string id, 0 = null |
| integer, size 1 or 2 | 2 bytes | value with the sign bit flipped (XOR 0x8000), 0 = null |
| integer, size 4 | 4 bytes | value XOR 0x80000000, 0 = null |

Other sizes give "Unsupported MSI column type". Columns are numbered from 1;
a gap gives "MSI column numbering broken in <table>".

### Installed files (`readFiles`)

| Table | Columns used |
|---|---|
| Directory | Directory, Directory_Parent, DefaultDir |
| Component | Component, Directory_ |
| Media | LastSequence, Cabinet |
| File | File, Component_, FileName, FileSize, Sequence |

- Target path: the Directory tree from the component's directory up to the
  root. `DefaultDir` is "target[:source]"; the target part is used, and in
  "short|long" the long name. "." means the parent itself. The root (no
  parent, or itself as parent, normally TARGETDIR = SourceDir) is "". Standard
  folder properties are shown with their usual names: `ProgramFilesFolder`
  and `ProgramFiles64Folder` give "Program Files", `CommonFilesFolder` "Program
  Files/Common Files", `SystemFolder` "Windows/System32", `AppDataFolder`
  "AppData/Roaming", `CommonAppDataFolder` "ProgramData", and so on
  (`SYSTEM_FOLDERS`). Recursion stops at depth 64.
- File name: `FileName`, long part of "short|long". Two files with the same
  path (case-insensitive) get " (2)", " (3)"... before the extension.
- Cabinet: the Media row with the smallest `LastSequence` greater than or
  equal to the file's `Sequence`. A `Cabinet` starting with "#" names a stream
  of the package (embedded cabinet); another non-empty value is an external
  cabinet file name.
- Inside a cabinet, a file is stored under its `File` key, not its name.

## Compression and encryption

MSI and compound files have no compression of their own: the installed files
are in Cabinet files, read with `CabReader` (stored, MSZIP, LZX; see
[cab.md](cab.md)). No encryption.

`OleExtractor.extract` for a package:

1. groups the installed files by cabinet (embedded stream or external name),
   and inside a cabinet by `File` key (one key may give several paths);
2. for an embedded cabinet, copies the stream to a temporary file
   (`arcana-msi-*.cab`, deleted afterwards); for an external one, asks the
   `CabinetResolver`, or by default looks for a file of that name in the
   directory of the package, then for a case-insensitive match there (names
   containing `/` or `\` are refused);
3. reads every entry of the cabinet whose name is an expected key and writes
   it to each of its target paths;
4. writes the other root streams to `[streams]/`: every stream that is not a
   table (name starting with "!"), not a property set (name starting with
   0x05, such as `SummaryInformation`) and not a cabinet referenced by the
   Media table: Binary and Icon table entries, digital certificates...

`OleExtractor.CabinetResolver` (`File resolve(String cabinet, Set<String>
keys)`) lets a caller supply external cabinets; `SfxExtractor` uses it to pick
the cabinet resource that holds the most expected keys.

For any other compound file, `extractStorage` writes storages as folders and
streams as files.

## Variants and versions

- Version 3 (512-byte sectors) and version 4 (4096-byte sectors) compound
  files.
- Packages built by `wixl` (`package.msi`: one embedded cabinet `data.cab`,
  MSZIP, files under `Program Files/ArcanaTest/`), by WiX
  (`7z2501-x64.msi`: 110 entries, `PowerShell-7.4.6-win-x64.msi`: 922
  extracted items, with `[streams]/Binary.*` and `[streams]/Icon.*`), and the
  package found in the Java installer resources (`jinstall-unpacked.exe`, with
  `[streams]/MsiDigitalCertificate.DgtlCert0`).
- External cabinet: verified with a package whose Media table names
  `Ext1.cab` and a cabinet `ext1.cab` next to it (found by the
  case-insensitive search).
- Patches (`.msp`) and transforms: listed and extracted in the raw view with
  decoded names (`!File`, `[5]SummaryInformation`...); storages, such as the
  transforms embedded in a patch, become folders. Verified by changing the
  root CLSID of `package.msi` to the transform CLSID: 19 streams listed,
  `data.cab` among them.
- Office 97-2003 documents and Outlook messages: raw view; names keep their
  control characters as "[n]" (`[5]SummaryInformation`, `[1]CompObj`).

## Limits

- Files of the File table that are not in a cabinet (uncompressed source
  files next to the package) are listed but not extracted. The same holds for
  files of an external cabinet that is not found: extraction ends with "Done."
  and no warning.
- The listing of a package shows the size from the File table, no date and no
  packed size; storage nodes below the root are not shown in the package view.
- Only the tables needed for the file tree are read. Other tables (Registry,
  Shortcut, CreateFolder...) are ignored, so empty folders are not created.
- Column types other than strings, binaries and 1, 2 or 4-byte integers give
  "Unsupported MSI column type" and the package falls back to the raw view.
  Temporary columns (type bit 0x4000) are not treated apart.
- Streams are limited to `Integer.MAX_VALUE - 64` bytes when read whole; the
  mini stream and the directory are read into memory.
- No stream extraction: "OLE compound files require random file access - use
  extract(File,File)." (`ArcanaUnsupportedFormatException`).
- No creation of compound files or packages.
- Errors raised by `CabReader` while reading a cabinet of a package are plain
  `IOException`s with a "CAB: " message; they are not rewrapped.
- Forced extraction (`arcana r`) of a bare `.msi` does not apply here: see
  [recovery.md](recovery.md).

## Implementation notes

- Robustness of `CompoundFile`: DIFAT loops are detected ("OLE DIFAT loop"),
  every chain is bounded by the FAT (or MiniFAT) size ("Invalid OLE sector
  chain"), every sector must lie in the file (the last one may be truncated),
  directory indexes must be inside the directory and are visited once ("Invalid
  OLE directory tree"), and storage nesting is limited to 256 levels. The
  recursion over siblings of one storage is not limited other than by the
  number of entries.
- Large streams are copied sector by sector to the output; only the directory,
  the MiniFAT, the mini stream and the MSI tables are held in memory.
- Names written to disk go through `safeName`: characters below 0x20 become
  "[n]", `/` and `\` become `_`, and "", "." and ".." get a "_" prefix. Paths
  are then built with `SafePathBuilder.buildSafePath` (path traversal refused)
  and files written through `ExtractionGuard.open` (output limits).
- Table streams are read only through the `_Columns` schema; a table missing
  from the package or from `_Columns` is read as empty (a package without
  Media rows has no cabinet).

## Sources

- Microsoft, [MS-CFB] Compound File Binary File Format:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
- Microsoft, Windows Installer documentation, File table:
  https://learn.microsoft.com/en-us/windows/win32/msi/file-table
- Microsoft, Windows Installer documentation, Database Tables (links to the
  Directory, Component and Media tables):
  https://learn.microsoft.com/en-us/windows/win32/msi/database-tables
- Microsoft, "Microsoft Cabinet Format" (cabinets of the packages, see
  [cab.md](cab.md)): https://learn.microsoft.com/en-us/previous-versions/bb267310(v=vs.85)

License: `CompoundFile`, `MsiPackage` and `OleExtractor` are Copyright 2026
Stephane Bury, Apache-2.0 (file headers). `CompoundFile` states that it was
written from [MS-CFB], `MsiPackage` from the Windows Installer SDK
documentation.
