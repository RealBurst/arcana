# Self-extracting archives and installers

| | |
|---|---|
| Extensions | `.exe`, `.sfx` (format name `sfx`), Linux ELF files, any file with an unknown prefix followed by an archive |
| Signature | `4D 5A` at offset 0 ("MZ") or `7F 45 4C 46` at offset 0 ("\x7FELF"); otherwise an archive found after an unrecognized prefix |
| Arcana support | list, extract, recover (through the embedded archive); identify (`arcana i`) |
| Main classes | `be.stef.arcana.extractor.SfxExtractor`, `be.stef.arcana.formats.carve.PeImage`, `be.stef.arcana.formats.carve.PeResources`, `be.stef.arcana.formats.carve.DotNetBundle`, `be.stef.arcana.formats.carve.FileCarver`, `be.stef.arcana.analyze.ExecutableAnalyzer` |
| Test samples | `test/samples/plugins/upx/` (ELF packed by UPX, no archive inside); references of real executables in `test/corpus/msi/jinstall-unpacked.exe.txt`, `test/corpus/upx/`, `test/corpus/jexepack/`, `test/corpus/innosetup/` |

## Overview

A self-extracting archive (SFX) is an executable stub followed by, or
containing, a standard archive: WinRAR SFX (RAR), 7-Zip SFX (7z, with an
optional configuration text), WinZip / Info-ZIP SFX (ZIP), IExpress (Microsoft
CAB). Some installers carry a Windows Installer package (.msi) and its cabinets
in their PE resources (the Java installer for example). .NET applications
published with `PublishSingleFile` carry their files after the apphost. Arcana
does not implement any SFX stub format: it finds the embedded archive and hands
it to the extractor of that archive's format.

## Detection

`ArchiveDetector.detectByMagic` returns `ArcanaFormat.SFX` for a file starting
with "MZ" or "\x7FELF". These two checks come after all the other magic
numbers, so a file starting with an archive signature is never taken for an
SFX. When no format is recognized at all (by content or extension),
`Arcana.resolveFormat` calls `SfxExtractor.locate`: if an archive is found
after the unknown prefix (shell script + ZIP, stub + 7z...), the file is
handled as SFX.

Plugins come first for executables. `Arcana.detectPlugin` consults the plugins
with a priority greater than 0, then the built-in detection by content; since a
result of `SFX` is not considered a built-in match, the other plugins
(`PluginManager.detect(file, false)`) are then asked too. A loaded NSIS, Inno
Setup, InstallShield, UPX or JexePack plugin therefore handles its executables
before `SfxExtractor` is used. `PluginManager` reads up to 4 MiB of the file
start for the plugins' `matches` method.

`arcana i` uses `AnalyzerRegistry`, whose first built-in analyzer is
`ExecutableAnalyzer`. For a PE it reports PE32 / PE32+, EXE or DLL,
architecture, subsystem, the name from the export directory or the
`OriginalFilename` of the version resource, the file version
(`VS_FIXEDFILEINFO` found after the UTF-16 "VS_VERSION_INFO" marker), a .NET
single-file bundle (`DotNetBundle.findInExecutable`) or a non-empty CLI header
(data directory 14), and the size of an Authenticode signature. It also
recognizes ELF, Mach-O, Java class files and WebAssembly modules. It does not
look for embedded archives; "MZ" without a valid PE header is reported as an
MS-DOS executable with 60% confidence.

### Search order

`SfxExtractor.extract` and `SfxExtractor.list` first try a .NET single-file
bundle (`DotNetBundle.findInExecutable`). If there is none, `locate` runs:

1. **End of the image.** `PeImage.parse(s, 0)`: the end is `sectionsEnd`
   (headers, sections, COFF symbol table; the certificate is not included).
   Without a PE header, `FileCarver.identifyAt(s, 0)` is tried: if it returns
   an `elf` or `mz` (MS-DOS) piece, its length is the end; otherwise the end is 0.
2. **Overlay.** `FileCarver.scan` cuts the whole file into pieces. The first
   piece that starts at or after the end of the image and whose type is `zip`,
   `7z`, `rar`, `cab`, `gzip` or `xz` is the payload.
3. **Windows Installer package in the resources.** `PeResources.read`, then
   the first resource accepted by `isMsiPackage` (see below). The payload is
   reported as `OLE` and the whole resource set is extracted.
4. **Archive inside the image.** `searchInside` scans every byte from 0 to the
   end of the image for `MSCF 00 00 00 00`, `7z BC AF 27 1C`, `Rar! 1A 07` and
   `PK 03 04`. Each hit is checked with `FileCarver.identifyAt`; it is kept if
   not truncated, at least 64 bytes long and ending inside the image. The
   largest one wins. This is how IExpress cabinets and archives stored as
   resources are found (the resource tree itself is not used here).
5. **Nothing found.** `installerKind` searches the first 64 MiB for
   "NullsoftInst" (NSIS), "Inno Setup Setup Data" or "rDlPtS" (Inno Setup),
   ".wixburn" in the first 4096 bytes (WiX Burn section name), then
   "InstallShield". An `ArcanaUnsupportedFormatException` names the installer
   type and, for NSIS, Inno Setup and InstallShield, the plugin that handles
   it (`arcana-plugin-nsis`, `arcana-plugin-innosetup`,
   `arcana-plugin-installshield`). Otherwise the message is
   "No archive found in X (not a self-extracting archive)".

## Structure

### PE image (`PeImage`)

Fields read, relative to the start of the image:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | "MZ" | |
| 0x3C | 4 | e_lfanew | must be 0x40..0x10000 and a multiple of 4 |
| lfanew | 4 | "PE\0\0" | |
| +4 | 2 | Machine | x86, x64, ARM64, ARM, IA64 named in `describe()` |
| +6 | 2 | NumberOfSections | 1..96 |
| +12, +16 | 4, 4 | PointerToSymbolTable, NumberOfSymbols | COFF symbols and string table (MinGW builds) |
| +20 | 2 | SizeOfOptionalHeader | at least 0x60 |
| +22 | 2 | Characteristics | 0x2000 = DLL |
| opt+0 | 2 | Magic | 0x10B (PE32) or 0x20B (PE32+) |
| opt+60 | 4 | SizeOfHeaders | |
| opt+68 | 2 | Subsystem | 1 gives `.sys`, 10..13 give `.efi` |
| opt+92 / +108 | 4 | NumberOfRvaAndSizes | |
| opt+96 / +112 | 8 each | data directories | 0 export, 2 resources, 4 certificate (file offset, not RVA) |
| section table | 40 each | VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData | |

`sectionsEnd` is the largest of SizeOfHeaders, the end of the section table,
the raw end of every section and the end of the COFF string table. A section
whose raw data ends more than 0x1000 bytes beyond the file makes `parse`
return null. `size` adds the certificate when it starts less than 8 bytes
after `sectionsEnd` (glued to the image). The name comes from the export
directory (DLL) or `OriginalFilename` in the RT_VERSION resource.

### Resources (`PeResources`)

The three-level tree (type, name, language) of data directory 2. Types with a
numeric ID get their standard name (`RCDATA`, `ICON`...) or `#id`; named
entries are UTF-16 counted strings (at most 256 characters). A leaf is kept only
if its data lies entirely in the raw data of one section. Directories already
visited are skipped (loop protection) and at most 20000 resources are read.
`isStandardUi()` is true for types 1-6, 8, 9, 11, 12, 14, 16, 17, 21-24, 240
and 241.

### Windows Installer package in the resources (`SfxExtractor.ResourceSet`)

`isMsiPackage` accepts a resource of at least 1536 bytes starting with the
compound file signature `D0 CF 11 E0 A1 B1 1A E1`, with sector shift 9 or 12,
whose root directory entry has the CLSID
`{000C1084-0000-0000-C000-000000000046}` (`MsiPackage.CLSID_PACKAGE`).
Resources starting with `MSCF 00 00 00 00` (at least 64 bytes) are candidate
cabinets. Extraction:

- each package is extracted by `OleExtractor`; when a package refers to an
  external cabinet, `resolve` returns the cabinet resource holding the most
  of the expected file keys (names read with `CabReader`). With one package
  the files go to the destination root, otherwise to `<type>_<name>/`;
- every other resource that is not a user interface type, not a cabinet used by
  a package and not empty is copied to `[resources]/<type>/<name>.<ext>`. The
  package itself is copied there too (extension `msi`). The extension comes
  from the content: `cab`, `ole`, `zip`, `7z`, `rar`, `dll` / `sys` / `efi` /
  `exe` (from `PeImage.extension()`), `xml`, else `bin`. A name already used
  gets `_<lang>`, then `_<lang>_<n>`; characters outside 0x20-0x7E and
  `/\:*?"<>|` become `_`.

`test/corpus/msi/jinstall-unpacked.exe.txt` shows the result for the Java
installer: six files under `Program Files/Common Files/Java/Java Update/`,
`[resources]/JAVA_INSTALLER/106.msi`, two DLL resources, and the
`[streams]/` entries written by `OleExtractor`.

### .NET single-file bundle (`DotNetBundle`)

The apphost holds an 8-byte manifest offset followed by a 32-byte signature
(SHA-256 of ".net core bundle"), searched in the first 16 MiB. Manifest
(little-endian):

| Field | Size | Notes |
|---|---|---|
| major, minor | 4, 4 | major 1..20 accepted |
| file count | 4 | 1..1000000 |
| bundle id | string | length prefix 7-bit encoded, UTF-8 |
| deps.json and runtimeconfig.json offset/size, flags | 40 | major >= 2, skipped |
| per file: offset, size | 8, 8 | |
| per file: compressed size | 8 | major >= 6; 0 = stored |
| per file: type | 1 | 1 assembly, 2 native library, 3 deps.json, 4 runtimeconfig.json, 5 symbols |
| per file: path | string | at most 4096 bytes |

Every file must end before the manifest. Up to 8 stored assemblies or native
libraries are checked to start with "MZ" or "\x7FE".

## Compression and encryption

`SfxExtractor` decodes nothing itself. A ZIP payload is read in place: the
whole executable is given to the ZIP extractor, which skips the stub. Other
payloads are copied to a temporary file (first extension of the format) and
extracted by the extractor of their format. `FormatRegistry` builds the
extractor as `new SfxExtractor(f -> builtin(f).createExtractor(pw))`, so the
password given with `-p` reaches the embedded format. Compressed .NET bundle
entries are raw deflate (`java.util.zip.Inflater` with `nowrap`).

## Variants and versions

| Kind | Where Arcana finds it | Step |
|---|---|---|
| WinRAR SFX (RAR 4 / 5) | overlay | 2 |
| 7-Zip SFX, Windows and Linux ELF | overlay; the configuration text (";!@Install@!UTF-8!" ... ";!@InstallEnd@!") is not parsed, it is an unrecognized piece before the 7z | 2 |
| WinZip / Info-ZIP SFX, script + ZIP | overlay | 2 |
| GZIP / XZ appended to a stub | overlay | 2 |
| Installer with .msi and cabinets in resources | resources | 3 |
| IExpress (CAB), 7z / ZIP / RAR stored in the image | anywhere in the image | 4 |
| .NET single-file application | bundle manifest | before step 1 |
| NSIS, Inno Setup, InstallShield, WiX Burn | not extracted, named in the error | 5 |

Example: a PE launcher (`t64.exe`, 108032 bytes) followed by a 7z gives with
`arcana s -n`:

```
  0x00000000       108032  pe       PE32+ EXE x64 (t64.exe)
  0x0001A600         6290  7z       7-Zip archive
```

and `arcana l` lists the content of the 7z.

## Limits

- Only one archive is used: the first one in the overlay, or the first
  package, or the largest one in the image.
- A ZIP payload is always read in place from the whole file, also when it was
  found inside the image (step 4). The ZIP reader looks for the end of central
  directory in the last 65557 bytes of the file only, so such a ZIP fails
  ("end of central directory not found") when more than about 64 KiB follow it.
- The proprietary installer formats (NSIS, Inno Setup, InstallShield, WiX
  Burn) and executable packers (UPX) need plugins. WiX Burn has no plugin hint.
- `installerKind` only looks at the first 64 MiB.
- Windows Installer patches and transforms in resources are not detected
  (only the package CLSID is accepted).
- An ELF file without an archive (for example `test/samples/plugins/upx/hello-elf.upx`
  without the UPX plugin) gives "No archive found".
- Stream extraction (`extract(InputStream, File)`) first copies the stream to
  a temporary file.
- A .NET bundle without its apphost is not handled by `SfxExtractor` (only by
  `arcana s`, see `embedded-files.md`).

## Implementation notes

- The overlay search relies on `FileCarver.scan`, which never looks inside a
  recognized piece: the PE at offset 0 is a single piece and the scan resumes
  after it. Archives stored inside the image are therefore only found by step 4.
- The image end used for the overlay is `sectionsEnd`, not `size`: an
  Authenticode certificate placed after the archive does not hide it.
- Listing an MSI resource set calls `markUsed` to resolve the external cabinets,
  so that the cabinets used by a package are not also listed as resources.
- Forced extraction (`arcana r`, `ForceUnpacker`) calls `SfxExtractor.locate`,
  copies the payload range to a temporary file and applies the recovery
  strategy of the payload format (see `recovery.md`).

## Sources

- Microsoft, "PE Format" (PE/COFF specification):
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Microsoft, [MS-CFB] Compound File Binary File Format:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
- .NET single-file design notes, dotnet/designs repository:
  https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/design.md
- .NET bundle manifest writer, dotnet/runtime repository:
  https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs
- 7-Zip documentation, "-sfx (Create SFX archive) switch" (DOCS in the 7-Zip
  distribution; mirror: https://documentation.help/7-Zip/sfx.htm)

License: `SfxExtractor`, `PeImage`, `PeResources`, `DotNetBundle`,
`FileCarver` and `ExecutableAnalyzer` are independent implementations,
Copyright Stephane Bury, Apache-2.0 (file headers).
