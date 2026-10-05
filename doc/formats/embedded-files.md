# Embedded files (file carving)

| | |
|---|---|
| Extensions | any (not an archive format) |
| Signature | none of its own; the file is scanned for the signatures listed under "Structure" |
| Arcana support | scan (`arcana s -n`, `Arcana.scanEmbedded`), split (`arcana s`, `Arcana.split`); used by the SFX search |
| Main classes | `be.stef.arcana.formats.carve.FileCarver`, `be.stef.arcana.formats.carve.ByteSource`, `be.stef.arcana.formats.carve.PeImage`, `be.stef.arcana.formats.carve.DotNetBundle`, `be.stef.arcana.plugin.PluginManager` |
| Test samples | `test/samples/plugins/upx/` (ELF executables); any concatenation of the formats below |

## Overview

Some files are several files placed one after the other: executables and DLLs
glued together, installers, self-extracting archives, firmware blobs, a shell
script followed by a ZIP. `FileCarver` scans such a file for known signatures,
parses the structure behind each one to compute the exact size of the embedded
file, and writes every piece separately. Bytes between recognized files are
kept as "unknown" pieces, so concatenating the pieces gives the original file
back, except the gaps made only of zero bytes, which are listed but not written.

## Detection

`FileCarver.scan` first tries `DotNetBundle.find` (see "Variants"). Otherwise
`scanRange` reads the file in 1 MiB buffers and, at every byte whose value is in
the candidate table, calls `identify`:

1. `identifyBuiltin` switches on the first two bytes and runs the parser of
   the format (table below). A signature alone is never enough: the parser
   must accept the structure.
2. If no built-in format matches and plugin probes are registered, every probe
   whose lead bytes include the current byte (or that declares no lead bytes)
   is asked with `probeAt`. The first non-null result with a positive length
   wins.

When a piece is recognized, the bytes since the end of the previous piece become
a gap piece (`padding` if all bytes are 0x00, else `unknown`), the piece is
added, and the scan jumps to its end. Recognized pieces are never searched
inside: a DLL stored in the resources of an EXE stays in the EXE.

The candidate table holds the lead bytes `'M'`, `0x7F`, `'P'`, `'7'`, `'R'`,
`0x1F`, `0xFD`, `0x89`, `0xFF`, `'G'`, `'%'`, `0xD0`, plus the lead bytes of the
registered probes.

## Structure

Recognized types and how the size is computed:

| Type | Start | Checks | Size |
|---|---|---|---|
| `pe` | "MZ" | `PeImage.parse` accepts the PE header | `PeImage.size`: headers, section raw data, COFF symbols and string table, plus the Authenticode certificate when it starts less than 8 bytes after the sections. Extension `exe`, `dll`, `sys` or `efi`; name from the export directory or `OriginalFilename` |
| `mz` | "MZ" without PE | bytes on last page < 512, page count > 0, header paragraphs >= 2, relocation table at 0x1C, 0x3E or 0x40 | `pages * 512`, or `(pages - 1) * 512 + last page bytes`; at least the header size |
| `elf` | `7F 45 4C 46` | class 1/2, data 1/2, version 1, header size >= 52, sane entry sizes and counts | largest end of: ELF header, program header table, segments, section header table, sections (SHT_NOBITS excluded); rejected if more than 1 MiB beyond the file. Extension `elf`, `so` or `o` |
| `zip` | `PK 03 04` | version <= 100, name 1..4096 bytes without control characters, method <= 20 or 93, 95-99 | end of central directory record + comment. EOCD records are searched forward; the one whose central directory offset is relative to this ZIP wins, else the first plausible one ("offsets relative to a container"); ZIP64 locator followed. No EOCD at all: up to the end of the file, truncated |
| `7z` | `37 7A BC AF 27 1C` | CRC32 of the start header | 32 + next header offset + next header size |
| `rar` | `Rar! 1A 07 00` | RAR 4: walk of the blocks (types 0x72-0x7B), a main header (0x73) must be seen | sum of header sizes, packed sizes (with HIGH_PACK_SIZE) and ADD_SIZE, up to the end block 0x7B or the first invalid block |
| `rar` | `Rar! 1A 07 01 00` | RAR 5: walk of the headers (vint sizes, types 1..5) | up to the end of archive header (type 5); with an archive encryption header (type 4) the rest of the file is taken |
| `cab` | `MSCF 00 00 00 00` | version 1.3 at offsets 24-25 | `cbCabinet` (offset 8), at least 36 |
| `gzip` | `1F 8B 08` | reserved flag bits zero | header fields skipped, deflate data inflated to its end, + 8 (CRC32, ISIZE). Name from FNAME |
| `xz` | `FD 37 7A 58 5A 00` | stream flags CRC32 | first stream footer ("YZ" at a 4-byte aligned end, footer CRC32 and flags equal to the header) plus the zero stream padding |
| `ole` | `D0 CF 11 E0 A1 B1 1A E1` | sector shift 9 or 12, FAT sector count 1..2^20 | `(highest used sector + 2) * sector size`, from the FAT sectors listed in the header DIFAT (109) and the DIFAT chain |
| `png` | `89 50 4E 47 0D 0A 1A 0A` | chunk types made of letters | chunks (length + 12 each) up to IEND |
| `jpeg` | `FF D8 FF` | markers in sequence | up to the EOI marker `FF D9`; after SOS the entropy-coded data is skipped up to the next marker that is not `FF 00`, a restart marker or a fill byte |
| `gif` | "GIF87a" / "GIF89a" | block introducers 0x21 / 0x2C | color tables, image descriptors and sub-blocks walked up to the trailer 0x3B |
| `pdf` | "%PDF-" | | up to the last "%%EOF" of the chain: after a "%%EOF" and its CR / LF / space, the search goes on if a digit or "x" follows (incremental update) |
| `riff` | "RIFF" | 4 printable characters of form type | 8 + chunk size + 1 padding byte if odd. Extension `wav`, `avi`, `ani`, `webp`, else `riff` |

When the structure announces more bytes than the file (or the scanned range)
holds, the piece is clipped and flagged `truncated` ("[TRUNCATED]" in the
listing). Several parsers return "file length + 1" on purpose to get this flag.

## Compression and encryption

Pieces are copied byte for byte. The only decoding is for the compressed
files of a .NET single-file bundle, written inflated (raw deflate,
`java.util.zip.Inflater` with `nowrap`). The `gzip` parser inflates the stream
only to find where it ends. Encryption is not handled.

## Variants and versions

### .NET single-file bundles

`DotNetBundle.find` first looks for the manifest through the apphost
(`findInExecutable`, signature in the first 16 MiB). If there is no apphost
(bundle cut out of its executable), `findWithoutHost` searches the last 16 MiB
backwards for a plausible manifest; the offsets are then shifted by the number
of missing bytes, and at least one stored assembly or native library must start
with "MZ" or "\x7FE" to confirm the shift. `scanBundle` then:

- writes each bundle file at its relative path (`\` becomes `/`), compressed
  files inflated; entries overlapping a previous one are skipped;
- scans the apphost and the gaps between files as usual;
- adds the manifest as a piece (`manifest`, name `bundle_manifest`);
- when the apphost signature lies after the manifest, lists the 8-byte
  WIN_CERTIFICATE header as padding (not written) and writes the PKCS#7 data
  as `signature.p7b`.

### Plugin carving probes

A plugin can make its format recognizable by `arcana s` by returning a
`FileCarver.FormatProbe` from `ArcanaPlugin.createProbe()`:

```java
public interface FormatProbe {
    int[] leadBytes();                              // possible first bytes (0-255)
    Probe probeAt(ByteSource s, long p) throws IOException;  // null if not at p
}
// new FileCarver.Probe(length, type, extension, description, name)
```

`PluginManager.registerProbe` calls `FileCarver.addProbe` for every plugin
loaded (and for plugins registered by code with `register`); `clearProbes`
runs before a (re)load. `Arcana.scanEmbedded`, `Arcana.split` and the `s`
command call `PluginManager.get()` first so the probes are in place. Built-in
formats are always tried before the probes. A probe that throws a
`RuntimeException` (in `leadBytes` or `probeAt`) is ignored.

### Output

`FileCarver.split` writes into `Arcana.splitDirectory(file, dest)`:
`dest/<file name without extension>`, or `<name>_split` if a file of that name
exists. Pieces are named `NNN_0xOFFSET[_name].ext`: a 3-digit index (4 digits
when more than 999 pieces are numbered), the offset in 8 hex digits, the
internal name without its extension and cut to 80 characters (or `_unknown` for
a gap), then the extension. Padding pieces get no file and no index. Example
(a gzip, a ZIP and an xz concatenated):

```
  0x00000000        45010  gzip     GZIP data
  0x0000AFD2        43955  zip      ZIP archive
  0x00015B85         4948  xz       XZ data
```

written as `000_0x00000000_b.txt.gz`, `001_0x0000AFD2.zip`, `002_0x00015B85.xz`.

## Limits

- No recursion: an archive or executable inside a recognized piece is not
  split (use `arcana s` again on the piece).
- Only the formats of the table are recognized: bzip2, Zstandard, LZ4, TAR,
  ISO, Mach-O and others end up in unknown pieces.
- A multi-member gzip gives one piece per member; a multi-stream xz gives one
  piece per stream (the scan restarts after the first).
- A RAR 4 archive with encrypted headers (`-hp`) has unreadable blocks after
  the main header: the walk stops there and the piece is too short.
- A "%%EOF" inside a PDF stream, or a JPEG with an unusual marker layout, can
  end the piece early.
- A probe's `IOException` is not caught and stops the scan.
- The `gzip` candidate inflates the whole stream, which costs time on large
  files.

## Implementation notes

- `ByteSource` is a random-access reader over a `RandomAccessFile` with a cache
  of 8 pages of 64 KiB. Reads outside the file return -1 (`u8`, `u16le`,
  `u32le`...) or 0 bytes (`read`) instead of throwing; `bytes` returns null
  when the file is shorter. The parsers rely on this and check plausibility
  themselves.
- `FileCarver.identifyAt` is public for `SfxExtractor`, which uses the same
  parsers to find the archive of a self-extracting executable (see
  `sfx-executables.md`).
- Plain pieces are written with a `FileOutputStream`; only the inflated bundle
  entries go through `ExtractionGuard.open`. Bundle paths go through
  `SafePathBuilder`.
- The scan of a gap stops at the first recognized candidate; bytes that only
  look like a signature (for example "MZ" in text) stay in the unknown piece.

## Sources

- Microsoft, "PE Format": https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Tool Interface Standard, ELF specification: https://refspecs.linuxfoundation.org/elf/elf.pdf
- PKWARE, APPNOTE.TXT (ZIP): https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- 7-Zip, `DOC/7zFormat.txt` in the 7-Zip source distribution
- RARLAB, RAR 5.0 archive format: https://www.rarlab.com/technote.htm
- RFC 1952, GZIP file format: https://www.rfc-editor.org/rfc/rfc1952
- The .xz file format: https://tukaani.org/xz/xz-file-format.txt
- Microsoft, [MS-CFB] Compound File Binary File Format:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
- W3C, PNG specification: https://www.w3.org/TR/png/
- GIF89a specification: https://www.w3.org/Graphics/GIF/spec-gif89a.txt
- ITU-T T.81 (JPEG): https://www.w3.org/Graphics/JPEG/itu-t81.pdf
- .NET bundle manifest writer, dotnet/runtime repository:
  https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs

License: `FileCarver`, `ByteSource`, `PeImage`, `PeResources` and
`DotNetBundle` are independent implementations, Copyright Stephane Bury,
Apache-2.0 (file headers).
