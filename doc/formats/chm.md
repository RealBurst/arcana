# Microsoft Compiled HTML Help (CHM)

| | |
|---|---|
| Extensions | `.chm` (format name `chm`; `.chi`, `.chq`, `.chw` are also registered names) |
| Signature | `49 54 53 46` ("ITSF") at offset 0 |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.formats.chm.ChmReader`, `be.stef.arcana.formats.lzx.LzxDecoder`, `be.stef.arcana.extractor.ChmExtractor` |
| Test samples | `test/samples/chm/help.chm` (made by `chmcmd`); corpus reference `test/corpus/chm/7-zip.chm.txt` (help file of 7-Zip 25.01) |

## Overview

Compiled HTML Help is the help file format of Windows since Windows 98 (HTML
Help 1.x, Microsoft, 1997). A `.chm` file is a small file system ("ITSF",
InfoTech Storage Format) holding the HTML pages, images, the table of contents
and index, and internal system files (`#SYSTEM`, `#TOPICS`, `$FIftiMain`...).
Most of the content is in one LZX-compressed section. CHM files are still
shipped as program documentation (7-Zip, many Windows tools).

## Detection

`ArchiveDetector.detectByMagic` returns `CHM` when the file starts with
"ITSF"; this check comes after the CAB, WIM, SquashFS and OLE signatures. The
extension fallback maps `.chm` to `CHM`. `ChmReader` checks "ITSF" again
("Not a CHM file") and "ITSP" at the directory offset ("CHM directory header
not found").

No analyzer recognizes CHM, so `arcana i` falls back to the format detection
and prints "CHM archive" (`Arcana.identify`).

## Structure

All integers are little-endian unless stated otherwise.

### ITSF header (`ChmReader` constructor)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "ITSF" |
| 4 | 4 | version | 2 or 3 |
| 8 | 4 | header length | 0x60 in version 3 |
| 12 | 4 | unknown | not read |
| 16 | 4 | timestamp | not read |
| 20 | 4 | language ID | not read |
| 24 | 32 | two GUIDs | not read |
| 56 | 16 | offset and length of header section 0 | not read |
| 72 | 8 | directory offset | offset of the ITSP header |
| 80 | 8 | directory length | |
| 88 | 8 | content offset | version 3 with a header length of at least 0x60 only |

Without the field at 88, the content (section 0) starts right after the
directory. In `help.chm`: version 3, directory at 120 (4180 bytes), content at
4300.

### ITSP directory header (`readDirectory`)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "ITSP" |
| 8 | 4 | header length | the chunks start at directory offset + this value |
| 16 | 4 | chunk size | 32 to 1 MiB accepted; 4096 in practice |
| 44 | 4 | number of chunks | chunks x chunk size must fit in the directory length |

The other fields (index depth, root index chunk, first and last listing chunk,
language, GUID) are not used.

### Listing chunks ("PMGL")

Every chunk of the directory is read in file order. Chunks that do not start
with "PMGL" (the "PMGI" index chunks) are skipped; the "first chunk" field and
the chunk links are not used, since they are not always right.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "PMGL" |
| 4 | 4 | free space | bytes at the end of the chunk (quick reference area) not holding entries |
| 8 | 4 | unknown | |
| 12 | 4 | previous chunk | not used |
| 16 | 4 | next chunk | not used |
| 20 | var | entries | until chunk size - free space |

Entry:

| Field | Coding | Notes |
|---|---|---|
| name length | encint | must be > 0 and stay inside the chunk |
| name | UTF-8 | "/path/name"; directories end with "/"; internal entries start with "::" |
| section | encint | 0 = stored, 1 = MSCompressed |
| offset | encint | offset in the section |
| length | encint | |

An encint is a big-endian sequence of 7-bit groups, the high bit of a byte
meaning that another byte follows (`encint`, at most 9 bytes).

### Sections

- **Section 0** (stored): the bytes at content offset + entry offset.
- **Section 1** ("MSCompressed"): one LZX stream stored in section 0 as
  `::DataSpace/Storage/MSCompressed/Content`, described by two more section 0
  entries:

`::DataSpace/Storage/MSCompressed/ControlData` (first 64 bytes read):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | size | in 32-bit words; not read |
| 4 | 4 | signature | "LZXC" |
| 8 | 4 | version | 2: the next two values are in 32 KiB units; 1: in bytes |
| 12 | 4 | reset interval | must be a non-zero multiple of 32 KiB |
| 16 | 4 | window size | must be a power of two from 2^15 to 2^21 |

`::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable`:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | version | not checked |
| 4 | 4 | entry count | at least the number of 32 KiB frames |
| 8 | 4 | entry size | must be 8 |
| 12 | 4 | header size | the entries start here |
| 16 | 8 | uncompressed length | of the whole section, at most 2^31 |
| 24 | 8 | compressed length | at most the length of `Content` |
| 32 | 8 | frame size | must be 32768 |
| header size | 8 each | entries | compressed offset of each frame in `Content` |

In `help.chm`: control data version 2, window 2 x 32 KiB, reset interval
2 frames; reset table with 5 entries (0, 3022, 3132, 4228, 4294) for a section
of 99092 bytes (4 frames) compressed to 4294 bytes.

## Compression and encryption

`ChmReader.decompressSection1` decodes the whole section 1 the first time an
entry of section 1 is extracted:

1. reads the control data and the reset table and checks them (messages
   "Invalid CHM LZX control data", "Invalid CHM LZX window size n",
   "Invalid CHM LZX reset interval", "Unsupported CHM reset table",
   "Invalid CHM section size", "CHM reset table incomplete");
2. reads the compressed `Content` into memory;
3. creates one `LzxDecoder` with the window size, and decodes frame i from
   reset table entry i to entry i + 1 (the compressed length for the last
   frame); before frame 0 it calls `reset()`, and before every frame that is a
   multiple of the reset interval `resetState()` (the LZX coding state starts
   again, the window goes on);
4. keeps the uncompressed section in memory; every section 1 entry is then a
   copy of its range ("CHM entry outside its section" when it does not fit).

See [lzx.md](lzx.md) for the LZX decoder. CHM has no encryption.

## Variants and versions

- ITSF versions 2 and 3 (content offset given or not). Verified on the version
  3 file made by `chmcmd` (Free Pascal) and on the 7-Zip help file of the
  corpus (103 entries listed).
- LZXC control data versions 1 (sizes in bytes) and 2 (sizes in 32 KiB units).
- Files with PMGI index chunks (larger help files): only the PMGL chunks are
  read, all of them.
- `.chi`, `.chq` and `.chw` are registered names of the format; such files are
  recognized by their "ITSF" signature, the extension fallback only knows
  `.chm`.

## Limits

- Sections other than 0 and 1 are refused when one of their entries is
  extracted: "CHM section n is not supported".
- Section 1 is decompressed entirely into memory, and the compressed content
  too; the section is limited to 2^31 bytes by the checks. (An uncompressed
  length of exactly 2^31 passes the check and then fails when the buffer is
  allocated.)
- A corruption anywhere in section 1 makes every section 1 entry fail, since
  the section is decoded at once (for example "Invalid LZX Huffman code" with
  one flipped byte in `help.chm`). Entries written before the error stay on
  disk.
- No dates: CHM entries have none; the listing shows "-".
- The internal `::DataSpace/...` entries and the root "/" are neither listed
  nor extracted (7-Zip 23.01 hides them too on `help.chm`).
- No stream extraction: "CHM requires random file access - use
  extract(File,File)." (`ArcanaUnsupportedFormatException`).

## Implementation notes

- Entry names keep the leading characters of the help file: `#SYSTEM`,
  `$OBJINST`, `_#_README_#_` are extracted like 7-Zip does. The leading "/" is
  removed, directories lose their trailing "/" and are created as folders.
- `ChmExtractor` builds the output path with `SafePathBuilder.buildSafePath`
  (path traversal refused) and writes through `ExtractionGuard.open` (output
  limits). Exceptions are not rewrapped: `ChmReader` throws
  `ArcanaCorruptedException` or `ArcanaUnsupportedFormatException` itself.
- Every read is bounds-checked against the file length ("CHM data outside the
  file"); the directory chunk size and chunk count are checked against the
  directory length before any chunk is read.
- An empty entry (length 0, such as `#ITBITS`) gives an empty file without
  touching the sections.
- The sample `help.chm` holds 7 files in section 1 and 3 in section 0
  (`#ITBITS`, `#SYSTEM`, `_#_README_#_`), with a reset interval smaller than the section,
  so both `reset()` and `resetState()` are exercised
  (`test/expected/chm/help.chm.txt`).

## Sources

- CHM format description, chmspec project (ITSF, ITSP, PMGL/PMGI, encint,
  LZXC, reset table): https://www.nongnu.org/chmspec/latest/ITSF.html
- Microsoft, [MS-PATCH] LZX DELTA Compression and Decompression (LZX, see
  [lzx.md](lzx.md)):
  https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf

License: `ChmReader` and `ChmExtractor` are Copyright 2026 Stephane Bury,
Apache-2.0 (file headers). `ChmReader` states that it was written from the
community description of the ITSF format.
