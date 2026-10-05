# Microsoft Cabinet (CAB)

| | |
|---|---|
| Extensions | `.cab` |
| Signature | `4D 53 43 46` ("MSCF") at offset 0 |
| Arcana support | list, extract (stored, MSZIP, LZX), create (MSZIP, one folder) |
| Main classes | `be.stef.arcana.formats.cab.CabReader`, `be.stef.arcana.formats.cab.CabWriter`, `be.stef.arcana.formats.cab.MszipDecoder`, `be.stef.arcana.formats.lzx.LzxDecoder`, `be.stef.arcana.extractor.CabExtractor`, `be.stef.arcana.compressor.CabCompressor` |
| Test samples | `test/samples/cab/stored.cab`, `test/samples/cab/mszip.cab` (both made by `gcab`), `test/samples/cab/arcana-created.cab` (made by `arcana c` from the test payload), `test/samples/damaged/truncated.cab` |

## Overview

The Cabinet format is Microsoft's archive format, introduced in the mid-1990s
for Windows and Office setup disks. It is still used by Windows Update packages,
driver packages, IExpress self-extractors and Windows Installer packages (the
files of an `.msi` are stored in cabinets, see [msi-ole.md](msi-ole.md)).

A cabinet groups its files into *folders*. A folder is one compressed stream:
the files of a folder are concatenated, and the result is cut into data blocks
(`CFDATA`) of at most 32 KiB of uncompressed data, each one compressed with
the method of the folder. A file is located by its folder index and its offset
in the uncompressed stream of that folder. A cabinet can be one volume of a
set, in which case a file or a folder may continue in the next cabinet.

## Detection

`ArchiveDetector.detectByMagic` returns `CAB` when the file starts with
"MSCF"; no other byte is checked. The extension fallback maps `.cab` to `CAB`.
`CabReader` itself only checks the same 4-byte signature
("CAB: not a Cabinet file (bad magic)").

`arcana i` uses `ArchiveAnalyzer.cab`: it reports "Cabinet" with the version
from offsets 25 (major) and 24 (minor), and the file and folder counts from
offsets 28 and 26.

Cabinets embedded in other files (IExpress, installers, resource sections) are
found by `FileCarver` with the stricter signature `MSCF 00 00 00 00`; see
[embedded-files.md](embedded-files.md) and
[sfx-executables.md](sfx-executables.md).

## Structure

All integers are little-endian.

### CFHEADER (`CabReader.readHeader`)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "MSCF" |
| 4 | 4 | reserved | ignored |
| 8 | 4 | cbCabinet | total size of the cabinet; ignored by the reader |
| 12 | 4 | reserved | ignored |
| 16 | 4 | coffFiles | offset of the first `CFFILE` |
| 20 | 4 | reserved | ignored |
| 24 | 1 | versionMinor | 3 |
| 25 | 1 | versionMajor | 1 |
| 26 | 2 | cFolders | number of `CFFOLDER` entries |
| 28 | 2 | cFiles | number of `CFFILE` entries |
| 30 | 2 | flags | 0x0001 previous cabinet, 0x0002 next cabinet, 0x0004 reserve fields present |
| 32 | 2 | setID | ignored |
| 34 | 2 | iCabinet | index of this cabinet in its set; ignored |
| 36 | 4 | reserve sizes | only with flag 0x0004: per-cabinet size (2 bytes), per-folder size (1), per-data-block size (1) |
| ... | n | per-cabinet reserve | skipped |
| ... | var | previous cabinet name and disk name | only with flag 0x0001: two zero-terminated strings, skipped |
| ... | var | next cabinet name and disk name | only with flag 0x0002: two zero-terminated strings, skipped |

### CFFOLDER (`CabReader.readFolders`)

The folders follow the header directly, `cFolders` times:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | coffCabStart | offset of the first `CFDATA` of the folder |
| 4 | 2 | cCFData | number of data blocks of the folder in this cabinet |
| 6 | 2 | typeCompress | bits 0-3: method; bits 8-12: LZX window size (log2) |
| 8 | n | per-folder reserve | skipped |

### CFFILE (`CabReader.readFiles`)

Read from `coffFiles`, `cFiles` times:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | cbFile | uncompressed size |
| 4 | 4 | uoffFolderStart | offset of the file in the uncompressed folder |
| 8 | 2 | iFolder | folder index; 0xFFFD, 0xFFFE, 0xFFFF mark files continued from/to another cabinet |
| 10 | 2 | date | MS-DOS date |
| 12 | 2 | time | MS-DOS time |
| 14 | 2 | attribs | 0x10 directory, 0x80 name is UTF-8; the other bits are ignored |
| 16 | var | name | zero-terminated; UTF-8 when 0x80 is set, ISO-8859-1 otherwise |

`CabEntry` turns `\` into `/` in names. The date and time are converted as UTC
(`dosToUnixMs`); an invalid month or a day of 0 gives no date.

### CFDATA (`CabReader.FolderCursor.advance`)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | csum | checksum; 0 = not computed |
| 4 | 2 | cbData | compressed size of the block |
| 6 | 2 | cbUncomp | uncompressed size of the block |
| 8 | n | per-data-block reserve | skipped |
| 8+n | cbData | data | |

The checksum (`CabReader.checksum`) is the XOR of the data read as 32-bit
little-endian words, the 1 to 3 trailing bytes being packed into one word with
the first byte in the highest position; the result is then used as the seed of
the same computation over the 4 bytes `cbData` + `cbUncomp`. A non-zero `csum`
that does not match gives "CAB: data block checksum error (block n)". The
per-data-block reserve is not part of the computed value (see Limits).

## Compression and encryption

The method is the low 4 bits of `typeCompress`:

| Value | Method | Arcana |
|---|---|---|
| 0 | none | `cbData` must equal `cbUncomp` ("CAB: stored block size mismatch") |
| 1 | MSZIP | `MszipDecoder` |
| 2 | Quantum | not supported |
| 3 | LZX | `LzxDecoder` (see [lzx.md](lzx.md)) |

- **MSZIP.** Each block starts with "CK" (`43 4B`) followed by raw Deflate
  data. `MszipDecoder.decompress` inflates it with `java.util.zip.Inflater`
  (`nowrap`), after giving the uncompressed output of the previous block of the
  same folder as preset dictionary (`setDictionary`): a block may refer to up
  to 32 KiB of the previous one. The block must produce exactly `cbUncomp`
  bytes. Errors: "CAB: missing MSZIP 'CK' signature in CFDATA block",
  "CAB: MSZIP decompressed n bytes, expected m", "CAB: MSZIP decompression
  error: ...".
- **LZX.** One `LzxDecoder` per folder, created with the window size of bits
  8-12 of `typeCompress` (15 when the field is 0). Every `CFDATA` is one LZX
  frame; the decoder state goes on from one block to the next.
- The format has no encryption.

### Creation (`arcana c dir out.cab`)

`CabCompressor` collects the regular files of the source (a file, or a
directory walked recursively: files of a directory first, sorted by name, then
its subdirectories); directories themselves are not stored. Paths are relative
to the source directory (or to the parent of a single file) with `\` as
separator. `CabWriter` then builds the whole cabinet in memory:

- one folder, method MSZIP, version 1.3, flags 0, setID 1, iCabinet 0;
- the data of all files is concatenated into the folder stream and cut into
  blocks of 32768 bytes; only the last block of the folder is shorter (a file
  may start or end anywhere in a block, an empty file takes no space); an
  empty cabinet gets one empty block;
- each block is "CK" followed by a complete raw Deflate stream
  (`Deflater.DEFAULT_COMPRESSION`, final block bit set), compressed with the
  uncompressed data of the previous block as preset dictionary
  (`setDictionary`): the Deflate history goes on across the blocks of the
  folder, as MS-ZIP defines it and as the reader expects;
- range checks before writing: at most 65535 files, at most 65535 blocks (so
  at most 65535 x 32768 bytes of data in the folder), and a cabinet of less
  than 4 GB; beyond, an `IOException` ("CAB: too many files (n, maximum
  65535)", "CAB: too much data for one folder (...)", "CAB: cabinet larger
  than 4 GB (...)") is thrown before anything is written;
- the checksum of every block is written (same function as the reader);
- attributes 0x20 (archive), plus 0x80 when the name is not pure ASCII (the
  name is then written in UTF-8);
- dates are written as MS-DOS date/time in UTC; years before 1980 become 1980.

The `-l` level is not used for CAB.

## Variants and versions

- Version 1.3 is the only version written by Microsoft tools; the version bytes
  are not checked by the reader.
- Cabinets with reserve fields: the three reserve areas are skipped. Verified with a cabinet rebuilt from
  `stored.cab` with 6 bytes of per-cabinet, 2 bytes of per-folder and 3 bytes
  of per-block reserve.
- Several folders: each file is read from its own folder; the folder methods
  can differ.
- Cabinets made by `gcab` (`test/samples/cab`) carry checksums; the 35106 bytes
  of the stored sample are two blocks (32768 + 2338 bytes), the MSZIP sample's
  first block is 4335 bytes for 32768.

## Limits

- **Quantum** (method 2): "Corrupted Cabinet archive: CAB: Quantum compression
  is not supported" (raised when the first file of a Quantum folder is
  extracted; listing works).
- **Multi-cabinet sets**: the previous/next cabinet names are skipped and the
  next cabinet is never opened. Files continued from a previous cabinet
  (`iFolder` 0xFFFD or 0xFFFF) are listed, but extraction stops with an index
  error ("Index 65533 out of bounds for length 1" for 0xFFFD in a one-folder
  cabinet), which is not wrapped in an Arcana exception. A file continued in
  the next cabinet fails when its folder runs out of blocks ("CAB: file data
  truncated (x of y bytes)").
- The per-data-block reserve is not included in the checksum. The Microsoft
  Cabinet Format document defines the checksum from `cbData` through the end of
  the block, reserve included; 7-Zip follows it, `gcab` does like Arcana. A
  cabinet with per-block reserve and checksums written the 7-Zip way is
  rejected with "data block checksum error".
- Attributes other than "directory" and "UTF-8 name" (read-only, hidden,
  system, execute) are not applied.
- Names without the UTF-8 flag are decoded as ISO-8859-1, not in the OEM code
  page of the creating system.
- No stream extraction: `extract(InputStream, File)` throws "CAB extraction
  requires random access; use extract(File, File) instead."
- Creation: a single folder, MSZIP only, no directory entries, no
  multi-cabinet sets, so at most 65535 files and about 2 GB of data (65535
  blocks of 32 KiB); every input file and all compressed blocks are held in
  memory. Created cabinets are checked with 7-Zip (`7zz t`, `x`) and `gcab`
  (`-t`, `-x`): same files as the source, also for a folder of 30 files of
  0 to 70000 bytes crossing block boundaries. (Before October 2026 every file
  started a new block, which left short blocks inside the folder: 7-Zip
  reported "Data Error" for the files after the first one.)
- No recovery strategy beyond normal extraction (see [recovery.md](recovery.md)).

## Implementation notes

- `CabReader` reads the header, folders and file entries once, then decodes
  data on demand through a `FolderCursor`: the cursor keeps the current block,
  its position in the folder and the decoder state (MSZIP history, LZX
  window). Files extracted in folder order continue from the current block;
  the folder is decoded again from its first block only when a file starts
  before the current block or is in another folder. (Before this, a cabinet of
  2000 files decoded its folder 2000 times.)
- Each block is read into a buffer of `cbData` bytes and decoded into a buffer
  of `cbUncomp` bytes (both at most 65535), so memory stays bounded whatever
  the size of the folder.
- `CabExtractor` builds output paths with `SafePathBuilder.buildSafePath`
  (path traversal is refused), opens files through `ExtractionGuard.open`
  (output limits), and sets the modification time when the entry has one. Any
  `IOException` except `ArcanaLimitExceededException` is rethrown as
  `ArcanaCorruptedException` ("Corrupted Cabinet archive: ..."). A cabinet cut
  in half lists correctly (the directory is at the start) and fails at
  extraction with "CAB: unexpected end of file"
  (`test/expected/damaged/truncated.cab.txt`).
- Listing reports the uncompressed size, the date and the directory flag; no
  packed size is given (it is not defined per file).

## Sources

- Microsoft, "Microsoft Cabinet Format" (CFHEADER, CFFOLDER, CFFILE, CFDATA,
  checksum method): https://learn.microsoft.com/en-us/previous-versions/bb267310(v=vs.85)
- Microsoft, [MS-MCI] Microsoft ZIP (MSZIP) Compression and Decompression Data
  Structure:
  https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-mci/27f0a9bf-9567-4e40-ad66-6ae9ab9d2786
- Microsoft, [MS-PATCH] LZX DELTA Compression and Decompression (for LZX, see
  [lzx.md](lzx.md)):
  https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf
- RFC 1951, DEFLATE compressed data format specification version 1.3:
  https://www.rfc-editor.org/rfc/rfc1951

License: `CabReader`, `CabWriter`, `CabEntry`, `MszipDecoder`, `CabExtractor`
and `CabCompressor` are Copyright 2025 Stephane Bury, Apache-2.0 (file
headers). The Javadoc of `CabReader.checksum` names libmspack's
`cabd_checksum` as the reference for the checksum algorithm; no code from it
is included. Deflate is the JDK implementation (`java.util.zip`).
