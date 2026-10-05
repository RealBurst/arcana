# Recovery of damaged archives (forced extraction)

| | |
|---|---|
| Extensions | any format Arcana extracts, and plugin formats |
| Signature | none of its own; the format is chosen as for a normal extraction (magic bytes, then extension) |
| Arcana support | forced extraction: `arcana r <archive> [dest] [-p password] [-f format]`, `Arcana.forceUnpack(File, File)`, `Arcana.with(...).forceExtract(File, File)` |
| Main classes | `be.stef.arcana.formats.recover.ForceUnpacker`, `RecoveryReport`, `ZipRecovery`, `TarRecovery`, `SevenZRecovery`, `Lzma2SegmentRecovery`, `BZip2Recovery`, `Outputs`, `ArchiveRecoverer`, `RecoveredFile` (same package) |
| Test samples | `test/samples/damaged/` (references in `test/expected/damaged/`) |

## Overview

A normal extraction stops at the first error. Forced extraction recovers as
much as possible from a damaged archive and writes a report giving the
reliability of every file. The result is uncertain by nature: the CLI prints
`RecoveryReport.WARNING` first, and the report repeats it. Each format either
has a dedicated strategy (resynchronization, block-level decoding...) or falls
back to a normal extraction that keeps whatever was written before the error.

## Detection

`Arcana.doForceUnpack` chooses the path:

1. **Plugin.** The forced plugin (`-f` with a plugin format name), or, when no
   format is forced, `detectPlugin` (plugins with a priority, then the other
   plugins when no built-in format matches the content). If the plugin returns
   an `ArchiveRecoverer` from `createRecoverer(password)`, it is used;
   otherwise `ForceUnpacker` runs the plugin's normal extractor with the
   generic strategy.
2. **Built-in format.** `resolveFormat` (forced format, else
   `ArchiveDetector.detect`: magic bytes, disc signatures, then the
   extension). A ZIP whose first local header is destroyed is still handled as
   ZIP when it is named `.zip`. `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`
   and `.tar.lz4` names promote the compressed format to its TAR variant.
   An unrecognized file is searched for an embedded archive (`SFX`).

Everything runs inside an `ExtractionGuard` scope, so the extraction limits
apply; `ArcanaLimitExceededException` is always rethrown, never turned into a
report note.

## Structure

### Statuses (`RecoveryReport.Status`)

| Status | Meaning |
|---|---|
| `OK` | decoded completely and the checksum, when the format has one, is correct |
| `UNVERIFIED` | decoded completely (or written by a normal extraction that later failed) but nothing confirms the content |
| `BAD_CHECKSUM` | decoded completely but the checksum does not match: the content is damaged |
| `PARTIAL` | decoding stopped on an error, or data is missing: only part of the file was written |
| `LOST` | nothing could be decoded (encrypted, unsupported method, destroyed data) |

### Report file

`RecoveryReport.writeTo` writes `_ARCANA_RECOVERY_REPORT.txt` (UTF-8) in the
destination: the warning, the archive name, the method used, a summary
(`N file(s): a OK, b unverified, c bad checksum, d partial, e lost`), the
notes, then one line per file: status, bytes written, expected size (`?` when
unknown), name and message. Example with `test/samples/damaged/bad-crc.zip`:

```
Method  : ZIP: local headers scanned one by one
Result  : 5 file(s): 4 OK, 0 unverified, 0 bad checksum, 0 partial, 1 lost

Status            Written / Expected     Name
OK                   1520 / 1520         readme.txt
OK                      5 / 5            deep/a/b/c/leaf.txt
OK                      0 / 0            docs/empty.txt
LOST                    0 / 29490        docs/notes.txt  (DataFormatException: invalid distance too far back)
OK                   4096 / 4096         bin/random.bin
```

### Strategies (`ForceUnpacker.run`)

| Format | Strategy | Class |
|---|---|---|
| ZIP | local headers searched one by one, central directory ignored | `ZipRecovery` |
| TAR | damaged headers skipped, resynchronization on the next valid header | `TarRecovery` |
| bzip2, tar.bz2 | every block decoded separately, then TAR recovery of the result | `BZip2Recovery` |
| xz, tar.xz | every block decoded separately through the index; index unreadable: sequential decoding up to the damage | `ForceUnpacker.xzBlocks` |
| gzip, zstd, lz4, lzma, brotli, snappy and their TAR | stream decoded up to the damage, then TAR recovery of the result | `ForceUnpacker.stream` |
| 7z | entries decoded separately; tail of a damaged LZMA2 block; raw decoding when the header is lost | `SevenZRecovery`, `Lzma2SegmentRecovery` |
| SFX | embedded archive located, copied, and recovered with its own strategy | `ForceUnpacker` + `SfxExtractor.locate` |
| plugin with `ArchiveRecoverer` | the plugin's strategy | plugin |
| others (RAR, CAB, ISO, WIM, plugins without recoverer...) | normal extraction, keeping everything written | `ForceUnpacker.generic` |

## Compression and encryption

**ZIP** (`ZipRecovery`). `PK 03 04` is searched from the start; a header is
accepted if the name is 1..4096 bytes without control characters. Sizes come
from the local header or its ZIP64 extra field. Methods: stored (0), deflate (8,
raw `Inflater`, which also tells how many compressed bytes were used), Deflate64
(9), bzip2 (12), LZMA (14), Zstandard (93), xz (95); other methods give `LOST`.
Encrypted entries (flag bit 0) are `LOST`. With a data descriptor (flag bit 3)
and no size, deflate data is decoded to its end and stored data runs up to the
next `PK 07 08`; CRC and size are then read from the descriptor. A decoding
error gives `PARTIAL` (or `LOST` with nothing written, the empty file being
deleted); a CRC or size mismatch gives `BAD_CHECKSUM`. After a damaged entry,
the next header is searched right after its header, since its sizes cannot be
trusted. Names: UTF-8 when flag bit 11 is set or the bytes are valid UTF-8,
else IBM437.

**TAR** (`TarRecovery`). A header is valid if its checksum field matches the
unsigned or signed sum of the 512 bytes. A zero block is skipped. A damaged
header triggers `resync`: the next "ustar" magic at any byte offset whose
header is valid, else the next 512-aligned valid header. GNU long names (`L`)
and PAX `path` / `size` records (`x`) are applied; `K` and `g` are skipped.
Directories are created; hard and symbolic links are reported `UNVERIFIED`
with 0 bytes and not recreated; devices and FIFOs are skipped. TAR has no
content checksum: complete files are `UNVERIFIED`, or `OK` when the TAR came
out of a compressed stream decoded completely with no lost block. A file cut by
the end of the archive is `PARTIAL`. When no valid header follows a file, that
file is downgraded to `PARTIAL`. With holes (data lost before, as after a lost
bzip2 or xz block), a valid header found inside the data of a file cuts it
there (`PARTIAL`) and recovery resumes from that header.

**bzip2** (`BZip2Recovery`, same principle as bzip2recover). The 48-bit block
magic `0x314159265359` and end-of-stream magic `0x177245385090` are searched at
every bit position. Each block (80 bits to 2 MB) is copied into a stand-alone
one-block stream (`BZh9` header, block, end-of-stream marker, the block CRC as
the combined CRC) and decoded by `BZip2InputStream`, which verifies the block
CRC. A damaged block is lost (up to 900 KB of data); the others are written in
order.

**xz.** `SeekableXZInputStream` reads the index; each block is decoded by a
fresh reader into memory and written only if complete. If the index is
unreadable the stream is decoded sequentially up to the error.

**Stream formats** (gzip, zstd, lz4, lzma, brotli, snappy). These formats
cannot restart after damage: the data is decoded with
`CompressedStreamExtractor.openDecompressed` up to the first error, and the
note gives the number of bytes decoded.

For bzip2, xz and the stream formats, the decoded data goes to a temporary
file. If it starts with a valid TAR header (or "ustar" at offset 257), TAR
recovery is applied; otherwise it is written as one file named after the
archive without its last extension and without ".tar" (`OK` if complete,
`PARTIAL` if not, `LOST` if empty).

**7z** (`SevenZRecovery`). When `SevenZFile` can read the header (with the
password given by `-p`), entries are decoded one by one. An error loses the
rest of that entry's folder (solid block): the following entries of the folder
are `LOST` ("follows the damaged point of its solid block"); other folders are
still decoded. Complete entries are `OK` with a CRC, `UNVERIFIED` without.
For a damaged folder made of a single LZMA2 coder (`getLzma2FolderInfo`),
`Lzma2SegmentRecovery.findTail` looks after the damage for a chunk with control
byte 0xE0-0xFF (dictionary and properties reset) from which the chain of chunk
headers leads exactly to the end marker of the stream. The segments of that
tail are decoded independently; their position in the uncompressed data is
computed from the end of the folder, and the entries they cover entirely are
written and checked against their CRC. This only helps when the encoder cut
the stream into independent segments (multithreaded 7-Zip, Arcana); otherwise a
note says the rest of the block is lost. When the header is unreadable
(truncated archive), the data after the 32-byte signature header is decoded as
raw LZMA2 (first byte 0x01 or >= 0xE0) or LZMA with default properties, into
`<name>_7z_data.bin`: names and boundaries are lost, status `PARTIAL` or `LOST`.

## Variants and versions

**Self-extracting executables.** `SfxExtractor.locate` finds the payload; its
byte range is copied to a temporary file and `run` is called again with the
payload format. The archive name in the report becomes
`<exe> -> <payload description>`.

**Generic strategy** (`ForceUnpacker.generic`). The normal extractor runs; the
regular files that appear in the destination (compared with a listing taken
before) are reported. Without error they are `OK`; after an error all of them
are `UNVERIFIED`, with notes saying that the last file may be incomplete and
that, in solid archives, files after the damaged point cannot be decoded.

**Plugin recoverer.** `ArchiveRecoverer.recover(archive, destination)` writes
the files (preferably with `PluginSupport.openOutput`) and returns a
`RecoveredFile` per file (name, status, bytes written, message;
`RecoveredFile.ok` and `RecoveredFile.partial` are shortcuts). A null status is
reported `UNVERIFIED`. An exception thrown by the recoverer becomes the note
"Plugin recovery stopped: ..."; the method is reported as
"plugin recovery strategy".

## Limits

- Encrypted ZIP entries are not recovered. RAR, CAB, ISO, WIM, SquashFS and
  the other formats have no dedicated strategy; for solid RAR archives nothing
  after the damaged point is decoded.
- gzip, zstd, lz4, lzma, brotli and snappy cannot resume after damage.
- A lost bzip2 block costs up to 900 KB of data; a lost xz block costs its whole
  block.
- The decoded data is recognized as TAR only from its first bytes. When the
  first bzip2 or xz block is lost, the rest is written as a single file even if
  it contains TAR headers (observed with a damaged `.tar.bz2`).
- The 7z LZMA2 tail recovery needs a single-coder LZMA2 folder (no BCJ filter,
  no encryption); entries starting before the tail are not recovered.
- The generic strategy cannot tell which file was being written when the error
  occurred: all files are `UNVERIFIED` after an error.
- Forced extraction of an executable whose payload is a Windows Installer
  package in its resources copies only the package and gives it to the generic
  strategy with `SfxExtractor`, which finds no archive in a bare `.msi`; the
  external cabinets in the resources are not copied either.

## Implementation notes

- `Outputs` builds safe paths (`SafePathBuilder`), opens files through
  `ExtractionGuard.open`, and never overwrites a name already written in the
  same run: the second copy gets `_2`, `_3`... before the extension (an entry
  found twice after a resynchronization). Files of entries of which nothing
  could be decoded are deleted (`dropLastIfEmpty`).
- The report file itself is excluded from the generic strategy's listing.
- Statuses can be revised: `TarRecovery` downgrades a file when no header
  follows it, and `SevenZRecovery` updates the entries recovered from an LZMA2
  tail.
- `RecoveryReport` and its `Entry` list are read-only for callers
  (`getEntries`, `getNotes`, `count`, `summary`, `toText`).

## Sources

- PKWARE, APPNOTE.TXT (ZIP): https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- POSIX `pax` (ustar header and pax extended headers):
  https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html
- bzip2 and libbzip2 manual (block structure, bzip2recover):
  https://sourceware.org/bzip2/manual/manual.html
- The .xz file format (blocks, index; LZMA2 chunk headers):
  https://tukaani.org/xz/xz-file-format.txt
- 7-Zip, `DOC/7zFormat.txt` in the 7-Zip source distribution
- RFC 1952, GZIP file format: https://www.rfc-editor.org/rfc/rfc1952

License: the classes of `be.stef.arcana.formats.recover` are independent
implementations, Copyright Stephane Bury, Apache-2.0 (file headers). The
decoders they call keep their own headers: for example
`be.stef.arcana.formats.xz` is ported from XZ for Java (0BSD) and
`BZip2InputStream` from Apache Commons Compress (Apache-2.0).
