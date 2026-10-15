# lzip

| | |
|---|---|
| Extensions | `.lz`, `.tar.lz`, `.tlz` |
| Signature | `4C 5A 49 50 01` ("LZIP" + version 1) at offset 0 |
| Arcana support | list, extract (no creation) |
| Main classes | `be.stef.arcana.formats.lzip.LzipInputStream`, `be.stef.arcana.extractor.LzipExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` (LZMA decoder: `be.stef.arcana.formats.xz.LZMAInputStream`) |
| Test samples | `test/samples/stream/notes.txt.lz`, `test/samples/stream/two-members.txt.lz`, `test/samples/tar/payload.tar.lz`, `test/samples/damaged/bad-crc.lz`, `test/samples/damaged/truncated.lz` |

## Overview

lzip (Antonio Diaz Diaz, 2008) is a single-file compressor based on LZMA,
the coder of 7-Zip. It wraps raw LZMA data in a very small container made
for long-term archiving: a 6-byte header, and a trailer with a CRC32 and
two sizes that allow the integrity of every member to be checked. It is the
format of the GNU project source tarballs (`.tar.lz`) and is used by some
Linux distributions. A file holds a single file (or a TAR).

## Detection

`ArchiveDetector.detectByMagic` returns `LZIP` for "LZIP" followed by the
version byte 1. The extension fallback maps `.lz` to `LZIP` and `.tar.lz` /
`.tlz` to `TAR_LZIP`. `Arcana.resolveFormat` promotes `LZIP` to `TAR_LZIP`
when the name ends with `.tar.lz` or `.tlz`.

Both are registered in `FormatRegistry` with a `CompressedStreamExtractor`
over `LzipExtractor`: it decompresses the first 512 bytes and unpacks a TAR
(ustar magic or valid v7 checksum) or CPIO found inside; otherwise
`LzipExtractor` writes the single file. A `.tar.lz` therefore extracts the
same way under any name. The `i` command reports "lzip compressed stream
(LZMA)" with the version and the dictionary size of the first member
(`ArchiveAnalyzer`).

## Structure

A file is one or more members, one after the other. Member layout (all
integers little-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | ID string | "LZIP" |
| 4 | 1 | version | 1 (version 0 came from lzip 1.3 and older) |
| 5 | 1 | coded dictionary size | bits 0-4: base-2 logarithm of the base size (12 to 29); bits 5-7: number of sixteenths of the base size to subtract |
| 6 | n | LZMA stream | raw LZMA (lc=3, lp=0, pb=2, so properties byte `5D`), ended by the end-of-stream marker |
| 6+n | 4 | CRC32 | CRC32 of the uncompressed data of the member |
| 10+n | 8 | data size | uncompressed size of the member |
| 18+n | 8 | member size | size of the whole member, header and trailer included |

Example: `0C` gives 4 KiB; `D3` gives 2^19 - 6 * 2^15 = 320 KiB. Valid
dictionary sizes go from 4 KiB to 512 MiB.

## Compression and encryption

- LZMA only, decoded by `LZMAInputStream` (XZ for Java) in raw mode with an
  explicit properties byte and dictionary size and an unknown uncompressed
  size, so the end-of-stream marker ends each member. The range decoder
  reads the input byte by byte, so the trailer that follows the marker is
  read exactly where it starts.
- No encryption.

## Variants and versions

- Multi-member files (several files concatenated, `lzip -b`, very large
  inputs): every member is decoded and checked, the data is concatenated.
  The sample `two-members.txt.lz` holds a `-9` member then a `-0` member.
- Data after the last member that does not start with "LZIP" is ignored, as
  lzip does by default. One to three bytes that are the start of "LZIP" fail
  with "lzip: truncated header after member N" (the same case lzip reports).
- Version 0 files (very old lzip) are not detected by content; by extension
  they fail with "lzip: version 0 not supported in member 1 (only version
  1)".

## Limits

- No creation (extraction and listing only).
- The listing shows `?` for the size and the archive file date: the sizes
  stored in the trailers are not read for `l`.
- The sync flush marker (an LZMA marker that lzlib can write in the middle
  of a stream, never written by the lzip tool) is taken as the end of the
  member; the trailer check then fails.
- The dictionary declared in each member header (up to 512 MiB) is allocated
  as declared, once per member.
- `.tlz` was also used for TAR + raw LZMA (`.tar.lzma`): such a file is not
  recognized by content (raw LZMA has no signature), is taken as `TAR_LZIP`
  by its extension and fails with "Not an lzip file". Rename it `.tar.lzma`.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Integrity: for every member the CRC32 of the decoded data, the data size
  and the member size (bytes really read from the header to the end of the
  trailer) are compared with the trailer. Errors: "lzip: CRC32 mismatch in
  member N (stored ..., computed ...)", "lzip: data size mismatch...",
  "lzip: member size mismatch...", "lzip: unexpected end of file in member
  N", "lzip: corrupted LZMA data in member N", "lzip: truncated trailer of
  member N". All are `ArcanaCorruptedException`, raised by `LzipInputStream`
  itself, so the stream API and `CompressedStreamExtractor` report the same
  errors as `LzipExtractor`.
- The data of a member is written before its CRC32 is checked (streaming);
  the output of a damaged file is left in place, like for gzip or xz.
- Output name (`LzipExtractor.deriveOutputName`): `.tar.lz` gives `.tar`,
  `.tlz` gives `.tar`, `.lz` is removed (case-insensitive), any other name
  gets `.out` appended. When the output file would be the archive itself
  (extraction into its own folder), `.out` is appended too. The stream API
  writes `output`.
- Recovery (`arcana r`): decoded up to the damage, like the other streams
  (`ForceUnpacker`).

## Sources

- lzip manual, section "File format":
  https://www.nongnu.org/lzip/manual/lzip_manual.html
- LZMA decoder: XZ for Java (0BSD), already part of Arcana
  (see [xz-lzma.md](xz-lzma.md)).

License: `LzipInputStream` and `LzipExtractor` are Copyright 2026 Stephane
Bury, Apache-2.0, written from the lzip manual. No lzip code is used.
