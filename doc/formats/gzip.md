# GZIP

| | |
|---|---|
| Extensions | `.gz`, `.gzip` (`.tar.gz`, `.tgz`: see [tar.md](tar.md)) |
| Signature | `1F 8B` at offset 0 |
| Arcana support | list, extract, create (single file) |
| Main classes | `be.stef.arcana.extractor.GzipExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor`, `be.stef.arcana.compressor.GzipCompressor`, `be.stef.arcana.formats.gzip.ParallelGzipOutputStream` |
| Test samples | `test/samples/stream/notes.txt.gz`, `test/samples/tar/payload.tar.gz`, `test/samples/damaged/bad-crc.gz` |

## Overview

GZIP wraps one Deflate stream with a small header and a CRC32/size trailer.
It was written for the GNU project in the early 1990s and is still the most
common single-file compressor on Unix systems (`.gz`, `.tar.gz`, HTTP
content encoding). It holds exactly one file and is not an archive format.

## Detection

`ArchiveDetector.detectByMagic` returns `GZIP` when the file starts with
`1F 8B`; no other header field is checked at that point. When the magic does
not match, the extension fallback maps `.gz` and `.gzip` to `GZIP` and
`.tar.gz` / `.tgz` to `TAR_GZ`.

`Arcana.resolveFormat` then promotes `GZIP` to `TAR_GZ` when the file name
ends with `.tar.gz` or `.tgz`; that case is handled by `TarGzExtractor`.

Every other `GZIP` file goes through `CompressedStreamExtractor` (registered
in `FormatRegistry`), which decompresses the first 512 bytes and looks at
them:

- `070701`, `070702` or `070707` at offset 0: the content is a CPIO archive
  and is unpacked (initramfs images, for example);
- `ustar` at offset 257, or a v7 TAR header whose checksum is valid: the
  content is a TAR archive and is unpacked (`backup.gz` holding a TAR);
- anything else: `GzipExtractor` writes the single decompressed file.

The `i` command reports "GZIP compressed stream" (`ArchiveAnalyzer`).

## Structure

Member header (all multi-byte fields little-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | ID1 ID2 | `1F 8B` |
| 2 | 1 | CM | 8 = Deflate, the only method defined |
| 3 | 1 | FLG | bit 0 FTEXT, bit 1 FHCRC, bit 2 FEXTRA, bit 3 FNAME, bit 4 FCOMMENT |
| 4 | 4 | MTIME | modification time, Unix seconds; ignored by Arcana |
| 8 | 1 | XFL | compression hint; ignored |
| 9 | 1 | OS | ignored |
| 10 | 2 + n | extra field | present if FEXTRA: length then data; skipped |
| ... | var | original name | present if FNAME: zero-terminated; skipped |
| ... | var | comment | present if FCOMMENT: zero-terminated; skipped |
| ... | 2 | header CRC16 | present if FHCRC |

Then the raw Deflate data, then the trailer:

| Offset from end of member | Size | Field | Notes |
|---|---|---|---|
| -8 | 4 | CRC32 | CRC32 of the uncompressed data |
| -4 | 4 | ISIZE | uncompressed size modulo 2^32 |

Header parsing, Deflate decoding and the trailer check are done by
`java.util.zip.GZIPInputStream` (JDK): it rejects a CM other than 8, skips
FEXTRA, FNAME and FCOMMENT, checks FHCRC when present, and checks CRC32 and
ISIZE at the end of each member ("Corrupt GZIP trailer").

## Compression and encryption

- Decompression: `java.util.zip.GZIPInputStream`, in `GzipExtractor`,
  `TarGzExtractor` and `CompressedStreamExtractor.openDecompressed`.
- Compression (`arcana c file out.gz`): `GzipCompressor` uses
  `ParallelGzipOutputStream.create`. With one worker it returns a plain
  `java.util.zip.GZIPOutputStream`. With several workers the input is cut
  into 256 KiB chunks deflated by worker threads; each chunk is primed with
  the last 32 KiB of the previous one as preset dictionary and ends with a
  sync flush, and the chunks are concatenated in order into one standard
  member. CRC32 and size are computed on the caller thread.
- The header written by `ParallelGzipOutputStream` has no name, MTIME 0,
  XFL 0 and OS 0. The level is `Deflater.DEFAULT_COMPRESSION`; the `-l`
  option is not used for GZIP.
- No encryption.

## Variants and versions

- Multi-member files (several gzip members concatenated, as produced by
  `cat a.gz b.gz` or pigz): `GZIPInputStream` continues with the next member
  and the output is the concatenation. Verified with two members holding the
  two halves of a TAR file: the TAR is unpacked completely.
- Trailing zero bytes after the last member are ignored (verified with 100
  zero bytes appended).

## Limits

- The original file name (FNAME) and MTIME are never used: the output name
  comes from the archive name (see Implementation notes) and the listed date
  is the archive file date. A file compressed as `orig_name.txt` and renamed
  `renamed.gz` extracts as `renamed`.
- The uncompressed size is not read from ISIZE: `l` shows `?`.
- No Deflate64 or other method (CM other than 8 is an error).
- Common extraction limits apply through `ExtractionGuard` (output/input
  ratio, free disk space; see `ExtractionLimits`).

## Implementation notes

- Output name (`GzipExtractor.deriveOutputName`): `.tar.gz` and `.tgz`
  become `.tar`, `.gz` and `.gzip` are stripped (case-insensitive), any other
  name gives `output`. The stream API (`extract(InputStream, File)`) always
  writes `output`.
- A `ZipException` from the JDK is rethrown as `ArcanaCorruptedException` by
  `GzipExtractor.extract`.
- `CompressedStreamExtractor` decodes through `ReadAheadInputStream` (a
  background thread) and, after an inner TAR or CPIO ends, drains the rest of
  the stream so that the gzip trailer is still verified.
- Listing also decodes the beginning of the stream (to look for a TAR or
  CPIO). On the small damaged sample `bad-crc.gz` the CRC error is therefore
  already reported by `l` ("Corrupt GZIP trailer",
  `test/expected/damaged/bad-crc.gz.txt`).
- With JDK 8, `GZIPInputStream` looks for a following member only when the
  underlying stream reports available bytes or the inflater still holds more
  than 26 unread bytes; files are read through a `BufferedInputStream` over a
  `FileInputStream`, where this works.

## Sources

- RFC 1952, GZIP file format specification version 4.3:
  https://www.rfc-editor.org/rfc/rfc1952
- RFC 1951, DEFLATE compressed data format specification version 1.3:
  https://www.rfc-editor.org/rfc/rfc1951
- pigz (parallel gzip, same chunking technique): https://zlib.net/pigz/

License: `GzipExtractor`, `GzipCompressor` and `ParallelGzipOutputStream`
are Copyright 2025 Stephane Bury, Apache-2.0. Deflate itself is the JDK
implementation (`java.util.zip`); no third-party code.
