# TAR

| | |
|---|---|
| Extensions | `.tar`, `.gem`; compressed: `.tar.gz` `.tgz`, `.tar.bz2` `.tbz2` `.tbz`, `.tar.xz` `.txz`, `.tar.lz4` `.tlz4`, `.tar.zst` `.tzst`, `.tar.br` `.tbr` |
| Signature | `75 73 74 61 72` ("ustar") at offset 257; none for old v7 headers |
| Arcana support | list, extract; create for `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.lz4` |
| Main classes | `be.stef.arcana.formats.tar.TarInputStream`, `be.stef.arcana.formats.tar.TarEntry`, `be.stef.arcana.formats.tar.TarOutputStream`, `be.stef.arcana.extractor.TarExtractor` (+ `TarGzExtractor`, `TarBz2Extractor`, `TarXzExtractor`, `TarLz4Extractor`, `TarZstdExtractor`, `TarBrotliExtractor`), `be.stef.arcana.compressor.TarCompressor` (+ `TarGzCompressor`, `TarBz2Compressor`, `TarXzCompressor`, `TarLz4Compressor`) |
| Test samples | `test/samples/tar/` (`ustar.tar`, `gnu.tar`, `pax.tar`, `payload.tar.*`), `test/samples/damaged/truncated.tar` |

## Overview

TAR ("tape archive") stores files one after the other, each preceded by a
512-byte header, with no compression and no central index. The format comes
from Version 7 Unix; POSIX later fixed the "ustar" layout and then the pax
extended headers, while GNU tar added its own extensions (long names, sparse
files). TAR is still the usual container of source tarballs and of most Unix
distribution formats, almost always behind a stream compressor.

## Detection

- `ArchiveDetector.detectByMagic` returns `TAR` when the 264-byte probe holds
  "ustar" at offset 257. This covers both the POSIX magic (`ustar\0`) and the
  GNU magic (`ustar ` followed by a space). A v7 header has no magic and is
  only recognized through the extension (`.tar`, `.gem`).
- Compressed TARs are first detected as the compressor (`GZIP`, `BZIP2`,
  `XZ`, `LZ4`, `ZSTD`). `Arcana.resolveFormat` promotes them to `TAR_GZ`,
  `TAR_BZ2`, `TAR_XZ`, `TAR_ZSTD`, `TAR_LZ4` when the file name has the
  matching double or short extension. Brotli has no signature, so `TAR_BROTLI`
  is chosen only by `.tar.br` / `.tbr` in `detectByExtension`.
- A compressed file without a TAR extension goes through
  `CompressedStreamExtractor`: it decompresses the first 512 bytes and
  unpacks the content as TAR when "ustar" is at offset 257 or when the bytes
  form a v7 header with a valid checksum (`isTarHeader`).

## Structure

The archive is a sequence of 512-byte records. Each entry is a header record
followed by the data padded to a multiple of 512. The end is marked by two
records of zeros. Header layout (numbers are ASCII octal, NUL or space
terminated, unless noted):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 100 | name | decoded with the reader charset (see Limits) |
| 100 | 8 | mode | |
| 108 | 8 | uid | |
| 116 | 8 | gid | |
| 124 | 12 | size | octal, or base-256 binary when the high bit is set (`TarUtils.parseOctalOrBinary`) |
| 136 | 12 | mtime | Unix seconds |
| 148 | 8 | checksum | computed (`TarUtils.verifyCheckSum`) but not enforced |
| 156 | 1 | type flag | `0`/NUL file, `1` hard link, `2` symlink, `3`/`4` devices, `5` directory, `6` FIFO, `7` contiguous, `L` `K` `S` `x` `g` extensions |
| 157 | 100 | link name | |
| 257 | 6 | magic | `ustar\0` (POSIX) or `ustar ` (GNU, with version " \0") |
| 263 | 2 | version | |
| 265 | 32 | user name | |
| 297 | 32 | group name | |
| 329 | 8 | device major | read only for type `3` and `4` |
| 337 | 8 | device minor | |
| 345 | 155 | prefix | POSIX: prepended to name with a `/`; GNU and xstar use this area differently |

`TarEntry.evaluateType` picks the layout of the area after offset 345: GNU
("ustar " magic: atime, ctime, four sparse slots, an "extended" flag and the
real size), xstar (`tar\0` at offset 508, or `SCHILY.archtype` = `xustar` /
`exustar` in a global pax header: 131-byte prefix, atime, ctime) or POSIX
(155-byte prefix).

## Compression and encryption

TAR itself is never compressed or encrypted. The compressed variants chain a
stream decoder in front of `TarInputStream`:

| Format | Extractor | Decoder | Creation |
|---|---|---|---|
| `.tar.gz` | `TarGzExtractor` | `GzipExtractor.openDecompressedStream` | `TarGzCompressor` (`ParallelGzipOutputStream`) |
| `.tar.bz2` | `TarBz2Extractor` | `BZip2Extractor.openDecompressedStream` | `TarBz2Compressor` (`BZip2OutputStream`, 900k blocks by default) |
| `.tar.xz` | `TarXzExtractor` | `XzExtractor.openDecompressedStream` | `TarXzCompressor` (`ParallelXZOutputStream`, preset 0-9 with `-l`) |
| `.tar.lz4` | `TarLz4Extractor` | `LZ4Extractor.openDecompressedStream` | `TarLz4Compressor` (`LZ4OutputStream`) |
| `.tar.zst` | `TarZstdExtractor` | `ZstdExtractor.openDecompressedStream` | none |
| `.tar.br` | `TarBrotliExtractor` | `BrotliInputStream` | none |

The decoders are wrapped in `ReadAheadInputStream` (decompression runs in
its own thread), except for the Brotli listing. After the TAR end marker, the gz, bz2, xz, lz4 and zst
extractors drain the decompressed stream to its real end so that the
compressor trailer checksum is still verified; the Brotli extractor does not
drain.

## Variants and versions

`TarInputStream` and `TarEntry` are ported from Apache Commons Compress
1.28.0 and keep its dialect handling:

- v7 (no magic), POSIX ustar (name + prefix), GNU (`ustar ` magic) and
  xstar headers.
- GNU long names and long link names: type `L` / `K` entries whose data is
  the full name; it replaces the name (or link name) of the next header
  (`getLongNameData`). Directory names get a trailing `/` (COMPRESS-509).
- pax extended headers: `x` (per entry) and `g` (global, kept for all
  following entries). Keys applied: `path`, `linkpath`, `uid`, `gid`,
  `uname`, `gname`, `size`, `mtime`, `atime`, `ctime`,
  `LIBARCHIVE.creationtime`, `SCHILY.devmajor`, `SCHILY.devminor`,
  `SCHILY.filetype` and the `GNU.sparse.*` keys. pax keys are UTF-8
  (`TarUtils.parsePaxHeaders`).
- Sparse files: old GNU sparse (type `S`, with extension records), pax
  sparse 0.0 / 0.1 (`GNU.sparse.map`) and 1.0 (map stored in front of the
  data, `TarUtils.parsePAX1XSparseHeaders`). Holes are rebuilt with
  `TarArchiveSparseZeroInputStream`. Verified: archives made by GNU tar 1.35
  with `--sparse` in gnu, pax 0.1 and pax 1.0 formats extract identical to
  the source file.
- Sizes and ids in base-256 (star/GNU binary numbers) are read.

`gnu.tar` and `pax.tar` hold the same 120-character name and a UTF-8 name
("cafe a la creme" with accents), stored as a GNU long name and as pax
`path` records respectively.

## Limits

- Hard links, symbolic links, devices and FIFOs are written by
  `TarExtractor.extractAll` as regular files with the entry data, which is
  empty for these types: a symlink or hard link becomes an empty file.
  Verified with a ustar archive holding a symlink and a hard link.
- Names in ustar/GNU headers and GNU long-name records are decoded with
  `Charset.defaultCharset()` (`TarInputStream` constructor). With a UTF-8
  default the sample names are correct; with `-Dfile.encoding=ISO-8859-1`
  the UTF-8 name of `gnu.tar` lists as mojibake, while `pax.tar` (UTF-8 pax
  `path`) stays correct. On a Java 8 Windows JVM the default is usually
  windows-1252.
- The header checksum is computed but never checked; a header with a wrong
  checksum is accepted.
- An archive without the end-of-archive records fails at the end with
  `EOFException` ("Expected 512 bytes but got 0") from
  `TarInputStream.readRecord`; one zero record followed by end of file is
  accepted. The truncated sample gives that error on `l` and "Truncated TAR
  archive" on `x` (`test/expected/damaged/truncated.tar.txt`).
- File times, modes and owners are not restored on extraction.
- Creation (`TarOutputStream`) writes headers through `TarEntry.writeEntryHeader`
  without star/binary mode and never writes pax headers:
  - a name longer than 100 characters gets a GNU `L` record (UTF-8), but the
    test uses the character count, not the byte count: a name of 51 to 100
    characters whose encoding exceeds 100 bytes is cut in the header (60
    two-byte characters give a 100-byte name without its extension);
  - a size of 8 GiB or more does not fit 11 octal digits and is written as
    0, which produces an unreadable archive.
- No `.tar.zst` / `.tar.br` creation, no append, no multi-volume (`M`)
  support, no encryption.
- Common extraction limits apply through `ExtractionGuard` (total size,
  ratio, free space; see `ExtractionLimits`).

## Implementation notes

- `TarInputStream.getNextTarEntry` skips the unread data of the previous
  entry with its own bounded `skip`, then the padding up to the next record.
- Default block size is 10240 bytes (20 records), record size 512.
- Paths go through `SafePathBuilder.buildSafePath`: `.` components are
  dropped (`./usr/...`), `..` and illegal characters are renamed, and the
  result must stay under the destination.
- Listing returns the raw names, so directory entries keep their trailing
  `/` and the CLI `l` command prints them with a second slash (`./bin//`,
  `Arcana.java` appends `/` to every directory).
- `TarCompressor` stores the content of a directory relative to it (the
  directory name itself is not stored); a single file is stored under its
  own name. Directory entries are written before their children.
- The deb and RPM readers reuse `TarInputStream` / `TarExtractor.extractFrom`
  (see [ar-deb.md](ar-deb.md)).

## Sources

- POSIX `pax` utility, ustar and pax interchange formats (The Open Group Base
  Specifications Issue 7):
  https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html
- GNU tar manual, Basic Tar Format:
  https://www.gnu.org/software/tar/manual/html_node/Standard.html
- GNU tar manual, GNU Extensions to the Archive Format:
  https://www.gnu.org/software/tar/manual/html_node/Extensions.html
- GNU tar manual, Storing Sparse Files:
  https://www.gnu.org/software/tar/manual/html_section/Sparse-Formats.html

License: `TarInputStream`, `TarEntry`, `TarUtils`, `TarConstants`,
`TarGnuSparseKeys`, `TarArchiveSparseEntry`, `TarArchiveSparseZeroInputStream`
and `TarArchiveStructSparse` carry the ASF Apache-2.0 header and state that
they are "Ported from org.apache.commons.compress.archivers.tar.* (Apache
Commons Compress 1.28.0)" by Stephane Bury (2025); `TarInputStream` also
keeps the note that the package is based on the work of Timothy Gerard
Endres. `TarOutputStream` is Copyright 2025 Stephane Bury, Apache-2.0,
"Inspired by org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
(Apache Commons Compress 1.28.0)". The extractors and compressors are
Copyright 2025 Stephane Bury, Apache-2.0.
