# lzop

| | |
|---|---|
| Extensions | `.lzo`, `.tar.lzo`, `.tzo` |
| Signature | `89 4C 5A 4F 00 0D 0A 1A 0A` ("\x89LZO\0\r\n\x1A\n") at offset 0 |
| Arcana support | list, extract (no creation) |
| Main classes | `be.stef.arcana.formats.lzo.LzopInputStream`, `be.stef.arcana.formats.lzo.Lzo1xDecompressor`, `be.stef.arcana.extractor.LzopExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/stream/notes.txt.lzo`, `test/samples/stream/notes-9.txt.lzo`, `test/samples/stream/notes-crc32.txt.lzo`, `test/samples/tar/payload.tar.lzo`, `test/samples/damaged/truncated.lzo`, `test/samples/damaged/flipped.lzo` |

## Overview

lzop (Markus F.X.J. Oberhumer, 1996) is a gzip-like command line tool built
on the LZO library: very fast compression and decompression, at a lower
ratio than gzip. Its container stores the original file name, mode and
date, then the data cut into blocks (256 KiB by default) that are compressed
independently, each with its own checksums. It is met in embedded systems,
Linux kernel and initramfs images, backups and Hadoop data sets. A file
holds a single file (or a TAR).

## Detection

`ArchiveDetector.detectByMagic` returns `LZOP` for the 9-byte magic. The
extension fallback maps `.lzo` to `LZOP` and `.tar.lzo` / `.tzo` to
`TAR_LZOP`. `Arcana.resolveFormat` promotes `LZOP` to `TAR_LZOP` when the
name ends with `.tar.lzo` or `.tzo`.

Both are registered in `FormatRegistry` with a `CompressedStreamExtractor`
over `LzopExtractor`: it decompresses the first 512 bytes and unpacks a TAR
(ustar magic or valid v7 checksum) or CPIO found inside; otherwise
`LzopExtractor` writes the single file. The `i` command reports "lzop
compressed stream (LZO)" with the lzop version that wrote the file and the
method (`ArchiveAnalyzer`).

## Structure

Header (all integers big-endian):

| Size | Field | Notes |
|---|---|---|
| 9 | magic | `89 4C 5A 4F 00 0D 0A 1A 0A` |
| 2 | version | of the lzop program that wrote the file (`10 40` = 1.04); below 0x0900: not supported |
| 2 | library version | of the LZO library (`20 A0` = 2.10) |
| 2 | version needed to extract | only when version >= 0x0940; above 0x1040 (lzop 1.04): not supported |
| 1 | method | 1 LZO1X-1, 2 LZO1X-1(15), 3 LZO1X-999 |
| 1 | level | only when version >= 0x0940 |
| 4 | flags | see below |
| 4 | filter | only with F_H_FILTER |
| 4 | mode | Unix file mode |
| 4 | mtime (low) | seconds since 1970 |
| 4 | mtime (high) | only when version >= 0x0940 |
| 1 | name length | |
| n | name | original file name, no terminator; empty for a pipe |
| 4 | header checksum | Adler-32 of every field from the version to the name; CRC32 with F_H_CRC32 |
| 4 + n + 4 | extra field | only with F_H_EXTRA_FIELD: length, data, checksum of both (same algorithm) |

Flags used by the decoder:

| Value | Name | Meaning |
|---|---|---|
| 0x0001 | F_ADLER32_D | Adler-32 of the uncompressed data of each block |
| 0x0002 | F_ADLER32_C | Adler-32 of the compressed data of each compressed block |
| 0x0040 | F_H_EXTRA_FIELD | extra field after the header |
| 0x0100 | F_CRC32_D | CRC32 of the uncompressed data of each block |
| 0x0200 | F_CRC32_C | CRC32 of the compressed data of each compressed block |
| 0x0400 | F_MULTIPART | multipart file (refused) |
| 0x0800 | F_H_FILTER | filter field present (refused) |
| 0x1000 | F_H_CRC32 | header checksum is CRC32 instead of Adler-32 |

The other bits (stdin/stdout, DOS names, operating system and character set
in the high byte...) are informative and ignored. Samples: `notes.txt.lzo`
and `payload.tar.lzo` have flags `03000009` (F_ADLER32_D, Unix),
`notes-crc32.txt.lzo` (`lzop -1 --crc32`) has `03001108` (F_CRC32_D,
F_H_CRC32) and version needed 0x1001.

Then blocks:

| Size | Field | Notes |
|---|---|---|
| 4 | uncompressed size | 0: end of the file; at most 64 MiB |
| 4 | compressed size | not 0, not above the uncompressed size; equal: the block is stored |
| 0 or 4 | Adler-32 of the uncompressed data | with F_ADLER32_D |
| 0 or 4 | CRC32 of the uncompressed data | with F_CRC32_D |
| 0 or 4 | Adler-32 of the compressed data | with F_ADLER32_C, only when the block is compressed |
| 0 or 4 | CRC32 of the compressed data | with F_CRC32_C, only when the block is compressed |
| n | data | one LZO1X block, or the stored bytes |

## Compression and encryption

- All three methods write LZO1X blocks; they differ only on the compressor
  side (LZO1X-999 searches harder). Every block is decoded by
  `Lzo1xDecompressor`, the decoder already used by SquashFS (moved to the
  shared package `formats.lzo`), with an output buffer of exactly the
  uncompressed size: a block that decodes to another size, a match before
  the start of the block or an output overflow is an error.
- The NRV methods of special lzop builds and the filters are not supported.
- No encryption.

## Variants and versions

- Several lzop files concatenated (`cat a.lzo b.lzo`) are decoded one after
  the other and their data is concatenated, as `lzop -dc` does; the name and
  date come from the first header.
- Data after the end block that is not another lzop header is ignored (lzop
  warns "ignoring trailing garbage").
- Header versions 0x0900 to 0x0939 (no version-needed, level and mtime-high
  fields) are read with the shorter layout.

## Limits

- No creation (extraction and listing only).
- Filters (F_H_FILTER), multipart files (F_MULTIPART), methods other than
  1, 2 and 3, and files that need a version above 1.04 fail with
  `ArcanaUnsupportedFormatException`.
- The listing shows the stored name and date but `?` for the size: the
  block sizes are not added up for `l`.
- The mode and the date are not restored on the extracted file.
- The checksums of the compressed data (F_ADLER32_C, F_CRC32_C) are not
  covered by a sample: the lzop 1.04 options tried (`-1` to `-9`,
  `--crc32`, `--no-checksum`) never write them. A file without any block
  checksum (`--no-checksum`, flags `03000008`) is decoded without check.
- Common extraction limits apply through `ExtractionGuard`; a block is
  limited to 64 MiB like in lzop.

## Implementation notes

- Output name (`LzopExtractor.outputName`): the name stored in the header,
  reduced to its last component (anything before the last `/` or `\` is
  dropped) and then made safe by `SafePathBuilder`; it is decoded as UTF-8
  when valid, else ISO-8859-1. When the name is empty (file compressed from
  a pipe), `.`, or `..`, the archive name is used: `.tar.lzo` and `.tzo`
  give `.tar`, `.lzo` is removed, any other name gets `.out` appended. When
  the output file would be the archive itself (for instance `notes.txt`, an
  lzop file storing the name `notes.txt`, extracted into its own folder),
  `.out` is appended. Note that the lzop tool itself uses the archive name by
  default (`-n`) and the stored name only with `-N`; Arcana always uses the
  stored name, like `-N`.
- Integrity: the header checksum, the extra field checksum and every block
  checksum announced by the flags are verified. Errors (all
  `ArcanaCorruptedException`): "Not an lzop file (bad signature)", "lzop:
  header checksum error", "lzop: Adler-32 error on the uncompressed data of
  a block" (and the CRC32 / compressed variants), "lzop: unexpected end of
  file in a block", "lzop: invalid compressed block size", "lzop: block
  size ... too large", and the LZO decoder errors ("LZO stream corrupted",
  "LZO output overflow"...).
- Memory: one compressed block and one output block buffer (at most 64 MiB
  each, 256 KiB with the default lzop block size).
- Recovery (`arcana r`): decoded up to the damage, like the other streams
  (`ForceUnpacker`).

## Sources

- lzop manual page (options -n, -N, --crc32, -1 to -9): https://manpath.be/c6/1/lzop
- File layout checked against hex dumps of files written by lzop 1.04 (LZO
  2.10) with `-1 --crc32`, `-3`, `-9`, from a file and from a pipe, and
  against the lzop reader of Apache Doris (`be/src/exec/lzo_decompressor.cpp`,
  Apache-2.0), used as a description only:
  https://apache.googlesource.com/doris/+/HEAD/be/src/exec/lzo_decompressor.cpp
- LZO1X bitstream: Linux kernel documentation,
  https://docs.kernel.org/staging/lzo.html (see [squashfs.md](squashfs.md)).

License: `LzopInputStream`, `LzopExtractor` and `Lzo1xDecompressor` are
Copyright 2026 Stephane Bury, Apache-2.0. lzop itself is GPL: none of its
code is used; the container is implemented from the descriptions above.
