# XZ and LZMA (.lzma)

| | |
|---|---|
| Extensions | `.xz`, `.lzma` (`.tar.xz`, `.txz`: see [tar.md](tar.md)) |
| Signature | XZ: `FD 37 7A 58 5A 00` at offset 0 ("\xFD7zXZ\0"); `.lzma`: none (extension only) |
| Arcana support | XZ: list, extract, create (single file); `.lzma`: list, extract |
| Main classes | `be.stef.arcana.formats.xz.XZInputStream`, `be.stef.arcana.formats.xz.ParallelXZInputStream`, `be.stef.arcana.formats.xz.ParallelXZOutputStream`, `be.stef.arcana.formats.xz.LZMAInputStream`, `be.stef.arcana.extractor.XzExtractor`, `be.stef.arcana.extractor.LzmaExtractor`, `be.stef.arcana.compressor.XzCompressor` |
| Test samples | `test/samples/stream/notes.txt.xz`, `test/samples/stream/notes.txt.lzma`, `test/samples/tar/payload.tar.xz`, `test/samples/damaged/flipped.xz` |

## Overview

LZMA is the dictionary coder of 7-Zip (Igor Pavlov, around 2001). Its first
standalone file format, written by the LZMA SDK and LZMA Utils, is the
`.lzma` file: a 13-byte header followed by one raw LZMA stream, with no
magic and no checksum. XZ (Tukaani project, Lasse Collin, 2009) replaced it:
a container with magic bytes, a filter chain (LZMA2 plus optional BCJ and
delta filters), integrity checks, and an index that allows several
independent blocks. `.tar.xz` is the usual format of Linux source tarballs
and distribution packages. Both formats hold a single file.

## Detection

`ArchiveDetector.detectByMagic` returns `XZ` when the file starts with
`FD 37 7A 58 5A 00`. The extension fallback maps `.xz` to `XZ`, `.tar.xz` /
`.txz` to `TAR_XZ`, and `.lzma` (also `.tar.lzma`) to `LZMA`.
`Arcana.resolveFormat` promotes `XZ` to `TAR_XZ` when the name ends with
`.tar.xz` or `.txz` (`TarXzExtractor`).

`.lzma` has no signature: the constant `MAGIC_LZMA` (`5D`, the most common
properties byte) is declared in `ArchiveDetector` but never tested, so a
`.lzma` file is recognized only by its extension. A renamed sample
(`noext.bin`) fails with "Cannot detect archive format".

`XZ` and `LZMA` files go through `CompressedStreamExtractor` (registered in
`FormatRegistry`), which decompresses the first 512 bytes and unpacks a TAR
(ustar magic or valid v7 checksum) or CPIO (`070701`, `070702`, `070707`)
found inside; otherwise `XzExtractor` or `LzmaExtractor` writes the single
file. This is how `.tar.lzma` and `cpio.xz` are handled (verified with a
`.tar.lzma` made by `lzma`). The `i` command reports "XZ compressed stream"
(`ArchiveAnalyzer`); it has no rule for `.lzma` ("unrecognized data", see
`test/expected/stream/notes.txt.lzma.txt`).

## Structure

### XZ

An XZ file is one or more streams, optionally separated by stream padding
(zero bytes, a multiple of 4). Integers are little-endian; sizes inside block
headers and the index are variable-length integers (7 bits per byte, high bit
= continuation, at most 9 bytes, `DecoderUtil.decodeVLI`).

Stream header (12 bytes, `DecoderUtil.decodeStreamHeader`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 6 | magic | `FD 37 7A 58 5A 00` |
| 6 | 1 | flags byte 0 | must be 0 |
| 7 | 1 | check type | 0 none, 1 CRC32, 4 CRC64, 10 SHA-256; values 16 and above rejected |
| 8 | 4 | CRC32 | of the two flag bytes |

Block header (`BlockInputStream`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | header size | real size = (value + 1) x 4; 0 here means "index follows" |
| 1 | 1 | block flags | bits 0-1: filter count - 1; bit 6: compressed size present; bit 7: uncompressed size present; bits 2-5 must be 0 |
| 2 | var | compressed size | VLI, optional |
| ... | var | uncompressed size | VLI, optional |
| ... | var | filter flags | per filter: ID (VLI), properties size (VLI), properties |
| ... | var | padding | zeros up to the CRC32 |
| size-4 | 4 | CRC32 | of the header |

Then the compressed data, zero padding to a multiple of 4, and the check
(0, 4, 8 or 32 bytes). The sizes stored in the header, the padding and the
check are verified at the end of each block.

Filter IDs decoded: `0x21` LZMA2 (`LZMA2Decoder`, 1 property byte giving the
dictionary size), `0x03` delta (`DeltaDecoder`), `0x04`..`0x0B` BCJ filters
for x86, PowerPC, IA-64, ARM, ARM-Thumb, SPARC, ARM64 and RISC-V
(`BCJDecoder`, classes in `formats/xz/simple`). Any other ID gives "Unknown
Filter ID n". The chain is checked by `RawCoder.validate`.

LZMA2 data (`LZMA2InputStream`) is a sequence of chunks, each starting with
a control byte:

| Control | Meaning | Following bytes |
|---|---|---|
| `00` | end of LZMA2 data | none |
| `01` | uncompressed chunk, dictionary reset | 2-byte size - 1 (big-endian), data |
| `02` | uncompressed chunk, no reset | same |
| `80`-`FF` | LZMA chunk; bits 0-4 are bits 16-20 of the uncompressed size - 1; bits 5-6 select the reset: none (`80`), state (`A0`), state + new properties (`C0`), everything including the dictionary (`E0`) | 2-byte uncompressed size - 1, 2-byte compressed size - 1, properties byte if control >= `C0`, then range-coded data |

The first chunk must reset the dictionary, and properties are required
before the first LZMA chunk; otherwise the data is reported as corrupt.

Index (after the last block, checked by `IndexHash` in sequential mode and
parsed by `IndexDecoder` in random-access mode):

| Size | Field | Notes |
|---|---|---|
| 1 | indicator | `00` |
| VLI | record count | |
| VLI x 2 per record | unpadded size, uncompressed size | one record per block |
| 0..3 | padding | zeros |
| 4 | CRC32 | of the index |

Stream footer (12 bytes, `DecoderUtil.decodeStreamFooter`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | CRC32 | of the next 6 bytes |
| 4 | 4 | backward size | index size = (value + 1) x 4; must match the index |
| 8 | 2 | stream flags | must equal the header flags |
| 10 | 2 | magic | "YZ" |

### .lzma (LZMA-alone)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | properties | (pb x 5 + lp) x 9 + lc; values above 224 rejected |
| 1 | 4 | dictionary size | unsigned |
| 5 | 8 | uncompressed size | all `FF` = unknown, the stream ends with an end marker |
| 13 | var | LZMA data | range-coded, no checksum |

The sample `notes.txt.lzma` starts with `5D 00 00 80 00` (lc=3, lp=0, pb=2,
8 MiB dictionary) and an unknown size.

## Compression and encryption

- XZ decompression: `XZInputStream` (one stream at a time through
  `SingleXZInputStream`, blocks through `BlockInputStream`), LZMA in
  `formats/xz/lzma`, range decoder in `formats/xz/rangecoder`, checks in
  `formats/xz/check` (`CRC32`, `CRC64`, `SHA256` from the JDK `MessageDigest`,
  `None`). All four check types were verified with files made by xz 5.4.5,
  as were the x86, ARM64 and delta filters.
- `.lzma` decompression: `LZMAInputStream` (no checksum: a damaged file is
  only detected if the LZMA decoder finds an inconsistency).
- XZ compression (`arcana c file out.xz [-l 0-9]`): `XzCompressor` builds
  `LZMA2Options(preset)` (default preset 6, 8 MiB dictionary) and writes
  through `ParallelXZOutputStream.create`. The output has one stream, one
  LZMA2 filter and a CRC64 check. When only one worker fits in the heap,
  `create` returns the single-threaded `XZOutputStream`. Otherwise the input
  is cut into blocks of 1 to 3 times the dictionary size (at least 1 MiB),
  compressed as independent XZ blocks by worker threads and written in order
  with one index. A 4 MB file at `-l 6` gives one block (block size cannot go
  below the 8 MiB dictionary); at `-l 1` (1 MiB dictionary) it gives two on a 2-CPU machine.
- No `.lzma` compressor. No encryption in either format.

## Variants and versions

- Concatenated XZ streams: `XZInputStream` decodes them in turn; two copies
  of the sample concatenated extract as the doubled file.
- Stream padding: zero bytes in groups of 4 between or after streams are
  skipped (verified with 8 zero bytes appended).
- Multi-block files (`xz -T`, pixz, Arcana itself) are decoded in parallel,
  see Implementation notes.
- `.lzma` files with a known size, with or without end marker, are accepted
  (`relaxedEndCondition`, inherited from XZ for Java 1.10).

## Limits

- `l` shows `?` for the size: the XZ index is not read for listing. The
  listed date is the archive date for XZ and empty ("-") for `.lzma`.
- Data after a valid XZ stream that is not padding fails with "Garbage after
  a valid XZ Stream". Padding whose length is not a multiple of 4 fails with
  an `EOFException` that has no message ("Error: null"). Data after a
  `.lzma` stream is ignored (verified with 7 bytes appended).
- Check IDs 2, 3, 5..9 and 11..15 (reserved) give "Unsupported Check ID".
- No memory limit is set on the decoders (`XZInputStream(in)` and
  `LZMAInputStream(in)` pass -1); the output is bounded by `ExtractionGuard`.
- `.lzma` without its extension is not detected (see Detection).

## Implementation notes

- Output name: `XzExtractor.deriveOutputName` turns `.tar.xz` and `.txz`
  into `.tar`, strips `.xz` (case-insensitive) and returns `output` for any
  other name. `LzmaExtractor` strips `.lzma` and otherwise keeps the archive
  name. The stream API writes `output`.
- `ParallelXZInputStream.open` opens the file with `SeekableXZInputStream`,
  which reads the index from the end. With two or more blocks, no block above
  256 MiB, and more than one thread (`ArcanaConcurrency`), each block is
  decoded into memory by a worker with its own seekable reader (checks still
  verified) and returned in order. Otherwise, or if the seekable open fails
  (damaged index, trailing data, size not a multiple of 4), the sequential
  `XZInputStream` is used and reports the error. Verified on a 9-block file
  from `xz -T4 --block-size=500000`.
- `XzExtractor` wraps decoder `IOException`s in `ArcanaCorruptedException`
  ("Corrupted XZ archive: name") but lets `ArcanaLimitExceededException`
  through. In practice, `CompressedStreamExtractor` decodes the start of the
  stream first, and an error found there is reported unwrapped: on
  `flipped.xz` both `l` and `x` print "Compressed data is corrupt"
  (`test/expected/damaged/flipped.xz.txt`).
- `LzmaExtractor` does not wrap errors.
- After an inner TAR or CPIO ends, `CompressedStreamExtractor` drains the
  stream so that the index, footer and checks are still verified.

## Sources

- The .xz File Format, version 1.2.1, Tukaani project:
  https://tukaani.org/xz/xz-file-format.txt
- XZ for Java: https://tukaani.org/xz/java.html
- LZMA SDK and the draft LZMA specification (`lzma-specification.7z`),
  Igor Pavlov: https://www.7-zip.org/sdk.html

License: the classes of `be.stef.arcana.formats.xz` and its subpackages are
ported from XZ for Java (`org.tukaani.xz`); their headers carry
`SPDX-License-Identifier: 0BSD` and "The XZ for Java authors and
contributors", and most add "Ported from org.tukaani.xz (XZ for Java).
Original licence: 0BSD. Changes: package only." `ParallelXZInputStream`,
`ParallelXZOutputStream`, `ParallelLZMA2InputStream` and
`ParallelLZMA2OutputStream` are Copyright 2025 Stephane Bury, Apache-2.0, as
are `XzExtractor`, `LzmaExtractor` and `XzCompressor`.
