# BZIP2

| | |
|---|---|
| Extensions | `.bz2`, `.bzip2` (`.tar.bz2`, `.tbz2`, `.tbz`: see [tar.md](tar.md)) |
| Signature | `42 5A 68` at offset 0 ("BZh"), followed by `'1'`..`'9'` |
| Arcana support | list, extract, create (single file) |
| Main classes | `be.stef.arcana.formats.bzip2.BZip2InputStream`, `be.stef.arcana.formats.bzip2.BZip2OutputStream`, `be.stef.arcana.extractor.BZip2Extractor`, `be.stef.arcana.compressor.BZip2Compressor` |
| Test samples | `test/samples/stream/notes.txt.bz2`, `test/samples/tar/payload.tar.bz2`, `test/samples/damaged/flipped.bz2` |

## Overview

bzip2 (Julian Seward, 1996) compresses a single file with the
Burrows-Wheeler transform, move-to-front, run-length coding and Huffman
coding, in independent blocks of 100 to 900 kB. It is still met in source
tarballs (`.tar.bz2`) and Linux distributions.

## Detection

`ArchiveDetector.detectByMagic` returns `BZIP2` for a file starting with
"BZh"; the block size digit is not checked there. The extension fallback maps
`.bz2` / `.bzip2` to `BZIP2` and `.tar.bz2` / `.tbz2` / `.tbz` to `TAR_BZ2`.
`Arcana.resolveFormat` promotes a `BZIP2` file to `TAR_BZ2` when its name
ends with `.tar.bz2`, `.tbz2` or `.tbz` (`TarBz2Extractor`).

Other files go through `CompressedStreamExtractor`, which decompresses the
first 512 bytes and unpacks a TAR (ustar magic or valid v7 checksum) or CPIO
(`070701`, `070702`, `070707`) found inside; otherwise `BZip2Extractor`
writes the single file. The `i` command shows the block size taken from the
fourth byte ("block size: 900 KB" for the samples).

## Structure

The stream is a bit stream, most significant bit first. Only the stream
header is byte aligned.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 3 bytes | magic | "BZh" |
| 3 | 1 byte | block size | `'1'`..`'9'`, block size = digit x 100 000 bytes; other values are rejected |

Then a sequence of blocks:

| Size (bits) | Field | Notes |
|---|---|---|
| 48 | block magic | `0x314159265359` |
| 32 | block CRC | CRC of the uncompressed block, checked |
| 1 | randomised | old "randomised" blocks, still decoded (`BZip2Rand`) |
| 24 | origPtr | start position of the BWT |
| var | symbol map, Huffman tables, selectors, coded data | |

The stream ends with:

| Size (bits) | Field | Notes |
|---|---|---|
| 48 | end magic | `0x177245385090` |
| 32 | combined CRC | rotate-and-xor of the block CRCs, checked |
| 0..7 | padding | up to the next byte boundary |

## Compression and encryption

- Decompression: `BZip2InputStream` (bit reading in `BZip2BitInputStream`,
  CRC in `BZip2CRC`). A wrong block CRC or combined CRC raises
  `IOException("BZip2 BZip2CRC error")`, as in
  `test/expected/damaged/flipped.bz2.txt`.
- Compression (`arcana c file out.bz2`): `BZip2Compressor` with
  `BZip2OutputStream` and the maximum block size (9); the `-l` option is not
  used for this format. Full blocks are sorted and Huffman-coded by worker
  threads and appended in order, bit by bit, to one standard stream; the class
  documentation states that the output is identical whatever the number of
  threads.
- The block sort (`BZip2BlockSort`) builds the BWT from a suffix array
  computed with SA-IS, after reducing the block to its primitive root and
  rotating it to a Lyndon word.
- No encryption.

## Variants and versions

- Concatenated streams (pbzip2, `cat a.bz2 b.bz2`): `BZip2InputStream` reads
  them when constructed with `decompressConcatenated = true`, which
  `BZip2Extractor` and `TarBz2Extractor` do. A two-stream file named `m.bz2`
  extracts completely. After a complete stream, data that does not start with
  "BZh" is ignored.
- NSIS variant (no "BZh" header, one-byte block signatures, no CRC):
  `BZip2InputStream.forNsis` decodes it; it is not used by the `.bz2` path.

## Limits

- The uncompressed size is unknown before decoding: `l` shows `?` and the
  archive file date.
- `CompressedStreamExtractor.openDecompressed` creates
  `new BZip2InputStream(in)`, which stops after the first stream. A
  multi-stream bzip2 file holding a TAR, whose name does not end with
  `.tar.bz2` / `.tbz2` / `.tbz`, is unpacked through this path and fails with
  "Truncated TAR archive" (verified). The same constructor is used for the
  stream API and by `ArExtractor` for `.bz2` members.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`BZip2Extractor.deriveOutputName`): `.tar.bz2`, `.tbz2` and
  `.tbz` become `.tar`; `.bz2` and `.bzip2` are stripped (case-insensitive);
  any other name gives `output`. The stream API always writes `output`.
- `BZip2Extractor.openStream` wraps the errors raised while opening the
  stream (stream header and first block header) in
  `ArcanaCorruptedException`; errors found later (CRC, bad block header)
  surface as `IOException`.
- Listing a small damaged file already reports the CRC error, because
  `CompressedStreamExtractor` decodes the start of the stream to look for a
  TAR.
- When a block CRC is wrong, the decoder updates the combined CRC from the
  stored value before throwing (code inherited from Commons Compress, marked
  there as an undocumented repair feature); Arcana does not use it to resume.

## Sources

- bzip2 home page and reference implementation: https://sourceware.org/bzip2/
- Joe Tsai, "BZip2 Format Specification":
  https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf
- Nong, Zhang, Chan, "Two Efficient Algorithms for Linear Time Suffix Array
  Construction" (SA-IS, 2009), cited in `BZip2BlockSort`.

License: `BZip2InputStream`, `BZip2OutputStream`, `BZip2BitInputStream`,
`BZip2CRC`, `BZip2Constants` and `BZip2Rand` are ported from Apache Commons
Compress 1.28.0 (Apache License 2.0, ASF header kept; based on work by Keiron
Liddle, Aftex Software), with the changes listed in each header.
`BZip2BlockSort`, `BZip2Extractor` and `BZip2Compressor` are Copyright 2025
Stephane Bury, Apache-2.0.
