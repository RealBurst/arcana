# Snappy

| | |
|---|---|
| Extensions | `.snappy` |
| Signature | `FF 06 00 00 73 4E 61 50 70 59` at offset 0 (framing format stream identifier, "sNaPpY"); raw blocks have none |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.formats.snappy.SnappyInputStream`, `be.stef.arcana.extractor.SnappyExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | none in `test/samples/`; the behaviour below was checked with hand-built files |

## Overview

Snappy is an LZ77-type compressor published by Google in 2011, designed for
speed rather than ratio, with no entropy coding. The basic unit is the raw
block: a length prefix followed by literal and copy elements. Files and
streams normally use the framing format, which cuts the data into chunks of
at most 64 KiB, each with a CRC-32C, after a fixed stream identifier. Snappy
is mostly met inside other formats (databases, RPC, Hadoop, Parquet); the
framing format is used for standalone `.snappy` / `.sz` files. A stream holds
a single file.

## Detection

`ArchiveDetector.detectByMagic` returns `SNAPPY` when the file starts with
the 10-byte stream identifier, whatever its name (a framed file renamed
`goodbin` is still recognized). The extension fallback maps `.snappy` only;
`.sz` is not mapped, so an `.sz` file is recognized only by its identifier.
There is no `TAR_SNAPPY` format and no `.tar.snappy` promotion in
`Arcana.resolveFormat`.

Every `SNAPPY` file goes through `CompressedStreamExtractor`, which
decompresses the first 512 bytes and unpacks a TAR (ustar magic or valid v7
checksum) or CPIO (`070701`, `070702`, `070707`) found inside; otherwise
`SnappyExtractor` writes the single file. A TAR in a framed file named
`backup.snappy` is listed and unpacked as a TAR. No analyzer handles Snappy:
`i` falls back to the detected format and prints "Snappy archive".

## Structure

Framing format, as read by `SnappyInputStream.readNextFramingChunk` (sizes
little-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | chunk type | see below |
| 1 | 3 | chunk length | length of the data that follows |
| 4 | n | chunk data | |

| Type | Content | Arcana |
|---|---|---|
| `00` | 4-byte masked CRC-32C of the uncompressed data, then a raw block | decoded, CRC checked |
| `01` | 4-byte masked CRC-32C, then the data itself | copied, CRC checked |
| `02`-`7F` | reserved, must not be skipped | error "reserved unskippable chunk type" |
| `80`-`FD` | reserved, skippable | skipped |
| `FE` | padding | skipped |
| `FF` | stream identifier, data "sNaPpY" | first one checked as magic; later ones skipped without checking |

The masked CRC is CRC-32C (Castagnoli, reflected polynomial `0x82F63B78`) of
the uncompressed bytes, rotated right by 15 bits and increased by
`0xA282EAD8` (`SnappyInputStream.maskedCrc32c`, table-driven because
`java.util.zip.CRC32C` needs Java 9).

Raw block (`SnappyInputStream.decompressBlock`): the uncompressed length as
a little-endian base-128 varint (at most 5 bytes), then elements whose tag
byte has the type in its low 2 bits:

| Tag type | Element | Length and offset |
|---|---|---|
| 0 | literal | upper 6 bits + 1 if below 60; values 60-63 mean the length - 1 follows in 1 to 4 bytes |
| 1 | copy, 1-byte offset | length = bits 2-4 + 4 (4..11); offset = bits 5-7 (high) and the next byte, 11 bits |
| 2 | copy, 2-byte offset | length = upper 6 bits + 1; offset in the next 2 bytes |
| 3 | copy, 4-byte offset | length = upper 6 bits + 1; offset in the next 4 bytes |

Copies are done byte by byte, so overlapping copies repeat data. Offset 0 or
an offset reaching before the start of the block gives "Snappy invalid copy
offset"; a block that does not produce the announced length gives "Snappy
block decompressed to n bytes, expected m".

## Compression and encryption

- Decompression only (`SnappyInputStream`); there is no Snappy compressor.
- No encryption.

## Variants and versions

- Framing format: the standard case. Verified with a hand-built file holding
  a compressed chunk (one literal and two overlapping copies), a padding
  chunk, a skippable chunk `80` and an uncompressed chunk.
- Raw block without framing: when the first 10 bytes are not the stream
  identifier, `SnappyInputStream` reads the whole input into memory and
  decodes it as one raw block. Such a file has no signature and is reached
  only through the `.snappy` extension (verified with `raw.txt.snappy`).
  There is no checksum in this mode.
- Other Snappy containers (for example the Hadoop codec block layout) are
  not recognized: without the stream identifier, the input is decoded as one
  raw block.

## Limits

- Errors inside a raw block other than the checks above are not all
  caught: a copy that runs past the announced length raises
  `ArrayIndexOutOfBoundsException` ("Index 20 out of bounds for length 20"
  on a crafted file), which `SnappyExtractor` does not turn into
  `ArcanaCorruptedException`. The same applies to literals that run past the
  end of the input.
- The announced uncompressed length of a chunk is allocated as is; it is not
  compared with the 64 KiB chunk limit of the framing format.
- Bytes left in a raw block after the announced length is reached are
  ignored.
- Data after the last chunk is read as a chunk header: 2 trailing bytes give
  "Snappy: truncated chunk header".
- `l` shows `?` and the archive file date.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`SnappyExtractor.deriveOutputName`): `.snappy` is stripped
  (case-insensitive); any other name, including `.sz`, gives `output`. The
  stream API writes `output`.
- `SnappyExtractor.extract(File, File)` wraps `IOException`s in
  `ArcanaCorruptedException` ("Corrupted Snappy archive: name") and lets
  `ArcanaLimitExceededException` through; the stream variant does not wrap.
  Errors found while `CompressedStreamExtractor` decodes the start of the
  stream are reported unwrapped ("Snappy: chunk checksum error" for a file
  with one CRC bit flipped).
- Each framing chunk is decoded into its own array, so memory use follows
  the chunk size; skipped chunks are handled by a recursive call per chunk.

## Sources

- Snappy framing format description:
  https://github.com/google/snappy/blob/main/framing_format.txt
- Snappy block format description:
  https://github.com/google/snappy/blob/main/format_description.txt
- RFC 3720 (iSCSI), which defines the CRC-32C polynomial:
  https://www.rfc-editor.org/rfc/rfc3720

License: `SnappyInputStream` and `SnappyExtractor` are Copyright 2025
Stephane Bury, Apache-2.0. The header of `SnappyInputStream` cites the two
Snappy format documents above, says "Public domain algorithm (Google / Jyrki
Alakuijala et al.)" and "Validated against python-snappy". No third-party
code. (The reference Snappy implementation itself is published by Google
under a BSD-style license.)
