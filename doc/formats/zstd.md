# Zstandard

| | |
|---|---|
| Extensions | `.zst`, `.zstd` (`.tar.zst`, `.tzst`: see [tar.md](tar.md)) |
| Signature | `28 B5 2F FD` at offset 0 (frame magic 0xFD2FB528, little-endian) |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.formats.zstd.ZstdInputStream`, `be.stef.arcana.formats.zstd.ZstdFrameDecompressor`, `be.stef.arcana.formats.zstd.ZstdHelper`, `be.stef.arcana.extractor.ZstdExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/stream/notes.txt.zst`, `seq-nosize.txt.zst`, `two-frames.txt.zst`, `skippable.txt.zst`, `zstd-no-extension.bin`; `test/samples/tar/payload.tar.zst`, `payload-pipe.tar.zst` |

## Overview

Zstandard (Yann Collet, Facebook, 2016; RFC 8878 in 2021) combines LZ77
matching with Huffman coding of literals and finite state entropy (FSE, a
tANS coder) for match descriptions. It is the default compressor of several
Linux distributions' packages, of `tar --zstd`, of RAR 7 and of many storage
systems. A `.zst` file is one or more frames and holds a single file.

## Detection

`ArchiveDetector.detectByMagic` compares the start of the file with
`MAGIC_ZSTD = {28, B5, 2F, FD}`, the little-endian encoding of 0xFD2FB528, so
a `.zst` renamed without extension is recognized by content
(`zstd-no-extension.bin`). The extension fallback (`.zst` / `.zstd` map to
`ZSTD`, `.tar.zst` / `.tzst` to `TAR_ZSTD`) remains for files that start
with a skippable frame (its magic `50..5F 2A 4D 18` is shared with LZ4 and is
not used for detection; `i` reports such a file as unrecognized data).
`Arcana.resolveFormat` promotes `ZSTD` to `TAR_ZSTD` when the name ends with
`.tar.zst` or `.tzst` (`TarZstdExtractor`).

Other files go through `CompressedStreamExtractor`, which decompresses the
first 512 bytes with `ZstdInputStream` and unpacks a TAR (ustar magic or
valid v7 checksum) or CPIO (`070701`, `070702`, `070707`) found inside;
otherwise `ZstdExtractor` writes the single file.

## Structure

Frame header (little-endian), read by `ZstdInputStream.readNextFrame` and
again by `ZstdFrameDecompressor.readFrameHeader`:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `28 B5 2F FD` |
| 4 | 1 | frame header descriptor | bits 6-7: content size field size (0, 2, 4, 8 bytes; 0 means 1 byte when single segment); bit 5: single segment; bit 2: content checksum; bits 0-1: dictionary ID size (0, 1, 2, 4 bytes) |
| 5 | 0 or 1 | window descriptor | absent when single segment; window = 2^(10 + exponent) + mantissa/8 of that |
| ... | 0-4 | dictionary ID | 0 (no dictionary) is accepted, any other value is rejected |
| ... | 0-8 | content size | the 2-byte form adds 256 |

Then blocks, each with a 3-byte header (24-bit little-endian):

| Bits | Field | Notes |
|---|---|---|
| 0 | last block | |
| 1-2 | type | 0 raw, 1 RLE (one byte repeated), 2 compressed, 3 reserved (error) |
| 3-23 | size | data size; for RLE, the number of repetitions |

A compressed block (at most 128 KiB) has a literals section (raw, RLE,
Huffman-compressed, or "treeless" reusing the previous Huffman table;
`Huffman`) and a sequences section whose literal-length, offset and
match-length codes are FSE-coded with predefined, RLE, compressed
(`FseTableReader`, `FiniteStateEntropy`) or repeated tables. Bits are read
backwards by `BitInputStream`. The three repeat offsets start at 1, 4, 8 for
each frame.

When bit 2 of the descriptor is set, the frame ends with 4 bytes: the low 32
bits of the XXH64 (seed 0) of the decompressed frame (`XxHash64`); a mismatch
gives "Bad checksum".

Skippable frame: magic `0x184D2A50`..`0x184D2A5F` (first byte `50`..`5F`,
then `2A 4D 18`), a 4-byte length and that many bytes.

The sample `notes.txt.zst` has descriptor `64`: single segment, 2-byte
content size (29490), checksum.

## Compression and encryption

- Decompression: `ZstdFrameDecompressor` does the actual decoding (its
  whole-frame `decompress` method is no longer used by Arcana; the stream
  calls its block decoders). `MemoryAccess` reads memory through
  `sun.misc.Unsafe` (reached by reflection) when available and falls back to
  plain array access otherwise; it throws `ZstdIncompatibleJvmException` on
  big-endian platforms.
- `ZstdInputStream` is the only front end: the TAR/CPIO path of
  `CompressedStreamExtractor`, `TarZstdExtractor`, ZIP method 93, RPM
  payloads, SquashFS, and the single-file path (`ZstdExtractor` through
  `ZstdHelper.decompress`, which copies the stream to the output file and
  optionally checks the expected size). It decodes one block (at most
  128 KiB) at a time into a history buffer, see Implementation notes.
- No compressor: `arcana c file out.zst` answers "Arcana cannot create
  Zstandard archives (extraction only)". No encryption.

## Variants and versions

- Content checksum present or absent: both handled.
- Windows up to 128 MiB (window log 27, the default decoding limit of the
  zstd tool): `--long=27`, `--ultra -22`, with or without a content size.
  For single-segment frames the window is the content size and the same
  limit applies in `ZstdInputStream`.
- Frames without a content size (zstd reading from a pipe, `tar --zstd`,
  `tar cf - dir | zstd`) are decoded whatever their size
  (`seq-nosize.txt.zst`, `payload-pipe.tar.zst`: 1 KiB window).
- Concatenated frames and skippable frames anywhere in the stream (before,
  between or after frames) are chained or skipped, on every path
  (`two-frames.txt.zst`, `skippable.txt.zst`).
- Frames in the old v0.7 format (magic 0xFD2FB527) are rejected with "Data
  encoded in unsupported ZSTD v0.7 format".

## Limits

- Windows above 128 MiB (`--long=28` and more, which the zstd tool itself
  only decodes with `--memory`) fail with "Window size too large: N bytes
  (maximum 134217728)"; single-segment frames whose content size exceeds
  128 MiB give "Zstd window size too large".
- Dictionaries are not supported: a frame with a non-zero dictionary ID
  fails with "Zstandard dictionaries are not supported (dictionary ID N)".
- Trailing data that is not a frame fails ("Not a Zstd stream (magic ...)").
- `l` shows `?` and the archive file date; the content size is not used for
  listing.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`ZstdExtractor.deriveOutputName`): `.zst` and `.zstd` are
  stripped (case-insensitive); any other name, including `.tzst`, gives
  `output`. The stream API writes `output`.
- `ZstdExtractor` rethrows `ZstdMalformedInputException` as
  `ArcanaCorruptedException` ("Corrupted Zstandard stream: ..."). Errors found
  while `CompressedStreamExtractor` decodes the start of the stream are
  reported as they are; a sample with one flipped bit gives for example
  "Input is corrupted: offset=522". The offset of decoder errors is counted
  from the start of the block being decoded (plus a constant base on JVMs
  where `MemoryAccess` uses `Unsafe`), not from the start of the file; for
  "Bad checksum" it is the decoded size of the frame.
- `ZstdInputStream` reads each block (3-byte header and payload) into a
  128 KiB buffer and decodes it into a history buffer with
  `ZstdFrameDecompressor.decodeRawBlock` / `decodeRleBlock` /
  `decodeCompressedBlock` (the decoder state - repeat offsets, Huffman and
  FSE tables - is kept for the whole frame and reset by `reset()` at each
  frame). The frame header is parsed by `ZstdFrameDecompressor.readFrameHeader`.
  The history buffer grows on demand up to the window size plus a margin
  (the window, or half of it from 16 MiB, at least 512 KiB), or up to the
  content size when it is smaller; when it is full, the last window-size
  bytes are moved to its start. Memory is therefore bounded by about twice
  the window (1.5 times from 16 MiB), never by the content size, and the
  compressed data is never buffered beyond one block.
- The XXH64 checksum is computed incrementally (`XxHash64.update`) and
  checked at the end of each frame ("Bad checksum"); when the frame has a
  content size, the decoded size is checked too ("Zstd frame content size
  mismatch").
- `Rar5ZstdTestArchiveBuilder`, a generator of RAR5 test archives with
  hand-built Zstandard frames, lives in the same package.

## Sources

- RFC 8878, Zstandard Compression and the 'application/zstd' Media Type:
  https://www.rfc-editor.org/rfc/rfc8878
- Zstandard format description (zstd repository):
  https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
- xxHash specification (XXH64):
  https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md
- aircompressor (Airlift), origin of the decoder:
  https://github.com/airlift/aircompressor

License: the decoder is derived from aircompressor 0.27 (Apache License
2.0). `BitInputStream`, `Constants`, `FiniteStateEntropy`, `FseTableReader`,
`Huffman`, `Util`, `XxHash64` and `ZstdFrameDecompressor` carry the Apache
License 2.0 notice without a copyright line. `FrameHeader` says "Ported from
io.airlift.compress.zstd.FrameHeader (aircompressor 0.27) ... Changes:
package declaration and imports only"; `ZstdMalformedInputException` and
`ZstdIncompatibleJvmException` say they are derived from aircompressor
exceptions. `ZstdHelper` is Copyright 2025 Stephane Bury, Apache-2.0, and
states that its decompression engine is derived from aircompressor and that
`sun.misc.Unsafe` was replaced by `MemoryAccess`. `ZstdInputStream`,
`MemoryAccess`, `Rar5ZstdTestArchiveBuilder` and `ZstdExtractor` are
Copyright 2025 Stephane Bury, Apache-2.0.
