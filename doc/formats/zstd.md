# Zstandard

| | |
|---|---|
| Extensions | `.zst`, `.zstd` (`.tar.zst`, `.tzst`: see [tar.md](tar.md)) |
| Signature | `28 B5 2F FD` at offset 0 (frame magic 0xFD2FB528, little-endian) |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.formats.zstd.ZstdInputStream`, `be.stef.arcana.formats.zstd.ZstdFrameDecompressor`, `be.stef.arcana.formats.zstd.ZstdHelper`, `be.stef.arcana.extractor.ZstdExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/stream/notes.txt.zst`, `test/samples/tar/payload.tar.zst` |

## Overview

Zstandard (Yann Collet, Facebook, 2016; RFC 8878 in 2021) combines LZ77
matching with Huffman coding of literals and finite state entropy (FSE, a
tANS coder) for match descriptions. It is the default compressor of several
Linux distributions' packages, of `tar --zstd`, of RAR 7 and of many storage
systems. A `.zst` file is one or more frames and holds a single file.

## Detection

`ArchiveDetector.detectByMagic` compares the start of the file with
`MAGIC_ZSTD = {FD, 2F, B5, 28}`. Files begin with the little-endian encoding
of 0xFD2FB528, i.e. `28 B5 2F FD` (see the samples), so this test never
matches: `.zst` files are recognized by the extension fallback (`.zst` /
`.zstd` map to `ZSTD`, `.tar.zst` / `.tzst` to `TAR_ZSTD`). A sample renamed
`renamed.bin` gives "Cannot detect archive format", while `i` (which tests
`28 B5 2F FD` in `ArchiveAnalyzer`) reports "Zstandard compressed stream".
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
| ... | 0-4 | dictionary ID | any value present is rejected |
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

- Decompression: `ZstdFrameDecompressor` does the actual decoding, on whole
  frames in memory. `MemoryAccess` reads memory through `sun.misc.Unsafe`
  (reached by reflection) when available and falls back to plain array
  access otherwise; it throws `ZstdIncompatibleJvmException` on big-endian
  platforms.
- Two front ends feed it:
  - `ZstdInputStream` (TAR/CPIO path of `CompressedStreamExtractor`,
    `TarZstdExtractor`, and also ZIP method 93, RPM payloads and SquashFS):
    reads one frame at a time by walking its block headers, then decodes it
    into a buffer of content-size bytes, or of window-size bytes when the
    content size is absent.
  - `ZstdHelper.decompress` (single-file path, `ZstdExtractor`): reads the
    whole file and decodes it in one call into a buffer whose size is the
    content size of the first frame.
- No compressor: `arcana c file out.zst` answers "Arcana cannot create
  Zstandard archives (extraction only)". No encryption.

## Variants and versions

- Content checksum present or absent: both handled.
- Large windows in single-segment frames (`--ultra -22`, `--long=27` on a
  file with known size) are decoded: the window limit is only checked for
  frames that have a window descriptor.
- Concatenated frames and skippable frames are skipped or chained by
  `ZstdInputStream`, so they work on the TAR/CPIO path (verified with a
  trailing skippable frame after a TAR). On the single-file path see Limits.
- Frames in the old v0.7 format (magic 0xFD2FB527) are rejected with "Data
  encoded in unsupported ZSTD v0.7 format".

## Limits

- Frames without a content size (written when zstd reads from a pipe, for
  example `tar --zstd` or `tar cf - dir | zstd`) are decoded by
  `ZstdInputStream` into a window-sized buffer. When the frame decompresses
  to more than the window, it fails with "Output buffer too small": a 4 MB
  file piped through `zstd` (2 MiB window) and a 4 MB `.tar.zst` made by
  `tar --zstd` both fail, in `l` and `x`.
- Single-file path (`ZstdExtractor`, content not TAR or CPIO):
  - without a content size in the first frame, `ZstdHelper` allocates
    `new byte[-1]` and fails with "Error: -1" (a 29 KB file piped through
    `zstd`, or a file starting with a skippable frame);
  - with several frames, the buffer is sized for the first one only:
    two copies of `notes.txt.zst` concatenated fail with "Output buffer too
    small";
  - a trailing skippable frame fails with "Invalid magic prefix: 184d2a50";
  - the whole compressed file and the whole output are held in memory, and
    sizes above 2^31 - 1 bytes are rejected.
- Non-single-segment frames with a window above 8 MiB fail with "Window size
  too large (not yet supported)" (`MAX_WINDOW_SIZE`; verified with
  `--ultra -22 --no-content-size`, 32 MiB window).
- Dictionaries are not supported: a frame with a dictionary ID field fails
  with "Custom dictionaries not supported".
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
  reported as they are; a sample with one flipped bit gives "Input is
  corrupted: offset=532".
- `ZstdInputStream` holds one compressed frame and its output at a time; the
  zstd tool writes one frame per file, so in practice the whole file is in
  memory.
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
