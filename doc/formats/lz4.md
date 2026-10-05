# LZ4

| | |
|---|---|
| Extensions | `.lz4` (`.tar.lz4`, `.tlz4`: see [tar.md](tar.md)) |
| Signature | `04 22 4D 18` at offset 0 (frame magic 0x184D2204, little-endian) |
| Arcana support | list, extract; create only as `.tar.lz4` |
| Main classes | `be.stef.arcana.formats.lz4.LZ4InputStream`, `be.stef.arcana.formats.lz4.LZ4BlockInputStream`, `be.stef.arcana.formats.lz4.LZ4OutputStream`, `be.stef.arcana.extractor.LZ4Extractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/stream/notes.txt.lz4`, `test/samples/tar/payload.tar.lz4` |

## Overview

LZ4 (Yann Collet, 2011) is a byte-oriented LZ77 compressor without entropy
coding, built for decompression speed. The raw block format carries no size
or checksum; the frame format adds a header, block sizes and optional xxHash32
checksums, and is what the `lz4` command line tool writes. An older "legacy"
format (`lz4 -l`) is still used for Linux kernel and initramfs images. It is
met in `.lz4` and `.tar.lz4` files, in SquashFS images and in many network
and storage protocols. A frame holds a single file.

## Detection

`ArchiveDetector.detectByMagic` returns `LZ4` for `04 22 4D 18`. The legacy
magic (`02 21 4C 18`) and a leading skippable frame are not tested there:
such files are recognized only by the extension (`.lz4` maps to `LZ4`,
`.tar.lz4` / `.tlz4` to `TAR_LZ4`). A `.lz4` file starting with a skippable
frame and renamed to `leadbin` gives "Cannot detect archive format".
`Arcana.resolveFormat` promotes `LZ4` to `TAR_LZ4` when the name ends with
`.tar.lz4` or `.tlz4` (`TarLz4Extractor`).

Other files go through `CompressedStreamExtractor`, which decompresses the
first 512 bytes and unpacks a TAR (ustar magic or valid v7 checksum) or CPIO
(`070701`, `070702`, `070707`) found inside; otherwise `LZ4Extractor` writes
the single file. The `i` command reports "LZ4 frame" (`ArchiveAnalyzer`).

## Structure

Frame (all integers little-endian), as read by `LZ4InputStream`:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `04 22 4D 18` |
| 4 | 1 | FLG | bits 6-7 version (must be 01); bit 5 block independence; bit 4 block checksum; bit 3 content size present; bit 2 content checksum; bit 0 dictionary ID present |
| 5 | 1 | BD | bits 4-6: maximum block size (4 = 64 KB .. 7 = 4 MB); not used by the decoder |
| 6 | 0 or 8 | content size | read and hashed, not used |
| ... | 0 or 4 | dictionary ID | read and hashed, not used |
| ... | 1 | HC | second byte of the xxHash32 (seed 0) of the descriptor (FLG to here); checked |

Then blocks:

| Size | Field | Notes |
|---|---|---|
| 4 | block size | bit 31 set: data stored uncompressed; 0: end mark |
| n | data | raw LZ4 block, or stored bytes |
| 0 or 4 | block checksum | xxHash32 of the stored data, if FLG bit 4; checked |

After the end mark comes the content checksum (4 bytes, xxHash32 of the whole
decompressed frame) when FLG bit 2 is set; it is checked.

The sample `notes.txt.lz4` has FLG `64` (version 1, independent blocks,
content checksum) and BD `40` (64 KB blocks).

Raw block (`LZ4BlockInputStream.decompress`): a series of sequences. Each
starts with a token byte; its high nibble is the literal count and its low
nibble the match length minus 4. A nibble value of 15 is extended by
following bytes, added up until one is not 255. The literals follow, then a
2-byte match offset (1 to 65535 bytes back) and the extra match length bytes.
The last sequence has literals only. Offset 0, a match before the start of
the output, or data ending inside a sequence raise an `IOException` ("LZ4
block malformed..." / "LZ4 block truncated...").

Legacy format: magic `02 21 4C 18`, then blocks made of a 4-byte compressed
size and an independent raw block (up to 8 MB uncompressed). There is no
checksum and no end mark; the file ends at EOF.

Skippable frame: magic `0x184D2A50`..`0x184D2A5F`, a 4-byte length, and that
many bytes, which are skipped.

## Compression and encryption

- Decompression: `LZ4InputStream` (frames) over `LZ4BlockInputStream`
  (raw blocks). Both block modes are handled: with linked blocks (FLG bit 5
  clear) the last 64 KB of output are kept and passed as prefix to the next
  block. xxHash32 is implemented in `LZ4OutputStream.XxHash32`.
- Verified on files made by lz4 1.9.4: legacy (`-l`), linked blocks (`-BD`),
  block checksums with 64 KB blocks (`-BX -B4`), content size
  (`--content-size`).
- Compression: `LZ4OutputStream` writes one frame with FLG `64` (independent
  blocks, content checksum) and BD `70` (4 MB blocks). Each block is
  compressed by a greedy hash-table matcher (16-bit hash, 4-byte minimum
  match); a block that does not shrink is stored uncompressed. It is used by
  `TarLz4Compressor` only (`arcana c dir out.tar.lz4`, accepted by
  `lz4 -t`); no single-file LZ4 compressor is registered, and
  `arcana c file out.lz4` answers "Arcana cannot create LZ4 archives
  (extraction only)".
- `LZ4BlockInputStream` is also used by `SquashfsReader` for LZ4-compressed
  SquashFS blocks.
- No encryption.

## Variants and versions

- Concatenated frames (as appended by the lz4 tool): after an end mark, a
  following standard, legacy or skippable magic starts a new frame; two
  copies of the sample concatenated extract as the doubled file.
- A legacy stream ends at EOF; a value too large to be a legacy block size is
  read as the magic of a new frame.
- Skippable frames before or between frames are skipped.

## Limits

- External dictionaries are not supported: the dictionary ID is read but no
  dictionary is loaded.
- A skippable frame at the very end of the file fails with "Unexpected end
  of LZ4 stream" (after skipping it, `readFrameHeader` reads another magic);
  `lz4 -t` accepts the same file.
- Trailing data after the last frame: 4 bytes or more that are not a known
  magic are ignored; 1 to 3 bytes fail with "LZ4: trailing garbage after the
  last frame" (verified with 9 and 2 bytes).
- The content size is not read for listing: `l` shows `?` and the archive
  file date.
- The block size from the stream is not compared with the BD maximum: a
  block buffer of that size is allocated (`LZ4InputStream`), and the output
  buffer of a block grows without bound.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`LZ4Extractor.deriveOutputName`): `.tar.lz4` and `.tlz4`
  become `.tar`, `.lz4` is stripped (case-insensitive), any other name gives
  `output`. The stream API writes `output`.
- `LZ4Extractor.extract` turns only "Not an LZ4..." errors into
  `ArcanaCorruptedException`; checksum and block errors keep their
  `IOException` message.
- Checksum errors are reported as "LZ4: frame header checksum error", "LZ4:
  block checksum error" and "LZ4: content checksum error" (a sample with one
  flipped bit gives the last one, for `l` too, because
  `CompressedStreamExtractor` decodes the start of the stream).
- Each block is decoded into a new array; a frame is processed block by
  block, so memory use is bounded by the block size.
- The class comment of `LZ4InputStream` (lines 31-33) still says that
  checksums are skipped without verification; the code verifies them.

## Sources

- LZ4 Frame Format Description:
  https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
- LZ4 Block Format Description:
  https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
- xxHash specification (XXH32):
  https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md

License: `LZ4InputStream`, `LZ4BlockInputStream`, `LZ4OutputStream` and
`LZ4Extractor` are Copyright 2025 Stephane Bury, Apache-2.0. The headers of
`LZ4InputStream` and `LZ4BlockInputStream` add that they follow the LZ4 frame
and block format documents, were validated against the Python `lz4.frame` /
`lz4.block` modules, and call the algorithm "Public domain algorithm (Yann
Collet)". No third-party code.
