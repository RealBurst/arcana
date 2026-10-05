# Brotli

| | |
|---|---|
| Extensions | `.br` (`.tar.br`, `.tbr`: see [tar.md](tar.md)) |
| Signature | none: recognized by its extension only |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.formats.brotli.BrotliInputStream`, `be.stef.arcana.formats.brotli.Decode`, `be.stef.arcana.extractor.BrotliExtractor`, `be.stef.arcana.extractor.TarBrotliExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/stream/notes.txt.br`, `test/samples/tar/payload.tar.br` |

## Overview

Brotli is a general-purpose compressor designed at Google (Jyrki Alakuijala
and Zoltan Szabadka) and published as RFC 7932 in 2016. It combines LZ77,
Huffman coding, second-order context modelling and a built-in static
dictionary of common words and phrases. It is mostly met as an HTTP content
encoding (`Content-Encoding: br`) and in WOFF2 fonts; `.br` files on disk are
produced by the `brotli` command-line tool. A `.br` file is a bare Brotli
stream: no magic, no file name, no date, no checksum. It holds one file.

## Detection

A Brotli stream starts with the window size bits and the first meta-block
header, so it has no fixed signature. `ArchiveDetector.detectByMagic` has no
Brotli rule; the extension fallback (`detectByExtension`) maps `.tar.br` and
`.tbr` to `TAR_BROTLI` and `.br` to `BROTLI`. The extension is only consulted
when no magic of another format matched first. A renamed file (`noext`)
fails with "Cannot detect archive format for: noext"; `-f br` forces the
format (the output is then named `noext.out`, see Implementation notes).

`TAR_BROTLI` is handled by `TarBrotliExtractor`, which feeds the decoded
stream to `TarExtractor`. `BROTLI` goes through `CompressedStreamExtractor`
(registered in `FormatRegistry`), which decodes the first 512 bytes and
unpacks a TAR (ustar magic or valid v7 checksum) or a CPIO (`070701`,
`070702`, `070707`) found inside; otherwise `BrotliExtractor` writes the
single file. So `payload.tar.br` renamed to `p.br` still lists its 13 TAR
entries.

The `i` command has no Brotli analyzer and the content detection finds
nothing: it reports "unrecognized data"
(`test/expected/stream/notes.txt.br.txt`).

## Structure

The stream is read as a little-endian bit stream (least significant bit
first). Header of the stream (`Decode.decodeWindowBits`):

| Bits | Field | Notes |
|---|---|---|
| 1 | first bit | 0: WBITS = 16 |
| 3 | next 3 bits | if non-zero n: WBITS = 17 + n (18..24) |
| 3 | next 3 bits | if non-zero n: WBITS = 8 + n (10..15); n = 1 is the large-window marker; if zero: WBITS = 17 |

The window (ring buffer) is 2^WBITS - 16 bytes for back references.

Then a sequence of meta-blocks. Meta-block header
(`Decode.decodeMetaBlockLength`):

| Bits | Field | Notes |
|---|---|---|
| 1 | ISLAST | last meta-block |
| 1 | ISLASTEMPTY | only if ISLAST; 1 ends the stream here |
| 2 | MNIBBLES | 0..2: 4..6 nibbles of length follow; 3: metadata block |
| 16..24 | MLEN - 1 | 4 bits per nibble; a final zero nibble is rejected ("exuberant nibble") |
| 1 | ISUNCOMPRESSED | only if not ISLAST |

Metadata block (MNIBBLES = 3): one reserved bit (must be 0), 2 bits giving
the number of length bytes (0..3), the length, then the data aligned on a
byte boundary; it is skipped. An uncompressed meta-block is also byte
aligned and copied as is (`copyUncompressedData`).

A compressed meta-block then holds, in order: block type counts and block
switch codes for literals, commands and distances; distance parameters
(NPOSTFIX, NDIRECT); context modes of the literal block types; literal and
distance context maps (with optional run-length and move-to-front coding);
the Huffman code groups (simple or complex prefix codes,
`readHuffmanCode`); and the command stream. Each command gives an insert
length, a copy length and a distance; a distance beyond the current output
refers to the static dictionary (`Dictionary`, `DictionaryData`, 122,784
bytes) transformed by one of 121 transforms (`Transform`). After the last
meta-block, the remaining bits up to the byte boundary must be zero, and no
byte may follow (`BitReader.checkHealth`).

## Compression and encryption

- Decompression: `BrotliInputStream` (Google's Java decoder, see Sources),
  used by `BrotliExtractor`, `TarBrotliExtractor` and
  `CompressedStreamExtractor.openDecompressed`.
- No compression: there is no Brotli encoder in Arcana ("Extraction only (no
  pure-Java encoder)", `ArcanaFormat.BROTLI`). No encryption.

## Variants and versions

- All standard window sizes are accepted (verified with `brotli -w 10`).
- Large-window Brotli (WBITS up to 30, `brotli --large_window`): the decoder
  supports it only after `enableLargeWindow()`, which Arcana never calls; such
  a stream fails with "Brotli stream decoding failed" (verified with
  `--large_window=26`).
- Shared dictionaries (`attachDictionaryChunk`) are not used.
- Concatenated streams are not a Brotli feature: two `.br` files concatenated
  fail with "Brotli stream decoding failed" (bytes after the end).

## Limits

- No checksum in the format: corruption is only found when the decoder meets
  an impossible value.
- `l` shows `?` for the size and `-` for the date (`BrotliExtractor.list`).
- Data after the end of the stream is an error (`BROTLI_ERROR_UNUSED_BYTES_AFTER_END`):
  `x` fails with "Brotli stream decoding failed" (verified with 8 bytes
  appended, also on a `.tar.br`). `l` on a `.tar.br` does not read to the end
  and does not see it.
- A truncated stream fails with the same message, both for `l` and `x`.
- The decoder error codes (`BrotliError`) are not translated into messages:
  `BrotliRuntimeException` carries "Error code: n" as the cause only.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`BrotliExtractor.stripBrSuffix`): `.br` is stripped
  (case-insensitive); any other name gets `.out` appended, so the output can
  never overwrite the input. The stream API (`extract(InputStream, File)`)
  writes `output`.
- `BrotliExtractor` wraps decoder errors in `ArcanaCorruptedException`
  ("Corrupted Brotli stream: ...") and lets `ArcanaLimitExceededException`
  through. On small files the error is usually met first while
  `CompressedStreamExtractor` decodes ahead for its 512-byte probe, and is
  then reported unwrapped ("Brotli stream decoding failed").
- `CompressedStreamExtractor` and `TarBrotliExtractor` decode through
  `ReadAheadInputStream`, a background thread. After an inner TAR or CPIO,
  `CompressedStreamExtractor` drains the rest of the stream so that the end
  of the stream is checked.
- The ring buffer is allocated lazily at each meta-block header
  (`maybeReallocateRingBuffer`): a power of two covering the meta-block
  lengths read so far (at least 16 KiB before the last meta-block), grown up
  to the window size, so small files do not allocate a 16 MiB window.
- `BrotliInputStream` blocks in its constructor until the first bytes of the
  source are read (`Decode.initState`).

## Sources

- RFC 7932, Brotli Compressed Data Format:
  https://www.rfc-editor.org/rfc/rfc7932
- Google Brotli reference implementation, including the Java decoder
  (`java/org/brotli/dec`): https://github.com/google/brotli

License: the classes of `be.stef.arcana.formats.brotli` are Google's Java
decoder moved to this package; their headers say "Copyright 2015 Google Inc.
All Rights Reserved." (2025 for `BrotliError`), "Distributed under MIT
license. See file LICENSE for detail or copy at
https://opensource.org/licenses/MIT". The repository does not ship a
separate MIT LICENSE file for them; its `LICENSE` is the Apache-2.0 text.
`BrotliExtractor`, `TarBrotliExtractor` and `CompressedStreamExtractor` are
Copyright 2025 Stephane Bury, Apache-2.0.
