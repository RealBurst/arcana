# Unix compress (.Z)

| | |
|---|---|
| Extensions | `.Z` (also `.z` through the extension fallback) |
| Signature | `1F 9D` at offset 0 |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.extractor.ZExtractor` |
| Test samples | `test/samples/stream/notes.txt.Z`, `test/samples/stream/seq-b12.txt.Z` (CLEAR codes), `test/samples/damaged/truncated-notes.txt.Z` |

## Overview

`compress` is the LZW file compressor of early Unix (Spencer Thomas, Jim
McKie, Joe Orost and others, 1984-1985), based on Welch's 1984 variant of
LZ78. It was the standard Unix compressor until the LZW patent disputes of
the 1990s pushed users to gzip. `.Z` and `.tar.Z` files are still met in old
software archives and FTP mirrors; ncompress maintains the tool today. A
`.Z` file holds one file and stores no name, date or checksum.

## Detection

`ArchiveDetector.detectByMagic` returns `Z` when the file starts with
`1F 9D`; the third byte is not checked. The extension fallback maps names
ending in `.z` (case-insensitive) to `Z`. `ArchiveAnalyzer` reports "Unix
compress (.Z) stream" for `1F 9D` and also for `1F A0`; the latter is not
recognized by the detector.

`Z` is registered in `FormatRegistry` with a plain `ZExtractor`, not through
`CompressedStreamExtractor`: a TAR inside is never unpacked. There is no
`TAR_Z` format and `Arcana.resolveFormat` has no `.tar.Z` rule, so
`p.tar.Z` lists and extracts as a single file `p.tar` (verified).

## Structure

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | magic | `1F 9D` |
| 2 | 1 | flags | bits 0-4: maximum code width (maxbits); bit 7: block mode; bits 5-6 unused (not checked) |
| 3 | var | codes | LZW codes, packed least significant bit first |

The sample starts with `1F 9D 90`: maxbits 16, block mode.

LZW codes (`ZExtractor.decompress`):

- Codes 0-255 are the single bytes. In block mode, code 256 (CLEAR) resets
  the table and the first free code is 257; without block mode, 256 is a
  normal code and the first free code is 256.
- Codes start 9 bits wide. Each decoded code after the first adds one table
  entry (previous string + first byte of the current one). When the next
  free code no longer fits in the current width, the width grows by one bit,
  up to maxbits. Once the table holds 2^maxbits entries, no entry is added.
- A code equal to the next free code is the "KwKwK" case (previous string +
  its own first byte). A larger code is an error.
- There is no end marker: the stream ends with the file.

The compressor writes codes in groups of 8 (so a group is n bytes for n-bit
codes), counted from the start of the code data or from the last CLEAR or
width change. After a CLEAR code it pads the rest of the group, and the
decoder skips to the next group boundary before reading 9-bit codes again
(`ZExtractor.skipGroupPadding`, the same rule as ncompress). The same skip is
applied on a width change; there it is always empty, because a width lasts
a multiple of 8 codes.

## Compression and encryption

- Decompression only, in `ZExtractor` (LZW decoder written in the class,
  no separate format package). The table is an array of byte arrays, one
  per code.
- No `.Z` compressor in Arcana. No encryption.

## Variants and versions

- maxbits 9 to 16 are accepted; any other value gives "Invalid .Z maxbits:
  n" (verified with 8).
- Files from `compress` (ncompress 5.0) with `-b 10` to `-b 16`, with and
  without CLEAR codes, decode correctly: `seq 1 200000` (1.2 MB), 200 KB of
  random data, a text/random mix and the payload notes were verified byte for
  byte at every width from 10 to 16 (`test/samples/stream/seq-b12.txt.Z`
  holds several CLEAR codes).
- maxbits 9: two incompatible conventions exist. compress 4.0, gzip and the
  ncompress 5.0 decoder switch to 10-bit codes once the 9-bit table is full;
  the ncompress sources after 5.0 (2021 fix "nine bits processing") and
  7-Zip stay at 9 bits. Arcana stays at 9 bits (verified with a test encoder
  following each rule). The `-b 9` output of ncompress 5.0 itself is broken
  (it can add entry 512): `compress -d` and `gzip -d` reject it ("corrupt
  input") and Arcana decodes it to wrong data without error.
- Non-block-mode files (very old compress versions) are handled by the code
  path described above; not verified with a real file (ncompress 5.0 cannot
  write them).
- The SCO `1F A0` variant is not supported (see Detection).

## Limits

- No checksum and no stored size, so truncation is only partly detected:
  compress writes the last code on as few bytes as possible, so a whole
  unused byte at the end, or a stream that ends inside the padding after a
  CLEAR, gives "Truncated .Z stream" (`test/samples/damaged/truncated-notes.txt.Z`,
  2002 bytes of the sample). Other cuts still extract a shorter file
  without error: about one cut in three was detected on a 12-bit and a
  16-bit test file (the 2000-byte prefix of the sample still gives 11183
  bytes and "Done.").
- `l` does not decode anything: it shows one entry with size `?` and date
  `-`, even for a damaged file.
- On an error, the partial output file is deleted (`ZExtractor.decompressTo`).
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`ZExtractor.stripExt`): the suffix `.Z` or `.z` is removed
  (case-insensitive test). Any other name gets `.out` appended (`file` gives
  `file.out`, as `BrotliExtractor` does), so the output never replaces the
  archive, even when extracting into its own directory (verified with
  `low.z` and `plain`). The stream API writes `output`.
- Errors are thrown as `ArcanaCorruptedException`.
- Output goes through a 64 KiB buffer inside the decoder and a
  `BufferedOutputStream`.

## Sources

- ncompress, the maintained version of compress, and its `compress(1)`
  manual page: https://github.com/vapier/ncompress
- T. A. Welch, "A Technique for High-Performance Data Compression", IEEE
  Computer, vol. 17 no. 6, June 1984.

License: `ZExtractor` is Copyright 2025 Stephane Bury, Apache-2.0. It is
written in the class itself; no third-party code.
