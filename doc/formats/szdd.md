# Microsoft SZDD (COMPRESS.EXE, MS-LZ)

| | |
|---|---|
| Extensions | none fixed: by convention the last character of the name is replaced by `_` (`setup.ex_`, `driver.dl_`, `notes.tx_`) |
| Signature | `53 5A 44 44 88 F0 27 33` ("SZDD" + 4 bytes) at offset 0 |
| Arcana support | list, extract |
| Main classes | `be.stef.arcana.extractor.MsLzExtractor` |
| Test samples | `test/samples/szdd/notes.tx_` |

## Overview

SZDD is the output format of Microsoft `COMPRESS.EXE` (shipped with MS-DOS
and the Windows SDKs), decompressed by `EXPAND.EXE` and by the `LZExpand` API of
Windows (LZEXPAND.DLL). Setup disks of DOS, Windows 3.x/9x/NT and many
applications of that time hold files such as `SETUP.EX_` or `USER.DL_`. The
format holds one file and uses a simple LZSS coder with a 4 KiB window.
Microsoft used two related formats, KWAJ and the QBasic "SZ" variant, which
Arcana does not support (see Variants).

## Detection

`ArchiveDetector.detectByMagic` returns `MSLZ` when the file starts with the
8-byte signature `53 5A 44 44 88 F0 27 33`. There is no extension fallback:
`ArcanaFormat.MSLZ` declares no extension, and names ending in `_` are not
recognized by name (the content decides). The format can be forced with
`-f szdd` or `-f mslz`.

`MSLZ` is registered in `FormatRegistry` with a plain `MsLzExtractor`, not
through `CompressedStreamExtractor`: an archive inside is not unpacked.

`ArchiveAnalyzer` has no SZDD rule; the `i` command falls back on the format
detection in `Arcana.identify` and prints "MS compress (SZDD) archive"
(`test/expected/szdd/notes.tx_.txt`).

## Structure

Header (14 bytes, read by `MsLzExtractor.header`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | signature | `53 5A 44 44 88 F0 27 33` |
| 8 | 1 | compression mode | `41` ('A'); any other value is refused |
| 9 | 1 | missing character | the character replaced by `_` in the file name, 0 if none |
| 10 | 4 | uncompressed size | little-endian, unsigned |

The sample header is `SZDD 88 F0 27 33`, `A`, `t`, size `0x7332` (29490).

Compressed data (`MsLzExtractor.decompress`), up to the end of the file:

- A flag byte announces the next 8 items, bit 0 first. Bit = 1: one literal
  byte follows. Bit = 0: a 2-byte match follows.
- Match: first byte = low 8 bits of the window position; second byte: high
  4 bits = bits 8-11 of the position, low 4 bits = length - 3 (lengths 3 to
  18). The position is an absolute index in the 4096-byte window, not a
  distance.
- The window is filled with spaces (`20`) at the start, and the write
  position starts at 4096 - 16 = 4080. Each output byte is also stored at the
  write position, which wraps at 4096. A match is copied byte by byte, so
  it may overlap the bytes it produces.
- Decoding stops as soon as the size from the header is reached; bytes after
  that point are ignored.

The space-filled window and the 4080 start were checked with a hand-made
file whose first match copies 5 bytes from window position 0 (output: 5
spaces) and whose third item copies 6 bytes from position 4080.

## Compression and encryption

- Decompression only, in `MsLzExtractor` (no separate format package).
- No SZDD encoder in Arcana. No encryption in the format.
- The test sample was not made by `COMPRESS.EXE`: it is written by a small
  Python LZSS encoder in `test/tools/make-samples.sh` (header with
  missing character `t`, matches of 3 to 18 bytes searched among the last
  32 positions with the same 3-byte prefix). That encoder only refers to
  data already written, so the sample does not exercise the initial spaces
  of the window.

## Variants and versions

- Compression modes other than 'A': "SZDD compression mode n is not
  supported" (`ArcanaUnsupportedFormatException`; verified with 'B').
- KWAJ files (signature `4B 57 41 4A 88 F0 27 D1`, methods 0-4 including
  LZH and MSZIP, optional header extensions with the name): not supported.
  They are not detected ("Cannot detect archive format for: name"); with
  `-f szdd` the error is "Not an SZDD file" (verified).
- The QBasic variant (signature `53 5A 20 88 F0 27 33 D1`, "SZ "): not
  supported, same messages.

## Limits

- No checksum: corruption that keeps the stream decodable gives wrong data
  without error.
- A stream that ends before the declared size fails with "SZDD data
  truncated (written of size bytes)"; the partial output stays on disk.
- A file shorter than 14 bytes fails with "SZDD header truncated" (for `l`
  too).
- The modification date is not stored: `l` shows `-`. The size shown by `l`
  comes from the header, without decoding.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- Output name (`MsLzExtractor.outputName`):
  - name ending in `_` and a printable missing character (`21`-`7E`, not
    `/`, `\` or `:`): the `_` is replaced by that character, lower-cased
    when the name contains lower-case letters (`notes.tx_` + `t` gives
    `notes.txt`). The character is kept as stored otherwise: `UPPER.TX_`
    with the sample header gives `UPPER.TXt`.
  - name ending in `_` and no usable character: the `_` is dropped, and a
    `.` left at the end too (`dot._` + 0 would give `dot`).
  - name not ending in `_`: kept unchanged; an empty name or one ending in
    `.` gets `out` appended.
  - the stream API (`extract(InputStream, File)`) writes `output`.
- Because a name without `_` is kept unchanged, extracting such a file into
  its own directory writes over the archive while it is being read. Up to
  64 KiB (the input buffer) this happens to work; a 112 KB file renamed
  `big.bin` was truncated to 58241 bytes and the extraction failed with
  "SZDD data truncated (58241 of 100000 bytes)" (verified).
- The output path goes through `SafePathBuilder.buildSafePath`.
- Errors are `ArcanaCorruptedException`, except the unsupported mode.

## Sources

- libmspack documentation, "SZDD and KWAJ file formats" (Stuart Caie):
  https://www.cabextract.org.uk/libmspack/doc/szdd_kwaj_format.html
- libmspack: https://www.cabextract.org.uk/libmspack/

License: `MsLzExtractor` is Copyright 2026 Stephane Bury, Apache-2.0; its
Javadoc states it was "written from the public description of the format".
No third-party code.
