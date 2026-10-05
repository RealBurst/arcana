# LHA / LZH

| | |
|---|---|
| Extensions | `.lzh`, `.lha` |
| Signature | none at offset 0; Arcana looks for `2D 6C 68` ("-lh") at offset 2 |
| Arcana support | list, extract (-lh0-, -lz4-, -lh4- to -lh7-), create (-lh5-, -lh6-, -lh7-, header level 2) |
| Main classes | `be.stef.arcana.formats.lha.LhaReader`, `be.stef.arcana.formats.lha.LhaDecoder`, `be.stef.arcana.formats.lha.LhaWriter`, `be.stef.arcana.formats.lha.Lh5Encoder`, `be.stef.arcana.formats.lha.Lh5HuffEncoder`, `be.stef.arcana.extractor.LhaExtractor`, `be.stef.arcana.compressor.LhaCompressor` |
| Test samples | none committed (see below) |

## Overview

LHA (first named LHarc) was written by Haruyasu Yoshizaki in the late 1980s
and became the usual archiver in Japan and on the Amiga; the compression
methods descend from LZHUF by Haruhiko Okumura. An archive is a sequence of
entries, each made of a header and the compressed data, with no central
directory. The header layout exists in four "levels" (0 to 3). LZH files are
still met in old Japanese software, Amiga collections and some firmware
packages.

There is no LHA sample in `test/samples`: the only LHA tool available on the
Linux machine that builds the samples is Lhasa (`lha` v0.4.0), which can list,
test and extract but not create archives. The behaviour described here was
checked with archives written by Arcana and tested with Lhasa (`lha t`), and
with level 0, 1 and 2 headers built by hand.

## Detection

- `ArchiveDetector.detectByMagic` returns `LHA` when bytes 2 to 4 are "-lh"
  (the start of the method of the first entry). This check comes after all
  the other signatures except TAR and executables.
- `detectByExtension` maps `.lzh` and `.lha` to `LHA`. An archive whose
  first entry uses `-lz4-`, `-lzs-` or `-lz5-` is only found through the
  extension ("Cannot detect archive format" otherwise).
- The `i` command (`ArchiveAnalyzer.isLha`) accepts both "-lh?-" and "-lz?-"
  at offset 2 and prints the method of the first entry, for example
  "LHA/LZH archive (method -lh5-)".

## Structure

An archive is a sequence of entries. A header size byte of 0 ends the
archive (trailing bytes after it are ignored); the end of the file is also
accepted. All numbers are little-endian. The header level is always the byte
at offset 20.

Level 0 header (`LhaReader.readLevel0`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | header size | header length minus 2 |
| 1 | 1 | checksum | sum of the header bytes from offset 2, modulo 256; checked |
| 2 | 5 | method | "-lh5-" etc.; must start and end with "-" |
| 7 | 4 | compressed size | |
| 11 | 4 | original size | |
| 15 | 4 | time | MS-DOS date and time |
| 19 | 1 | attribute | ignored |
| 20 | 1 | level | 0 |
| 21 | 1 | name length | |
| 22 | n | name | 0xFF and `\` are path separators |
| 22+n | 2 | CRC-16 | of the original data |

Any bytes after the CRC (up to the header size) are covered by the checksum
and otherwise ignored.

Level 1 header (`LhaReader.readLevel1`): same first 22 bytes, except that
offset 7 holds the "skip size" (compressed size plus the size of the
extended headers), then the name, the CRC-16, an OS id byte (ignored) and
the 2-byte size of the first extended header. The extended headers follow
the base header and are counted in the skip size.

Level 2 header (`LhaReader.readLevel2`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | header size | whole header, extended headers included |
| 2 | 5 | method | |
| 7 | 4 | compressed size | |
| 11 | 4 | original size | |
| 15 | 4 | time | Unix seconds |
| 19 | 1 | reserved | 0x20 |
| 20 | 1 | level | 2 |
| 21 | 2 | CRC-16 | of the original data |
| 23 | 1 | OS id | ignored |
| 24 | 2 | first extended header size | |
| 26 | var | extended headers | inside the header size |

An extended header is a type byte, its data, and the 2-byte size of the next
extended header (0 for the last one). `LhaReader.applyExtHeader` uses:

| Type | Content | Use in Arcana |
|---|---|---|
| 0x00 | common: header CRC-16 | ignored (not checked) |
| 0x01 | file name | replaces the name |
| 0x02 | directory name, 0xFF separators | prepended to the current name |
| 0x54 | Unix time (4 bytes) | replaces the time |
| others | permissions, owner, comments... | ignored |

Level 3 headers (4-byte sizes, used by some Unix versions of LHa) are not
supported: "LHA: unknown header level 3".

Directories are entries with the method "-lhd-" and no data.

## Compression and encryption

| Method | Window | Arcana |
|---|---|---|
| `-lh0-`, `-lz4-` | - | stored: extracted |
| `-lh4-` | 4 KiB | extracted (`LhaDecoder.lh4`) |
| `-lh5-` | 8 KiB | extracted (`LhaDecoder.lh5`), created (default) |
| `-lh6-` | 32 KiB | extracted, created with `-l 6` |
| `-lh7-` | 64 KiB | extracted, created with `-l 7` |
| `-lhd-` | - | directory |
| `-lh1-`, `-lh2-`, `-lh3-`, `-lzs-`, `-lz5-`, `-pm0-`, `-pm1-`, `-pm2-` and others | | listed, not extracted |

LHA has no encryption.

### -lh4- to -lh7- (`LhaDecoder`)

The four methods share one coding: LZ77 over a sliding window with Huffman
codes that are static within a block and sent at the start of each block.
Bits are read most significant bit first (`LhaBitInputStream`). A block is:

1. the number of commands in the block (16 bits); 0, or the end of the data,
   ends the stream;
2. the code-length code: a 5-bit count (at most 19), then 3-bit lengths,
   the value 7 being extended by a run of 1 bits; after the third length a
   2-bit count of zero lengths follows;
3. the command code: a 9-bit count (at most 510), then lengths coded with
   the code-length code: symbol 0 is one zero length, 1 is 3 to 18 zeros
   (4 more bits), 2 is 20 to 531 zeros (9 more bits), n > 2 is the length
   n - 2;
4. the distance code: a 4-bit (lh4, lh5) or 5-bit (lh6, lh7) count, at most
   14, 14, 16 and 17 for lh4 to lh7, then lengths coded like step 2 (without
   the skip).

A count of 0 in steps 2 to 4 means a single symbol, whose value follows on
the same number of bits and which is coded with zero bits
(`LhaBinaryTree`). Commands 0-255 are literals, 256-509 are matches of
length command - 253 (3 to 256). A distance symbol d gives the number of
bits of the distance: 0 and 1 stand for themselves, otherwise the distance
is 2^(d-1) plus d-1 more bits; the copy starts distance + 1 bytes back
(`LhaCircularBuffer.copy`).

### Compression (`Lh5Encoder`, `Lh5HuffEncoder`, `LhaWriter`)

- LZ77: hash chains on 3-byte strings (16-bit hash, at most 1024 positions
  examined, 256 when the previous match is 32 bytes or longer) with lazy
  evaluation; a 3-byte match farther than 4096 bytes is
  not used. The window streams through the input.
- A block is written every 16384 commands. `Lh5HuffEncoder` builds
  canonical codes limited to 16 bits from the block frequencies and writes
  the single-symbol form when a table uses 0 or 1 symbol.
- `LhaWriter.writeEntry(String, byte[], long)` computes the CRC-16,
  compresses, and writes the entry as `-lh0-` when the compressed data is
  not smaller than the original. Empty files are written as the selected
  method with no data.
- Headers are level 2: method, sizes, Unix time, reserved byte 0x20, OS id
  'U', then the extended headers 0x00 (header CRC-16), 0x01 (file name,
  UTF-8) and 0x02 (directory, 0xFF separators) when the path has one. When
  the header size would end with a 0x00 byte (it would read as the end of
  the archive), one padding byte is added. The archive ends with a single 0
  byte.
- `LhaCompressor` (`arcana c dir out.lzh [-l 6|7]`) writes all files first
  (depth first, names sorted within each directory), then one `-lhd-` entry
  per directory. Archives made with `-lh5-`, `-lh6-` and `-lh7-` pass
  `lha t` (Lhasa) and extract identically with Arcana.

## Variants and versions

- Header levels 0, 1 and 2 are read; level 3 is refused.
- Names: 0xFF and `\` become `/`, leading `/` are removed. Names are decoded
  as UTF-8 (`LhaReader` default charset); other encodings such as Shift_JIS
  are not converted and their invalid bytes become replacement characters.
- Times: level 2 and extended header 0x54 hold Unix seconds; the MS-DOS time
  of levels 0 and 1 is converted as if it were UTC (`dosToUnixMs`).

## Limits

- Unsupported methods (`-lh1-` to `-lh3-`, `-lzs-`, `-lz5-`, PMarc and
  others) are listed but silently skipped during extraction: no file and no
  error.
- Level 3 headers: "LHA: unknown header level 3". All reader errors are
  reported by `LhaExtractor` as `ArcanaCorruptedException` "Corrupted LHA
  archive: ...", including the unsupported level.
- Extended headers are applied in file order: a directory header (0x02)
  placed before the file name header (0x01) is lost, because the file name
  then replaces the whole name (verified with a hand-made level 2 header:
  Lhasa shows `dd/f.txt`, Arcana `f.txt`). Archives written by Arcana put
  0x01 first.
- The header CRC (extended header 0x00) is not checked; the level 0/1 header
  checksum is.
- The original size is not checked: the decoder stops at the end of the
  compressed data, and only the CRC-16 is compared.
- The compressor reads each file completely in memory, and stores sizes on
  32 bits.
- Unix permissions, owner and comments are neither read nor written.

## Implementation notes

- `LhaReader` is a stream: it reads the headers and data in order, so
  `LhaExtractor` supports `extract(InputStream, File)`. The data of an entry
  that is not read is skipped by `BoundedStream.drain`.
- CRC-16 (`LhaCrc16`): reflected polynomial 0xA001, initial value 0. The
  check is done when the decompressed stream reaches its end and is skipped
  when the stored CRC is 0. A mismatch raises "LHA: CRC-16 mismatch
  (expected 0x..., got 0x...)"; the partly written file is left on disk.
- Paths go through `SafePathBuilder` (path traversal is refused) and output
  files through `ExtractionGuard`.
- The same `LhaDecoder` coding (with a 64 KiB buffer, 5-bit distance count,
  17 distance codes) is used by `ArjReader` for ARJ methods 1 to 3 (see
  [arj.md](arj.md)).

## Sources

- LHa for UNIX, header format notes (`header.doc`):
  https://github.com/jca02266/lha/blob/master/header.doc.md
- LHA page of the Just Solve the File Format Problem wiki:
  http://fileformats.archiveteam.org/wiki/LHA
- Apache Commons Compress: https://commons.apache.org/proper/commons-compress/

License, from the file headers: `LhaReader`, `LhaDecoder`, `LhaBinaryTree`,
`LhaBitInputStream` and `LhaCircularBuffer` are "Copyright 2025 Stephane
Bury - Derived from Apache Commons Compress" (`LhaArchiveInputStream`,
`LhStaticHuffmanCompressorInputStream`, `BinaryTree`, `BitInputStream`,
`CircularBuffer`), Apache License 2.0. `LhaEntry`, `LhaCrc16`, `LhaWriter`,
`Lh5Encoder`, `Lh5HuffEncoder`, `LhaBitOutputStream`, `LhaExtractor` and
`LhaCompressor` are Copyright 2025 Stephane Bury, Apache License 2.0.
