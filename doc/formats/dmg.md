# Apple disk image (DMG, UDIF)

| | |
|---|---|
| Extensions | `.dmg` (also found by content, whatever the name); `.sparseimage` recognized to be refused |
| Signature | "koly" trailer (header size 512) in the last 512 bytes of the file; "encrcdsa" at offset 0 (encrypted image) |
| Arcana support | list, extract, identify (UDIF version 4: zlib, bzip2, LZFSE, LZMA, ADC, raw and zero chunks; files of the HFS+ / HFSX volumes; other partitions as raw images) |
| Main classes | `be.stef.arcana.formats.dmg.UdifImage`, `be.stef.arcana.formats.dmg.DmgContent`, `be.stef.arcana.formats.dmg.AdcDecoder`, `be.stef.arcana.formats.lzfse.LzfseDecoder`, `be.stef.arcana.formats.lzfse.LzvnDecoder`, `be.stef.arcana.formats.hfs.HfsPlusReader` (see [hfsplus.md](hfsplus.md)), `be.stef.arcana.extractor.DmgExtractor` |
| Test samples | `test/samples/dmg/`, `test/samples/damaged/truncated.dmg`, `test/samples/damaged/flipped.dmg`; corpus `test/corpus/dmg/` |

## Overview

A DMG is the disk image format of macOS, made with `hdiutil` or the Disk
Utility since Mac OS X 10.2; almost every Mac application distributed outside
the App Store comes in one. The current format is UDIF (Universal Disk Image
Format): the image of a whole disk (partition map and partitions) cut in
chunks of sectors, each chunk stored compressed, raw, or not stored at all
(zero-filled). The partitions usually hold an HFS+ volume (images made before
macOS 10.13 or with `-fs HFS+`) or an APFS volume (recent `hdiutil` defaults).
The image format name given by `hdiutil` comes from the chunk compression:
UDZO (zlib), UDBZ (bzip2), ULFO (LZFSE, macOS 10.11+), ULMO (LZMA, macOS
10.15+), UDCO (ADC, legacy), UDRO (read-only, uncompressed).

Samples (`test/tools/make-samples.sh`, `dmg` section):

| Sample | Made by | Content |
|---|---|---|
| `udzo-hfsplus.dmg`, `udbz-hfsplus.dmg`, `ulfo-hfsplus.dmg`, `ulmo-hfsplus.dmg` | `mkfs.hfsplus` (hfsprogs), then `hfsplus addall` and `dmg -c zlib\|bzip2\|lzfse\|lzma build` (libdmg-hfsplus) | the payload in an HFS+ volume, Apple partition map (DDM, map, driver, `Apple_HFSX`, free space) |
| `udzo-renamed.bin` | copy of `udzo-hfsplus.dmg` | detection by the trailer, without the extension |
| `udro-hfsx.dmg`, `udco-hfsx.dmg` | `SampleGenerator dmg-hfsx PAYLOAD raw\|adc` | the payload in an HFSX volume, one partition, raw (UDRO) or ADC (UDCO) chunks, zero-fill and "ignore" chunks |
| `hfsx-features.dmg` | `SampleGenerator dmg-hfsx PAYLOAD features` | zlib chunks; decomposed Unicode names, hard links, a symbolic link, decmpfs files (zlib, LZVN, LZFSE), a file in 10 extents (extents overflow), a resource fork |
| `whole-disk-apm.dmg` | `SampleGenerator dmg-hfsx PAYLOAD whole` | one "whole disk (Apple_HFS : 0)" entry holding a driver descriptor, an Apple partition map and the HFSX volume at sector 64 (zlib chunks) |
| `encrypted-header.dmg` | `SampleGenerator dmg-encrypted` | a 4 KiB "encrcdsa" header only: reported as not supported |
| `damaged/truncated.dmg` | first half of `udzo-hfsplus.dmg` | no trailer left |
| `damaged/flipped.dmg` | `udzo-hfsplus.dmg` with byte 3000 changed | inside a zlib chunk of the data fork |

The libdmg-hfsplus images contain the standard payload only: its `hfsplus`
tool writes names byte by byte (no UTF-8 conversion) and has no command for
links or compressed files, which is why `SampleGenerator` writes the
"features" volume itself (pure Java, test code only). That volume was
checked with 7-Zip 23.01, which lists and extracts it identically except
where noted in [hfsplus.md](hfsplus.md).

Real-world images (corpus, not committed; see `test/README.md`):

| File | Format | Partitions | Result |
|---|---|---|---|
| `KeePassXC-2.7.12-arm64.dmg` | UDBZ | GPT, `Apple_HFS` (100 MB) | 116 files, same SHA-256 as 7-Zip |
| `MacVim-release-183.dmg` | ULFO | GPT, `Apple_APFS` (123 MB) | `disk image.apfs.img`, identical to the partition given by `7z e -tDmg` |
| `Rectangle2.0.3.dmg` | UDZO, raw and "ignore" chunks | GPT, `Apple_HFS` | 156 files, same SHA-256 as 7-Zip |
| `Syncthing-2.1.6-1.dmg` | UDZO | Apple partition map, `Apple_HFS` | 248 files, same SHA-256 as 7-Zip |
| `Transmission-4.1.3.dmg` | UDBZ | GPT, `Apple_HFS` | 555 files, same SHA-256 as 7-Zip |

7-Zip refuses the absolute symbolic link `Applications -> /Applications`
that these images hold; Arcana writes it as an empty file (see Limits).
`dmg2img` 1.6.7 was not usable as a reference for ULFO images (it skips the
LZFSE chunks: 50 MB of output for the 129 MB MacVim disk).

## Detection

- `ArchiveDetector.detect` and `detectByContent` call `hasUdifTrailer`
  before the magic bytes: "koly" at the start of the last 512 bytes and a
  header size of 512. This must come first, because the data fork starts
  with the first chunk, which may begin with any signature ("BZh" for a
  UDBZ image would otherwise be taken for bzip2). A renamed image is found
  the same way (`udzo-renamed.bin`).
- `detectByMagic` maps "encrcdsa" (encrypted image, version 2) to `DMG`;
  `detectByExtension` maps `.dmg` and `.sparseimage` to `DMG`.
- `ArchiveAnalyzer.dmg` runs before every other signature of the analyzer
  for the same reason, and reports the format, the image variant, the size,
  the data fork checksum and every partition, for example
  `partition 3: disk image (Apple_HFS : 4): HFS+ volume "Rectangle2.0.3" (signature H+, version 4, 156 files, 116 folders)`
  or `partition 3: disk image (Apple_APFS : 4): APFS, extracted as a raw image: disk image.apfs.img`.
  The HFS+ catalog is walked to count the resource forks and the directory
  hard links that will not be extracted.
- `UdifImage.probe` tells "udif", "encrypted" ("encrcdsa" at 0, or
  "cdsaencr" at the end of the last 512 bytes), "sparse" ("sprs" at 0) or
  nothing.
- A `.dmg` without trailer is read as a raw disk image (see Variants).

## Structure

### Trailer ("koly", last 512 bytes, big-endian)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "koly" |
| 4 | 4 | version | must be 4 |
| 8 | 4 | header size | 512 |
| 12 | 4 | flags | ignored |
| 16 | 8 | running data fork offset | ignored |
| 24 | 8 | data fork offset | usually 0 |
| 32 | 8 | data fork length | |
| 40 | 8 | resource fork offset | ignored |
| 48 | 8 | resource fork length | only to name old images (see Limits) |
| 56 | 4 | segment number | |
| 60 | 4 | segment count | more than 1: refused |
| 64 | 16 | segment ID (UUID) | ignored |
| 80 | 4 | data fork checksum type | 2 = CRC32 |
| 84 | 4 | checksum size in bits | 32 |
| 88 | 128 | checksum | CRC32 in the first 4 bytes |
| 216 | 8 | XML offset | |
| 224 | 8 | XML length | at most 64 MiB |
| 232 | 120 | reserved | |
| 352 | 136 | master checksum | type, size, value; not checked |
| 488 | 4 | image variant | 1 device image, 2 partition image (shown by `i`) |
| 492 | 8 | sector count | 512-byte sectors |
| 500 | 12 | reserved | |

### Property list

The XML property list (Apple plist 1.0) holds a `resource-fork` dictionary
whose `blkx` array has one dictionary per partition: `Name` / `CFName`
("disk image (Apple_HFS : 4)": name, partition type, index), `ID`,
`Attributes`, and `Data`, the base64 "mish" block table. The other
resources (`plst`, `cSum`, `nsiz`, `size`) are ignored. `PlistParser` is a
small reader for this subset (dict, array, key, string, integer, real, date,
data, true, false); the DOCTYPE is skipped, never loaded.

### Block table ("mish", big-endian)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | "mish" |
| 4 | 4 | version | 1 |
| 8 | 8 | first sector | position of the partition in the disk |
| 16 | 8 | sector count | size of the partition |
| 24 | 8 | data offset | added to the chunk offsets |
| 32 | 4 | buffers needed | ignored |
| 36 | 4 | block descriptors | ignored |
| 40 | 24 | reserved | |
| 64 | 136 | checksum | type (2 = CRC32), size, value |
| 200 | 4 | chunk count | |
| 204 | 40 x n | chunks | |

Each 40-byte chunk: type (4), comment (4), first sector (8, relative to the
partition), sector count (8), offset (8) and length (8) in the data fork.
The position in the file is data fork offset + data offset + chunk offset.

| Type | Meaning | Arcana |
|---|---|---|
| 0x00000000 | zero-fill | zeros |
| 0x00000001 | raw | read from the file |
| 0x00000002 | ignore (free space) | zeros |
| 0x80000004 | ADC | `AdcDecoder` |
| 0x80000005 | zlib | `java.util.zip.Inflater` |
| 0x80000006 | bzip2 | `be.stef.arcana.formats.bzip2.BZip2InputStream` |
| 0x80000007 | LZFSE | `LzfseDecoder` |
| 0x80000008 | LZMA | `XZInputStream` (xz stream, as written by libdmg-hfsplus) or `LZMAInputStream` (other data) |
| 0x7FFFFFFE | comment | skipped |
| 0xFFFFFFFF | end of table | stops the table |

Chunks must be in sector order, inside the partition; an unknown type stops
with "Unknown disk image chunk type 0x...".

## Compression and encryption

### ADC

Apple Data Compression, a byte-oriented LZ77 of the first DMGs. Each
instruction starts with one byte: `1LLLLLLL` = L + 1 literal bytes follow;
`01LLLLLL` + 2 bytes = copy L + 4 bytes from (16-bit big-endian distance) + 1
back; `00LLLLDD` + 1 byte = copy L + 3 bytes from (10-bit distance) + 1 back.
No real UDCO image was available: `AdcDecoder` is checked with
`udco-hfsx.dmg`, written by a greedy encoder in `SampleGenerator`.

### LZFSE and LZVN

LZFSE (Apple, 2015) combines LZ77 with finite state entropy coding. A stream
is a list of blocks with a 4-byte little-endian magic:

| Magic | Block |
|---|---|
| "bvx-" | raw: size (4), bytes |
| "bvxn" | LZVN: raw size (4), payload size (4), LZVN data |
| "bvx1" | LZFSE with plain frequency tables (772-byte header) |
| "bvx2" | LZFSE with packed tables: raw size, three 64-bit words of packed fields, then the frequencies coded with a 2 to 14-bit prefix code |
| "bvx$" | end of stream |

An LZFSE block holds up to 40000 literals, coded with four interleaved FSE
states over 1024 states, and up to 10000 (L, M, D) triplets (literal count,
match length, distance) coded with FSE "value" tables of 64, 64 and 256
states: each symbol gives a base value and a number of extra bits. Both
payloads are read backwards from their end; the first bits of the last
8 bytes are skipped as told by the header. A distance of 0 reuses the
previous one.

LZVN is a byte-oriented LZ77: opcodes `sml_d`, `med_d`, `lrg_d` (literals
then a match with a new 11, 14 or 16-bit distance), `pre_d` (previous
distance), `sml_l` / `lrg_l` (literals only), `sml_m` / `lrg_m` (match with
the previous distance), 0x06 end of stream, 0x0E / 0x16 no-op; the others
are invalid. It is used inside LZFSE streams for small blocks and by HFS+ /
APFS compressed files.

`LzfseDecoder` and `LzvnDecoder` were checked against Apple's reference
encoder (`lzfse` command of the lzfse 1.0 package): files of 3 KB (LZVN
block), 5 KB of random data (raw block), 14 KB to 27 MB (bvx2 blocks) decode
identically; 27 MB decode in about 0.2 s.

### Encryption

Encrypted images ("encrcdsa", AES-128 or AES-256 with a key derived from the
password or a certificate) are not supported:
"Encrypted disk image (AES, encrcdsa / cdsaencr header): not supported";
`i` prints "Apple disk image, encrypted (AES): not supported".

## Variants and versions

- Partition schemes met: Apple partition map (`DDM`, `Apple_partition_map`,
  `Apple_Driver_ATAPI`, `Apple_HFS`, `Apple_Free`: libdmg-hfsplus, older
  hdiutil, Syncthing) and GUID partition table (`MBR`, `Primary GPT Header`,
  `Primary GPT Table`, `Apple_Free`, `Apple_HFS` or `Apple_APFS`, backup GPT:
  current hdiutil). One-partition images (`hdiutil -layout NONE`,
  `SampleGenerator`) also work.
- `DmgContent.plan` decides what each partition gives: the entries of the
  partition scheme (types `DDM`, `MBR`, `*GPT*`, `Apple_partition_map`,
  `Apple_Free`, `Apple_Driver*`, `Apple_Patches`, `Apple_Void`,
  `Apple_Scratch`) and the partitions made only of zero / ignore chunks give
  nothing; a partition whose first 4 KiB hold an HFS+ / HFSX volume header
  (or an HFS wrapper with an embedded HFS+ volume) gives its files; any other
  partition is written as a raw image named after the partition
  (`disk image.apfs.img` for APFS, recognized by "NXSB" at offset 32;
  `<name>.img` for FAT, NTFS, exFAT, plain HFS and unknown file systems).
  With one HFS+ volume, its files are at the root of the output; with
  several, each volume goes into a folder named after it.
- "Whole disk" entries: some images (for example the DbVisualizer 26.2 macOS
  installer, UDZO, image variant 2) have a single `blkx` entry named
  "whole disk (Apple_HFS : 0)" that holds the whole disk: driver descriptor
  ("ER"), Apple partition map, and the HFS+ volume further on (sector 64).
  When a partition has no known file system but starts with an Apple
  partition map or a GPT, `DmgContent.plan` replaces it by the partitions of
  that map (`UdifImage.readPartitionMap`, the code used for raw images); `i`
  shows them as `partition 0.1 : whole disk (Apple_HFS : 0) / disk image
  (Apple_HFS : 1): ...`. The CRC32 of the partition is still checked on the
  whole entry.
- Raw images (no trailer): a `.dmg` (or a file forced with `-f dmg`) with
  an HFS+ volume header at 1024, a GUID partition table ("EFI PART" at 512)
  or an Apple partition map ("ER" at 0, "PM" entries) is read as a disk of
  raw chunks: read/write UDRW images, `dmg2img` outputs. Verified with the
  `dmg2img` image of `Rectangle2.0.3.dmg` (same files) and a bare HFS+
  volume. `i` does not name these files (no signature at a fixed place).
- Sparse images (`.sparseimage`, "sprs"): "Sparse disk image
  (.sparseimage, "sprs" header): not supported - convert it with hdiutil
  convert -format UDZO". Sparse bundles are folders and are not opened.

## Limits

- Not supported: encrypted, sparse and segmented images (`.dmgpart`,
  "Segmented disk image (segment 1 of 3): not supported"), UDIF versions
  other than 4, and very old images whose partition table is only in a
  resource fork ("Disk image without XML property list (resource fork only,
  very old UDIF): not supported").
- APFS volumes are not read: the partition is extracted as a raw image
  (`<name>.apfs.img`), which 7-Zip or `apfs-fuse` can open.
- The master checksum of the trailer is not checked (the data fork and the
  partition checksums are).
- Inside the HFS+ volumes: symbolic links are written as empty files (like
  TAR, CPIO, SquashFS and UDF), resource forks and directory hard links are
  skipped (counted by `i`); see [hfsplus.md](hfsplus.md).
- A damaged chunk is reported when it is decoded: listing reads only the
  chunks of the catalog, so `damaged/flipped.dmg` lists normally and its
  extraction stops at once with "Disk image data fork CRC32 mismatch
  (stored 10d810a0, computed 41f380f6)". A truncated image has no trailer
  left: "No UDIF "koly" trailer (truncated or not a disk image) and no HFS+
  volume or partition map found".
- `extract(InputStream, File)` throws "DMG requires random file access -
  use extract(File,File)." No creation of disk images.

## Implementation notes

- Random access: `UdifImage.PartitionReader` maps a byte position of a
  partition to its chunk (binary search), returns zeros for zero-fill,
  ignore chunks and gaps, reads raw chunks from the file, and decodes
  compressed chunks on demand. Decoded chunks stay in an LRU cache of
  32 MiB per partition (at least one chunk), so the HFS+ reader works
  without decoding the whole image. hdiutil chunks are 1 MiB or less; a
  chunk decoded or stored larger than 64 MiB is refused ("Chunk n of
  partition ... too large"), as is a property list above 64 MiB.
- Every chunk must decode to exactly its sector count x 512 bytes, else
  "Chunk n of partition ... (zlib) decoded to x bytes instead of y";
  decoder exceptions become `ArcanaCorruptedException` with the chunk
  number and method.
- Checksums: the CRC32 of the data fork (koly) is checked before the
  extraction (one sequential read of the compressed data). The CRC32 of a
  partition (mish) is the CRC32 of its decoded chunks in sector order,
  the "ignore" chunks left out (found on `Rectangle2.0.3.dmg`, whose
  partition has two ignore chunks: with them the CRC does not match); it is
  checked after the files of an HFS+ partition are written and after a raw
  partition image is written. `PartitionReader` keeps the CRC32 of every
  chunk it decoded, and combines them with zlib's GF(2) `crc32_combine`
  method, so the check decodes only the chunks the extraction did not need;
  zero-fill chunks use the CRC of n zero bytes, computed the same way.
  `udro-hfsx.dmg` with one data byte changed and its data fork CRC fixed
  stops with "Checksum mismatch in partition disk image (Apple_HFS : 0)".
- Speed: `KeePassXC-2.7.12-arm64.dmg` (100 MB bzip2 partition) extracts
  in about 5 s, `MacVim-release-183.dmg` (123 MB LZFSE partition, written
  as a raw image) in 0.8 s, `Rectangle2.0.3.dmg` (zlib) in 0.3 s.
- Paths go through `SafePathBuilder.buildSafePath`, files through
  `ExtractionGuard.open`.

## Sources

- Jonathan Levin, "Demystifying the DMG File Format" (koly trailer, mish
  block table, chunk types): http://newosxbook.com/DMG.html
- Apple, `hdiutil(1)` manual page (image formats UDZO, UDBZ, ULFO, ULMO,
  UDRO, UDRW, UDCO, UDSP; partition layouts).
- Apple, LZFSE reference implementation (format description: block headers,
  FSE tables, bit streams, LZVN opcodes), BSD-3-Clause, Copyright (c)
  2015-2016 Apple Inc.: https://github.com/lzfse/lzfse - read as a
  description, no code copied; its `lzfse` command was used to check the
  decoder.
- Apple Data Compression (ADC): the three-instruction format summarized in
  the ADC section above, as commonly documented for UDCO images; no
  reference implementation was read, and no real UDCO image was available
  (the decoder is checked with `udco-hfsx.dmg` only).
- zlib, `crc32_combine` (GF(2) matrix method, zlib license), for the
  combination of chunk CRC32 values.
- Tools used to make or check samples (not part of Arcana): hfsprogs
  (`mkfs.hfsplus`), libdmg-hfsplus (GPL-3.0,
  https://github.com/mozilla/libdmg-hfsplus: `hfsplus`, `dmg`), 7-Zip 23.01
  and dmg2img (oracles for the corpus).

License: `UdifImage`, `PlistParser`, `AdcDecoder`, `DmgContent`,
`LzfseDecoder`, `LzvnDecoder` and `DmgExtractor` are Copyright 2026 Stephane
Bury, licensed under the Apache License 2.0, written from the public
descriptions above. The LZFSE and LZVN class comments credit Apple's
reference implementation (BSD-3-Clause) as the description they follow.
