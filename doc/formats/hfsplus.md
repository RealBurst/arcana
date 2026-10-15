# HFS+ / HFSX (Mac OS Extended)

| | |
|---|---|
| Extensions | none of its own: read inside Apple disk images (`.dmg`, see [dmg.md](dmg.md)) |
| Signature | "H+" (version 4) or "HX" (version 5) at offset 1024 of the volume; "BD" with an embedded "H+" volume (HFS wrapper) |
| Arcana support | list, extract (data forks, Unicode names, hard links, symbolic links as empty files, decmpfs compression: zlib, LZVN, LZFSE) |
| Main classes | `be.stef.arcana.formats.hfs.HfsPlusReader`, `be.stef.arcana.formats.lzfse.LzvnDecoder`, `be.stef.arcana.formats.lzfse.LzfseDecoder`, `be.stef.arcana.extractor.DmgExtractor` |
| Test samples | all of `test/samples/dmg/` (HFS+ from mkfs.hfsplus, HFSX from `SampleGenerator`); `hfsx-features.dmg` for the special cases |

## Overview

HFS Plus is the file system of Mac OS 8.1 (1998) to macOS 10.12, replaced by
APFS on internal disks since macOS 10.13 but still the usual file system of
application disk images. HFSX (signature "HX") is the same format with an
optional case-sensitive name order. The volume is described by Apple
Technical Note TN1150: fixed-size allocation blocks, and special files
organized as B-trees (catalog, extents overflow, attributes).

`HfsPlusReader` reads a volume through a random-access `Source` (in Arcana,
a partition of a disk image: `UdifImage.PartitionReader`). There is no
standalone `.hfs` format entry: a raw volume or a raw disk named `.dmg` is
handled by the raw-image path of [dmg.md](dmg.md).

## Detection

- `DmgContent.fileSystem` reads the first 4 KiB of each partition: "H+"
  (0x482B) or "HX" (0x4858) at offset 1024, or "BD" with "H+" at offset
  1024 + 0x7C (HFS wrapper). The partition type name ("Apple_HFS",
  "Apple_HFSX") is not trusted: the libdmg-hfsplus samples name an "H+"
  volume `Apple_HFSX`.
- `HfsPlusReader` checks the signature, a power-of-two block size from 512
  bytes to 64 MiB, and the B-tree header nodes (node kind 1, node size from
  512 to 32768, node count within the file).

## Structure

All numbers are big-endian (except the decmpfs data, see below).

### Volume header (offset 1024, 512 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | signature | "H+" or "HX" |
| 2 | 2 | version | 4 (H+), 5 (HX) |
| 4 | 4 | attributes | bit 13: journaled (shown by `i`) |
| 12 | 4 | journal info block | ignored |
| 16 | 16 | create, modify, backup, checked dates | ignored |
| 32 | 4 | file count | shown by `i` |
| 36 | 4 | folder count | shown by `i` |
| 40 | 4 | block size | |
| 44 | 4 | total blocks | bound for the extents |
| 112 | 80 | allocation file fork | ignored |
| 192 | 80 | extents overflow file fork | |
| 272 | 80 | catalog file fork | |
| 352 | 80 | attributes file fork | |
| 432 | 80 | startup file fork | ignored |

A fork (HFSPlusForkData, 80 bytes): logical size (8), clump size (4), total
blocks (4), then 8 extents of (start block, block count). When the 8 extents
do not cover the fork, the next ones are in the extents overflow file,
keyed by (fork type 0 data / 0xFF resource, file ID, first block of the
fork they describe).

HFS wrapper: an HFS volume ("BD", Master Directory Block at 1024) whose
`drEmbedSigWord` (0x7C) is "H+" holds the HFS+ volume at
`drAlBlSt` (0x1C) x 512 + `drEmbedExtent.startBlock` (0x7E) x `drAlBlkSiz`
(0x14); every position of the HFS+ volume is then relative to that offset.

### B-trees

Each B-tree file is a sequence of nodes of the size given by its header
node (node 0). A node starts with a 14-byte descriptor: forward link (4),
backward link (4), kind (1: -1 leaf, 0 index, 1 header, 2 map), height (1),
record count (2), reserved (2); the record offsets are 16-bit values stored
backwards from the end of the node. The header record (at 14) gives the
depth, root node, leaf record count, first leaf (offset 24), last leaf,
node size (offset 32), maximum key length and node count (offset 36).
`HfsPlusReader.BTree.forEachLeafRecord` starts at the first leaf and
follows the forward links: every record of the tree is visited without
using the index nodes or the key order (so HFS+ case-folding and HFSX binary
orders need no special code).

### Catalog

Key: key length (2), parent folder ID (4), name length (2), name (UTF-16,
up to 255 units). Records:

| Type | Record | Fields used |
|---|---|---|
| 1 | folder (88 bytes) | folder ID (8), content modification date (16) |
| 2 | file (248 bytes) | file ID (8), content modification date (16), owner flags (41), special / iNode number (44), Finder type (48) and creator (52), data fork (88), resource fork (168) |
| 3, 4 | folder / file thread | skipped |

The root folder has ID 2 and its record (parent 1) holds the volume name.
Dates are seconds since 1904-01-01 GMT; 0 means unknown.

### Attributes

Key: key length (2), pad (2), file ID (4), start block (4), name length
(2), name (UTF-16). Record: type (4): 0x10 inline data (reserved 8, size 4,
data), 0x20 fork data (reserved 4, fork 80), 0x30 extents (ignored). Only
"com.apple.decmpfs" is read.

## Compression and encryption

HFS+ has no encryption. Files compressed by macOS (`ditto
--hfsCompression`, Installer, `afsctool`) have the `UF_COMPRESSED` owner
flag (0x20), an empty data fork, and a "com.apple.decmpfs" attribute
starting with a 16-byte little-endian header: magic "fpmc" (0x636D7066),
compression type (4), uncompressed size (8).

| Type | Data | Arcana |
|---|---|---|
| 1 | uncompressed, in the attribute | yes |
| 3 | zlib, in the attribute (first byte with low nibble 0xF: stored) | yes |
| 4 | zlib, 64 KiB blocks in the resource fork: resource file header (data offset, usually 0x100), then at the data offset the resource length (big-endian), the block count and the (offset, size) table (little-endian, offsets from data offset + 4) | yes |
| 7 | LZVN, in the attribute (first byte 0x06: stored) | yes |
| 8 | LZVN, 64 KiB blocks in the resource fork, after a table of block count + 1 little-endian offsets | yes |
| 11 | LZFSE, in the attribute | yes |
| 12 | LZFSE, blocks in the resource fork (same table as type 8) | yes |
| others (5, 9, 10, 13, 14...) | sparse, LZBITMAP... | "HFS+ compression type n is not supported" |

The LZVN and LZFSE decoders are described in [dmg.md](dmg.md).

## Variants and versions

- HFS+ volumes made by `mkfs.hfsplus` + libdmg-hfsplus (`udzo-hfsplus.dmg`
  and the other libdmg samples) and by hdiutil (the corpus images:
  KeePassXC, Rectangle, Syncthing, Transmission) extract with the same
  SHA-256 as 7-Zip 23.01.
- HFSX volumes written by `SampleGenerator` (`udro-hfsx.dmg`,
  `udco-hfsx.dmg`, `hfsx-features.dmg`; binary key order 0xBC). 7-Zip
  23.01 lists `hfsx-features.dmg` like Arcana and extracts the same data,
  with these differences: it shows the private folder
  (`[HFS+ Private Data]/iNode33`) and the resource fork as `name:rsrc`,
  writes hard links as empty files, keeps names decomposed, and does not
  support decmpfs LZFSE in the resource fork ("Unsupported Method").
- Names: HFS+ stores names in a decomposed form (close to NFD);
  `HfsPlusReader` returns them in NFC (`java.text.Normalizer`), so
  "caf&#233;" stored as "cafe" + U+0301 is extracted as "caf&#233;" (one
  code point). A '/' in a name becomes ':', as the macOS BSD layer shows it.
- Hard links: a file record with type "hlnk" and creator "hfs+" points to
  the file "iNode&lt;special&gt;" of the folder "\0\0\0\0HFS+ Private
  Data"; the link is listed and extracted with the content of that file
  (`links/hard-1.txt`, `links/hard-2.txt` in `hfsx-features.dmg`).
- Symbolic links: type "slnk", creator "rhap", target in the data fork.
- Fragmented files: `fragmented.bin` in `hfsx-features.dmg` has 10 one-block
  extents, 8 in its catalog record and 2 in an extents overflow record.

## Limits

- Symbolic links are written as empty files and listed with size 0, like
  the TAR, CPIO, SquashFS and UDF extractors (the corpus images all hold an
  `Applications -> /Applications` link).
- Resource forks of normal files are not extracted; `i` counts them
  ("1 resource fork(s) not extracted" for `hfsx-features.dmg`). Extended
  attributes and Finder information are ignored.
- Directory hard links (type "fdrp", creator "MACS", Time Machine volumes)
  are skipped and counted by `i`.
- The private folders ("\0\0\0\0HFS+ Private Data", ".HFS+ Private Directory
  Data\r") and the journal files (".journal", ".journal_info_block") of the
  root are not listed. The journal is not replayed: a volume that was not
  cleanly unmounted may show its last committed state only.
- Modification times are set on files, not on folders; permissions, owners
  and the creation dates are ignored.
- A decmpfs attribute stored in a fork with more than 8 extents is refused
  ("HFS+ attribute with extents records: not supported"); an unsupported
  compression type stops the extraction at that file.
- Plain HFS volumes (Mac OS Standard, "BD" without an embedded HFS+ volume)
  are not read: the partition is written as a raw image.

## Implementation notes

- Listing reads the whole catalog once (leaf records grouped by parent
  ID), then walks the tree from the root folder, parents before children.
  Loops and trees deeper than 512 raise "HFS+ folder loop"; a hard link
  without target raises "HFS+ hard link without target".
- Every B-tree node number is checked against the node count, record
  offsets against the node size, the leaf chain against the node count
  ("HFS+ B-tree leaf loop"), extents against the total block count and the
  source length, and every fork against its logical size ("HFS+ fork
  shorter than its size").
- File data is copied 64 KiB at a time through the extents; decmpfs
  resource fork files are decoded block by block (64 KiB of output each),
  and every block must decode to its exact size.
- The decmpfs attributes are loaded once, only if the catalog has a
  compressed file.

## Sources

- Apple, Technical Note TN1150 "HFS Plus Volume Format" (volume header,
  fork data, B-trees, catalog and extents records, hard links, HFSX, HFS
  wrapper): https://developer.apple.com/library/archive/technotes/tn/tn1150.html
- decmpfs ("com.apple.decmpfs" attribute, compression types, resource fork
  layouts): public format descriptions of HFS+ / APFS compression, such as
  the libyal format documents "Mac OS Extended (HFS+) file system format"
  and "Apple File System (APFS)" (https://github.com/libyal/libfshfs,
  https://github.com/libyal/libfsapfs, `documentation/` folders); no code
  of these projects was used. The layouts were checked with 7-Zip 23.01,
  which decodes the zlib and LZVN files of `hfsx-features.dmg` identically.
- Apple, LZFSE reference implementation (BSD-3-Clause), for LZVN and LZFSE:
  https://github.com/lzfse/lzfse

License: `HfsPlusReader` is Copyright 2026 Stephane Bury, licensed under the
Apache License 2.0, written from TN1150 and the public decmpfs
descriptions.
