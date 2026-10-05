# UDF (Universal Disk Format)

| | |
|---|---|
| Extensions | `.udf`; usually `.iso` or `.img` (found by content) |
| Signature | "NSR02" or "NSR03" at byte 1 of a descriptor of the volume recognition sequence (sectors 16 to 31) |
| Arcana support | list, extract (UDF 1.02 to 2.60: physical, sparable, virtual and metadata partitions) |
| Main classes | `be.stef.arcana.formats.udf.UdfReader`, `be.stef.arcana.extractor.UdfExtractor` |
| Test samples | `test/samples/iso/udf-bridge.iso` |

## Overview

UDF is the file system defined by OSTA (Optical Storage Technology
Association) as a profile of the ECMA-167 standard (also ISO/IEC 13346).
Revision 1.02 (1996) is the file system of DVD-Video and DVD-ROM; later
revisions added packet writing on CD-RW (1.50: sparable and virtual
partitions), named streams (2.00), and the metadata partition used by
Blu-ray (2.50, 2.60). Windows installation media and most DVD images are
"bridge" discs: they hold both an ISO 9660 tree and a UDF tree pointing to
the same file data.

`udf-bridge.iso` was made with `genisoimage -udf -J -R`
(`test/tools/make-samples.sh`); its UDF revision is 1.02.

## Detection

- `ArchiveDetector.discFormat` runs when no magic matched the first 264
  bytes, and tests UDF before ISO 9660. `isUdf` needs a file of at least
  34 x 2048 bytes and reads byte 1 of each 2 KiB block from sector 16 to 31:
  "NSR02" or "NSR03" means UDF, "TEA01" (end of the sequence) or an unknown
  identifier means no; "BEA01", "CD001", "CDW02", "BOOT2" and all-zero
  blocks (images with 4096-byte sectors) are skipped.
- Bridge discs therefore go to `UdfExtractor`, whatever their extension.
  The ISO 9660 side can still be read with `-f iso`
  (verified on `udf-bridge.iso`, see [iso9660.md](iso9660.md)).
- Without the sequence, the `.udf` extension selects `UDF`.
- `UdfReader` then looks for the Anchor Volume Descriptor Pointer at sector
  256, at the last sector and at the last sector minus 256, trying sector
  sizes 2048, 512, 4096 and 1024. The anchor must have a valid tag checksum
  and a tag location equal to its sector. Failure: "UDF anchor volume
  descriptor not found".
- The `i` command prints "UDF archive". `UdfReader.getRevision()` (from the
  domain identifier of the logical volume) is not used by the CLI.

## Structure

All numbers are little-endian. Every descriptor starts with a 16-byte tag:
identifier (2 bytes), version (2), checksum (1, sum of the other 15 bytes),
serial number, CRC and CRC length, tag location (4 bytes at offset 12).
`UdfReader.tagId` checks the checksum only; the CRC is not checked.

| Tag | Descriptor | Fields read |
|---|---|---|
| 2 | Anchor Volume Descriptor Pointer | main sequence extent (length 16, sector 20), reserve sequence extent (24, 28) |
| 3 | Volume Descriptor Pointer | next extent of the sequence (length 20, sector 24) |
| 5 | Partition Descriptor | partition number (22), first sector (188), length in sectors (192) |
| 6 | Logical Volume Descriptor | block size (212), domain identifier suffix (240: revision), File Set Descriptor address (248), map count (268), maps (440) |
| 8 | Terminating Descriptor | ends the sequence |
| 256 | File Set Descriptor | root directory ICB (400) |
| 257 | File Identifier Descriptor | directory entry |
| 258 | Allocation Extent Descriptor | continuation of allocation descriptors |
| 261, 266 | File Entry, Extended File Entry | see below |

`readVds` walks the main sequence (the reserve one if the main has no
logical volume or partition), follows Volume Descriptor Pointers and stops
at a terminator or a bad tag. Other descriptors (primary, implementation
use, unallocated space, integrity) are skipped. When a partition number
appears twice the last descriptor wins; the last logical volume wins.

### Partition maps

| Map | Bytes | Handling (`UdfReader.PartitionMap`) |
|---|---|---|
| type 1 | partition number at 4 | physical: block n is at partition start + n x block size |
| type 2 "*UDF Sparable Partition" | partition number at 38 | read as physical; the sparing tables are ignored |
| type 2 "*UDF Virtual Partition" | partition number at 38 | blocks translated through the Virtual Allocation Table (VAT) |
| type 2 "*UDF Metadata Partition" | partition number at 38, metadata file at 40, mirror at 44 | blocks translated through the extents of the metadata file |

Other type 2 maps raise "Unsupported UDF partition map: ..." and other
types "Unsupported UDF partition map type N". The logical block size must
be a power of two from 512 to 65536.

The VAT is the last file written on a write-once disc. `readVat` finds the
last sector that is not all zeros (searching at most the last 256 MiB),
then looks back up to 64 sectors for a File Entry of type 248 (UDF 2.00
and later: header length in the first 2 bytes, then 4-byte entries) or of
type 0 whose data ends with the "*UDF Virtual Alloc Tbl" identifier and a
4-byte field (UDF 1.50). The metadata file (types 250, then 251 for the
mirror) is read by `readMetadataFile`; the mirror is used when the main
copy is unreadable.

### Directories and file entries

A directory is a file whose data is a list of File Identifier Descriptors,
each padded to a multiple of 4 bytes:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 16 | tag | 257 |
| 18 | 1 | characteristics | 0x01 hidden, 0x02 directory, 0x04 deleted, 0x08 parent |
| 19 | 1 | name length | |
| 20 | 16 | ICB | long allocation descriptor: block at 24, partition reference at 28 |
| 36 | 2 | implementation use length | skipped |
| 38+iu | var | name | first byte 8 or 254: one byte per character (Latin-1), 16 or 255: UTF-16BE |

Deleted and parent entries are skipped. The ICB points to a File Entry
(tag 261) or an Extended File Entry (tag 266, UDF 2.00 and later), read by
`parseNode`:

| Field | FE offset | EFE offset | Notes |
|---|---|---|---|
| file type | 27 | 27 | 4 directory, 5 file, 12 symbolic link, 0 unspecified (taken as a file) |
| ICB flags | 34 | 34 | low 3 bits: allocation descriptor type |
| information length | 56 | 56 | file size |
| modification time | 84 | 92 | 12-byte timestamp, time zone applied when the type is 1 |
| extended attributes length | 168 | 208 | skipped |
| allocation descriptors length | 172 | 212 | |
| extended attributes, then descriptors | 176 | 216 | |

Allocation descriptor types: 0 short (8 bytes, length and block in the
partition of the entry), 1 long (16 bytes, with a partition reference),
2 extended (20 bytes, block at 12 and reference at 16), 3 data embedded in
the entry itself. The two high bits of each length give the extent type:
0 recorded, 1 and 2 not recorded (read as zeros), 3 pointer to an
Allocation Extent Descriptor holding more descriptors (`readAllocation`).

## Compression and encryption

UDF has no compression and no encryption. Disc content protection (CSS on
DVD-Video, AACS on Blu-ray) applies to the file data, not to UDF; Arcana
has no decryption and copies such files as stored.

## Variants and versions

- 1.02 (genisoimage, DVD): verified with `udf-bridge.iso` (same SHA-256 as
  `test/expected/iso/udf-bridge.iso.txt`) and with a bridge image holding
  accented names and 10 nested directories, extracted identical.
- Empty file systems made by mkudffs (udftools 2.3) are opened and walked:
  revisions 1.02 to 2.01 with a physical partition and 512-byte blocks, 2.01
  with 4096-byte blocks, 1.50 to 2.01 with a sparable partition, and 1.50
  to 2.60 with a virtual
  partition (`--media-type=cdr`; the root directory is read through the
  VAT). The revision reported by `getRevision()` matches.
- The metadata partition (2.50 and 2.60 on hard disk or Blu-ray media) is
  implemented but was not verified: the installed mkudffs does not create
  it.
- UDF 1.50 "Non-Allocatable Space" (a hidden system file of the root) is
  skipped.

## Limits

- Named streams, stream directories and extended attributes are ignored.
- Symbolic links are extracted as empty files (`copyFile` writes nothing),
  but `l` shows them with the size of their data. Hard links (several
  identifiers for one entry) become separate copies.
- Entries of other types (devices, FIFOs, sockets...) are skipped without
  message.
- Hidden files are extracted. Permissions and owners are not restored;
  modification times are set on files, not on directories.
- The sparing tables, the integrity descriptor, descriptor CRCs and
  multi-volume sets are not used.
- `extract(InputStream, File)` throws "UDF requires random file access -
  use extract(File,File)."
- No creation of UDF images.

## Implementation notes

- Data is copied with `copyRaw` in 64 KiB pieces; for virtual and metadata
  partitions, block by block through `PartitionMap.position`. Only
  directory data is held in memory (`readAll`).
- Safety checks: directory loops (an "active" set of partition:block keys)
  and trees deeper than 256 raise "UDF directory loop"; directories larger
  than 64 MiB raise "UDF directory too large"; more than 64 chained
  allocation extents or 1,000,000 extents raise "Too many UDF allocation
  descriptors"; every read is checked against the image size ("UDF data
  outside the image") and physical blocks against their partition. Names
  with `/` or NUL get `_`; empty names, `.` and `..` raise "Invalid UDF
  file name".
- Paths go through `SafePathBuilder.buildSafePath`, files through
  `ExtractionGuard.open`.
- A bridge image cut after its directories lists normally and fails on
  extraction with "UDF data outside the image" (verified).

## Sources

- ECMA-167, Volume and File Structure for Write-Once and Rewritable Media
  using Non-Sequential Recording for Information Interchange, 3rd edition
  (1997): https://ecma-international.org/publications-and-standards/standards/ecma-167/ ,
  https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
- OSTA, Universal Disk Format Specification, revision 2.60 (2005), which
  also documents the differences with the earlier revisions:
  http://www.13thmonkey.org/documentation/UDF/udf260.pdf

License: `UdfReader` and `UdfExtractor` are Copyright 2026 Stephane Bury,
licensed under the Apache License 2.0. The `UdfReader` class comment says it
was "written from ECMA-167 3rd edition and the OSTA UDF specification
(revisions 1.02 to 2.60)".
