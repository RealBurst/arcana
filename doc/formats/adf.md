# Amiga disk image (ADF)

| | |
|---|---|
| Extensions | `.adf` |
| Signature | `DOS` + a flag byte 0 to 7 at offset 0, in a file of 901,120 bytes (double density) or 1,802,240 bytes (high density) |
| Arcana support | list, extract (AmigaDOS OFS and FFS; DOS0 to DOS5) |
| Main classes | `be.stef.arcana.formats.adf.AdfVolume`, `be.stef.arcana.extractor.AdfExtractor` |
| Test samples | `test/samples/adf/` (`payload-ofs.adf`, `payload-ffs.adf`, made by `SampleGenerator adf`) |

## Overview

An ADF ("Amiga Disk File") is the sector-by-sector copy of an Amiga floppy disk: 80 cylinders, 2
heads, 11 sectors of 512 bytes (880 KiB), or 22 sectors on high density disks (1760 KiB). It is how
Amiga software of the 1980s and 1990s is kept today (emulators such as WinUAE and FS-UAE).

## Detection

By content: the size of a floppy image and an AmigaDOS boot block (`DOS` and a flag byte 0 to 7).
Fallback on the `.adf` extension. A disk without `DOS` (most games with their own track loader,
"NDOS" disks) is recognized by the extension but has no file system: extraction stops with "Not an
AmigaDOS disk (no "DOS" boot block): a game with its own track loader, nothing to extract as files".

## Structure

Blocks of 512 bytes, numbers counted from the start of the image; all values big-endian.

* Boot block (blocks 0-1): `DOS`, then flags: bit 0 FFS (else OFS), bit 1 international mode
  (hash of names with accented capitals), bit 2 directory cache (DOS4/5, the cache blocks are not
  used by Arcana). DOS6/7 (long names) are refused.
* Root block: block 880 (DD) or 1760 (HD), type 2, secondary type 1.
* Header blocks (root, directory, file; type 2):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | type | 2 (header), 16 (file extension), 8 (OFS data) |
| 4 | 4 | own block number | |
| 8 | 4 | high_seq | data blocks listed in this block (files) |
| 16 | 4 | first data block | OFS files |
| 20 | 4 | checksum | the sum of the 128 longs of the block is 0 |
| 24 | 72 x 4 | hash table (root, directory) / data block numbers (file, from 308 downward) | |
| 324 | 4 | file size | |
| 328 | 80 | comment | length byte, 79 characters at most |
| 420 | 12 | date | days since 1978-01-01, minutes, ticks of 1/50 s |
| 432 | 31 | name | length byte, 30 characters at most, ISO-8859-1 |
| 496 | 4 | hash_chain | next entry of the same hash slot |
| 500 | 4 | parent | |
| 504 | 4 | extension | next file extension block (type 16, same layout of the data block table) |
| 508 | 4 | secondary type | 1 root, 2 directory, -3 file, 3 soft link, -4 / 4 hard links |

* OFS data blocks: type 8, file header, sequence number, data size (12), next data block (16),
  checksum (20), then 488 bytes of data. FFS data blocks: 512 bytes of data, no header.

## Compression and encryption

None: the files are stored as they are (`.adz` images, gzip-compressed ADF, are not opened yet).

## Variants and versions

* OFS (DOS0, DOS2, DOS4) and FFS (DOS1, DOS3, DOS5), double and high density: same reader, the
  data blocks are read from the block tables of the file header and its extension blocks.
* Checked with an original game disk (Marble Madness, 1986, OFS): its 52 files are identical to
  those of an independent reader that follows the OFS "next data block" chain instead of the tables.

## Limits

* Soft and hard links are not extracted (their names are printed).
* A file whose blocks are not valid is skipped with a message, the others are extracted. Copy
  protections do this on purpose: on the Marble Madness disk, `c/sigfile` points at blocks of the
  first track that held a special format on the real floppy ("block 11 of c/sigfile is not a data
  block").
* The bitmap, the directory cache blocks and the protection bits are not used.
* Whole hard disk images (HDF, RDB) are not supported.

## Implementation notes

* The image is read in memory (1.7 MiB at most), so `extract(InputStream, File)` works too.
* Header blocks with a wrong checksum are skipped; loops of hash chains and of extension blocks are
  detected.
* Dates are set on the extracted files and folders.

## Sources

* "The ADF format" (ADFlib documentation, Laurent Clevy): https://lclevy.free.fr/adflib/adf_info.html
* AmigaDOS file system description (Amiga ROM Kernel Reference Manual, Devices and Libraries).
