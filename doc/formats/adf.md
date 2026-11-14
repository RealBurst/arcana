# Amiga disk image (ADF)

| | |
|---|---|
| Extensions | `.adf` |
| Signature | `DOS` + a flag byte 0 to 7 at offset 0, in a file of 901,120 bytes (double density) or 1,802,240 bytes (high density) |
| Arcana support | list, extract (AmigaDOS OFS and FFS; DOS0 to DOS5); disks without file system cut into pieces, packed programs unpacked, game directory files extracted |
| Main classes | `be.stef.arcana.formats.adf.AdfVolume`, `AdfRawDisk`, `AmigaDecruncher`, `be.stef.arcana.extractor.AdfExtractor` |
| Test samples | `test/samples/adf/` (`payload-ofs.adf`, `payload-ffs.adf`, `payload-raw.adf`, made by `SampleGenerator adf`) |

## Overview

An ADF ("Amiga Disk File") is the sector-by-sector copy of an Amiga floppy disk: 80 cylinders, 2
heads, 11 sectors of 512 bytes (880 KiB), or 22 sectors on high density disks (1760 KiB). It is how
Amiga software of the 1980s and 1990s is kept today (emulators such as WinUAE and FS-UAE).

## Detection

By content: the size of a floppy image and an AmigaDOS boot block (`DOS` and a flag byte 0 to 7).
Fallback on the `.adf` extension. A disk without `DOS` ("NDOS" disks), or with a `DOS` boot block
but no root block in the middle of the disk, has no file system: most games, whose boot block starts
their own loader. Such a disk is cut into pieces (see "Disks without file system").

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

## Disks without file system

Most games do not use AmigaDOS: the Kickstart reads the boot block (2 blocks) and runs its code
(offset 12, A1 = an I/O request of trackdisk.device, A6 = ExecBase), which reads the game code at a
fixed position of the disk to a fixed memory address and jumps to it. The game then reads its data
with its own loader (hardware registers, MFM decoding). There are no file names: `AdfRawDisk` names
the pieces after their offset in the image.

| Piece | Content |
|---|---|
| `bootblock.bin` | the 1024 bytes of the boot block |
| `OFFSET.bin` read by the boot block | when the boot block checksum is valid, its code is searched for reads: `MOVE.L #value,d16(A1)` (`237C`) with d16 = `0x28` io_Data (address), `0x24` io_Length, `0x2C` io_Offset, then `JSR -456(A6)` DoIO or `JSR -462(A6)` SendIO (`4EAE FE38` / `FE32`). The code is read, never run |
| `OFFSET.unpacked.bin` | content of a piece holding a packed program known by `AmigaDecruncher` |
| `file-NNN.bin` | files of the game directory, when one is found in the programs read by the boot block (see below); NNN is the number the game loads the file by |
| `OFFSET.bin` other areas | runs of non-empty blocks in no other piece; a gap of less than one cylinder (22 blocks) does not split them |

The listing comment of each piece says where it comes from (address of the read, load and entry
addresses of the unpacked program).

Packed programs ("crunchers"): the packed data follows a small 68000 routine that unpacks it to a
fixed address and jumps to it. `AmigaDecruncher` recognizes the routine by its bytes (a few bytes
that change between files are ignored) and unpacks in Java. Known routine, "LZ+RLE cruncher
(absolute address)", 0x168 bytes (its family name is not known):

* Data after the routine: destination end address, packed length (longs), packed stream read
  backwards: bit counter, bit buffer, one byte replacing the last entry of the second offset table,
  then bits (highest first, from bytes read backwards) and literal bytes from the same stream.
* Pass 1, LZ77 written backwards from the destination end: literal run (`0`: none, `11`: 1,
  `10`+2 bits: 2-4, then escapes to 5-7, 8-14 and a 9-bit count), then while packed bytes remain a
  match: `1` = length 2 with table 1, `0`+`0` = 3, `0`+`1`+2 bits = 4-5, then escapes to 6-9, 10-39,
  40-71 and 72-583, with table 2; offset = 3-bit index, then index-table bits + 1 bits + base.
  Tables in the routine at 0x138 (bits) and 0x148 (bases, words).
* Pass 2, RLE: the pass 1 output starts with the final end address, the end of the RLE data and the
  zero-run escape byte; the run escape is at 0x107 of the routine. Read backwards: escape + count +
  byte = count + 1 bytes, zero escape + count = count + 1 zeros, escape + 1 = end. The routine then
  jumps to the address at 0x134.
* Checked with a game disk (Lotus Esprit Turbo Challenge, crack): the boot block reads two packed
  programs, both unpack exactly up to the address the routine jumps to; same result as an
  independent reader written from the 68000 code.

Game directory: many games load their data by number, through a table of the disk positions of
their files. `AdfRawDisk.Directory` looks for one in the programs read by the boot block (as read,
and unpacked): entries of two longs, (length, offset) or (offset, length) in the image, at least 4
files that follow each other on the disk (each file starts at the end of the previous one, rounded
up to 4 bytes at most), with at most 64 empty entries (two zeros) in a row between them. The longest
table found is used; files are numbered by their entry, from the first file of the table.

* Checked with the same disk: the main program holds a table of 256 entries (length, offset) at
  $71000 (copied to $400; the game loads file N with `LEA $400,A1`, `ASL.W #3,D0`, then its loader
  at $71C00 with D0 = offset, D1 = length). Its 98 files cover cylinders 1 to 69 exactly; each
  extracted file is identical to the bytes at the position the table gives.

What cannot be done: a game whose directory has another form (track and sector numbers, block
numbers, 16-bit values, lengths in sectors, positions computed by code) keeps its data as raw areas.
The files are in the formats of the game (graphics often compressed its own way). Disks whose
tracks have a non-standard format (copy protections) cannot be stored in an ADF at all (IPF images
are needed).

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
* Disks without file system: only reads written as `MOVE.L #value,d16(A1)` in the boot block are
  found (not values computed or loaded from a table), one cruncher is known, and only game
  directories made of (length, offset) or (offset, length) longs are found.

## Implementation notes

* The image is read in memory (1.7 MiB at most), so `extract(InputStream, File)` works too.
* Header blocks with a wrong checksum are skipped; loops of hash chains and of extension blocks are
  detected.
* Dates are set on the extracted files and folders.

## Sources

* "The ADF format" (ADFlib documentation, Laurent Clevy): https://lclevy.free.fr/adflib/adf_info.html
* AmigaDOS file system description (Amiga ROM Kernel Reference Manual, Devices and Libraries).
