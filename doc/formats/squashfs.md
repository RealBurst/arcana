# SquashFS

| | |
|---|---|
| Extensions | `.sqfs`, `.squashfs`, `.snap` |
| Signature | `68 73 71 73` ("hsqs") at offset 0 |
| Arcana support | list, extract (version 4.0; gzip, LZMA, LZO, XZ, LZ4, Zstandard) |
| Main classes | `be.stef.arcana.formats.squashfs.SquashfsReader`, `be.stef.arcana.formats.squashfs.Lzo1xDecompressor`, `be.stef.arcana.extractor.SquashfsExtractor` |
| Test samples | `test/samples/squashfs/` (`gzip.sqfs`, `xz.sqfs`, `zstd.sqfs`, `lz4.sqfs`), `test/samples/damaged/flipped.sqfs` |

## Overview

SquashFS is a compressed read-only file system for Linux, written by Phillip
Lougher and merged in the kernel in 2009 (2.6.29) in its version 4.0. Files,
inodes and directories are compressed in blocks, small files and file tails
are packed together in "fragments", and identical files are stored once. It
is used by live CDs, Snap packages, AppImage payloads and router firmware.
Images are made with `mksquashfs` (squashfs-tools).

The samples were made with mksquashfs (`-comp gzip|xz|zstd|lz4 -all-root`,
see `test/tools/make-samples.sh`). `flipped.sqfs` is `xz.sqfs` with one byte
changed at offset 300, inside the compressed data.

## Detection

- `ArchiveDetector.detectByMagic` returns `SQUASHFS` when the file starts
  with "hsqs" (the little-endian magic of version 4). The check runs after
  WIM.
- Without the magic, `detectByExtension` maps `.sqfs`, `.squashfs` and
  `.snap` to `SQUASHFS`. A big-endian image (magic "sqsh", versions 3 and
  older) is only reached this way, and refused (see Limits).
- `SquashfsReader` checks the magic, version 4, the block size and the
  compressor id, and that the inode and directory tables are inside the file
  ("Invalid SquashFS table positions").
- The superblock must be at offset 0. An AppImage (ELF runtime followed by
  the image) is not opened: verified, a file made of an ELF header and
  `gzip.sqfs` gives "No archive found ... (not a self-extracting archive)".
- The `i` command prints "SquashFS archive"; `getCompressorName()` and
  `getBlockSize()` are not used by the CLI.

## Structure

All numbers are little-endian. The image starts with a 96-byte superblock:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | "hsqs" |
| 4 | 4 | inode count | ignored |
| 8 | 4 | modification time | ignored |
| 12 | 4 | block size | 4096 to 1 MiB, must equal 2^(block log) |
| 16 | 4 | fragment count | bound for fragment indexes |
| 20 | 2 | compressor | 1 gzip, 2 lzma, 3 lzo, 4 xz, 5 lz4, 6 zstd |
| 22 | 2 | block log | |
| 24 | 2 | flags | ignored |
| 26 | 2 | id count | ignored |
| 28 | 2 | major version | must be 4 |
| 30 | 2 | minor version | |
| 32 | 8 | root inode reference | |
| 40 | 8 | bytes used | ignored |
| 48 | 8 | id table | ignored |
| 56 | 8 | xattr id table | ignored |
| 64 | 8 | inode table | |
| 72 | 8 | directory table | |
| 80 | 8 | fragment table | |
| 88 | 8 | export table | ignored |

The data blocks and fragment blocks follow, then the tables. The inode and
directory tables are sequences of metadata blocks: a 2-byte header (bit 15
set: stored uncompressed; low 15 bits: stored size) followed by at most
8 KiB of data once decompressed (`SquashfsReader.metadata`). Records may
span two blocks; `SquashfsReader.Cursor` reads across them. An inode is
addressed by a 48-bit reference: (position of its metadata block relative
to the inode table) << 16 | offset in the decompressed block.

### Inodes

Each inode starts with a 16-byte header: type (2 bytes), permissions,
uid index, gid index (2 bytes each, ignored), modification time (4) and
inode number (4). `readInode` then reads:

| Type | Kind | Fields used |
|---|---|---|
| 1 | basic directory | directory block (4), link count, size (2), offset (2) |
| 8 | extended directory | link count, size (4), directory block (4), parent, index count, offset (2); the index is not used |
| 2 | basic file | blocks start (4), fragment index (4), fragment offset (4), size (4), block list |
| 9 | extended file | blocks start (8), size (8), sparse bytes, link count, fragment index, fragment offset, xattr index, block list |
| 3, 10 | symbolic link | link count, target size (4), target (UTF-8) |
| 4-7, 11-14 | devices, FIFOs, sockets | header only |

The block list has one 4-byte word per data block: the number of full
blocks, plus one when the file has no fragment and a partial last block.
In each word, the low 24 bits are the stored size and bit 24 means
"stored uncompressed"; a size of 0 is a hole (a block of zeros, nothing
stored). A fragment index of 0xFFFFFFFF means no fragment.

### Directories

A directory inode points into the directory table (block, offset) and gives
its listing size plus 3. The listing is a series of headers, each followed
by its entries:

| Record | Fields |
|---|---|
| header (12 bytes) | entry count - 1 (at most 256), inode block start, base inode number |
| entry (8 bytes + name) | inode offset (2), inode number delta (2, signed), type (2), name size - 1 (2), name |

The inode of an entry is (header block start << 16 | entry offset). The
entry type is ignored: the inode is always read.

### Fragments

The fragment table is a list of 8-byte positions of metadata blocks; each
block holds 512 entries of 16 bytes: start position (8), size word (4, same
encoding as data blocks), unused (4). The tail of a file is read from
(fragment block, fragment offset) after its full blocks
(`SquashfsReader.fragment`).

## Compression and encryption

Every data block, fragment block and metadata block is compressed alone,
with the compressor of the superblock (`SquashfsReader.decompress`):

| Id | Compressor | Decoder |
|---|---|---|
| 1 | gzip (zlib stream) | `java.util.zip.Inflater` |
| 2 | lzma (LZMA "alone" format) | `be.stef.arcana.formats.xz.LZMAInputStream` |
| 3 | lzo (LZO1X) | `Lzo1xDecompressor` |
| 4 | xz | `be.stef.arcana.formats.xz.XZInputStream` (see [xz-lzma.md](xz-lzma.md)) |
| 5 | lz4 (raw block) | `be.stef.arcana.formats.lz4.LZ4BlockInputStream` (see [lz4.md](lz4.md)) |
| 6 | zstd | `be.stef.arcana.formats.zstd.ZstdInputStream` (see [zstd.md](zstd.md)) |

The optional compressor options stored after the superblock are not read;
none of the decoders needs them. SquashFS has no encryption.

`Lzo1xDecompressor` decodes the LZO1X bitstream (as written by `lzo1x_1`
and `lzo1x_999`): a first byte above 17 starts with a literal run, then
each instruction byte selects a match length and distance and the number
of literals (0 to 3, or a longer run) that follow; a distance of 16384 in
the `0001HLLL` form ends the stream.

## Variants and versions

- All six compressors verified with images made by mksquashfs 4.6.1
  (`-comp gzip|lzo|lz4|xz|zstd|lzma`), and with `-no-compression`,
  `-b 4096`, `-b 1M -no-fragments -comp xz -Xbcj x86`, `-comp lz4 -Xhc` and
  `-xattrs-add`: the files extract identical to the source (300 KB random
  file, 2 MiB sparse file, hard link, small files packed in fragments).
- The four committed samples give the SHA-256 of
  `test/expected/squashfs/*.txt`.
- Big-endian images (magic "sqsh"): "Big-endian SquashFS (version 3 or
  older) is not supported". Little-endian images with another major version:
  "SquashFS version 3.0 is not supported (4.0 only)". An unknown compressor
  id: "Unknown SquashFS compressor N" (all three verified by patching
  `gzip.sqfs`).

## Limits

- Symbolic links are written as empty files (`copyFile` writes data only
  for regular files) and listed with size 0; the target is read but not
  used by the extractor.
- Devices, FIFOs and sockets are listed (size 0) and not extracted.
- Hard links become separate copies.
- Extended attributes, uid/gid, permissions and the export table are
  ignored. Modification times are set on files and links, not on
  directories.
- There is no checksum in SquashFS: damage is only found when a decoder
  fails or a block decodes to a wrong size. `flipped.sqfs` lists normally
  (the change is in file data); extraction stops with "Compressed data is
  corrupt" from the XZ decoder, leaving `bin/random.bin` empty, as in
  `test/expected/damaged/flipped.sqfs.txt`.
- A truncated image whose tables are past the end fails at once with
  "Invalid SquashFS table positions" (verified).
- `extract(InputStream, File)` throws "SquashFS requires random file
  access - use extract(File,File)."
- No creation of SquashFS images.

## Implementation notes

- Memory: one data block buffer per file (`blockSize`), one cached
  decompressed fragment block (the last one used, keyed by its position),
  and an LRU cache of 256 decompressed metadata blocks (`metaCache`).
  Small files sharing a fragment decompress it once when they are read in
  order.
- Checks: a decompressed data block shorter than needed raises "SquashFS
  data block too short"; LZMA, XZ, LZ4 and Zstandard blocks that decode to
  more than the block size raise "SquashFS block larger than the block
  size" (`readAll`); fragment indexes are checked against the fragment
  count and fragment reads against the decoded length; every read is
  checked against the file size ("SquashFS data outside the image").
- Directory walk: parents before children; loops and trees deeper than 256
  raise "SquashFS directory loop"; names that are empty, `.`, `..` or
  contain `/` raise "Invalid SquashFS file name".
- Paths go through `SafePathBuilder.buildSafePath`, files through
  `ExtractionGuard.open`.

## Sources

- Linux kernel documentation, Squashfs 4.0 Filesystem:
  https://docs.kernel.org/filesystems/squashfs.html
- Zachary Dremann, Squashfs Binary Format (community description of the
  on-disk format): https://dr-emann.github.io/squashfs/squashfs.html
- squashfs-tools (mksquashfs, unsquashfs), used to make the samples:
  https://github.com/plougher/squashfs-tools
- Linux kernel documentation, LZO stream format:
  https://docs.kernel.org/staging/lzo.html

License: `SquashfsReader`, `Lzo1xDecompressor` and `SquashfsExtractor` are
Copyright 2026 Stephane Bury, licensed under the Apache License 2.0. The
`SquashfsReader` class comment says it was "written from the community
description of the on-disk format" (it does not name the document); the
`Lzo1xDecompressor` comment says it was "written from the description of
the bitstream in the Linux kernel documentation
(Documentation/staging/lzo.rst)".
