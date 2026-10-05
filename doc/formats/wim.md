# WIM (Windows Imaging Format)

| | |
|---|---|
| Extensions | `.wim`, `.esd`; `.swm` (split parts) is recognized but refused |
| Signature | `4D 53 57 49 4D 00 00 00` ("MSWIM\0\0\0") at offset 0 |
| Arcana support | list, extract (uncompressed, XPRESS, LZX, LZMS, solid LZMS resources) |
| Main classes | `be.stef.arcana.formats.wim.WimReader`, `be.stef.arcana.formats.wim.XpressHuffmanDecoder`, `be.stef.arcana.formats.wim.WimLzxDecoder`, `be.stef.arcana.formats.wim.LzmsDecoder`, `be.stef.arcana.extractor.WimExtractor` |
| Test samples | `test/samples/wim/` (`none.wim`, `xpress.wim`, `lzx.wim`, `lzms.wim`, `solid-lzms.wim`, `lzx-uncompressed-block.wim`), `test/samples/damaged/flipped.wim` |

## Overview

WIM is the file-based disk image format introduced by Microsoft with Windows
Vista deployment tools. A WIM file holds one or more "images" (directory
trees of a volume); identical file contents are stored once and found by
their SHA-1. It is the format of `install.wim` and `boot.wim` on Windows
installation media and is handled by DISM and the Windows ADK. The `.esd`
files used by Windows Update and the Media Creation Tool are WIM files with
"solid" resources compressed with LZMS.

The committed samples were made with `wimlib-imagex capture` (see
`test/tools/make-samples.sh`), with `--compress=none|xpress|lzx|lzms` and
`--solid`.

## Detection

- `ArchiveDetector.detectByMagic` returns `WIM` when the file starts with the
  8 bytes "MSWIM\0\0\0". The check runs after CAB and before SquashFS.
- Without the magic, `detectByExtension` maps `.wim`, `.swm` and `.esd` to
  `WIM`.
- `WimReader` checks only the first 5 bytes ("MSWIM") and rejects files
  shorter than 208 bytes ("WIM file too short").
- The `i` command prints "WIM archive" and no further detail.
  `WimReader.getCompressionName()` and `hasSolidResources()` exist but are
  not used by the CLI.

## Structure

All integers are little-endian. The file starts with a 208-byte header:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | "MSWIM\0\0\0" |
| 8 | 4 | header size | 208; not checked |
| 12 | 4 | version | 0x10D00 for classic files, 0xE00 (3584) for LZMS/solid files; not checked |
| 16 | 4 | flags | 0x2 compressed, 0x8 spanned; compression type: 0x20000 XPRESS, 0x40000 LZX, 0x80000 LZMS, 0x200000 (treated as XPRESS) |
| 20 | 4 | chunk size | 0 means 32768; must be a power of two from 4 KiB to 64 MiB |
| 24 | 16 | GUID | ignored |
| 40 | 2 | part number | must be 1 |
| 42 | 2 | total parts | must be 1 (or 0) |
| 44 | 4 | image count | 0 to 10000 |
| 48 | 24 | lookup table | resource header (below) |
| 72 | 24 | XML data | ignored |
| 96 | 24 | boot metadata | ignored |
| 120 | 4 | boot index | ignored |
| 124 | 24 | integrity table | ignored (no integrity check) |
| 148 | 60 | reserved | |

A resource header (24 bytes, `WimReader.reshdr`) locates a resource in the
file:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 7 | stored size | 56-bit size of the resource in the file |
| 7 | 1 | flags | 0x2 metadata, 0x4 compressed, 0x10 solid |
| 8 | 8 | offset | file offset of the resource |
| 16 | 8 | original size | uncompressed size |

The lookup table (`WimReader.readLookupTable`) is an array of 50-byte
entries, one per stored stream; its size must be a multiple of 50 and at
most 256 MiB:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 24 | resource header | |
| 24 | 2 | part number | ignored |
| 26 | 4 | reference count | ignored |
| 30 | 20 | SHA-1 | hash of the uncompressed stream |

Entries flagged "metadata" are the metadata resources of the images, taken
in table order (image 1 first). The others are indexed by their SHA-1.

### Metadata resource

Each image has one metadata resource (at most 512 MiB). It starts with the
security data, whose first 4 bytes give its total length; the root directory
entry follows, aligned on 8 bytes. `WimReader.walkDir` then follows the
"subdirectory offset" of each directory entry. A directory entry
(DIRENTRY) is:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | length | 0 ends a directory; minimum 102 |
| 8 | 4 | attributes | 0x10 directory, 0x400 reparse point |
| 12 | 4 | security id | ignored |
| 16 | 8 | subdirectory offset | offset of the first child in the metadata, 0 if none |
| 24 | 16 | reserved | |
| 40 | 8 | creation time | ignored |
| 48 | 8 | last access time | ignored |
| 56 | 8 | last write time | FILETIME, converted to Unix seconds |
| 64 | 20 | SHA-1 | of the unnamed data stream, all zero for an empty file |
| 84 | 12 | reparse tag, hard link id | ignored |
| 96 | 2 | stream count | number of stream entries after this entry |
| 98 | 2 | short name length | ignored |
| 100 | 2 | name length | in bytes |
| 102 | var | name | UTF-16LE |

The next entry starts at the current offset plus the length rounded up to 8,
after the stream entries. A stream entry has a length (8 bytes), 8 reserved
bytes, a SHA-1 (20 bytes) and a name length (2 bytes) followed by the
UTF-16LE name. The stream whose name is empty is the file data and its
SHA-1 replaces the one of the directory entry; named streams (alternate
data streams) are skipped.

### Compressed resources

A compressed resource is cut into chunks of the header chunk size, each one
compressed separately. It starts with a table of chunk offsets: one entry for
chunks 1 to n-1 (chunk 0 starts right after the table), relative to the end
of the table; entries are 4 bytes, or 8 when the original size is above
4 GiB. A chunk whose stored size equals its uncompressed size is stored as
is. This is `WimReader.copyChunked`.

### Solid resources

In version 3584 files, several streams can share one "solid" resource. In
the lookup table, a solid resource is an entry flagged 0x10 whose original
size field holds the value 0x100000000; the entries that follow, also
flagged 0x10, are the streams it contains: their "offset" is the offset in
the uncompressed data of the solid resource, and their "stored size" is
their size. Several consecutive solid resources form one group whose
uncompressed data are concatenated (`WimReader.SolidGroup`).

A solid resource has its own 16-byte header, then a table with the
compressed size of every chunk (4 bytes each), then the chunks:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | uncompressed size | |
| 8 | 4 | chunk size | power of two, 4 KiB to 64 MiB (64 MiB in `solid-lzms.wim`) |
| 12 | 4 | compression | 1 XPRESS, 2 LZX, 3 LZMS |

## Compression and encryption

| Method | Class | Notes |
|---|---|---|
| none | `WimReader.copyRaw` | data copied from the file |
| XPRESS (Huffman) | `XpressHuffmanDecoder` | chunks up to 2 MiB |
| LZX | `WimLzxDecoder` | chunks up to 2 MiB (window 32 KiB to 2 MiB) |
| LZMS | `LzmsDecoder` | chunks up to 64 MiB |

WIM has no encryption.

XPRESS (`XpressHuffmanDecoder`): every 64 KiB of output starts with 256
bytes holding 512 4-bit code lengths (low nibble first), then a stream of
16-bit little-endian words read most significant bit first. Symbols 0-255
are literals; for symbols 256-511 the low nibble is the length minus 3 (15:
one more byte follows in the byte stream, and 255 there: a 16-bit length)
and the high nibble is the number of offset bits. Reads past the end of the
chunk return zeros.

LZX (`WimLzxDecoder`): the coding is described in [lzx.md](lzx.md). In WIM,
every chunk is an independent LZX stream whose window is the chunk size;
there is no E8 header bit and the E8 call translation is always undone with
a translation size of 12000000; a block size is either the bit "1" (32768)
or 16 bits, plus 8 more bits when the window is 64 KiB or more. Code lengths
are reset to 0 at the start of each chunk and the three recent offsets to 1.
An uncompressed block is aligned as in CAB: when its header ends on a 16-bit
boundary, a whole 16-bit word of padding follows (wimlib's decompressor
requires it). wimlib never writes uncompressed blocks (incompressible chunks
are stored as is instead); `lzx-uncompressed-block.wim` holds two hand-made
LZX chunks with one, built by `test/tools/make-samples.sh`.

## LZMS

LZMS is the compression of `.esd` files and of solid resources. Microsoft
does not publish its description. `LzmsDecoder` decodes one chunk (one
"block") at a time; blocks are independent. A block must have an even size
of at least 4 bytes.

### Two bit streams

The block is read as 16-bit little-endian words from both ends:

- forwards, by a binary range decoder (`LzmsDecoder.bit`). Range and code
  are 32-bit; the code is initialized from the first two words (first word
  high). Before each decision, when the range is below 2^16, range and code
  are shifted left by 16 and the next word is added to the code. The
  probability of a 0 is a 6-bit value p (clamped to 1..63): the bound is
  (range >>> 6) * p, and the bit is 0 when code < bound (unsigned).
- backwards, from the last word towards the first, as a plain bit reader
  (most significant bit first) for Huffman symbols and extra bits
  (`LzmsDecoder.need`, `readBits`). Words past the start read as 0.

### Adaptive probabilities

Each decision uses one probability entry selected by a context: the last
decisions of the same kind. An entry keeps its last 64 bits and the number
of zeros among them; it starts at 48 zeros with the bit history
0x0000000055555555. After each bit, the bit leaving the 64-bit history and
the new bit update the zero count.

| Decision | Entries | Context |
|---|---|---|
| literal or match | 16 | last 4 decisions |
| LZ or delta match | 32 | last 5 decisions |
| explicit or repeated LZ offset | 64 | last 6 decisions |
| explicit or repeated delta pair | 64 | last 6 decisions |
| LZ repeat index (2 decisions) | 2 x 64 | last 6 decisions of each |
| delta repeat index (2 decisions) | 2 x 64 | last 6 decisions of each |

### Adaptive Huffman codes

Five canonical Huffman codes (`LzmsDecoder.Code`), with code lengths
limited to 15 bits, read from the backward stream:

| Code | Symbols | Rebuilt every |
|---|---|---|
| literals | 256 | 1024 symbols |
| LZ offset slots | depends on the block size | 1024 symbols |
| lengths | 54 slots | 512 symbols |
| delta offset slots | depends on the block size | 1024 symbols |
| delta powers | 8 | 512 symbols |

All frequencies start at 1. Each decoded symbol increments its frequency;
when the counter reaches the rebuild interval, the code is rebuilt from the
frequencies and the frequencies are then halved (f / 2 + 1). The code is
built from the symbols sorted by (frequency, symbol) with a two-queue
Huffman construction, ties going to leaves; the longest codes go to the
first sorted symbols.

There are 799 offset slots and 54 length slots, built from runs of
(extra bits, number of slots) in `OFFSET_RUNS` and `LENGTH_RUNS`; both start
at the value 1. The number of offset slots used by a block is the slot of
(block size - 1) plus one.

### Items

Each item is chosen by range-coded decisions:

- literal: one symbol of the literal code;
- LZ match: an offset, either explicit (offset slot plus extra bits) or one
  of the 3 recent offsets, then a length (length slot plus extra bits); the
  bytes are copied from `offset` bytes back;
- delta match: a pair (power, raw offset), either explicit (delta power
  symbol, then a delta offset slot plus extra bits) or one of the 3 recent
  pairs, then a length. With span = 2^power and offset = raw << power, each
  output byte is `out[i - offset] + out[i - span] - out[i - offset - span]`
  (modulo 256).

A recent value that is used is removed from its queue. The value used by an
item enters the front of its queue only after the next item ("one item
later"), so each queue holds 4 slots for 3 visible values. Matches that
reach before the start of the block or past its end raise "Invalid LZMS
match" / "Invalid LZMS delta match".

### x86 post-filter

After decoding, `LzmsDecoder.undoX86` converts back the x86 addresses that
the encoder made absolute (blocks of more than 17 bytes; no opcode is
looked for in the first byte and in the last 16 bytes). It recognizes CALL (`E8`), RIP-relative LEA/MOV (`48`
or `4C`, then `8D` or `8B`, ModR/M ending in `101`), `F0 83 05` and
`FF 15`; `E9` skips 5 bytes. A table remembers, for each 16-bit target, the
last place it was used: two uses within 65535 bytes mark a likely x86 region,
and the 4-byte operands are converted (value minus position) for 1023 bytes
after the last mark (511 for `E8`).

## Variants and versions

- Uncompressed, XPRESS, LZX and LZMS files: verified on the five samples
  (same SHA-256 as `test/expected/wim/*.txt`), and with wimlib files using
  2 MiB LZX chunks, 64 KiB XPRESS chunks and 1 MiB LZMS chunks, and on
  binaries (x86 filters of LZX and LZMS).
- Solid resources (`.esd`, `wimlib-imagex --solid`): verified with
  `solid-lzms.wim` and larger solid files.
- Several images: each image is listed and extracted under a directory named
  after its number (`1/`, `2/`...), like 7-Zip. With one image there is no
  prefix. Verified with a two-image file made by `wimlib-imagex append`.
- Hard links and duplicated files (same SHA-1) are written as separate
  copies.

## Limits

- Split WIM (`.swm`): refused with "Split WIM files (.swm) are not
  supported: part N of M" (spanned flag, part number other than 1, or more
  than one part).
- Reparse points (symbolic links, junctions) are listed with size 0 and
  extracted as empty files. Alternate data streams, security descriptors,
  attributes, short names, creation and access times are ignored.
- The XML data and the integrity table are not read. The boot image index is
  ignored.
- Times are set on files only, not on directories.
- `extract(InputStream, File)` is not supported ("WIM requires random file
  access"): the reader needs `RandomAccessFile`.
- No creation of WIM files.

## Implementation notes

- Data order: `WimExtractor` first walks the trees (creating directories),
  then sorts the files with `WimReader.DATA_ORDER` (resource offset, then
  offset inside a solid group) and extracts them in that order. With the
  one-chunk cache of `copyChunked` (`cachedChunk`, keyed by the file position
  of the compressed chunk), several small files of one large LZMS chunk
  decompress it once.
- SHA-1 check: `copyFile` hashes the output and compares with the lookup
  table SHA-1; a difference raises "WIM data corrupted (SHA-1 mismatch)".
  This is the result of `test/samples/damaged/flipped.wim`: the listing
  works, the extraction fails on `bin/random.bin`.
- Safety checks: file names that are empty, `.`, `..` or contain `/` or `\`
  are rejected ("Invalid WIM file name"); directory loops and trees deeper
  than 1024 levels raise "WIM directory loop"; every offset is checked
  against the metadata or file size; chunk sizes, chunk tables and match
  distances are checked. Paths also go through `SafePathBuilder` and output
  files through `ExtractionGuard`.
- One decoder of each kind is kept per reader; LZX decoders are kept per
  chunk size.
- Memory: the decompression buffer has the size of a chunk. For solid
  resources this is the chunk size of the solid header (64 MiB with wimlib),
  allocated even when the resource is small.

## Sources

- Microsoft, "Windows Imaging File Format (WIM)" (document distributed with
  the Windows deployment tools):
  https://www.microsoft.com/en-us/download/details.aspx?id=13096 , also
  https://learn.microsoft.com/en-us/previous-versions/msdn10/dd861280(v=msdn.10)
- [MS-XCA] Xpress Compression Algorithm (LZ77+Huffman):
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
- LZX: see [lzx.md](lzx.md).
- wimlib documentation (format notes, compression formats, `wimlib-imagex`
  used to make the samples): https://wimlib.net/compression.html ,
  https://wimlib.net/man1/wimcapture.html

License and provenance, from the file headers: `WimReader`,
`XpressHuffmanDecoder`, `WimLzxDecoder`, `LzmsDecoder` and `WimExtractor`
are Copyright 2026 Stephane Bury, Apache-2.0. `WimReader` says it was
"written from the Microsoft 'Windows Imaging File Format (WIM)'
specification"; `XpressHuffmanDecoder` "from the Microsoft specification
[MS-XCA] section 2.2"; `WimLzxDecoder` "from the LZX format description
([MS-PATCH] LZX DELTA, and the Cabinet LZX documentation)". The header of
`LzmsDecoder` says that the format is not documented by Microsoft, that the
implementation "follows the public description of the format (bit streams,
item types, adaptive probabilities and Huffman codes, x86 post-filter)" and
that it "was checked against data written by an independent LZMS encoder";
it does not name the description it used. wimlib, the main public
implementation of LZMS, is licensed GPLv3+, with its library also offered
under LGPLv2.1+ (wimlib COPYING file); the Arcana sources contain no wimlib
file and no reference to it. wimlib is only used, as a tool, to build the
test samples.
