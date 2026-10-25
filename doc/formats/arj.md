# ARJ

| | |
|---|---|
| Extensions | `.arj` (volumes `.a01`, `.a02`... are found by their signature) |
| Signature | `60 EA` at offset 0, with an archive header (file type 2) |
| Arcana support | list, extract (methods 0 to 4, garbled entries with the password) |
| Main classes | `be.stef.arcana.formats.arj.ArjReader`, `be.stef.arcana.formats.arj.ArjEntry`, `be.stef.arcana.extractor.ArjExtractor` (+ `be.stef.arcana.formats.lha.LhaDecoder` for methods 1 to 3) |
| Test samples | `test/samples/arj/` (`method0.arj`, `method1.arj`, `method4.arj`, `garbled.arj` and `garbled-m4.arj` with password `secret`), `test/samples/damaged/wrong-password-arj.arj` (password `wrong`) |

## Overview

ARJ ("Archived by Robert Jung") is a DOS archiver of the early 1990s, used
for BBS distributions and floppy-disk backups (it can split an archive into
volumes). Its compression is an LZ77 + static Huffman scheme of
the same family as LHA `-lh7-`. ARJ archives are now mostly met in old
software collections. The open-source ARJ (ARJ32 3.10, ARJ Software
Russia) is packaged by Linux distributions; it was used to build the samples (`arj a -m0|-m1|-m4`,
`arj a -g<password>`, see `test/tools/make-samples.sh`).

## Detection

- `ArchiveDetector.detectByMagic` returns `ARJ` when the file starts with
  `60 EA`, the basic header size at offset 2 is between 1 and 2600, and the
  byte at offset 10 (file type of the first header) is 2 (archive header).
- `detectByExtension` maps `.arj` to `ARJ`. Volume extensions (`.a01`...)
  are not mapped, but volumes start with an archive header and are detected
  by their signature.
- `ArjReader` itself requires the archive header at offset 0 ("ARJ header
  id not found", "Not an ARJ archive"). There is no scan for an archive
  embedded in a self-extracting executable.
- The `i` command prints "ARJ archive".

## Structure

An archive is a sequence of header blocks: the archive (main) header, then
one local header per file followed by its compressed data, then an end
marker. Every header block has the same frame (`ArjReader.readHeader`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | header id | `60 EA` |
| 2 | 2 | basic header size | 0 marks the end of the archive; at most 2600 |
| 4 | n | basic header | below |
| 4+n | 4 | basic header CRC-32 | checked ("ARJ header CRC error") |
| 8+n | 2 | extended header size | repeated until 0; each extended header is followed by its CRC-32 |

Extended headers are skipped without checking their CRC. An archive that
ends without the end marker is accepted.

Basic header of a local file header (offsets relative to the start of the
basic header, as used in `ArjReader.nextEntry`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | first header size | where the name starts; at least 30 |
| 1 | 1 | archiver version | ignored |
| 2 | 1 | minimum version to extract | ignored |
| 3 | 1 | host OS | 0 MS-DOS, 2 Unix, 8 NeXT...; selects the time format |
| 4 | 1 | flags | 0x01 garbled, 0x04 volume, 0x08 extfile, 0x10 path translated, 0x20 backup |
| 5 | 1 | method | 0 to 4 |
| 6 | 1 | file type | 0 binary, 1 text, 3 directory, 4 volume label, 5 chapter label |
| 7 | 1 | reserved | password modifier of a garbled file (see Encryption) |
| 8 | 4 | modification time | Unix seconds for hosts 2 and 8, MS-DOS date and time otherwise |
| 12 | 4 | compressed size | |
| 16 | 4 | original size | |
| 20 | 4 | CRC-32 | of the original data |
| 24 | 2 | file spec position in name | ignored |
| 26 | 2 | access mode | ignored |
| 28 | 2 | host data | ignored |
| 30 | var | extra data | up to "first header size" (for example the start position of a split file); ignored |
| first | var | file name | zero-terminated |
| ... | var | comment | zero-terminated; ignored |

The archive header has the same frame with file type 2. Arcana only checks
that type and a minimum length of 30 bytes; its other fields (archive name,
comment, dates, security envelope) are ignored.

Entries of type 4 and 5 (labels) and entries whose cleaned name is empty are
skipped. Text files (type 1) are extracted as binary data.

## Compression and encryption

| Method | Name in ARJ | Decoder |
|---|---|---|
| 0 | stored | data copied; compressed and original size must be equal |
| 1, 2, 3 | compressed (slowest to faster) | `LhaDecoder.arj` |
| 4 | compressed (fastest) | `ArjReader.FastestDecoder` |

Methods 1 to 3 differ only in the effort of the encoder; they share one
format, the LHA `-lh7-` coding (static Huffman codes sent per block, 5-bit
distance code count, up to 17 distance codes, matches of 3 to 256 bytes;
see [lha.md](lha.md)) with a 26 KiB window. `LhaDecoder.arj` uses a 64 KiB
buffer, which covers it. The stream has no end marker: the decoded data is
cut at the original size.

Method 4 (`FastestDecoder`) uses no Huffman code. Bits are read most
significant bit first, zeros past the end of the data:

- a length prefix: one-bits, each adding 2^k to a base (k = 0, 1, 2...),
  ended by a zero bit or after the seventh; the number of one-bits is the
  number of extra bits that follow and are added to the base.
  The value 0 means a literal: 8 bits follow;
- otherwise the match length is the value plus 2, and the distance is coded
  the same way with a prefix of up to 4 one-bits starting at 9 extra bits
  (9 to 13 bits);
- the copy starts distance + 1 bytes back in a 26624-byte circular window.

Encryption: ARJ "garbles" the data of protected files with the password
(flag 0x01, `arj a -g<password>`). The technical notes do not describe the
algorithm; it was found by comparing archives made by `arj` 3.10 with known
contents and passwords (stored zeros, then bytes 0 to 255, several
passwords, several files): each byte of the stored data (the compressed
data, before decoding) is XORed with `password[i % length] + modifier`
(8 bits), where `i` counts from 0 at the start of each entry and `modifier`
is byte 7 of the file header (a value chosen per archive, the same for its
files). The password is used as given (`-p`, bytes of
`Arcana.withPassword`).

- No password: `ArcanaEncryptedException` "ARJ entry is encrypted and no
  password was provided: <name>". Listing needs no password (the entries
  are marked encrypted).
- Wrong password: the CRC-32 differs ("Wrong password for ARJ entry (CRC
  error)"), or the decoder of methods 1 to 4 fails first ("Wrong password
  for ARJ entry (data error)"); both are `ArcanaEncryptedException`.
- Main header byte 28: "currently not used" in the 1993 technical notes;
  `arj` 3.10 writes 1 there in garbled archives (the `file` command shows
  it as the encryption version). Arcana decrypts when it is 0 or 1 and
  refuses higher values ("ARJ encryption version N (ARJCRYPT) is not
  supported"), assumed to be the ARJCRYPT (GOST) modes of later ARJ
  versions: not verified, the `arjcrypt` module of the Debian `arj` package
  crashes, so no sample could be made.

## Variants and versions

- Methods 0, 1 and 4 are verified with the committed samples (same SHA-256
  as `test/expected/arj/*.txt`); methods 2 and 3, empty files and
  directories (`arj a -a1`) were checked with archives made by `arj` 3.10.
- Times: the ARJ technical notes describe an MS-DOS date and time. The Unix
  ARJ writes Unix seconds with host OS 2 (the samples hold 1704164645,
  2024-01-02 03:04:05 UTC), and `ArjReader` reads Unix seconds for hosts 2
  and 8. Other hosts are decoded as MS-DOS time in the local time zone.
- Names: decoded as UTF-8 when they are valid UTF-8, else as code page 437
  (`IBM437`, or ISO-8859-1 when the JVM lacks it). `\` and `/` are both
  separators; empty, `.` and `..` parts and drive parts (ending with `:`) are
  dropped.
- Multi-volume archives: each volume can be listed on its own; the sizes
  shown for a split file are those of the part in that volume.

## Limits

- ARJCRYPT (GOST) encrypted archives: not supported, see Encryption.
- Files split across volumes (flag 0x04 or 0x08): "ARJ entry split across
  volumes: <name>". The error stops the whole extraction, so the complete
  files of that volume that come after the split one are not extracted
  either (verified with `arj a -v100K`).
- Other methods: "ARJ method N is not supported: <name>".
- Comments, chapters, file attributes, the archive header fields and the
  extended headers are ignored.
- No creation of ARJ archives, no self-extracting ARJ.

## Implementation notes

- `ArjReader` is sequential, so `ArjExtractor` also supports
  `extract(InputStream, File)`. Data not read is skipped before the next
  header.
- The `Checked` stream stops at the original size and compares the CRC-32
  there: "ARJ CRC error: <name>" (the partly written file stays on disk),
  "ARJ data truncated: <name>" when the decoder ends early.
- Header sizes above 2600 bytes, short headers and a first header size
  outside the basic header are rejected as `ArcanaCorruptedException`.
- Paths go through `SafePathBuilder`, output files through `ExtractionGuard`.
  Directory times are set after all files are written.

## Sources

- ARJ technical information (TECHNOTE), Robert Jung, April 1993 version:
  https://www.opennet.ru/docs/formats/arj.txt
- Open-source ARJ (the `arj` tool used for the samples):
  https://sourceforge.net/projects/arj/
- ARJ page of the Just Solve the File Format Problem wiki:
  http://fileformats.archiveteam.org/wiki/ARJ

License, from the file headers: `ArjReader`, `ArjEntry` and `ArjExtractor`
are Copyright 2026 Stephane Bury, Apache License 2.0. `ArjReader` says it
was "written from the ARJ technical notes (header layout) and the
description of the ARJ compression methods". Methods 1 to 3 use
`LhaDecoder`, which is "Derived from Apache Commons Compress"
(`LhStaticHuffmanCompressorInputStream`, Apache License 2.0).
