# AR and Debian packages

| | |
|---|---|
| Extensions | `.a`, `.deb` |
| Signature | `21 3C 61 72 63 68 3E 0A` ("!<arch>\n") at offset 0 |
| Arcana support | list, extract; a `.deb` is unpacked like `dpkg-deb -R` (contents of `data.tar.*` plus `DEBIAN/`) |
| Main classes | `be.stef.arcana.extractor.ArExtractor`; for the deb members `be.stef.arcana.formats.tar.TarInputStream`, `be.stef.arcana.extractor.TarExtractor`, `be.stef.arcana.extractor.CompressedStreamExtractor` |
| Test samples | `test/samples/ar/` (`files.a`, `arcana-test.deb`) |

## Overview

`ar` is the old Unix archiver. Today it survives mostly as the container of
static libraries (`.a`, a set of object files plus a symbol table) and as
the outer layer of Debian binary packages. The format has no compression and
no checksum: an 8-byte magic, then for each member a 60-byte text header and
the data. System V/GNU and BSD tools disagree on how to store names longer
than 16 characters and on the name of the symbol table member.

A Debian package is an ar archive whose first member is `debian-binary`
(the text `2.0\n`), followed by `control.tar.*` (package metadata and
maintainer scripts) and `data.tar.*` (the files to install).

## Detection

- `ArchiveDetector.detectByMagic` returns `AR` when the file starts with
  `!<arch>\n`; `.a` and `.deb` map to `AR` in `detectByExtension` as a
  fallback.
- The `i` command (`ArchiveAnalyzer.ar`) reports `DEB` ("Debian package (ar
  archive)") when `debian-binary` is found at offset 8, that is as the name
  of the first member, and `AR` otherwise. Both are handled by the same
  extractor.
- GNU thin archives (`!<thin>\n`) are not recognized; given to
  `ArExtractor` they fail with "Not an AR archive".

## Structure

The file starts with the 8-byte magic. Each member header is 60 bytes of
ASCII text, fields padded with spaces:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 16 | name | see the name forms below |
| 16 | 12 | mtime | decimal Unix seconds; ignored |
| 28 | 6 | owner id | ignored |
| 34 | 6 | group id | ignored |
| 40 | 8 | mode | octal; ignored |
| 48 | 10 | size | decimal size of the member data |
| 58 | 2 | end marker | `` ` `` followed by `\n` (`60 0A`), checked by `readHeader` |

The data follows the header; when the size is odd, one padding byte
(normally `\n`) follows it (`skipPad`).

Name forms handled by `ArExtractor.resolveEntry`:

| Raw name | Meaning | Handling |
|---|---|---|
| `name/` | GNU / System V short name, `/` terminated | trailing `/` removed |
| `name` | BSD short name | used as is (spaces trimmed) |
| `//` | GNU long name table | kept in memory, not listed |
| `/N` | GNU long name: offset N in the `//` table | name read up to the next `\n`, then every `/` is removed |
| `/` | GNU symbol table | skipped |
| `/SYM64/` | GNU 64-bit symbol table | skipped |
| `#1/N` | BSD long name: the N first bytes of the data are the name | name cut at the first NUL; data size is size - N |

The deb layout inside the ar archive:

| Member | Content | Arcana |
|---|---|---|
| `debian-binary` | format version, `2.0\n` | skipped |
| `control.tar[.gz/.xz/.zst/.bz2/.lzma]` | `control`, `md5sums`, scripts | unpacked into `DEBIAN/` |
| `data.tar[.gz/.xz/.zst/.bz2/.lzma]` | installed files | unpacked at the destination root |

## Compression and encryption

ar has neither. For a deb, `ArExtractor.debTarStream` picks the decoder from
the suffix of the member name: `.tar` (none), `.gz`, `.xz`, `.zst`, `.bz2`,
`.lzma`, through `CompressedStreamExtractor.openDecompressed` (GZIP, XZ,
ZSTD, BZIP2, LZMA). Any other suffix gives "Unsupported Debian package member
compression: <name>". The decompressed stream is read with `TarInputStream`
(see [tar.md](tar.md)). The sample `arcana-test.deb` uses `control.tar.xz`
and `data.tar.xz`.

## Variants and versions

- GNU / System V: `/`-terminated names, `//` long name table, `/` and
  `/SYM64/` symbol tables. Verified with a hand-built archive holding a
  symbol table, a `//` table and two long names: both names list correctly
  and the symbol table is not shown. `files.a` uses the GNU short form
  (`readme.txt/`).
- BSD: `#1/N` long names are resolved (verified with a hand-built archive).
  The BSD symbol table `__.SYMDEF` / `__.SYMDEF SORTED` is not recognized as
  such: it is listed and extracted as an ordinary member.
- Debian packages: deb mode is chosen when the first member is named
  `debian-binary`. The `ArExtractor(boolean unpackDeb)` constructor can turn
  it off (the members are then extracted as plain ar members), but the CLI
  always uses `new ArExtractor()` (`FormatRegistry`), so `.deb` files are
  always unpacked there.

## Limits

- Member times, modes and owners are not read; the `l` command shows `-` as
  the time of plain ar members. Deb entries get the times of the TAR headers.
- A truncated archive is not always reported: the skipping helper
  (`skipFully`) stops silently at end of file, so `l` on a cut copy of
  `files.a` lists the first member and ends without error. `x` fails with
  "Unexpected end of stream: expected N more bytes" from
  `IOHelper.copyExactly`, leaving the partial file on disk.
- An invalid size field is read as 0 (`parseLong`), with no error.
- A `/N` name found before any `//` table fails with "GNU long names table
  missing".
- Header names and BSD long names are decoded as single-byte text (platform
  default charset for the header, "ASCII" for the `#1/N` and `//` names).
- In deb mode, symbolic and hard links of `data.tar` become empty files, as
  with TAR (see [tar.md](tar.md)).
- The extractor needs a file: `extract(InputStream, File)` throws
  `UnsupportedOperationException` ("AR extraction requires seekable file")
  and `supportsStream()` is false, although the reading itself is
  sequential.
- No creation, no thin archives.

## Implementation notes

- Listing and extraction run one sequential pass on a
  `BufferedInputStream`; nothing is held in memory except the `//` name
  table.
- Each deb tar member is read through a `StreamBoundedInputStream` limited
  to the member size, so the decompressor cannot read into the next member.
  On extraction the decompressed stream is drained to its end after the TAR
  end marker (so the xz/gzip/zstd trailer checks run), then the rest of the
  member is drained. During listing only the member is drained, so a
  compressor trailer error may only show on extraction.
- In deb mode the listed names come from the TAR headers with leading `./`
  removed; the `.` entry is skipped; control files get the `DEBIAN/` prefix.
  Directory names keep their trailing `/`, which the CLI prints doubled
  (`usr//`), as for TAR.
- Plain members are written through `SafePathBuilder.buildSafePath` and
  `ExtractionGuard.open`; deb members through `TarExtractor.extractFrom`,
  which applies the same checks.
- Regression results: `test/expected/ar/files.a.txt` (3 members) and
  `test/expected/ar/arcana-test.deb.txt` (16 entries, `DEBIAN/control` plus
  the tree under `usr/share/arcana-test/`).

## Sources

- ar(5), FreeBSD File Formats Manual (layout, SVR4/GNU and BSD name
  variants): https://man.freebsd.org/cgi/man.cgi?query=ar&sektion=5
- GNU Binary Utilities, ar:
  https://sourceware.org/binutils/docs/binutils/ar.html
- deb(5), Debian binary package format (dpkg-dev):
  https://manpages.debian.org/testing/dpkg-dev/deb.5.en.html

License: `ArExtractor` is Copyright 2025 Stephane Bury, Apache-2.0; the file
header carries no third-party notice. For the TAR classes used by the deb
mode, see [tar.md](tar.md).
