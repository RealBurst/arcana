# CPIO

| | |
|---|---|
| Extensions | `.cpio` (also inside `.cpio.gz`, `.cpio.xz`, `.cpio.zst`... and RPM payloads) |
| Signature | `30 37 30 37 30 31` ("070701", newc), `30 37 30 37 30 32` ("070702", crc), `30 37 30 37 30 37` ("070707", odc) at offset 0 |
| Arcana support | list, extract (newc, crc, odc); old binary format rejected |
| Main classes | `be.stef.arcana.formats.cpio.CpioInputStream`, `be.stef.arcana.formats.cpio.CpioEntry`, `be.stef.arcana.extractor.CpioExtractor` |
| Test samples | `test/samples/cpio/` (`newc.cpio`, `crc.cpio`, `odc.cpio`, `bin.cpio`) |

## Overview

cpio is the archive format of the Unix `cpio` utility, older than POSIX tar.
Each member is a header, the name and the data; the archive ends with a
member named `TRAILER!!!`. It is still used for Linux initramfs images and as
the payload of RPM packages (see [rpm.md](rpm.md)).

## Detection

- `ArchiveDetector.detectByMagic` returns `CPIO` for the three ASCII magics
  `070701`, `070702` and `070707`.
- The binary format has no magic in the detector: `bin.cpio` is reported as
  unknown data by `i` and reaches `CpioExtractor` only through the `.cpio`
  extension (`detectByExtension`).
- A compressed stream whose first decompressed bytes are one of the three
  magics is unpacked as CPIO by `CompressedStreamExtractor` (for example an
  initramfs `.cpio.gz`).

## Structure

newc and crc header (110 bytes, all fields 8 ASCII hexadecimal digits):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 6 | magic | `070701` or `070702` |
| 6 | 8 | inode | ignored |
| 14 | 8 | mode | file type bits and permissions |
| 22 | 8 | uid | ignored |
| 30 | 8 | gid | ignored |
| 38 | 8 | nlink | ignored |
| 46 | 8 | mtime | Unix seconds |
| 54 | 8 | file size | |
| 62 | 32 | dev major/minor, rdev major/minor | ignored |
| 94 | 8 | name size | includes the terminating NUL |
| 102 | 8 | check | CRC sum for `070702`, read into `CpioEntry.getChecksum()`, not verified |

The name follows the header; header + name is padded to a multiple of 4
bytes, and so is the data.

odc header (76 bytes, octal ASCII, no padding at all):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 6 | magic | `070707` |
| 6 | 6 | dev | ignored |
| 12 | 6 | inode | ignored |
| 18 | 6 | mode | |
| 24 | 6 | uid | ignored |
| 30 | 6 | gid | ignored |
| 36 | 6 | nlink | ignored |
| 42 | 6 | rdev | ignored |
| 48 | 11 | mtime | |
| 59 | 6 | name size | |
| 65 | 11 | file size | |

The type is taken from the mode (`CpioEntry`): `0040000` directory,
`0100000` regular file, `0120000` symbolic link (the data is the link
target).

## Compression and encryption

None in the format. Compressed cpio files are handled by the stream
extractors through `CompressedStreamExtractor`, RPM payloads by
`RpmExtractor`.

## Variants and versions

- newc (`070701`) and crc (`070702`) share `readNewcHeader`; the crc variant
  only differs by the checksum field, which is ignored.
- odc (`070707`) is read by `readOdcHeader`.
- Old binary cpio (magic `070707` octal stored as a 16-bit word, bytes
  `C7 71` or `71 C7`): `CpioInputStream.getNextEntry` recognizes both byte
  orders and throws "Binary CPIO format is not supported (only newc/odc
  ASCII formats are)". Confirmed with `bin.cpio`
  (`test/expected/cpio/bin.cpio.txt`).
- Any other magic gives "Not a CPIO archive (unknown magic: ...)".

## Limits

- Symbolic links are extracted as regular files whose content is the link
  target; devices, FIFOs and sockets are skipped (`CpioExtractor.extractFrom`).
- Hard links are not resolved: in newc the data is usually stored with only
  one of the names, so the other names extract as empty files.
- The `070702` checksum is not verified; times, modes and owners are not
  restored.
- Header numbers are not validated: non-hexadecimal or non-octal characters
  are converted without error, and the name size is used as is to allocate
  the name buffer (no upper bound).
- Names are decoded as UTF-8; a leading `./` is removed and trailing NULs
  are stripped (`trimName`). An empty name (from `.` after stripping) is
  skipped on extraction.
- `CpioExtractor.supportsStream()` is true; listing and extraction are
  sequential, the archive is read once.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- `getNextEntry` stops at the `TRAILER!!!` entry and returns `null`; any
  bytes after it (block padding) are not read.
- Before reading a header, `getNextEntry` skips the unread data and padding
  of the previous entry only for newc/crc entries; for odc this relies on the
  caller calling `closeEntry()`, which `CpioExtractor` and `RpmExtractor`
  always do.
- `CpioExtractor.extract(File, File)` turns any `IOException` whose message
  contains "CPIO" into `ArcanaCorruptedException` ("Corrupted CPIO
  archive"), including the binary-format message: `x` on `bin.cpio` reports
  a corrupted archive while `l` reports the unsupported variant.
- The three ASCII samples list and extract the same tree with identical
  checksums (`test/expected/cpio/`).

## Sources

- cpio(5), format of cpio archive files (FreeBSD / libarchive manual page):
  https://man.freebsd.org/cgi/man.cgi?query=cpio&sektion=5
- GNU cpio manual: https://www.gnu.org/software/cpio/manual/cpio.html

License: `CpioInputStream`, `CpioEntry` and `CpioExtractor` are Copyright
2025 Stephane Bury, Apache-2.0; independent implementation, no ported code.
