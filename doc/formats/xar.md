# XAR

| | |
|---|---|
| Extensions | `.xar` (macOS flat `.pkg` and `.xip` files are XAR too, recognized by signature only) |
| Signature | `78 61 72 21` ("xar!") at offset 0 |
| Arcana support | list, extract (encodings none, gzip/zlib, bzip2, xz, lzma) |
| Main classes | `be.stef.arcana.extractor.XarExtractor` (header and TOC in the nested class `Xar`, heap reads through `RangeInputStream`) |
| Test samples | `test/samples/xar/` (`none.xar`, `gzip.xar`, `bzip2.xar`) |

## Overview

XAR (eXtensible ARchiver) is an open-source archive format adopted by
Apple: macOS flat installer packages (`.pkg`), Safari
extensions and `.xip` archives are XAR files. The archive is a small binary
header, a table of contents (TOC) in XML compressed with zlib, and a heap
holding the file data. All metadata (names, tree, times, owners, extended
attributes, data location, encoding, checksums) lives in the TOC.

## Detection

- `ArchiveDetector.detectByMagic` returns `XAR` when the file starts with
  `xar!`. The only extension fallback is `.xar` (`detectByExtension`); a
  `.pkg` or `.xip` file is detected by its signature, independently of its
  name.
- `Xar.open` checks the magic again ("Not a XAR archive").

## Structure

Header (big-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `xar!` |
| 4 | 2 | header size | 28, or more when a checksum algorithm name follows; must be 28..4096 |
| 6 | 2 | version | 1 in the samples; not checked |
| 8 | 8 | TOC compressed length | must be 1..256 MiB and not larger than the file |
| 16 | 8 | TOC uncompressed length | not used |
| 24 | 4 | checksum algorithm | 1 (SHA-1) in the samples; not used |

Bytes between offset 28 and the header size are skipped. Then:

| Position | Content |
|---|---|
| header size | TOC, zlib stream (with zlib header) of the given compressed length |
| header size + TOC compressed length | heap: all `offset` values in the TOC are relative to this point |

TOC elements used by `XarExtractor` (other elements are ignored):

| Element | Use |
|---|---|
| `xar/toc` | root of the file tree |
| `file` (nested) | one entry; children `file` elements are the content of a directory |
| `file/name` | entry name; the path is built from the nesting |
| `file/type` | `directory`, `file`, `hardlink` (with a `link` attribute), others |
| `file@id` | id used to resolve hard links |
| `file/size` | listed size, when present directly under `file` |
| `data/offset`, `data/length` | location of the stored bytes in the heap |
| `data/size` | decoded size, checked after extraction |
| `data/encoding@style` | MIME type of the encoding (element text if the attribute is empty) |
| `data/extracted-checksum@style` | digest of the decoded data, verified |

The heap of the samples starts with the 20-byte SHA-1 of the compressed TOC
(the `toc/checksum` element points to offset 0, size 20), followed by the
file data.

## Compression and encryption

The TOC is always inflated with `java.util.zip.InflaterInputStream` and an
`Inflater` in zlib mode. File data is decoded by `XarExtractor.decode`
according to the encoding style:

| Style | Decoder |
|---|---|
| none, empty, `application/octet-stream` | stored |
| `application/x-gzip`, `application/zlib` | `InflaterInputStream` (zlib stream, despite the name) |
| `application/x-bzip2` | `formats.bzip2.BZip2InputStream` |
| `application/x-xz` | `formats.xz.XZInputStream` |
| `application/x-lzma` | `XZInputStream` when the data starts with the xz magic, else `formats.xz.LZMAInputStream` |

Any other style fails with "XAR encoding '<style>' is not supported
(<name>)". The three samples use `application/octet-stream`,
`application/x-gzip` and `application/x-bzip2` and extract to the same
files (`test/expected/xar/`).

The `extracted-checksum` is verified when its style is `sha1`, `md5`,
`sha256` or `sha512` (`MessageDigest`); a mismatch fails with "XAR checksum
mismatch: <name>". Verified by flipping one byte of `none.xar`. A decoded
size different from `data/size` fails with "XAR size mismatch: <name>".
XAR signatures (the `signature` elements of signed packages) are not
checked; XAR has no encryption.

## Variants and versions

- Header sizes above 28 (algorithm name stored after the fixed header) are
  accepted by skipping the extra bytes.
- Hard links: an entry whose `type` is `hardlink` and that has no `data`
  takes the `data` of the file whose `id` equals its `link` attribute
  (`collectData`), so each name gets the full content.
- The `application/x-lzma` style is read as xz or as LZMA "alone",
  depending on the first six bytes.

## Limits

- Listing does not show sizes for the samples: `collectEntries` looks for
  `size` directly under `file`, while the TOCs of the samples hold it under
  `data`. The `l` command prints `?` and the regression files record `-1`
  (`test/expected/xar/*.txt`). Times are not listed either (`-`).
- Symbolic links, devices and FIFOs have no `data` and are written as empty
  files; times, modes, owners and extended attributes (`ea` elements) are
  not restored.
- The TOC checksum (header field at offset 24 and `toc/checksum` in the
  heap) and the `archived-checksum` of each file are not verified; an
  unknown `extracted-checksum` style is silently not checked.
- The TOC is inflated into memory with no limit on the decompressed size;
  only the compressed size is bounded (256 MiB).
- Nested payloads are written as stored: for example the `Payload` member of
  a flat `.pkg` is not unpacked further.
- The extractor needs a file: `extract(InputStream, File)` throws
  `ArcanaUnsupportedFormatException` ("XAR requires random file access").
- No creation.

## Implementation notes

- `Xar.open` reads the header and TOC with a stream, parses the XML with a
  DOM `DocumentBuilder` that has
  `http://apache.org/xml/features/disallow-doctype-decl` set, so DOCTYPE
  declarations (and with them external entities) are rejected. Parse
  errors become "Failed to parse XAR TOC: ...".
- Extraction keeps one `RandomAccessFile`; `RangeInputStream` seeks to
  heap start + `offset` for every read and stops after `length` bytes. The
  range is checked against the file length first ("XAR data outside the
  archive"), as are missing or non-numeric `offset` / `length` values.
- Entries are visited in TOC order, which is not alphabetical (`bin`,
  `docs`, `deep`... in the samples).
- Paths go through `SafePathBuilder.buildSafePath` and files are opened with
  `ExtractionGuard.open`.

## Sources

- xar file format description (xar project wiki, mackyle/xar on GitHub):
  https://github.com/mackyle/xar/wiki/xarformat
- xar(1) manual page: https://linux.die.net/man/1/xar

License: `XarExtractor` is Copyright 2025 Stephane Bury, Apache-2.0; the file
header carries no third-party notice.
