# RPM

| | |
|---|---|
| Extensions | `.rpm` |
| Signature | `ED AB EE DB` at offset 0 (lead magic) |
| Arcana support | list, extract (payload compressed with gzip, bzip2, xz, zstd, lzma, or stored) |
| Main classes | `be.stef.arcana.extractor.RpmExtractor`; payload read by `be.stef.arcana.formats.cpio.CpioInputStream` |
| Test samples | `test/samples/rpm/` (`payload-gz.rpm`, `payload-bz.rpm`, `payload-xz.rpm`, `payload-zst.rpm`) |

## Overview

RPM is the package format of Red Hat, Fedora, SUSE and related Linux
distributions. A package is a fixed-size lead, a signature header, the main
header holding the package metadata (name, version, dependencies, file list,
scripts), and a payload: a cpio archive, normally compressed. Arcana only
needs enough of the headers to find the payload and its compressor; the
files come from the cpio archive (see [cpio.md](cpio.md)).

## Detection

- `ArchiveDetector.detectByMagic` returns `RPM` when the file starts with
  `ED AB EE DB`; `.rpm` is the extension fallback (`detectByExtension`).
- `RpmExtractor.openCpio` checks the same four bytes again ("Not an RPM
  file") and the first three bytes of each header structure, `8E AD E8`
  ("Invalid RPM header magic").

## Structure

Lead (96 bytes, big-endian). Only the magic is checked; the other fields are
skipped:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | `ED AB EE DB` |
| 4 | 1 | major version | 3 in the samples; not checked |
| 5 | 1 | minor version | |
| 6 | 2 | type | 0 binary, 1 source |
| 8 | 2 | architecture number | |
| 10 | 66 | name | NUL-terminated `name-version-release` |
| 76 | 2 | OS number | |
| 78 | 2 | signature type | 5 = header-style signature |
| 80 | 16 | reserved | |

Header structure, used for both the signature header and the main header:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 3 | magic | `8E AD E8` |
| 3 | 1 | header version | 1; not checked |
| 4 | 4 | reserved | |
| 8 | 4 | index count (nindex) | number of 16-byte index entries |
| 12 | 4 | store size (hsize) | size of the data store in bytes |
| 16 | 16 x nindex | index entries | see below |
| 16 + 16 x nindex | hsize | data store | values referenced by the entries |

Index entry (16 bytes):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | tag | e.g. 1000 name, 1124 payload format, 1125 payload compressor |
| 4 | 4 | type | 6 = NUL-terminated string |
| 8 | 4 | offset | position of the value in the data store |
| 12 | 4 | count | number of values; not used |

File order:

1. Lead, 96 bytes.
2. Signature header, skipped as a whole by `skipRpmHeaderAligned`, then
   padded with zeros to a multiple of 8 bytes. The padding is computed from
   the header length (16 + 16 x nindex + hsize); since the lead is 96 bytes
   this is also the file alignment.
3. Main header, parsed by `readMainHeader`: all index entries are read, then
   the data store into a byte array. No padding follows it.
4. Payload, up to the end of the file.

In the four samples the signature header has 7 entries and a 4276-byte
store; the main header has 51 entries, with tag 1124 = `cpio` and tag 1125 =
`gzip`, `bzip2`, `xz` or `zstd`.

## Compression and encryption

The payload compressor is chosen in two steps (`wrapPayload`):

1. The first six payload bytes are peeked (mark/reset) and compared with
   known signatures (`payloadSignature`): `1F 8B` gzip, `BZh` bzip2,
   `FD 37 7A 58 5A 00` xz, `28 B5 2F FD` zstd, `0707` (an uncompressed cpio
   magic) none.
2. When no signature matches, the value of tag 1125 (`RPMTAG_PAYLOADCOMPRESSOR`,
   type string) from the main header is used, in lower case; without that
   tag, `gzip` is assumed.

Decoders: `java.util.zip.GZIPInputStream` (`gzip`, `gz`),
`formats.bzip2.BZip2InputStream` (`bzip2`, `bz2`), `formats.xz.XZInputStream`
(`xz`), `formats.zstd.ZstdInputStream` (`zstd`, `zst`),
`formats.xz.LZMAInputStream` (`lzma`). Any other value leaves the payload
undecoded and hands it to `CpioInputStream` as is.

The signature header (digests and signatures over the header and payload) is
not read, so no package signature or digest is verified. RPM has no payload
encryption.

## Variants and versions

- Fix: the compressor was read from tag 1124, which is the payload format
  (`cpio`), not the compressor. The extractor now reads tag 1125 and,
  before that, looks at the payload signature, so a package whose tag is
  missing or wrong is still decoded when its payload starts with a known
  magic.
- All four samples list the same 13 entries and extract the same 6 items
  with identical SHA-256 values (`test/expected/rpm/`).
- The payload is read with `CpioInputStream`, so newc (the form used by
  RPM), crc and odc payloads are accepted.
- An `lzma` payload (LZMA "alone" format) has no signature in
  `payloadSignature`; it is decoded only when tag 1125 says `lzma`.

## Limits

- Only the payload is extracted. Package metadata (name, version,
  dependencies, scripts, per-file modes and owners from the header) is not
  exposed; the `l` command shows no modification times (`-`), since
  `RpmExtractor` does not pass the cpio mtime.
- Every non-directory cpio entry is written as a regular file with its
  data: a symbolic link becomes a file containing the link target, devices
  and FIFOs become empty files. Hard links share the data with only one of
  their names (see [cpio.md](cpio.md)).
- A truncated payload fails in the decoder (with gzip: "Unexpected end of
  ZLIB input stream"); a file cut inside the headers fails with "EOF".
- The index count and store size are not bounded before arrays of that size
  are allocated, and the string offset of tag 1125 is not checked against
  the store size; a damaged main header can cause an `OutOfMemoryError` or
  an index exception instead of a clean "corrupted" error.
- The extractor needs a file (`supportsStream()` is false;
  `extract(InputStream, File)` throws `UnsupportedOperationException`), even
  though the reading is sequential.
- No creation, no source/binary distinction, no delta RPMs.

## Implementation notes

- The whole package is read in one sequential pass over a
  `BufferedInputStream`; only the main header data store is kept in memory.
- Names lose one leading `./` (already removed by `CpioInputStream`) or `/`
  (`stripDotSlash`), so absolute paths of the payload are extracted under
  the destination. The `TRAILER!!!` checks in `RpmExtractor` are a second
  guard: `CpioInputStream.getNextEntry` already returns `null` at the
  trailer.
- Output files go through `SafePathBuilder.buildSafePath` and
  `ExtractionGuard.open`, so path traversal and the common extraction
  limits are handled as for the other formats.
- The gzip decoder is the JDK one, not Arcana's `GzipExtractor` stream.

## Sources

- RPM V4 Package format (rpm.org):
  https://rpm-software-management.github.io/rpm/manual/format_v4.html
- RPM Package Header format (rpm.org):
  https://rpm-software-management.github.io/rpm/manual/format_header.html
- RPM Tags (rpm.org), for 1124 `PAYLOADFORMAT` and 1125
  `PAYLOADCOMPRESSOR`: https://rpm-software-management.github.io/rpm/manual/tags.html
- Linux Standard Base Core, Package File Format:
  https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/pkgformat.html

License: `RpmExtractor` is Copyright 2025 Stephane Bury, Apache-2.0; the file
header carries no third-party notice. For the cpio reader, see
[cpio.md](cpio.md).
