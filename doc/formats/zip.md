# ZIP

| | |
|---|---|
| Extensions | `.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.ipa`, `.xpi`, `.crx`, `.vsix`, `.nupkg`, `.kmz`, `.aar`, `.whl`, `.egg`, `.cbz`, `.xps`, `.oxps`, `.fcstd`, `.3mf`, Office Open XML (`.docx` `.xlsx` `.pptx` and their macro/template variants), OpenDocument (`.odt` `.ods` `.odp` `.odg` `.odf` `.odb` `.odc` `.odm`), `.epub` |
| Signature | `50 4B 03 04` ("PK\3\4") at offset 0; the end of central directory record `50 4B 05 06` near the end of the file is what the reader really needs |
| Arcana support | list, extract (ZipCrypto and WinZip AES), create (Deflate, optional WinZip AES-256 or ZipCrypto) |
| Main classes | `be.stef.arcana.formats.zip.ZipArchiveReader`, `be.stef.arcana.extractor.ZipExtractor`, `be.stef.arcana.formats.zip.ZipCryptoInputStream`, `be.stef.arcana.formats.zip.AesZipInputStream`, `be.stef.arcana.formats.zip.WinZipAesCtr`, `be.stef.arcana.formats.deflate64.Deflate64InputStream`, `be.stef.arcana.compressor.ZipCompressor`, `be.stef.arcana.formats.zip.AesZipOutputStream`, `be.stef.arcana.formats.zip.ZipCryptoOutputStream` |
| Test samples | `test/samples/zip/` (`store.zip`, `deflate.zip`, `deflate64.zip`, `bzip2.zip`, `lzma.zip`, `zipcrypto.zip`, `aes256.zip`, `aes256-tampered.zip`, `aes256-utf8-password.zip`, `names-utf8.zip`) |

## Overview

ZIP was defined by Phil Katz (PKWARE) in 1989 and is documented in PKWARE's
APPNOTE.TXT, which has been extended many times since (ZIP64, new
compression methods, strong encryption). Each file is stored as a local
header followed by its data; a central directory at the end of the file
repeats the metadata of every entry and gives the offset of each local
header. ZIP is the container of Java archives, Android packages, Office Open
XML and OpenDocument files, EPUB books and many other formats, which is why
the extension list above is long.

## Detection

- `ArchiveDetector.detectByMagic` returns `ZIP` when the file starts with
  `PK 03 04`. Nothing else is checked at that point.
- When the magic does not match (empty archive starting with `PK 05 06`,
  damaged first header, data prepended), `detectByExtension` maps all the
  extensions listed above to `ZIP`.
- A file that starts with `MZ` or ELF is detected as `SFX`; a file with an
  unknown prefix goes through `SfxExtractor.locate` (`Arcana.resolveFormat`).
  When the payload found is a ZIP, `SfxExtractor` hands the whole file to
  `ZipExtractor`, which skips the stub itself (see Variants). See
  [sfx-executables.md](sfx-executables.md).
- `ArchiveAnalyzer` (command `i`) recognizes `PK` followed by 3, 5 or 7,
  reports "minimum version to extract" from the first local header and
  refines the type by looking for member names in the first 64 KB: APK
  (`AndroidManifest.xml` + `classes.dex`), EPUB (`mimetypeapplication/epub+zip`
  at offset 30), DOCX / XLSX / PPTX / OOXML (`[Content_Types].xml`), JAR
  (`META-INF/MANIFEST.MF` with a `.jar`, `.war` or `.ear` name).

## Structure

All numbers are little-endian. The reader only uses the central directory to
find the entries; the local header is read only to find where the data
starts.

End of central directory (EOCD), searched backwards from the end of the
file over the last 22 + 65535 bytes (`ZipArchiveReader.readCentralDirectory`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | `50 4B 05 06` |
| 4 | 2 | number of this disk | ignored |
| 6 | 2 | disk where the central directory starts | ignored |
| 8 | 2 | entries on this disk | ignored |
| 10 | 2 | total entries | 0xFFFF means "see ZIP64" |
| 12 | 4 | central directory size | |
| 16 | 4 | central directory offset | relative to the start of the ZIP data |
| 20 | 2 | comment length | a candidate is accepted only if the comment fits in the file |

When a ZIP64 end of central directory locator (`50 4B 06 07`, 20 bytes) sits
just before the EOCD, its 8-byte field at offset 8 gives the position of the
ZIP64 end of central directory record (`50 4B 06 06`), from which the reader
takes the entry count (offset 32), the central directory size (offset 40)
and offset (offset 48), all 8 bytes.

Central directory record (46 bytes + variable parts):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | signature | `50 4B 01 02`; the loop stops at the first record without it |
| 4 | 2 | version made by | ignored |
| 6 | 2 | version needed | ignored |
| 8 | 2 | general purpose flags | bit 0 encrypted, bit 1 (LZMA) end marker present, bit 3 data descriptor, bit 6 strong encryption, bit 11 UTF-8 names |
| 10 | 2 | compression method | see next section |
| 12 | 2 | DOS time | |
| 14 | 2 | DOS date | |
| 16 | 4 | CRC-32 | |
| 20 | 4 | compressed size | 0xFFFFFFFF: in the ZIP64 extra field |
| 24 | 4 | uncompressed size | 0xFFFFFFFF: in the ZIP64 extra field |
| 28 | 2 | name length | |
| 30 | 2 | extra field length | |
| 32 | 2 | comment length | skipped |
| 34 | 2 | disk number start | ignored |
| 36 | 2 | internal attributes | ignored |
| 38 | 4 | external attributes | ignored (no permissions restored) |
| 42 | 4 | local header offset | 0xFFFFFFFF: in the ZIP64 extra field |
| 46 | n | name, extra field, comment | |

Extra fields read by `ZipArchiveReader.parseExtra`:

| Id | Name | Use in Arcana |
|---|---|---|
| `0x0001` | ZIP64 | 8-byte uncompressed size, compressed size, local header offset, in that order, each present only when the 32-bit field is 0xFFFFFFFF |
| `0x5455` | extended timestamp | if flag bit 0 is set, the 4-byte Unix modification time replaces the DOS date |
| `0x7075` | Info-ZIP Unicode path | version 1 only; the UTF-8 name replaces the header name when the stored CRC-32 matches the CRC-32 of the header name |
| `0x9901` | WinZip AES | vendor version (AE-1 / AE-2), key strength (1, 2, 3 = 128, 192, 256 bits), real compression method |

Local file header (30 bytes + name + extra): `50 4B 03 04`, then the same
fields as the central record from "version needed" to "extra field length".
`ZipArchiveReader.openRaw` only checks the signature and uses the two length
fields at offsets 26 and 28 to find the data. Sizes, CRC and the optional
data descriptor after the data are taken from the central directory, never
from the local header.

## Compression and encryption

Methods decoded by `ZipExtractor.decompress`:

| Method | Name | Decoder |
|---|---|---|
| 0 | Stored | none |
| 8 | Deflate | `java.util.zip.Inflater` in raw mode (`RawInflaterInputStream`) |
| 9 | Deflate64 | `Deflate64InputStream` (pure Java, 64 KiB window, length code 285 = 3 + 16 extra bits, distance codes 30 and 31) |
| 12 | BZIP2 | `BZip2InputStream` |
| 14 | LZMA | `LZMAInputStream`, after a 4-byte header (LZMA SDK version, properties size which must be 5) and the 5 properties bytes; with flag bit 1 the size is unknown and the end marker ends the stream |
| 93 | Zstandard | `ZstdInputStream` |
| 95 | XZ | `XZInputStream` |
| 98 | PPMd variant I rev. 2 | `Ppmd8`, after a 2-byte header: order = bits 0-3 + 1, memory = bits 4-11 + 1 MB, restore method = bits 12-15 (0 or 1 accepted); decoding stops after the declared size |

Encryption (flag bit 0), decoded in `ZipExtractor.openEntry`:

- ZipCrypto (PKWARE traditional encryption), `ZipCryptoInputStream`: three
  32-bit keys initialised with the APPNOTE constants and updated with each
  password byte, then a 12-byte encryption header. The last decrypted header
  byte is compared with the high byte of the CRC-32, or with the high byte of
  the DOS time when the entry has a data descriptor (flag bit 3); a mismatch
  gives "Wrong password for ZIP entry ...". Any compression method can be
  under it.
- WinZip AES (method 99 + extra field `0x9901`), `AesZipInputStream`: salt
  of 8, 12 or 16 bytes (half the key length), then a 2-byte password
  verifier, then the encrypted data, then a 10-byte authentication code.
  PBKDF2-HMAC-SHA1 with 1000 iterations derives 2 x key length + 2 bytes:
  the AES key, the HMAC key and the verifier. Decryption is AES in CTR mode
  with a 16-byte little-endian counter starting at 1; `WinZipAesCtr` builds
  it from `AES/ECB/NoPadding` because the JCE CTR mode increments in
  big-endian order. The real method comes from the extra field.
- Bit 6 (PKWARE strong encryption) gives
  `ArcanaUnsupportedFormatException` "PKWARE strong encryption is not
  supported".
- Without a password, an encrypted entry gives `ArcanaEncryptedException`
  "Encrypted ZIP entry '...' - supply a password". Listing never needs the
  password (names are not encrypted in the formats supported).

Creation, `ZipCompressor` (`arcana c <source> out.zip [-p password]`):

- Without password: `java.util.zip.ZipOutputStream` with
  `Deflater.DEFAULT_COMPRESSION`; every entry (directories too) is Deflate
  with flags `0x808` (data descriptor + UTF-8), and the JDK writes ZIP64
  records when needed. The `-l` option is not used. When the source is a
  directory, its content is stored relative to it.
- With `-p`: WinZip AES-256, AE-2, Deflate, written by a raw writer in
  `ZipCompressor.compressEncrypted` (`AesZipOutputStream` writes a
  `SecureRandom` salt, the verifier, the CTR data and the HMAC-SHA1 code
  truncated to 10 bytes). The CRC field is 0, as AE-2 requires. Directories
  are stored, empty and not encrypted. Each file is streamed (file, CRC-32,
  raw Deflate, encryption, archive): the local header has flags `0x809`
  (encrypted + data descriptor + UTF-8) and zero sizes, and a data
  descriptor follows the data. ZIP64 is written when needed: a ZIP64 extra
  field in the local header (and 8-byte sizes in the data descriptor) for a
  file of about 4 GiB or more, ZIP64 values in the central directory for
  sizes and offsets of 4 GiB or more, and a ZIP64 end of central directory
  record and locator for 65535 entries or more or a central directory beyond
  4 GiB. Verified with 7-Zip 25.01 (`7zz t`), including a 70000-entry
  archive, a 4.4 GB file and a 4.3 GB archive.
- ZipCrypto creation (`ZipCompressor.ENCRYPT_ZIPCRYPTO`) is available from
  the API only. `ZipCryptoOutputStream` fills the 12-byte header with
  `SecureRandom`; as the entry has a data descriptor, the last header byte
  is the high byte of the DOS time (APPNOTE 6.1.6). Verified with 7-Zip and
  Info-ZIP `unzip -t`.

## Variants and versions

- ZIP64: sizes, offsets and entry count from the ZIP64 extra field and the
  ZIP64 end of central directory. Verified with a 70000-entry archive made by
  Python `zipfile`.
- Prepended data (self-extracting stubs, script + ZIP): the reader computes
  `shift = end of central directory - central directory size - central
  directory offset` and adds it to every offset. If the ZIP64 locator points
  to a wrong place because of the prefix, the ZIP64 record is looked for just
  before the locator. Verified with 5000 random bytes in front of
  `deflate.zip`, and with `-f zip` in front of the 70000-entry ZIP64 archive.
- Names: flag bit 11 means UTF-8. Without it, a pure ASCII name is ASCII, a
  name that is valid UTF-8 is decoded as UTF-8, and anything else as IBM437
  (ISO-8859-1 if the JRE has no IBM437). `names-utf8.zip` holds UTF-8 names
  without the flag ("cafe a la creme" with accents) and a 120-character name;
  both list and extract correctly. The Info-ZIP Unicode path field (`0x7075`)
  overrides the name when its CRC matches.
- Data descriptors (flag bit 3) are supported because sizes and CRC come
  from the central directory; `zipcrypto.zip` has flags `0x9` (encrypted +
  data descriptor).
- AE-1 and AE-2: the CRC-32 is checked for AE-1 and not for AE-2.
- Samples: `store.zip` (method 0), `deflate.zip` (8, with flag bit 1 set by
  the writer), `deflate64.zip` (9), `bzip2.zip` (12), `lzma.zip` (14 with end
  marker), `zipcrypto.zip` (ZipCrypto + Deflate), `aes256.zip` (AE-2,
  AES-256), `aes256-tampered.zip` (`aes256.zip` with one encrypted byte of
  `bin/random.bin` flipped: "Authentication code mismatch"),
  `aes256-utf8-password.zip` (AE-2 written by a Python script with the
  password "cafe" with an acute e, UTF-8 `63 61 66 C3 A9`, accepted by
  `7zz t`; 7-Zip refuses non-ASCII passwords when it creates a ZIP). The
  incompressible `bin/random.bin` is stored (method 0) in most of them.
  PPMd (98) and Deflate64 archives written by 7-Zip 16.02 were also
  extracted correctly while writing this page.

## Limits

- Split and spanned archives (`.z01`, `.z02`, ..., `.zip`): disk numbers are
  ignored. Listing the last part works, extraction fails with "Invalid local
  header for ZIP entry ..."; opening `.z01` gives "Not a ZIP archive (end of
  central directory not found)".
- Methods other than those of the table (Shrink 1, Reduce 2-5, Implode 6,
  Tokenize 7, IBM TERSE, LZ77 z/OS, WavPack 97, ...) give
  `ArcanaUnsupportedFormatException` "ZIP compression method N not supported
  (entry '...')".
- PKWARE strong encryption and central directory encryption are not
  supported.
- File times, permissions, symbolic links (Unix mode in the external
  attributes) and comments are not restored; links become regular files
  holding the link target.
- Encrypted creation decides from the file length, before compressing it,
  whether the entry gets a ZIP64 local header: a file that grows to 4 GiB or
  more while it is being read stops the creation with an `IOException`.
- Common extraction limits apply through `ExtractionGuard` (see
  `ExtractionLimits`).

## Implementation notes

- `ZipArchiveReader` replaces `java.util.zip.ZipFile`, which refuses
  encrypted entries on recent JDKs and only decodes methods 0 and 8. It reads
  the central directory in one `byte[]` (at most `Integer.MAX_VALUE` bytes,
  otherwise "ZIP central directory too large").
- Entry data is read with positional `FileChannel.read` calls through a
  64 KiB buffered slice, so several entries can be decoded at once.
  `ZipExtractor.extract` first creates the directories, then decodes the
  files in parallel (one entry per worker, 64 MiB of memory budget per
  worker, `ArcanaConcurrency.workersFor`); the first error in archive order
  stops the extraction. When the same name is stored twice, only the last
  copy is written, as in sequential mode.
- `EntryCheckInputStream` checks every entry against its central record: the
  output may not exceed the declared size while it is produced (protection
  against a lying header), the final size must match (modulo 2^32) and the
  CRC-32 must match ("CRC mismatch for ZIP entry ..."), except for AE-2.
- `RawInflaterInputStream` feeds one extra zero byte at the end of input, as
  `Inflater` in raw mode may need it; a second end of input is an
  `EOFException`.
- `Deflate64InputStream` rejects distances larger than the data produced so
  far or than 64 KiB, over-subscribed Huffman codes and block type 3 with
  `ArcanaCorruptedException`.
- Paths go through `SafePathBuilder.buildSafePath`: `\` becomes `/`, a
  leading `/` is dropped and `..` is renamed `._` (verified: `../evil.txt`
  extracts as `._/evil.txt`).
- Stream input (`extract(InputStream, File)`) is first copied to a
  temporary file, because the central directory is at the end.
- WinZip AES password handling: PBKDF2-HMAC-SHA1 is computed by
  `AesZipInputStream.pbkdf2HmacSha1` with `javax.crypto.Mac` over the raw
  password bytes (UTF-8 from the CLI, as WinZip and 7-Zip use), not with the
  JDK `PBKDF2WithHmacSHA1`, which takes a `char[]` and would encode a UTF-8
  password a second time. Checked both ways with 7-Zip 25.01 and the password
  "cafe" with an acute e (`aes256-utf8-password.zip`, and an Arcana archive
  tested with `7zz t`). Versions before this fix encoded such passwords
  twice: their AES archives with non-ASCII passwords no longer open with the
  same password.
- WinZip AES authentication code: `AesZipInputStream` updates an HMAC-SHA1
  (key = the second part of the PBKDF2 output) with the encrypted bytes as it
  reads them. At the end of the entry, `EntryCheckInputStream` calls
  `isAuthentic()`, which reads the encrypted bytes left by the decoder, then
  the 10-byte code, and compares; a mismatch gives `ArcanaCorruptedException`
  "Authentication code mismatch for ZIP entry '...'". Modified data that also
  breaks the compressed stream is reported by the decoder first (for example
  "invalid code lengths set" for Deflate).
- Damaged archives can be scanned header by header with the recovery mode
  (`ZipRecovery`, see [recovery.md](recovery.md)).

## Sources

- PKWARE, APPNOTE.TXT - .ZIP File Format Specification, version 6.3.10:
  https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.10.TXT
- WinZip, AES Encryption Information (AE-1 / AE-2, extra field 0x9901):
  https://www.winzip.com/en/support/aes-encryption/
- RFC 1951, DEFLATE compressed data format specification version 1.3:
  https://www.rfc-editor.org/rfc/rfc1951
- RFC 8018, PKCS #5 v2.1 (PBKDF2): https://www.rfc-editor.org/rfc/rfc8018

License: `ZipArchiveReader`, `ZipExtractor`, `ZipCompressor`,
`ZipCryptoInputStream`, `ZipCryptoOutputStream`, `AesZipInputStream`,
`AesZipOutputStream`, `WinZipAesCtr`, `Deflate64InputStream` and
`ZstdInputStream` are Copyright 2025 Stephane Bury, Apache-2.0: an
independent Java implementation written from the documents above. `Ppmd8`
(Copyright 2026 Stephane Bury, Apache-2.0) states that it is a Java port of
Ppmd8.c / Ppmd8Dec.c by Igor Pavlov (public domain). `BZip2InputStream`
carries the ASF Apache-2.0 header and is "Ported from
org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
(Apache Commons Compress 1.28.0)". `LZMAInputStream` and `XZInputStream`
are "Ported from org.tukaani.xz (XZ for Java)", license 0BSD. Deflate
(method 8) and the AES / HMAC / PBKDF2 primitives come from the JDK.
