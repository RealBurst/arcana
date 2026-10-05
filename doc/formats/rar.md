# RAR (versions 4 and 5)

| | |
|---|---|
| Extensions | `.rar`, `.cbr`; volumes `.partN.rar` |
| Signature | RAR 5: `52 61 72 21 1A 07 01 00` ("Rar!" 1A 07 01 00); RAR 4 (1.5 to 4.x): `52 61 72 21 1A 07 00`, at offset 0 |
| Arcana support | list, extract (solid, volumes, AES encryption, encrypted headers); no creation |
| Main classes | `be.stef.arcana.extractor.RarExtractor`, `be.stef.arcana.formats.rar.Unrar5j`; RAR 5: `rar5.Rar5Reader`, `rar5.Rar5Extractor`, `rar5.Rar5HeaderDecryptor`, `rar5.crypto.Rar5Crypto`, `rar5.decompress.Rar5LZDecoder`, `util.Blake2sp`; RAR 4: `rar4.Rar4HeaderParser`, `rar4.Rar4Extractor`, `rar4.crypto.Rar4Crypto`, `rar4.decompress.Lz77Decompressor` (all under `be.stef.arcana.formats.rar`) |
| Test samples | `test/samples/rar/` (`rar5.rar`, `rar5-solid.rar`, `rar5-encrypted.rar`, `rar5-encrypted-headers.rar`, `rar4.rar`, `rar4-solid.rar`, `rar4-encrypted.rar`, `rar4-encrypted-headers.rar`, `names-utf8.rar`, `volumes/rar5-volumes.part1.rar` to `part5.rar`), `test/samples/damaged/flipped.rar`, `test/samples/damaged/truncated-rar4.rar`, `test/samples/damaged/wrong-password-rar5.rar` and `wrong-password-rar4.rar` (encrypted headers, wrong password) |

## Overview

RAR is the format of WinRAR and the `rar` command line tool, written by
Eugene Roshal in 1993 and maintained by RARLAB. The archive format changed
completely with RAR 5.0 (2013): RAR 4 uses fixed-size block headers with
16-bit header CRCs, RAR 5 uses variable-length integers, 32-bit header CRCs,
AES-256 and BLAKE2sp. WinRAR still writes RAR 4 archives on request
(`rar -ma4`). The compression algorithms are proprietary but decoding them is
documented by existing free decoders; RARLAB publishes the container layout
of RAR 5 (technote) and published a technical note for RAR 4.

Arcana only reads RAR. Everything goes through `Unrar5j`, an embedded
engine (its own command line prints "unrar5j v2.0.4"), which picks the
RAR 4 or RAR 5 code from the signature.

## Detection

- `ArchiveDetector.detectByMagic` returns `RAR` for both signatures (RAR 5
  checked first); the extension fallback maps `.rar` and `.cbr` to `RAR`.
- `Unrar5j.detectFormat` reads the first 8 bytes again and chooses
  `Rar5Extractor` or `Rar4Extractor`. Both readers need the signature at
  offset 0. A RAR SFX (WinRAR self-extractor) is handled by `SfxExtractor`,
  see [sfx-executables.md](sfx-executables.md).
- `ArchiveAnalyzer` (command `i`) reports "RAR archive, version 5.0" or
  "RAR archive, version 1.5-4.x" from byte 6.
- RAR 1.4 archives (`RE~^` signature) are not recognized.

## Structure: RAR 5

Numbers are little-endian; "vint" is the RAR 5 variable-length integer (7
bits per byte, high bit = more bytes, `util.VIntReader`). Every block has the
same frame (`Rar5Block`, read by `Rar5Reader.readBlock`):

| Field | Size | Notes |
|---|---|---|
| header CRC32 | 4 | CRC-32 of the header size field and the header; checked ("Header CRC error at offset N") |
| header size | vint | size of the rest of the header |
| type | vint | 1 main, 2 file, 3 service, 4 archive encryption, 5 end of archive |
| flags | vint | 0x01 extra area present, 0x02 data area present, 0x08 continues from previous volume, 0x10 continues in next volume |
| extra area size | vint | if flag 0x01 |
| data size | vint | if flag 0x02 |
| type-specific fields, extra area | | |
| data | data size | packed (and possibly encrypted) file data |

Main archive header flags: 0x01 volume, 0x02 volume number present, 0x04
solid, 0x08 recovery record, 0x10 locked.

File header (`Rar5FileBlock`), after the common fields:

| Field | Size | Notes |
|---|---|---|
| file flags | vint | 0x01 directory, 0x02 Unix mtime present, 0x04 CRC32 present, 0x08 size unknown |
| unpacked size | vint | |
| attributes | vint | not restored |
| mtime | 4 | Unix seconds, if flag 0x02; used by the listing |
| CRC32 | 4 | if flag 0x04 |
| compression info | vint | bits 0-5 algorithm version (0, or 1 for the RAR 7 variant), bit 6 solid, bits 7-9 method 0-5, bits 10-13 (version 0) or 10-14 (version 1) dictionary size exponent, bits 15-19 dictionary fraction (version 1) |
| host OS | vint | |
| name length, name | vint, n | UTF-8 |

Extra records read: 1 encryption, 2 hash (BLAKE2sp), 3 high precision
times, 4 version, 5 link, 6 Unix owner, 7 service data. Only 1 and 2 are
used for extraction. Service blocks (comments, quick open, NTFS streams...)
are parsed and ignored.

## Structure: RAR 4

Each block starts with a 7-byte header (`Rar4Block`, `Rar4HeaderParser`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | HEAD_CRC | low 16 bits of the CRC-32 of the header from offset 2; checked for main (0x73), file (0x74) and new sub-block (0x7A) headers |
| 2 | 1 | HEAD_TYPE | 0x72 marker, 0x73 archive, 0x74 file, 0x7A service, 0x7B end; other types skipped |
| 3 | 2 | HEAD_FLAGS | 0x8000: ADD_SIZE present |
| 5 | 2 | HEAD_SIZE | 7 to 65535 |
| 7 | 4 | ADD_SIZE | size of the data after the header |

Archive header flags: 0x0001 volume, 0x0008 solid, 0x0010 new volume
naming, 0x0080 encrypted headers, 0x0100 first volume.

File header (`Rar4FileBlock`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 7 | 4 | packed size | low 32 bits (ADD_SIZE) |
| 11 | 4 | unpacked size | low 32 bits |
| 15 | 1 | host OS | |
| 16 | 4 | file CRC32 | |
| 20 | 4 | file time | MS-DOS format; not used (listing shows no date) |
| 24 | 1 | version needed | 29 for RAR 2.9 / 3.x / 4.x |
| 25 | 1 | method | 0x30 store to 0x35 best |
| 26 | 2 | name size | |
| 28 | 4 | attributes | |
| 32 | 4 + 4 | high packed / unpacked size | if flag 0x0100 (LHD_LARGE); also used to find the next header |
| ... | n | name | flag 0x0200: ASCII part, zero byte, then the RAR Unicode encoding (decoded by `decodeUnicodeName`); else ISO-8859-1 |
| ... | 8 | salt | if flag 0x0400 (encrypted file) |

File flags: 0x0001 / 0x0002 continued from / to another volume, 0x0004
encrypted, 0x0010 solid, bits 5-7 dictionary size (64 KiB to 4 MiB; value 7
means directory). RAR 4 names use `\` as separator: the listing shows them
as stored (`bin\random.bin`), extraction converts them.

## Compression and encryption

RAR 5 decoding (`Rar5LZDecoder`):

- methods 1 to 5 share one LZ + Huffman decoder; method 0 is copied
  (`Rar5Extractor.decompressToFile`);
- dictionary size from the compression info, at least 256 KiB, kept between
  files of a solid archive;
- filters: Delta, E8, E8E9 (x86 calls and jumps) and ARM; another filter
  type gives "Unsupported RAR5 filter type";
- the RAR 7 variant (algorithm version 1: larger distance table, dictionary
  fraction bits) is handled by the same decoder (no sample).

RAR 4 decoding: `StoreDecompressor` (0x30) and `Lz77Decompressor` (0x31 to
0x35 with version 29 or more). `Lz77Decompressor` handles LZ blocks and PPMd
variant H blocks (`Ppmd7` with `RarRangeDecoder`), which RAR 3.x may mix in
one file, with a fixed 4 MiB window. RAR 3.x VM filters are not interpreted:
the filter code is identified by its length and CRC-32 and replaced by a
Java implementation of the standard filters E8, E8E9, Itanium, RGB, Audio
and Delta; any other code gives "RAR4: unknown VM filter code not supported".

RAR 5 encryption (`Rar5Crypto`, `Rar5ExtraCrypto`):

| Field | Size | Notes |
|---|---|---|
| version | vint | 0 = AES-256 |
| flags | vint | 0x01 password check present, 0x02 checksums are tweaked with a MAC |
| KDF count | 1 | log2 of the PBKDF2 iteration count |
| salt | 16 | |
| IV | 16 | file records only; for headers, each header is preceded by its own IV |
| check value | 12 | 8 bytes + 4 bytes of SHA-256 of them, if flag 0x01 |

- The AES-256 key is PBKDF2-HMAC-SHA256 of the UTF-8 password with
  2^count iterations. The password check is the PBKDF2 output after
  2^count + 32 iterations folded to 8 bytes by XOR; a mismatch gives "Wrong
  password" before any data is read. Data is AES-256-CBC.
- For encrypted files of an archive whose headers are not encrypted, the
  stored CRC32 is compared with an HMAC-SHA256 of the computed CRC32 (key =
  PBKDF2 after 2^count + 16 iterations) folded to 32 bits
  (`Rar5Crypto.verifyCrcWithHMAC`). BLAKE2sp values are always compared
  without this step.
- Encrypted headers (`rar -hp`): the first block after the signature is the
  archive encryption header (type 4). `Rar5Extractor.decryptHeadersToTemp`
  (used by extraction and listing) checks the password against its check
  value, then `Rar5HeaderDecryptor.decryptToFile` decrypts every header (IV +
  padded AES-256-CBC header) and writes a temporary copy of the archive with
  plain headers and still encrypted data, which `Rar5Reader` then reads; the
  copy is deleted at the end. No password gives `ArcanaEncryptedException`
  "RAR archive has encrypted headers and no password was provided", a wrong
  password "Wrong password for RAR archive with encrypted headers" (list and
  extract).

RAR 4 encryption (`Rar4Crypto`, files with flag 0x0004 and a salt): AES-128
in CBC mode. The key comes from SHA-1 run 2^18 times over password (2 bytes
per character) + salt + 3-byte counter; the IV is byte 19 of the
intermediate digest every 2^14 rounds. There is no password check: a wrong
password shows as CRC or decoding errors (on `rar4-encrypted.rar`: "CRC32
mismatch ... (corrupted data or wrong password)" and "RAR4: corrupted PPMd
data"). Encrypted RAR 4 headers (flag 0x0080): each header is preceded by an
8-byte salt and padded to 16 bytes (`Rar4HeaderParser.readEncryptedBlock`);
listing and extraction decrypt them with the password. Without a password
the archive is reported as encrypted (`ArcanaEncryptedException`). As there is
no check value, a wrong password is recognized when no file header and no
end-of-archive header could be decrypted (`Rar4Extractor.isWrongHeaderPassword`:
header CRC error on the first encrypted header) and reported as "Wrong
password for RAR archive with encrypted headers".

Integrity: CRC32 of every file (RAR 4 and RAR 5) and BLAKE2sp when the
RAR 5 hash record is present (`util.Blake2sp`, `Blake2spOutputStream`).

## Variants and versions

- Solid archives: `rar5-solid.rar`, `rar4-solid.rar`. The decoder state is
  kept from file to file; with a file filter, skipped files of a solid
  stream are decoded to nowhere (`Rar5Extractor.decompressToNull`).
- Volumes: `Rar5Extractor.discoverVolumes` and
  `Rar4Extractor.discoverVolumes` find `nameN.rar`, `nameN+1.rar`, ... (any
  digit width). For RAR 5 the search first goes back to the lowest existing
  number, so opening any part extracts the whole set (every
  `rar5-volumes.partN.rar` reference shows the same 6 extracted items);
  RAR 4 starts from the part given. File pieces are chained by
  `Rar5MultiVolumeInputStream` / `Rar4MultiVolumeInputStream`. Old style
  names (`.rar`, `.r00`, `.r01`) are not searched. Listing a volume lists the
  headers of that volume only.
- Encryption: `rar5-encrypted.rar` (data only, names visible),
  `rar5-encrypted-headers.rar` (`-hp`), `rar4-encrypted.rar` (data only),
  `rar4-encrypted-headers.rar` (`-ma4 -hp`); `damaged/wrong-password-rar5.rar`
  and `damaged/wrong-password-rar4.rar` are copies of the `-hp` samples whose
  reference uses the password `wrong`.
- `names-utf8.rar` was made by `rar` in a non-UTF-8 locale: the stored name
  of the accented file is already wrong (private-use characters), and Arcana
  and 7-Zip both show it as stored.
- Non-solid RAR 5 archives are extracted with one thread per file
  (`Runtime.availableProcessors()` threads); solid archives and single-file
  extraction are sequential.

## Limits

- No creation, no stream input ("RAR requires random file access").
- RAR 4: only algorithm 2.9 (version 29+); RAR 1.5, 2.0 and 2.6 data gives
  "Compression method 0x3N (version NN) not supported". Encrypted files
  without a salt (RAR 2.x encryption) give "Encrypted file without salt".
- RAR 4 passwords are converted with ISO-8859-1 before being spread to 2
  bytes per character, so characters above U+00FF do not give the RAR key.
- RAR 5 with encrypted headers: `Rar5HeaderDecryptor` reads the whole
  archive into memory
  (`Files.readAllBytes`), so such archives are limited to less than 2 GiB
  and need that much heap.
- RAR 5 dictionary: `setDecoderProperties` refuses sizes above 2 GiB (its
  message says "max 4GB"); the window is one `byte[]` allocated from the
  header value, with no memory limit (unlike 7z).
- RAR 4 entries of 4 GiB or more (flag 0x0100): handled by code reading
  only, there is no sample (the high 32 bits give the packed size, the
  unpacked size and the position of the next header).
- Links (extra record 5), file times, attributes, owners, NTFS streams and
  comments are not restored. Recovery records are not used.
- Existing files are never overwritten: `formats.rar.util.SafePathBuilder`
  renames the new file (`readme_1.txt` when extracting twice into the same
  directory), unlike the ZIP and 7z extractors.
- Common extraction limits apply through `ExtractionGuard`.

## Implementation notes

- `RarExtractor` checks `Unrar5j.isEncrypted` first and throws
  `ArcanaEncryptedException` "RAR archive is encrypted and no password was
  provided" (RAR 5: first block is the encryption header; RAR 4: encrypted
  headers or first file encrypted). Errors collected in `ExtractionResult`
  are turned into `ArcanaEncryptedException` (an archive-level password
  error keeps its own message), `ArcanaLimitExceededException` or one
  `ArcanaCorruptedException` listing every failed file. A file without a
  RAR signature at offset 0 is an error ("Unknown or unsupported archive
  format"), not an empty result.
- Empty files (RAR 4 entries with packed and unpacked size 0) are created
  without running a decoder (`Rar4Extractor.createEmptyFile`).
- Header damage is collected as "problems" (header CRC error, truncated
  header, data beyond the end of file, missing end-of-archive block for
  RAR 5) and reported as errors; files before the damage are still
  extracted.
- Paths: `formats.rar.util.SafePathBuilder` turns `\` into `/`, replaces
  `<>:"|?*` and control characters by `_`, renames trailing dots (`..`
  becomes `._`) and Windows reserved names (`AUX.txt` becomes `_AUX.txt_`),
  and checks that the canonical path stays under the destination.
- Data is read through `BoundedInputStream` over the `RandomAccessFile`
  and decrypted on the fly (`Rar5Reader.createDecryptingStream`,
  `Rar4DecryptInputStream`); no file is loaded whole in memory except for
  the header decryption described above.
- The RAR 4 VM is avoided on purpose: standard filters are recognized by the
  CRC-32 of their byte code (`Lz77Decompressor`).

## Sources

- RARLAB, RAR 5.0 archive format: https://www.rarlab.com/technote.htm
- RARLAB, `TechNote.txt` shipped with RAR 4.x (RAR 4 block layout); a copy:
  http://rescene.wikidot.com/rar-420-technote
- Library of Congress format descriptions: RAR version 4,
  https://www.loc.gov/preservation/digital/formats/fdd/fdd000458.shtml ;
  RAR version 5, https://www.loc.gov/preservation/digital/formats/fdd/fdd000460.shtml
- RFC 7693, BLAKE2 (BLAKE2s used by BLAKE2sp): https://www.rfc-editor.org/rfc/rfc7693
- RFC 8018, PKCS #5 v2.1 (PBKDF2): https://www.rfc-editor.org/rfc/rfc8018

License: every file of `formats/rar` and `RarExtractor` is Copyright 2025
Stephane Bury, Apache-2.0, with no third-party notice. The RARLAB documents
above describe the containers, not the compression algorithms. Some comments
name the matching routines of other decoders: unrar (`TablesRead3`,
`ModelPPM::DecodeInit`, `Unpack29` in `Lz77Decompressor`) and 7-Zip
(`CDecoder::InitFilters` in `Rar5LZDecoder`); `Rar5Crypto` thanks a 7-Zip
forum member for the CRC key derivation. `Ppmd7` (used for RAR 4 PPMd
blocks) is a Java port of Ppmd7.c by Igor Pavlov (public domain).
