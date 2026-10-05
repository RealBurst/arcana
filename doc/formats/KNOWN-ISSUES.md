# Known issues

Problems found while writing the format pages (October 2026), with the place
in the code. "Confirmed" means reproduced on a test file; "code" means found
by reading the code only. Line numbers are those of the code at that time.

Severity: **high** = wrong data without error, loss of data, crash or hang on
a crafted file; **medium** = valid files that fail, missing check; **low** =
message, comment or consistency.

## High

None left: see "Fixed in 1.0.6" at the end.

## Medium

| Format | Problem | Where | Status |
|---|---|---|---|
| LZ4 | A skippable frame at the very end fails ("Unexpected end of LZ4 stream"); block size not checked against the maximum | `formats/lz4/LZ4InputStream.java:107,173` | confirmed |
| Snappy | Corrupt copies or literals escape as ArrayIndexOutOfBoundsException; announced size allocated without limit | `formats/snappy/SnappyInputStream.java:176,194-221` | confirmed |
| XZ / LZMA | Truncated files print "Error: null" (EOFException without message); the per-format error wrapping is skipped because `detect()` runs first | `extractor/CompressedStreamExtractor.java:124,171` | confirmed |
| XZ / LZMA | `.lzma` and LZ4 legacy are detected by extension only (`MAGIC_LZMA` declared but unused) | `detector/ArchiveDetector.java:64` | confirmed |
| Unix compress | About two cuts in three of a truncated .Z are not detected (the format has no checksum); `1F A0` reported by `i` but not extracted; no `.tar.Z` handling | `extractor/ZExtractor.java`, `analyze/ArchiveAnalyzer.java:49`, `plugin/FormatRegistry.java:128` | confirmed |
| 7z | Entries without a name (`7z a -si`) fail: "name must not be null" / NullPointerException | `extractor/SevenZExtractor.java:64,70` | confirmed |
| RAR 4 | Password converted through ISO-8859-1: characters above U+00FF give a wrong key | `formats/rar/rar4/crypto/Rar4Crypto.java:53` | confirmed |
| RAR 5 | Real dictionary limit 2 GB (message says 4 GB); exactly 2 GB overflows; no memory limit | `formats/rar/rar5/decompress/Rar5LZDecoder.java:1215,1278` | code |
| RAR 5 | Whole archive read in memory for encrypted headers; header size not capped before allocation | `formats/rar/rar5/Rar5HeaderDecryptor.java:104`, `Rar5Reader.java:359` | code |
| RAR | Extraction never overwrites (second run creates `readme_1.txt`), unlike ZIP and 7z; unknown format returns an empty result | `formats/rar/Unrar5j.java:119` | confirmed |
| CAB | CFDATA checksum leaves out the per-block reserve (the Microsoft document includes it) | `formats/cab/CabReader.java:197,207` | confirmed |
| CAB | File continued from another cabinet (folder 0xFFFD-0xFFFF): raw IndexOutOfBoundsException | `formats/cab/CabReader.java:233`, `extractor/CabExtractor.java:54-57` | confirmed |
| MSI | Files outside any cabinet or in a missing external cabinet are listed but silently not extracted ("Done.") | `extractor/OleExtractor.java:102,112` | confirmed |
| OLE | Recursion over sibling entries only bounded by the entry count: possible StackOverflowError on a crafted file | `formats/ole/CompoundFile.java:181-193` | code |
| CHM | Uncompressed length of exactly 2^31 passes the check then fails with NegativeArraySizeException | `formats/chm/ChmReader.java:202,207` | code |
| LHA | Directory name lost when the file-name extended header follows the directory header | `formats/lha/LhaReader.java:300-308` | confirmed |
| LHA | Detection only accepts `-lh` at offset 2, while `i` also accepts `-lz`: a `-lz4-` archive without `.lzh` extension cannot be opened | `detector/ArchiveDetector.java:212-216` | confirmed |
| LHA | Methods lh1-lh3, lzs, lz5, pm? listed but silently skipped on extraction; CRC not checked when stored CRC is 0 | `formats/lha/LhaReader.java:508` | confirmed |
| LHA (creation) | Stream variant of `writeEntry` writes CRC 0 and may label compressed data as -lh0- (not used by `LhaCompressor`) | `formats/lha/LhaWriter.java:87,137` | code |
| ARJ | One entry split across volumes stops the whole extraction (later complete files not extracted) | `formats/arj/ArjReader.java` | confirmed |
| WIM | After a decompression error, the chunk cache may keep a partly overwritten chunk (caught by SHA-1); solid buffer sized to the header chunk size (64 MiB for a small resource) | `formats/wim/WimReader.java:420-424` | code |
| AR / DEB | Truncated archive listed without error; BSD symbol table (`__.SYMDEF`) listed as a member; every `/` removed from GNU long names; invalid size read as 0 | `extractor/ArExtractor.java:72,104,198,209,211` | confirmed |
| RPM | Header counts not bounded before allocation; input stream not closed on error; symbolic links written as files | `extractor/RpmExtractor.java:73-79,94-103,116-122` | code |
| XAR | Listing never shows sizes (`<size>` searched under `<file>` instead of `<data>`); checksums not verified; TOC inflated without limit | `extractor/XarExtractor.java:100,166-176,298` | confirmed |
| UDF | Symbolic links extracted as empty files; descriptor sequence numbers ignored | `formats/udf/UdfReader.java:73,255-261,529` | confirmed |
| SquashFS | Only gzip errors become ArcanaCorruptedException; gzip output longer than the block cut without error | `formats/squashfs/SquashfsReader.java:447-491` | confirmed |
| Recovery | `arcana r` on an executable whose payload is an MSI in its resources: the OLE payload is not handled | `formats/recover/ForceUnpacker.java:171-189` | code |
| Recovery | TAR not recognized after a lost first block (only offset 0 checked) | `formats/recover/ForceUnpacker.java:283-288` | confirmed |
| Recovery | ZIP64 data descriptors read as 4-byte sizes (wrong BAD_CHECKSUM) | `formats/recover/ZipRecovery.java:136-141` | code |
| Carving | RAR 4 with encrypted headers cut short; an IOException from a plugin probe stops the scan; split pieces bypass the extraction limits | `formats/carve/FileCarver.java:198,375,588` | code |
| Carving | A ZIP64 archive with data before it is not recognized, so the scan becomes very slow on large archives | `formats/carve/FileCarver.java:535` | confirmed |
| GZIP / XZ / LZMA | Output name falls back to `output` (GZIP, XZ), or keeps the archive name when it has no `.lzma` suffix (LZMA): extracting such a file in its own folder can overwrite it | `extractor/GzipExtractor.java`, `XzExtractor.java` (`deriveOutputName`), `LzmaExtractor.java` (`stripExt`) | code |
| Unix compress | `-b 9` files: two incompatible rules exist (switch to 10 bits when the 9-bit table is full, as compress 4.0 and gzip do, or stay at 9 bits, as ncompress after 5.0 and 7-Zip do); Arcana follows the second one | `extractor/ZExtractor.java` | confirmed |
| Zstandard | A file that starts with a skippable frame is not recognized by content (its magic is shared with LZ4) | `detector/ArchiveDetector.java`, `analyze/ArchiveAnalyzer.java` | confirmed |
| RAR | Listing a RAR archive (without encrypted headers) that cannot be parsed returns an empty list instead of an error (extraction reports it) | `formats/rar/Unrar5j.java` (`listRar5`, `listRar4`) | code |

## Low

| Format | Problem | Where |
|---|---|---|
| ZIP | Tolerance for sizes wrong by a multiple of 4 GB never applies | `extractor/ZipExtractor.java:381` |
| 7z / ZIP | Archives created with a password keep file names visible (headers not encrypted) | `compressor/SevenZCompressor.java` |
| 7z | Javadoc gives the hashing order password + salt; the code (correctly) uses salt + password | `formats/sevenz/SevenZAesOutputStream.java:39` |
| RAR | Stale javadoc of `list()`, unused helpers; `availableProcessors()` instead of `ArcanaConcurrency` | `extractor/RarExtractor.java:131`, `rar5/Rar5Extractor.java:241` |
| CAB | Quantum folder reported as corrupted instead of unsupported; MSZIP javadoc says blocks are independent | `formats/cab/CabReader.java:184`, `MszipDecoder.java:19` |
| LHA / ARJ | MS-DOS times read as UTC (LHA) or local time (ARJ); "adaptive Huffman" wrongly used for lh4-lh7; end marker comment | `LhaReader.java:27,428`, `ArjReader.java:209`, `LhaWriter.java:117` |
| WIM / LHA / CAB | Outdated format descriptions ("not LZMS", "-lh0- to -lh7-", "files + directories") | `ArcanaFormat.java:100,118`, `plugin/FormatRegistry.java:110,118` |
| WIM | `getCompressionName()` and `hasSolidResources()` unused: `i` only prints "WIM archive" | `formats/wim/WimReader.java` |
| Brotli | Error codes lost ("Brotli stream decoding failed"); large-window streams rejected; headers refer to an MIT LICENSE file that is not shipped | `formats/brotli/Utils.java:150-161`, `formats/brotli/*.java:1-5` |
| Snappy | Header attributes Snappy to "Jyrki Alakuijala" and calls it public domain (Google publishes it under a BSD-style license) | `formats/snappy/SnappyInputStream.java:18` |
| SZDD | All-uppercase names get the stored last character as is (`UPPER.TXt`); KWAJ and QBasic SZ not supported | `extractor/MsLzExtractor.java:250` |
| LZ4 | Class comment says checksums are not verified; they are | `formats/lz4/LZ4InputStream.java:31-33` |
| Zstandard | Test-archive generator `Rar5ZstdTestArchiveBuilder` in a production package | `formats/zstd/` |
| SFX / carving | Javadoc omits CAB overlays and WEBP; `hasCliHeader` does not check the directory count | `SfxExtractor.java`, `FileCarver.java:56`, `analyze/ExecutableAnalyzer.java:112-123` |
| Recovery | Dead extension fallback in `doForceUnpack` | `Arcana.java:135-139` |

## Test samples to revisit

- `test/samples/rar/names-utf8.rar` was made by `rar` in a non-UTF-8 locale: the accented name is stored wrongly and the reference records it.

## Fixed in 1.0.6

Each fix comes with a test sample (`test/samples`), named in brackets.

- Unix compress: CLEAR codes (padding to the end of the code group skipped) [`stream/seq-b12.txt.Z`]; output name never the archive itself (`.Z` / `.z`, else `.out`); partial output removed on error; some truncations detected [`damaged/truncated-notes.txt.Z`].
- SZDD: output name never the archive itself, upper-case last letter for upper-case names [`szdd/UPPER.TX_`]; partial output removed on error.
- ZIP: WinZip AES authentication code checked [`zip/aes256-tampered.zip`]; UTF-8 passwords used as given (PBKDF2 over the raw bytes) [`zip/aes256-utf8-password.zip`]; creation with a password streamed, with ZIP64 (large files, more than 65535 entries, offsets over 4 GiB); ZipCrypto header from `SecureRandom`.
- 7z: AES key derivation limited to 2^24 rounds, as 7-Zip [`damaged/7z-aes-rounds.7z`].
- RAR: wrong password with encrypted headers raises an error [`damaged/wrong-password-rar5.rar`, `damaged/wrong-password-rar4.rar`]; listing decrypts the headers with the password; RAR 4 empty files created; RAR 4 archives with encrypted headers reported as encrypted [`rar/rar4-encrypted-headers.rar`]; RAR 4 sizes over 4 GiB used to find the next header (not tested: no sample).
- ISO 9660: loops and depth limited [`damaged/iso-loop.iso`]; directory length limited [`damaged/iso-huge-dir.iso`]; image cut inside the volume descriptors [`damaged/iso-cut.iso`]; Rock Ridge and record lengths checked [`damaged/iso-bad-rr.iso`, `damaged/iso-bad-record.iso`]; Rock Ridge relocated directories (`rr_moved`) put back in place [`iso/rr-deep.iso`].
- Zstandard: magic number byte order [`stream/zstd-no-extension.bin`]; streaming decoder for frames without content size, several frames and skippable frames, memory bounded by the window [`stream/seq-nosize.txt.zst`, `stream/two-frames.txt.zst`, `stream/skippable.txt.zst`, `tar/payload-pipe.tar.zst`]; windows up to 128 MiB; dictionary ID 0 accepted, real dictionaries refused with a clear message.
- CAB creation: one data stream cut into 32 KiB blocks (accepted by 7-Zip and gcab), range checks [`cab/arcana-created.cab`].
- WIM: LZX uncompressed blocks starting on a 16-bit boundary [`wim/lzx-uncompressed-block.wim`].
- SFX: ZIP stored inside the image, not at the end of the file [`sfx/zip-inside-image.exe`].
