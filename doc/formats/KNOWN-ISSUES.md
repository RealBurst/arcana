# Known issues

Problems found while writing the format pages (October 2026), with the place
in the code. "Confirmed" means reproduced on a test file; "code" means found
by reading the code only. Line numbers are those of the code at that time.

Severity: **high** = wrong data without error, loss of data, crash or hang on
a crafted file; **medium** = valid files that fail, missing check; **low** =
message, comment or consistency.

## High

| Format | Problem | Where | Status |
|---|---|---|---|
| Unix compress | A CLEAR code does not skip the padding to the end of the code group: files compressed with `-b 9` to `-b 15` fail ("Bad code") or, with `-b 9`, decode to wrong data reported as "Done." | `extractor/ZExtractor.java:101-104` | confirmed |
| Unix compress | The output name keeps the archive name when it does not end with `.Z` (case-sensitive test): extracting `file.z` in its own folder truncates the archive to 0 bytes | `extractor/ZExtractor.java:139-141` | confirmed |
| SZDD | Same output-name problem when the name does not end with `_`: a 112 KB file extracted in place was truncated | `extractor/MsLzExtractor.java:246` | confirmed |
| ZIP | The 10-byte WinZip AES authentication code is never checked; AES-256 entries have no CRC, so tampered data extracts without error | `extractor/ZipExtractor.java:203,221` | confirmed |
| ZIP | AES passwords with non-ASCII characters are encoded twice (UTF-8 bytes turned into chars, then UTF-8 again): other tools reject the password of an Arcana AES archive | `formats/zip/AesZipInputStream.java:70`, `AesZipOutputStream.java:75` | confirmed |
| ZIP | Creation with a password loads each file in memory and has no ZIP64: files of 4 GB or more, archives over 4 GB or more than 65535 entries give a broken archive | `compressor/ZipCompressor.java:211,257-303` | code |
| 7z | The AES key-derivation round count is not bounded: a hostile archive can make Arcana hash practically forever | `formats/sevenz/AES256SHA256Decoder.java:197` | code |
| RAR 5 | Wrong password on an archive with encrypted headers: prints an error, then "Done.", nothing extracted and no exception | `formats/rar/rar5/Rar5Extractor.java:188-189` | confirmed |
| RAR 4 | The high 32 bits of the packed size are ignored when finding the next header: an entry of 4 GB packed or more breaks everything after it | `formats/rar/rar4/Rar4HeaderParser.java:207,221` | code |
| ISO 9660 | No loop or depth guard in the directory walk: a directory pointing back to the root gives a StackOverflowError | `formats/iso/IsoReader.java:220-278` | confirmed |
| ISO 9660 | Directory length cast to int without limit: NegativeArraySizeException or huge allocation on a crafted image | `formats/iso/IsoReader.java:442-444` | confirmed |
| Zstandard | Frames without a content size larger than the window fail ("Output buffer too small"): `.tar.zst` made by `tar --zstd` or through a pipe, over about 2 MiB, cannot be read | `formats/zstd/ZstdInputStream.java:158,180-181` | confirmed |
| Zstandard | Single-file path: no content size gives `new byte[-1]` ("Error: -1"); several frames or a trailing skippable frame fail; whole file in memory | `extractor/ZstdExtractor.java:75,185`, `formats/zstd/ZstdHelper.java:93-94` | confirmed |
| CAB (creation) | Every file starts a new CFDATA block, so a folder has short blocks that are not the last one: 7-Zip rejects the files after the first one ("Data Error") | `formats/cab/CabWriter.java:247-258` | confirmed |
| WIM | Uncompressed LZX block starting on a 16-bit boundary: the padding word is not skipped, unlike `LzxDecoder` | `formats/wim/WimLzxDecoder.java:111` | code |
| SFX | A ZIP stored inside the image (not at the end) fails: the ZIP reader only searches the end of central directory in the last 65557 bytes | `extractor/SfxExtractor.java:128-129,163` | confirmed |

## Medium

| Format | Problem | Where | Status |
|---|---|---|---|
| Zstandard | Magic number in the wrong byte order: Zstandard files are only recognized by their extension | `detector/ArchiveDetector.java:59` | confirmed |
| Zstandard | Windows above 8 MiB (non single-segment frames) and any frame with a dictionary ID field are rejected | `formats/zstd/ZstdFrameDecompressor.java:63,301,921` | code |
| LZ4 | A skippable frame at the very end fails ("Unexpected end of LZ4 stream"); block size not checked against the maximum | `formats/lz4/LZ4InputStream.java:107,173` | confirmed |
| Snappy | Corrupt copies or literals escape as ArrayIndexOutOfBoundsException; announced size allocated without limit | `formats/snappy/SnappyInputStream.java:176,194-221` | confirmed |
| XZ / LZMA | Truncated files print "Error: null" (EOFException without message); the per-format error wrapping is skipped because `detect()` runs first | `extractor/CompressedStreamExtractor.java:124,171` | confirmed |
| XZ / LZMA | `.lzma` and LZ4 legacy are detected by extension only (`MAGIC_LZMA` declared but unused) | `detector/ArchiveDetector.java:64` | confirmed |
| Unix compress | Truncated .Z extracts silently; partial output left after an error; `1F A0` reported by `i` but not extracted; no `.tar.Z` handling | `extractor/ZExtractor.java:93`, `analyze/ArchiveAnalyzer.java:49`, `plugin/FormatRegistry.java:128` | confirmed |
| 7z | Entries without a name (`7z a -si`) fail: "name must not be null" / NullPointerException | `extractor/SevenZExtractor.java:64,70` | confirmed |
| RAR 5 | Listing an archive with encrypted headers returns nothing even with the right password; RAR 4 listing ignores the password | `formats/rar/Unrar5j.java:163,171,184` | confirmed |
| RAR 4 | Empty files are not created (`rar4.rar` gives 5 items instead of 6; the test reference records it) | `formats/rar/rar4/Rar4Extractor.java:117-118` | confirmed |
| RAR 4 | Archive with encrypted headers not reported as encrypted ("corrupted" instead of "password needed") | `formats/rar/rar4/Rar4Extractor.java:373` | code |
| RAR 4 | Password converted through ISO-8859-1: characters above U+00FF give a wrong key | `formats/rar/rar4/crypto/Rar4Crypto.java:53` | confirmed |
| RAR 5 | Real dictionary limit 2 GB (message says 4 GB); exactly 2 GB overflows; no memory limit | `formats/rar/rar5/decompress/Rar5LZDecoder.java:1215,1278` | code |
| RAR 5 | Whole archive read in memory for encrypted headers; header size not capped before allocation | `formats/rar/rar5/Rar5HeaderDecryptor.java:104`, `Rar5Reader.java:359` | code |
| RAR | Extraction never overwrites (second run creates `readme_1.txt`), unlike ZIP and 7z; unknown format returns an empty result | `formats/rar/Unrar5j.java:119` | confirmed |
| CAB | CFDATA checksum leaves out the per-block reserve (the Microsoft document includes it) | `formats/cab/CabReader.java:197,207` | confirmed |
| CAB | File continued from another cabinet (folder 0xFFFD-0xFFFF): raw IndexOutOfBoundsException | `formats/cab/CabReader.java:233`, `extractor/CabExtractor.java:54-57` | confirmed |
| CAB (creation) | No range check on 16-bit counts and 32-bit offsets; whole cabinet built in memory | `formats/cab/CabWriter.java:287-302` | code |
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
| ISO 9660 | Image cut inside the volume descriptors: "Error: null"; Rock Ridge and directory-record parsing do not check lengths | `formats/iso/IsoReader.java:435-446`, `RockRidgeParser.java:71-89`, `IsoDirectoryRecord.java:101-104` | confirmed / code |
| ISO 9660 | Rock Ridge relocated directories (`rr_moved`) not followed | `formats/iso/` | confirmed |
| UDF | Symbolic links extracted as empty files; descriptor sequence numbers ignored | `formats/udf/UdfReader.java:73,255-261,529` | confirmed |
| SquashFS | Only gzip errors become ArcanaCorruptedException; gzip output longer than the block cut without error | `formats/squashfs/SquashfsReader.java:447-491` | confirmed |
| Recovery | `arcana r` on an executable whose payload is an MSI in its resources: the OLE payload is not handled | `formats/recover/ForceUnpacker.java:171-189` | code |
| Recovery | TAR not recognized after a lost first block (only offset 0 checked) | `formats/recover/ForceUnpacker.java:283-288` | confirmed |
| Recovery | ZIP64 data descriptors read as 4-byte sizes (wrong BAD_CHECKSUM) | `formats/recover/ZipRecovery.java:136-141` | code |
| Carving | RAR 4 with encrypted headers cut short; an IOException from a plugin probe stops the scan; split pieces bypass the extraction limits | `formats/carve/FileCarver.java:198,375,588` | code |
| Carving | A ZIP64 archive with data before it is not recognized, so the scan becomes very slow on large archives | `formats/carve/FileCarver.java:535` | confirmed |

## Low

| Format | Problem | Where |
|---|---|---|
| ZIP | Tolerance for sizes wrong by a multiple of 4 GB never applies | `extractor/ZipExtractor.java:381` |
| ZIP | ZipCrypto header uses `java.util.Random` instead of `SecureRandom` | `formats/zip/ZipCryptoOutputStream.java:76` |
| 7z / ZIP | Archives created with a password keep file names visible (headers not encrypted) | `compressor/SevenZCompressor.java` |
| 7z | Javadoc gives the hashing order password + salt; the code (correctly) uses salt + password | `formats/sevenz/SevenZAesOutputStream.java:39` |
| RAR | Stale javadoc of `list()`, unused helpers; `availableProcessors()` instead of `ArcanaConcurrency` | `extractor/RarExtractor.java:131`, `rar5/Rar5Extractor.java:241` |
| Sources | Em dash in messages (not ASCII) | `extractor/SevenZExtractor.java:211`, `extractor/RarExtractor.java:122` |
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
- `test/expected/rar/rar5-encrypted-headers.rar.txt` ("0 entries") and `rar4.rar.txt` (missing empty file) record bugs listed above: update them with `--update` once fixed.
