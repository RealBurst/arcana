# Arcana format documentation

One page per format: how Arcana detects it, the layout of the file, the
compression and encryption methods, what is supported and what is not, the
implementation choices, and the public documents the code is based on.
Every page follows [TEMPLATE.md](TEMPLATE.md); a new format comes with its
page and its test samples (see [test/README.md](../../test/README.md)).

## Archives and containers

| Format | Page | Arcana support |
|---|---|---|
| ZIP (ZipCrypto, WinZip AES, Deflate64, Zip64) | [zip.md](zip.md) | list, extract, create (Deflate, optional AES-256 or ZipCrypto) |
| 7z | [7z.md](7z.md) | list, extract (AES-256, encrypted headers, split volumes), create (LZMA2, optional AES-256) |
| RAR 4 and 5 | [rar.md](rar.md) | list, extract (solid, volumes, encryption, RAR 5 encrypted headers) |
| TAR and .tar.gz / .bz2 / .xz / .lz4 / .zst / .br | [tar.md](tar.md) | list, extract; create .tar, .tar.gz, .tar.bz2, .tar.xz, .tar.lz4 |
| CPIO | [cpio.md](cpio.md) | list, extract (newc, crc, odc) |
| AR and Debian .deb | [ar-deb.md](ar-deb.md) | list, extract (.deb unpacked like `dpkg-deb -R`) |
| RPM | [rpm.md](rpm.md) | list, extract (gzip, bzip2, xz, zstd, lzma payloads) |
| XAR (.pkg, .xip) | [xar.md](xar.md) | list, extract |
| Microsoft Cabinet | [cab.md](cab.md) | list, extract (stored, MSZIP, LZX), create (MSZIP) |
| OLE compound files, Windows Installer (.msi) | [msi-ole.md](msi-ole.md) | list, extract (installed file tree, embedded or external cabinets) |
| Compiled HTML Help (.chm) | [chm.md](chm.md) | list, extract |
| ARJ | [arj.md](arj.md) | list, extract (methods 0 to 4) |
| LHA / LZH | [lha.md](lha.md) | list, extract (-lh0-, -lz4-, -lh4- to -lh7-), create (-lh5- to -lh7-) |

## Disk images and file systems

| Format | Page | Arcana support |
|---|---|---|
| ISO 9660, Joliet, Rock Ridge | [iso9660.md](iso9660.md) | list, extract (multi-extent files, zisofs) |
| UDF | [udf.md](udf.md) | list, extract (UDF 1.02 to 2.60) |
| WIM / ESD | [wim.md](wim.md) | list, extract (XPRESS, LZX, LZMS, solid resources) |
| SquashFS | [squashfs.md](squashfs.md) | list, extract (version 4.0, all compressors) |

## Single-file compressors

| Format | Page | Arcana support |
|---|---|---|
| GZIP | [gzip.md](gzip.md) | list, extract, create |
| BZIP2 | [bzip2.md](bzip2.md) | list, extract, create |
| XZ and LZMA | [xz-lzma.md](xz-lzma.md) | list, extract; create XZ |
| Zstandard | [zstd.md](zstd.md) | list, extract |
| LZ4 | [lz4.md](lz4.md) | list, extract (create as .tar.lz4) |
| Snappy | [snappy.md](snappy.md) | list, extract |
| Brotli | [brotli.md](brotli.md) | list, extract |
| Unix compress (.Z) | [compress-z.md](compress-z.md) | list, extract |
| Microsoft SZDD (COMPRESS.EXE) | [szdd.md](szdd.md) | list, extract |

## Codecs shared by several formats

| Codec | Page | Used by |
|---|---|---|
| LZX | [lzx.md](lzx.md) | CAB, CHM, WIM |
| LZMS | [wim.md](wim.md) (section LZMS) | WIM / ESD |

## Executables and tools

| Subject | Page | Arcana support |
|---|---|---|
| Self-extracting archives, installers, MSI in resources, .NET bundles | [sfx-executables.md](sfx-executables.md) | list, extract, identify |
| Files glued together (carving, `arcana s`) | [embedded-files.md](embedded-files.md) | scan, split |
| Damaged archives (`arcana r`) | [recovery.md](recovery.md) | forced extraction with a report |

## Plugins

Formats handled by the official plugins are documented with each plugin:

| Plugin | Documentation |
|---|---|
| Inno Setup | [plugins/arcana-plugin-innosetup/README.md](../../plugins/arcana-plugin-innosetup/README.md) |
| InstallShield | [plugins/arcana-plugin-installshield/README.md](../../plugins/arcana-plugin-installshield/README.md) |
| JexePack | [plugins/arcana-plugin-jexepack/README.md](../../plugins/arcana-plugin-jexepack/README.md) |
| NSIS | [plugins/arcana-plugin-nsis/README.md](../../plugins/arcana-plugin-nsis/README.md) |
| UPX | [plugins/arcana-plugin-upx/README-upx.md](../../plugins/arcana-plugin-upx/README-upx.md) |
| Quake PAK | sources in `plugins/arcana-plugin-pak/` |

## Known issues

Problems found while writing these pages are listed in
[KNOWN-ISSUES.md](KNOWN-ISSUES.md), with the file and line of the code.
