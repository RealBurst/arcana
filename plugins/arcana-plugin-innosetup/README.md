# arcana-plugin-innosetup

Arcana plugin that extracts the files of **Inno Setup installers**, the `setup.exe` of a large
part of the free Windows software (Git for Windows, ShareX, Greenshot, Inno Setup itself, many
utilities and games).

| | |
|---|---|
| Inno Setup versions | setup data formats 5.4.2 to 7.x (Unicode; old ANSI builds too) |
| Compression | LZMA, LZMA2, zlib, bzip2, stored; solid or not; x86 CALL/JMP filter |
| Data | inside the installer, or in `setup-1.bin`, `setup-1a.bin`... next to it (disk spanning) |
| Encryption | RC4 (up to 6.3), XChaCha20 (6.4 and later), including "Encryption=full": give the password with `-p` |
| Checks | SHA-256 / SHA-1 of every file, CRC of the setup data |
| Capabilities | extract, list, identify (`arcana i`) |
| Requires | Arcana 1.0.4 or later (4 MiB plugin probe) |

## Usage

```
arcana l setup.exe
arcana x setup.exe -o out
arcana x setup.exe -o out -p password
arcana i setup.exe
arcana x setup.exe -f inno -o out     (force the format)
```

## Names of the extracted files

Paths are relative to the application directory: `{app}\bin\tool.exe` gives `bin/tool.exe`.
Files installed elsewhere keep their folder constant as first directory: `sys/x.dll`,
`tmp/helper.dll`, `commonappdata/...`, `code_GetDir/...` for `{code:GetDir}`.

* When the script installs two different files to the same path (one per language or per
  architecture, for instance), the second one is named `name (2).ext`. The same file listed twice
  with the same data is extracted once.
* The uninstaller is not extracted: Setup writes its own executable at install time.
* External files (`Flags: external`) are not inside the installer and are skipped.
* Only the files are extracted: the script (registry keys, shortcuts, Pascal code) is not decompiled.

## Supported formats

Every Inno Setup release whose setup data format changed has its own layout, generated from the
record declarations of the Inno Setup sources by `tools/gen_layouts.py` (see the script to add a
newer version). An installer with an unknown format version is refused with its version string.
Inno Setup older than 5.4.2 (before 2011) is not supported.

## License

Apache-2.0. Written from the record declarations and the setup loader of the Inno Setup sources
(Inno Setup License, a permissive license); no Inno Setup code is included.
