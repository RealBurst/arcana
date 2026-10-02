# arcana-plugin-nsis

Arcana plugin that extracts the files of **NSIS installers** (Nullsoft Scriptable Install System),
the `setup.exe` of Notepad++, OBS Studio, Wireshark, Electron applications and many others.

| | |
|---|---|
| NSIS versions | 2.x and 3.x, ANSI and Unicode (including "Unicode NSIS" 2.x) |
| Compression | zlib (Deflate), bzip2, LZMA (with or without x86 BCJ filter), stored |
| Modes | solid (`SetCompressor /SOLID`) and non-solid |
| Capabilities | extract, list, identify (`arcana i`) |
| Requires | Arcana 1.0.2 or later (NSIS mode of the bzip2 decoder) |

## Usage

```
arcana l setup.exe
arcana x setup.exe -o out
arcana i setup.exe
arcana x setup.exe -f nsis -o out     (force the format)
```

## Names of the extracted files

Paths are relative to `$INSTDIR`, like 7-Zip: `$INSTDIR\bin\tool.exe` gives `bin/tool.exe`.
Files written elsewhere keep their root as first directory: `$PLUGINSDIR/nsDialogs.dll`,
`$SYSDIR/x.dll`, `$APPDATA/...`.

* When the script writes two different files to the same path (32-bit and 64-bit versions, for
  instance), the second one is named `name (2).ext`; 7-Zip overwrites the first one.
* The uninstaller (`WriteUninstaller`) is not extracted: NSIS builds it at install time.
* Only the files are extracted: the script itself (registry keys, shortcuts...) is not decompiled.

## License

Apache-2.0. Written from the NSIS file format (Source/exehead/fileform.h of NSIS, zlib license);
no NSIS code is included.
