# arcana-plugin-installshield

Arcana plugin for **InstallShield**: the cabinet sets (`data1.hdr`, `data1.cab`, `data2.cab`...)
found on the media of many commercial programs, drivers and games, and the files embedded in
InstallShield `setup.exe` launchers.

| | |
|---|---|
| Cabinets | InstallShield 5 to 2020+ (`ISc(` signature): header in `data1.hdr` or in `data1.cab`, several volumes, split files, obfuscated files, linked (duplicate) files, files stored next to old cabinets |
| Compression | Deflate chunks, and the older single-stream layout (tried automatically) |
| Checks | size of every file, MD5 from version 6 |
| setup.exe | "InstallShield" and "ISSetupStream" embedded file lists (InstallShield 9 to 2021+), with their XOR encoding and zlib compression; older "plain" lists |
| Capabilities | extract, list, identify (`arcana i` on a cabinet) |
| Requires | Arcana 1.0.4 or later (4 MiB plugin probe) |

## Usage

```
arcana l data1.hdr                (or data1.cab: the whole set is read)
arcana x data1.hdr -o out
arcana x setup.exe -o out         (embedded files: setup.ini, .msi, data1.cab...)
arcana x setup.exe -f installshield -o out   (force the format)
```

The volumes must be in the same directory as the header, with their usual names (`data1.cab`,
`data2.cab`...: any prefix works, the case does not matter).

## Names of the extracted files

Cabinet files are written as `file group/directory/name`, like unshield. A setup.exe gives its
embedded files with their names; an extracted `.msi` is then opened by Arcana itself, an extracted
`data1.hdr` / `data1.cab` set by this plugin.

## Limits

* InstallShield 3 `.z` archives and the InstallScript (`setup.inx`) are not supported.
* The cabinet reader was checked on cabinets of InstallShield 5 and older (four test sets of
  unshield: identical files); the setup.exe reader was checked on generated samples only.

## License

Apache-2.0. Format knowledge from unshield (Copyright (c) 2003 David Eriksson, MIT license) and
ISx (Copyright (c) 2017 lifenjoiner, MIT license); no code of these projects is included.
