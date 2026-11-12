# arcana-plugin-sarc

Arcana plugin for **Nintendo SARC archives**: the archives of Nintendo's "sead" library, used by
Wii U and Switch games for resource packs (`.pack`, `.sarc`, `.bactorpack`, `.blarc`...), and the
Yaz0-compressed form (`.szs`).

| | |
|---|---|
| Byte orders | little-endian (Switch, byte order mark bytes `FF FE`) and big-endian (Wii U, `FE FF`) |
| Compression | Yaz0 (`.szs`, decoded by the plugin); a Zstandard `.pack.zs` is first decompressed by Arcana (`arcana x file.pack.zs` gives `file.pack`) |
| Capabilities | extract, list |
| Requires | Arcana 1.2.0 or later |

## Usage

```
arcana l Actor.pack
arcana x ZsDic.pack -o out        (after arcana x ZsDic.pack.zs)
arcana x course.szs -o out
```

## Format

* Header (0x14): `SARC`, header size, byte order mark, file size, data offset, version 0x0100.
* SFAT: node count and hash key (0x65); 16-byte nodes: name hash, attributes (bit 24: has a name,
  at (attributes & 0xFFFF) x 4 in the name table), start and end of the data from the data offset.
* SFNT: names, NUL-terminated, on 4-byte boundaries.
* A file without a name is extracted as `0xHASH.bin`; a repeated name gets `~index`.
* Yaz0: `Yaz0`, decompressed size (big-endian), 8 reserved bytes, then groups of a flag byte
  (1 = literal) and copies of 2 bytes (length 3 to 17) or 3 bytes (length 18 to 273), distance up to 4 KiB.

## Not supported

* Creation of SARC archives. The archive is read in memory (Yaz0 data up to 2 GB).

## Sources

* SARC: https://zeldamods.org/wiki/SARC and the Mario Kart 8 wiki (SARC file format)
* Yaz0: https://zeldamods.org/wiki/Yaz0
* Test samples: `test/samples/plugins/sarc/` (made by `SampleGenerator sarc`).
