# arcana-plugin-xci

Arcana plugin for **Nintendo Switch XCI** files: images of Switch gamecards. The plugin lists and
extracts the files the card holds (NCA content archives, tickets, certificates); it does not
decrypt them.

| | |
|---|---|
| Layouts | plain dumps (card header first, "HEAD" at 0x100) and dumps that keep the 0x1000-byte key area ("HEAD" at 0x1100) |
| Structure | root HFS0 at the address given by the card header (usually 0xF000 from the header), listing the partitions `update`, `normal`, `logo`, `secure`, each an HFS0 of its own |
| Capabilities | extract, list, recover (`arcana r`: what is present in a truncated or damaged image) |
| Requires | Arcana 1.1.0 or later |

## Usage

```
arcana l game.xci
arcana x game.xci -o out
arcana r damaged.xci -o rescue
arcana x game.xci -f xci -o out         (force the format)
```

## Names of the extracted files

* `partition/file`, for example `secure/0123456789abcdef0123456789abcdef.nca`,
  `update/....cnmt.nca`. An empty partition gives nothing.
* An entry of the root HFS0 that is not itself an HFS0 is extracted as a file at the root.

## Not supported

* Decryption of the NCA files (it needs the console keys).
* The SHA-256 hashes of the HFS0 entries are not checked.
* Finding an XCI inside another file (`arcana s`): an XCI starts with an RSA signature, not with a
  fixed signature, so the carver cannot spot its start.

## Sources

* switchbrew, XCI: https://switchbrew.org/wiki/XCI
* Test samples: `test/samples/plugins/xci/` (made by `SampleGenerator xci`).
