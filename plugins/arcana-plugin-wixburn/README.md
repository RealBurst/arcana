# arcana-plugin-wixburn

Arcana plugin for **WiX Burn bundles**: the `setup.exe` bootstrappers made by the WiX toolset
(the installers of the WiX toolset itself, Dokany, PowerToys, the .NET and Visual C++ runtimes,
many drivers and SDKs). A bundle chains several packages (MSI, MSP, MSU, EXE, other bundles) and
shows its own user interface, the "bootstrapper application".

| | |
|---|---|
| WiX versions | 3.x (manifest namespace `schemas.microsoft.com/wix/2008/Burn`), 4, 5 and 6 (`EngineVersion` of the manifest) |
| Containers | the UX container and the attached containers (cabinets, read by Arcana's CAB reader: MSZIP, LZX, stored) |
| Checks | size and hash (SHA-1 for WiX 3, SHA-512 for WiX 4 and later) of every payload that has them in the manifest |
| Capabilities | extract, list, identify (`arcana i`: bundle name and version, publisher, WiX engine version, packages) |
| Requires | Arcana 1.0.4 or later |

## Usage

```
arcana i setup.exe
arcana l setup.exe
arcana x setup.exe -o out
arcana x setup.exe -f wixburn -o out     (force the format)
arcana l out/product.msi                 (then open an extracted package with Arcana)
```

## Names of the extracted files

* `ux/BurnManifest.xml`: the manifest of the bundle (stored as `0` in the UX container).
* `ux/...`: the files of the bootstrapper application at their `FilePath` (the BA dll or exe,
  `BootstrapperApplicationData.xml`, `BootstrapperExtensionData.xml`, theme, localization files,
  license, images...).
* The packages and their files (MSI, external cabinets of an MSI, MSU, EXE...) at their `FilePath`,
  for example `data/core.msi`, `redist/vc_redist.x64.exe`.
* A cabinet entry that the manifest does not describe keeps its name in the cabinet, under `ux/`
  or under the id of its container.
* Two payloads with the same path: the second one is named `name (2).ext`.

The packages are not opened: run Arcana again on an extracted `.msi` (or `.exe`, `.cab`) to see
its files.

## Payloads not in the bundle

A payload can be outside the bundle file: `Packaging="external"` (next to the bundle, or
downloaded at install time from its `DownloadUrl`) or stored in a detached container. Such
payloads are listed with a note, for example
`redist/NDP462-KB3151800-x86-x64-AllOS-ENU.exe (not in the bundle: external, downloaded)`, are
counted in the `not in the bundle` line of `arcana i`, and are not extracted (nothing is
downloaded).

## Layout of a bundle

Described from the WiX documentation and from the analysis of real bundles (the files listed in
`test/README.md`):

* The engine (a PE executable, the "stub") has a section named `.wixburn`. Its data: the magic
  number `0x00F14300`, a format version (2), the bundle GUID (16 bytes), the size of the stub, the
  original PE checksum, the offset and size of the Authenticode signature of the engine, the
  container format (1 = cabinet), the number of containers, then the size of each container.
  The list of sizes can go past the virtual size of the section: the raw data of the section is
  read.
* The UX container starts right after the stub (at the stub size). It is a cabinet that holds the
  manifest (`0`) and the files of the bootstrapper application (`u0`, `u1`...).
* The attached containers follow the signature of the engine (offset + size of the `.wixburn`
  section), or the UX container when the engine was not signed; a few alignment bytes may come
  between them. Each one is a cabinet whose entries (`a0`, `a1`...) are the payloads. The
  Authenticode signature of the whole bundle comes last.
* The manifest (`BurnManifest.xml`) gives, for every `Payload`: its `Id`, its `FilePath`, the
  name inside its cabinet (`SourcePath`), its `Container`, its `Packaging` (embedded / external),
  `FileSize` and `Hash`. The payloads of the bootstrapper application are inside the `UX`
  element. The `Container` elements say which containers are attached (`Attached`,
  `AttachedIndex` = index in the `.wixburn` list) and which are detached. `Registration` and
  `Arp` give the bundle id, version and name; the children of `Chain` are the packages.

Each container is located by the "MSCF" signature and the cabinet size given by the section, then
copied to a temporary file for the CAB reader (the file table used by `arcana l` is read in place).

## Limits

* Detached containers and external payloads are not extracted (they are not in the file).
* The packages are extracted as they are: MSI files, MSU and EXE packages are not unpacked
  (Arcana itself opens MSI and CAB files; an EXE package may be another installer).
* Only cabinet containers (format 1) exist and are supported.
* The WiX 3 engine does not record its exact version in the manifest: `arcana i` shows `3.x`.
* Tested with bundles of WiX 3.14 and 5.0 (see `test/README.md`). WiX 4 and 6 bundles have the
  same manifest namespace and `.wixburn` section as WiX 5, but no sample of them was tested.

## Sources

* WiX toolset documentation: Burn bundles, containers and payloads, signing bundles (engine
  detach / reattach): https://docs.firegiant.com/wix/tools/burn/ (formerly wixtoolset.org/docs).
* Microsoft cabinet format: [MS-CAB] (through Arcana's CAB reader).
* Own analysis of the bundles listed in `test/README.md` (section contents, container offsets,
  manifests).

No code of the WiX toolset (MS-RL for WiX 3, MIT for WiX 4 and later) is included or translated.

## License

Apache-2.0.
