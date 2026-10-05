# Arcana regression tests

Every sample is identified, listed and extracted by Arcana (core and plugins),
and the result is compared with its reference file. A change that breaks a
format shows up as a `DIFF` line.

```
build.bat test                      (Windows)
./build.sh test                     (Linux / macOS)
build.bat test --corpus D:\arcana-corpus
build.bat test rar                  (only the samples whose path contains "rar")
build.bat test --update             (write the references of new or changed samples)
```

`test` builds Arcana and every plugin, compiles `test/src`, then runs
`be.stef.arcana.test.RegressionRunner`. The exit code is 0 when everything
matches. The runner can also be started directly:

```
java -cp bin;test/bin be.stef.arcana.test.RegressionRunner [--update] [--corpus DIR] [--root DIR] [--timeout SEC] [filter]
```

## Results

| Status | Meaning |
|---|---|
| `OK` | same result as the reference |
| `DIFF` | different result: the first different line is shown, the full result is written to `test/out/<sample>.actual.txt` |
| `NEW` | no reference yet: run with `--update` to write it |
| `SKIP` | corpus file missing on this machine |
| `TIMEOUT` / `FAILED` | the sample took more than the time limit (300 s by default) or the runner itself failed |

"the sample file changed" means that the input file is not the one of the
reference (rebuilt sample, other version of a corpus file); the message says
whether the results changed too.

## Reference files

One text file per sample, same relative path plus `.txt`:

```
# Arcana regression reference (RegressionRunner --update)
input: <SHA-256 of the sample> <size>
password: secret                          (optional, kept by --update)
identify: archive | 7-Zip 0.04 - 7-Zip archive (format version 0.04)
list: 12 entries
  bin (folder)
  bin/random.bin 4096
  ...
extracted: 6 items
  bin/random.bin 4096 8fe774a9e65a...
  empty-dir/ (empty folder)
  ...
```

A step that fails is recorded as `ERROR <exception>: <message>`: for damaged
samples, the error IS the expected result. When the extraction fails, the
files written before the error are not compared (they depend on timing).

Always check the diff of `test/expected` / `test/corpus` before committing an
`--update`: a reference must only change when the change is wanted.

## The two sets of samples

### test/samples (committed)

Small files, committed with the project: the tests never rebuild them. They
were built with the official tool of each format by
`test/tools/make-samples.sh`, an optional Linux tool only needed to add or
rebuild samples: ZIP (store, deflate, deflate64, bzip2,
LZMA, ZipCrypto, AES-256, UTF-8 names), 7z (LZMA, LZMA2, PPMd, BZip2, Deflate,
Copy, Delta, encrypted, encrypted headers), RAR 4 and 5 (solid, encrypted,
encrypted headers, volumes), TAR (ustar, GNU, PAX) and its compressed forms,
single streams (gz, bz2, xz, lzma, lz4, zst, br, Z), ARJ, CAB, CPIO, AR, DEB,
RPM (gzip, bzip2, xz, zstd payloads), ISO 9660 / Joliet / Rock Ridge / UDF,
WIM (XPRESS, LZX, LZMS, solid), SquashFS, XAR, MSI, CHM, SZDD, and the PAK and
UPX plugins. `test/samples/damaged` holds broken files (truncated, flipped
byte, bad CRC, garbage): Arcana must report an error, never hang or crash.

The password of the encrypted samples is `secret`.

The payload held by every archive and the hand-made samples (SZDD, PAK, SFX,
damaged and crafted files, WinZip AES variants, Zstandard skippable frames,
WIM with an LZX uncompressed block...) come from
`be.stef.arcana.test.SampleGenerator` (`test/src`, pure Java, no dependency):
`make-samples.sh` calls it, and it runs on Windows too. It is compiled by
`build.bat test` / `./build.sh test`; run it without arguments for the list of
generators:

```
java -cp bin;test/bin be.stef.arcana.test.SampleGenerator payload C:\tmp\payload
java -cp bin;test/bin be.stef.arcana.test.SampleGenerator szdd C:\tmp\payload\docs\notes.txt C:\tmp\notes.tx_
java -cp bin:test/bin be.stef.arcana.test.SampleGenerator damaged /tmp/samples      (Linux)
```

`make-samples.sh [output folder]` (default `test/samples`) needs a build first
(`./build.sh test`); a missing official tool only skips its samples.

To add a sample: add it to `make-samples.sh` (or to `SampleGenerator` for a
hand-made file, or drop the file in `test/samples/<format>/` if it cannot be
built), run `build.bat test --update`, check the new reference.

### The corpus (not committed)

Real files that cannot be committed (third-party installers, large archives):
they stay in a folder of your own, given by `--corpus DIR` or the environment
variable `ARCANA_CORPUS`. Only their references are committed, in
`test/corpus`; a missing file is reported as `SKIP`. The SHA-256 of the
reference tells which exact file is expected.

Current references (put the files at these paths in the corpus folder):

| Path | Source |
|---|---|
| `chm/7-zip.chm` | help file of 7-Zip 25.01 (7-zip.org) |
| `innosetup/innosetup-6.0.5.exe`, `innosetup-6.4.3.exe`, `innosetup-7.1.0-x64.exe` | jrsoftware.org (old versions: files.jrsoftware.org/is/) |
| `innosetup/Greenshot-INSTALLER-1.2.10.6-RELEASE.exe` | Greenshot releases (GitHub) |
| `innosetup/ShareX-12.4.1-setup.exe` | ShareX releases (GitHub) |
| `jexepack/eMailTrackerPro.exe` | JexePack 5.5 program |
| `jexepack/install-jexepack.exe` | JexePack 8.3a installer (duckware.com) |
| `msi/7z2501-x64.msi` | 7-zip.org |
| `msi/PowerShell-7.4.6-win-x64.msi` | PowerShell releases (GitHub) |
| `msi/jinstall-unpacked.exe` | `_installjava_.exe` unpacked by the UPX plugin (Java 6 Update 31 online installer) |
| `upx/_installjava_.exe` | Java installer packed with UPX (found inside install-jexepack.exe) |
| `upx/EasyPythonDecompiler.exe` | Easy Python Decompiler |

To add a corpus file: copy it into the corpus folder, run
`build.bat test --corpus DIR --update`, check and commit its reference.

`ignore.txt` (in `test/corpus` or `test/expected`) lists the files that are
not samples by themselves, such as the volumes after the first one
(`*/data[2-9].cab`).
