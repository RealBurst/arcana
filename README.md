# Arcana

**Pure-Java archive library and command-line tool.**
ZIP, 7z, RAR 4 and 5, TAR, GZIP, BZIP2, XZ, LZMA, LZ4, Zstandard, Snappy, Brotli, Unix compress, LHA, ARJ, CAB, MSI and OLE compound files, CHM, CPIO, ISO 9660, UDF, WIM, SquashFS, AR / DEB, RPM, XAR, self-extracting archives, and more through plugins.

No native libraries. No JNI. No external dependencies. Runs on Java 8 or later.

> **Arcana is a young project and may still contain bugs.**
> If a file is not extracted correctly, a command fails or something behaves unexpectedly, please [open an issue](https://github.com/RealBurst/arcana/issues).
> Include the command line, the error message and, if possible, the file or a way to reproduce the problem.

> **Like Arcana? Spread the word and give the project a star on GitHub!**

---

## Features

- **Extract** every supported format, including encrypted archives: ZIP (ZipCrypto and WinZip AES), 7z (AES-256, encrypted headers included), RAR 4 (AES-128) and RAR 5 (AES-256), with encrypted headers and multi-volume RAR archives.
- **Open archive-based files**: Office documents, OpenDocument files, EPUB books, Java and Android packages, Dia diagrams... (see [below](#archive-based-files)).
- **Compress** to ZIP, 7z, TAR, TAR+GZIP, TAR+BZIP2, TAR+XZ, TAR+LZ4, GZIP, BZIP2, XZ, LHA and CAB.
- **Encrypt** ZIP archives (WinZip AES-256, or ZipCrypto from the library) and 7z archives (AES-256).
- **Identify** any file: archive format, executable (PE / ELF / Mach-O), .NET single-file bundle, image with its dimensions, PDF, SQLite database, OLE2 document, font, media container...
- **Recover** damaged archives: forced extraction that keeps everything readable, with a report on the state of each file.
- **Split** files made of several files glued together: self-extracting archives, installers, firmware images...
- **Extend** with plugins: add a format without changing Arcana (see [PLUGIN-API.md](PLUGIN-API.md)).
- **Safe extraction**: entry names are sanitized (no absolute paths, no `..`, no characters forbidden on Windows), and extraction stops on decompression bombs or when the disk is nearly full.

---

## Supported formats

Each format has a technical page (detection, file layout, methods, limits, sources) in [doc/formats](doc/formats/README.md).

| Format | Extract | Compress | Encryption |
|--------|:-------:|:--------:|------------|
| ZIP (also JAR, WAR, EAR) | yes | yes | ZipCrypto, WinZip AES (AES-256 when compressing) |
| 7-Zip (.7z, split .7z.001) | yes | yes (LZMA2) | AES-256 |
| RAR 4 / RAR 5 (also .cbr) | yes | - | AES-128 (RAR 4), AES-256 (RAR 5) |
| TAR (also .gem) | yes | yes | - |
| TAR+GZIP (.tar.gz, .tgz) | yes | yes | - |
| TAR+BZIP2 (.tar.bz2, .tbz2) | yes | yes | - |
| TAR+XZ (.tar.xz, .txz) | yes | yes | - |
| TAR+LZ4 (.tar.lz4) | yes | yes | - |
| TAR+Zstandard (.tar.zst) | yes | - | - |
| TAR+Brotli (.tar.br) | yes | - | - |
| GZIP | yes | yes | - |
| BZIP2 | yes | yes | - |
| XZ | yes | yes | - |
| LZMA (raw stream) | yes | - | - |
| LZ4 | yes | - | - |
| Zstandard | yes | - | - |
| Snappy | yes | - | - |
| Brotli | yes | - | - |
| Unix compress (.Z) | yes | - | - |
| MS compress.exe (SZDD: .ex_, .dl_...) | yes | - | - |
| LHA / LZH | yes | yes (-lh5-, -lh6-, -lh7-) | - |
| ARJ (methods 0 to 4) | yes | - | - |
| Microsoft Cabinet (.cab) | yes (stored, MSZIP, LZX) | yes (MSZIP) | - |
| Windows Installer (.msi: installed file tree, embedded or external cabinets) | yes | - | - |
| OLE compound file (.msp, Office 97-2003, .msg: streams) | yes | - | - |
| Compiled HTML Help (.chm) | yes | - | - |
| CPIO (newc, odc) | yes | - | - |
| ISO 9660 | yes | - | - |
| UDF (DVD, Blu-ray, Windows media; revisions 1.02 to 2.60) | yes | - | - |
| WIM / ESD (XPRESS, LZX, LZMS; not split .swm) | yes | - | - |
| SquashFS 4.0 (gzip, LZMA, LZO, XZ, LZ4, Zstandard) | yes | - | - |
| AR / Debian package (.a, .deb) | yes | - | - |
| RPM (gzip, bzip2, xz, zstd payload) | yes | - | - |
| XAR | yes | - | - |
| Self-extracting archive (.exe: ZIP, RAR, 7z, CAB / IExpress inside, MSI in the resources) | yes | - | - |

A TAR or CPIO inside any single-file compressor is unpacked automatically (`.cpio.gz`, `.cpio.xz`, `.tar.lzma`...).

`arcana formats` prints the complete and current list, including the formats added by plugins.

### Archive-based files

Many file types are archives under another name. Arcana detects them by their content, not by their extension, so they can be extracted directly:

| Built on | Examples |
|----------|----------|
| ZIP | Microsoft Office (`.docx`, `.xlsx`, `.pptx` and their templates and macro-enabled variants), OpenDocument (`.odt`, `.ods`, `.odp`, `.odg`), EPUB, `.jar`, `.war`, `.apk`, `.ipa`, `.aar`, `.whl`, `.xpi`, `.vsix`, `.nupkg`, `.kmz`, `.cbz`, `.xps`, `.3mf`, FreeCAD `.fcstd` |
| GZIP | Dia diagrams (`.dia`), compressed SVG (`.svgz`) |
| RAR / 7z / TAR | Comic books (`.cbr`, `.cb7`), Ruby gems (`.gem`) |

```
arcana x report.docx -o ./report
arcana l presentation.odp
arcana x schema.dia -o ./schema
```

---

## Download

Download `Arcana-vX.Y.Z.jar` from the [Releases](https://github.com/RealBurst/arcana/releases) page.
It is both the command-line tool and the library: add it to your class path to use the Java API.

Or get it from Maven Central (`io.github.realburst:arcana`):

```xml
<dependency>
  <groupId>io.github.realburst</groupId>
  <artifactId>arcana</artifactId>
  <version>1.0.6</version>
</dependency>
```

```
implementation 'io.github.realburst:arcana:1.0.6'
```

---

## Command-line usage

```
java -jar Arcana-v1.0.0.jar <command> [options]
```

Run it without arguments to see the syntax of every command, and with `help` for the full description, the options and some examples.

### Commands

```
arcana x <archive> [-o dest] [-p password]  [-f format]
    Extract an archive (default destination: current directory).

arcana l <archive>           [-p password]  [-f format]
    List the contents of an archive.

arcana c <source>  <archive> [-t format]    [-l 0-9]    [-p password]
    Compress a file or directory. The format is inferred from the archive
    extension (backup.tar.gz gives tar.gz); -t forces it.

arcana r <archive> [-o dest] [-p password]  [-f format]
    Recover a DAMAGED archive: forced extraction + recovery report.

arcana s <file>    [-o dest] [-n]
    Split a file made of files glued together (EXE, archives, images...)
    into dest/<file name>/.

arcana i <file>
    Identify a file: category, type, version and details.

arcana formats [extract|compress]
    List the supported formats.

arcana plugins [<file>]
    List the plugins (loaded or refused, with the reason).
    With a <file>, show which plugin or format Arcana chooses for it and why.

arcana version     (also -v, --version)
arcana help        (also -h, --help)
```

The destination can be given with `-o dest` or as the second argument: `arcana x archive.zip out` is the same as `arcana x archive.zip -o out`.

### Options

```
-o <dir>       Output directory for x, r and s.
-p <password>  Password: decryption, or encryption with c (zip and 7z: AES-256).
-f <format>    Force the input format (format name, extension or plugin id).
-t <format>    Force the output format of c.
-l <level>     Compression level: 0-9 for 7z, xz and tar.xz (default 6);
               5, 6 or 7 for lzh (-lh5- by default).
-n             With s: list the pieces without writing anything.
```

### Examples

```
arcana x game.rar -o ./out
arcana x secure.zip -o ./out -p secret
arcana l disc.iso
arcana c ./mydir backup.tar.xz
arcana c ./mydir vault.7z -l 9 -p secret
arcana r damaged.zip -o ./rescue
arcana s setup.exe -n
arcana i mystery.bin
```

### Plugin status

On **every** run, before anything else, Arcana prints on the error output:

- `[plugins] No plugin found in any plugin directory.` when no plugin JAR was found;
- the list of **refused** plugins, one line each with the reason (missing sources, missing license, reserved namespace, duplicate id, missing service file...).

Nothing is printed when every plugin loaded correctly. `arcana plugins` gives the details (directories searched, SHA-256 of each JAR, capabilities).

### Windows Explorer context menu

The `windows/` folder adds three entries to the right-click menu of every file in Windows Explorer:
**Arcana Unpack ...** (extracts into `<name>_extracted` next to the file), **Arcana List ...** and **Arcana Info ...**.

1. Put `arcana-explorer.cmd`, `install-context-menu.cmd` and `uninstall-context-menu.cmd` in the folder of `Arcana-vX.Y.Z.jar` (plugins in its `plugins` subfolder).
2. Run `install-context-menu.cmd` (current user only, no administrator rights; run it again if the folder moves).
3. `uninstall-context-menu.cmd` removes the entries.

Java must be on the `PATH` (or `JAVA_HOME` set). On Windows 11 the entries are under **Show more options** (Shift+F10).

---

## Library API

```java
import be.stef.arcana.Arcana;
import be.stef.arcana.ArcanaEntry;
import be.stef.arcana.ArcanaFormat;
```

### Extract and list

```java
// Format detected automatically
Arcana.extractTo(new File("archive.tar.gz"), new File("out"));

// List the entries without extracting
for (ArcanaEntry e : Arcana.listEntries(new File("archive.rar"))) {
    System.out.println(e.getName() + "  " + e.getUncompressedSize());
}

// Encrypted archive
Arcana.withPassword("secret".getBytes("UTF-8")).extract(new File("secure.7z"), new File("out"));

// From a stream: the format must be given
try (InputStream in = new FileInputStream("data.bz2")) {
    Arcana.with(ArcanaFormat.BZIP2).extract(in, new File("out"));
}
```

### Compress

```java
import be.stef.arcana.compressor.ZipCompressor;
import be.stef.arcana.plugin.FormatRegistry;

byte[] password = "secret".getBytes("UTF-8");

new ZipCompressor().compress(new File("mydir"), new File("backup.zip"));
new ZipCompressor(password).compress(new File("mydir"), new File("secure.zip"));      // WinZip AES-256
new ZipCompressor(password, ZipCompressor.ENCRYPT_ZIPCRYPTO).compress(new File("mydir"), new File("legacy.zip"));

// Any format by its ArcanaFormat: level 0-9 (-1 = default), password or null
FormatRegistry.builtin(ArcanaFormat.SEVEN_Z).createCompressor(9, password).compress(new File("mydir"), new File("vault.7z"));
FormatRegistry.builtin(ArcanaFormat.TAR_XZ).createCompressor(-1, null).compress(new File("mydir"), new File("backup.tar.xz"));
```

`createCompressor` returns `null` for a format that Arcana can only extract.

### Identify

```java
import be.stef.arcana.analyze.Identification;

Identification id = Arcana.identify(new File("mystery.bin"));   // never null
System.out.println(id.category + " / " + id.type + (id.version != null ? " " + id.version : ""));
System.out.println(id.description);
System.out.println(id.getDetails());                             // e.g. image dimensions
```

### Recover a damaged archive

```java
import be.stef.arcana.formats.recover.RecoveryReport;

RecoveryReport report = Arcana.forceUnpack(new File("damaged.zip"), new File("rescue"));
System.out.println(report.summary());
System.out.println(report.count(RecoveryReport.Status.OK) + " file(s) intact");
```

The result is uncertain: check every recovered file. The full report is also written to `rescue/_ARCANA_RECOVERY_REPORT.txt`.

### Split a file

```java
import be.stef.arcana.formats.carve.FileCarver;

for (FileCarver.Item item : Arcana.scanEmbedded(new File("setup.exe"))) {   // list only
    System.out.println(item);
}
Arcana.split(new File("setup.exe"), new File("out"));                       // writes out/setup/...
```

### Plugins

```java
import be.stef.arcana.plugin.PluginManager;

// Use a plugin format: by plugin id or by extension
Arcana.withPlugin("pak", null).extract(new File("game.pak"), new File("out"));

// Loaded and refused plugins
for (PluginManager.PluginInfo info : PluginManager.get().getPlugins()) {
    System.out.println(info);
}

// Register a plugin by code (no source check: for tests and embedding applications)
PluginManager.get().register(new MyPlugin());
```

### Extraction limits

Every extraction through `Arcana` is guarded by the limits of `be.stef.arcana.util.ExtractionLimits` (public static fields, changeable at run time):

| Field | Default | Meaning |
|-------|---------|---------|
| `maxRatio` | 1000 | Maximum size ratio output / archive (decompression bomb), checked once `ratioThreshold` bytes are written |
| `ratioThreshold` | 1 GiB | Output size from which the ratio is checked |
| `maxTotalBytes` | 0 (unlimited) | Maximum total size written by one extraction |
| `minFreeSpace` | 256 MiB | Extraction stops when the free disk space falls below this value |

---

## Plugins

A plugin is a JAR dropped into one of these directories:

1. the directories listed in the system property `arcana.plugins.dir` (separated by the path separator; replaces the directories below);
2. `<user home>/.arcana/plugins/`;
3. `plugins/` next to the Arcana JAR;
4. `plugins/` in the working directory.

A plugin JAR is refused unless it contains its **source code**, declares its **source URL** and its **license**, has a **unique id** and uses its **own package** (`be.stef.arcana.*` is reserved).
Writing a plugin: see [PLUGIN-API.md](PLUGIN-API.md).

---

## Building from source

The project uses no build tool: only `javac` and `jar` (JDK 8 or later).

The version number is read from the `VERSION` file at the root of the repository (one line, e.g. `1.0.0`).

```
build.bat arcana          (Windows)     ./build.sh arcana          (Linux / macOS)
build.bat plugin-pak                    ./build.sh plugin-pak
build.bat all                           ./build.sh all
```

| Command | Result |
|---------|--------|
| `arcana` | `jar/Arcana-v<version>.jar`, with the version in its manifest (shown by `arcana version`) |
| `plugin-xxx` | `plugins/arcana-plugin-xxx/jar/arcana-plugin-xxx.jar` (classes + sources + manifest) |
| `all` | Arcana, then every `plugins/arcana-plugin-*` directory |

Repository layout:

```
src/                         Arcana sources (package be.stef.arcana)
plugins/arcana-plugin-xxx/   one directory per official plugin: src/, META-INF/
VERSION                      version number used by the build
build.bat, build.sh          build scripts
test/                        regression tests (samples, references, runner)
```

When running from an IDE (classes not packaged in a JAR), `arcana version` prints `Arcana (dev)`.

### Regression tests

`build.bat test` (or `./build.sh test`) builds Arcana and the plugins, then identifies, lists and extracts every sample of `test/samples` (and of your own corpus folder, `--corpus DIR` or `ARCANA_CORPUS`) and compares the results with the committed references. See [test/README.md](test/README.md).

---

## Known plugins

> **Warning.** A plugin is ordinary Java code that runs with the same rights as Arcana and the application using it.
> Being listed here is **not** a security audit nor an endorsement.
> **Always review the source code of a plugin before installing it**, download it only from its own repository, and check that the SHA-256 shown by `arcana plugins` matches the published one.

| Plugin | Description | Formats | Capabilities | Author | License | Tested with |
|--------|-------------|---------|--------------|--------|---------|-------------|
| [arcana-plugin-pak](plugins/arcana-plugin-pak) | Quake PAK archives (id Software, 1996) | `.pak` | extract, compress, recover, split | Stephane Bury | Apache-2.0 | 1.0.0 |
| [arcana-plugin-upx](plugins/arcana-plugin-upx) | Unpacks UPX-compressed executables (NRV2B/2D/2E and LZMA) for static analysis, without ever running them | Windows PE32 / PE32+, Linux ELF (by content) | extract | Stephane Bury | GPL-3.0-or-later | 1.0.0 |
| [arcana-plugin-nsis](plugins/arcana-plugin-nsis) | NSIS installer | Windows exe | extract | Stephane Bury | Apache-2.0 | 1.0.0 |


### Submit your plugin

To have your plugin listed, open an [issue](https://github.com/RealBurst/arcana/issues) titled `Plugin: <name>`, or a pull request that adds a row to the table above, with:

| Information | Example |
|-------------|---------|
| Name | `arcana-plugin-foo` |
| Repository URL (public, with the source code) | `https://github.com/you/arcana-plugin-foo` |
| Plugin id (`getId()`) | `io.github.you.foo` |
| Description: what the plugin does, in one sentence | Extracts Foo game archives |
| Formats: extensions and/or detection by content | `.foo` |
| Capabilities | extract, compress, recover, split, identify |
| Author | Your name |
| License (SPDX identifier) | `Apache-2.0`, `MIT`... |
| Arcana version it was tested with | `1.0.0` |
| Download link of the plugin JAR and its SHA-256 | link to a release of your repository |

The plugin must load without being refused (`arcana plugins` shows `[LOADED]`).
The plugin stays in your repository and under your control: you publish its updates, and the table is updated on request.

---

## License

Arcana is licensed under the Apache License 2.0 - see [LICENSE](LICENSE).

Each plugin in `plugins/` has its own license, given in the [Known plugins](#known-plugins) table.
In particular `arcana-plugin-upx` is licensed under the GPL-3.0-or-later (see [its LICENSE](plugins/arcana-plugin-upx/LICENSE)): it is a separate JAR, loaded only when you install it.

Copyright 2025 Stephane Bury
