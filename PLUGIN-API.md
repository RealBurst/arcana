# Arcana Plugin API

A plugin adds support for an archive or file format that Arcana does not handle natively.
It is a single JAR dropped into a plugin directory. No change to Arcana is needed.

Plugins require **Arcana 1.0.0 or later** and **Java 8 or later**.

---

## Rules enforced at load time

A plugin JAR is **refused** unless all of the following conditions are met:

1. **Source code included.** Every `.class` in the JAR must have its `.java` source at the same path (`com/example/Foo.class` requires `com/example/Foo.java`; paths under `src/` and `src/main/java/` are also accepted). Nested classes (`Foo$Bar.class`) are covered by the source of their enclosing class.

2. **Source URL and license declared.** By the plugin (`getSourceUrl()`, `getLicense()`, both mandatory in `ArcanaPlugin`). When one of them returns `null` or an empty string, the JAR manifest attributes `Arcana-Plugin-Source-Url` and `Arcana-Plugin-License` are used instead.

3. **Unique plugin id.** No other loaded plugin may share the same id.

4. **Own namespace.** No class in the JAR may use the package `be.stef.arcana` or any of its sub-packages. That namespace is reserved for Arcana itself. Use your own: `io.github.yourname.arcana.plugin.xxx` is the recommended pattern.

Refused plugins are reported on **every** run of Arcana (one line per plugin with the reason, on the error output), and in detail by `arcana plugins`.

> **Security.** A plugin is ordinary Java code that runs with the rights of the application using Arcana. The mandatory sources make it possible to review what it does; the SHA-256 of each JAR is shown by `arcana plugins` to identify exactly which binary is loaded. Only install plugins you trust.

---

## Namespace convention

| Who | Package root |
|-----|--------------|
| Arcana core (reserved) | `be.stef.arcana.*` |
| Your official plugin | `io.github.yourname.arcana.plugin.<format>` |
| Any other scheme | your own reverse-domain prefix |

A plugin that puts classes in `be.stef.arcana.*` is refused with a clear error message.

---

## Writing a format plugin

### 1. Implement `be.stef.arcana.plugin.ArcanaPlugin`

```java
package io.github.example.arcana.plugin.foo;

import be.stef.arcana.plugin.ArcanaPlugin;
import be.stef.arcana.extractor.ArchiveExtractor;
import be.stef.arcana.compressor.ArchiveCompressor;
import java.io.IOException;

public final class FooPlugin implements ArcanaPlugin {

    public String getId()           { return "io.github.example.foo"; }  // unique, reverse domain
    public String getName()         { return "Foo archive"; }
    public String getVersion()      { return "1.0.0"; }
    public String getAuthor()       { return "Your Name"; }
    public String getSourceUrl()    { return "https://github.com/example/arcana-plugin-foo"; }
    public String getLicense()      { return "Apache-2.0"; }             // SPDX identifier
    public String[] getExtensions() { return new String[]{"foo"}; }
    public int getProbeSize()       { return 16; }                       // bytes given to matches()

    // Detection by magic bytes (header) and/or extension
    public boolean matches(byte[] header, String fileName) {
        return header.length >= 4
            && header[0] == (byte) 'F' && header[1] == (byte) 'O'
            && header[2] == (byte) 'O' && header[3] == 0;
    }

    public ArchiveExtractor createExtractor(byte[] password) throws IOException {
        return new FooExtractor();
    }

    // Return null if this plugin is extraction-only
    public ArchiveCompressor createCompressor(int level) throws IOException {
        return null;
    }
}
```

The implementation must have a **public no-argument constructor** and must be **thread-safe** (one instance serves every extraction).

### Optional methods

| Method | Default | Purpose |
|--------|---------|---------|
| `getAuthor()` | `""` | Author or organization shown by `arcana plugins` |
| `getProbeSize()` | `512` | Number of bytes of the file start passed to `matches()` |
| `getPriority()` | `0` | Greater than 0: consulted **before** built-in formats (to replace one) |
| `createCompressor(int level)` | `null` | Compressor for the format; null = extraction only |
| `createCompressor(int level, byte[] password)` | delegates to above | Encrypting compressor; override if the format supports encryption |
| `createRecoverer(byte[] password)` | `null` | Recovery strategy for a damaged archive (`arcana r`) |
| `createProbe()` | `null` | Carving probe for `arcana s`: recognizes the format embedded in another file |

These are **capabilities, not separate plugin types**: implement only those your format supports.

### 2. Implement the extractor

The extractor implements `be.stef.arcana.extractor.ArchiveExtractor`:

| Method | Purpose |
|--------|---------|
| `extract(File archive, File destination)` | Extract every entry to the destination directory |
| `extract(InputStream in, File destination)` | Same from a stream (copy to a temp file if random access is needed) |
| `list(File archive)` | Return entries built with `new ArcanaEntry.Builder(name)...build()` |
| `supportsStream()` | Return `true` if `extract(InputStream, ...)` is implemented |

**Always create output files with `PluginSupport.openOutput(destination, entryName)`** and directories with `PluginSupport.createDirectory(destination, entryName)`. This gives your plugin the same protections as the built-in formats: path sanitization (no absolute paths, no `..`, no characters forbidden on Windows) and Arcana's extraction limits (decompression bombs, free disk space).

Throw an `IOException` (preferably `be.stef.arcana.exceptions.ArcanaCorruptedException`) on damaged data. Arcana reports it and `arcana r` (forced extraction) keeps whatever was written before the error.

### 3. Optionally implement the compressor

The compressor implements `be.stef.arcana.compressor.ArchiveCompressor`:

| Method | Purpose |
|--------|---------|
| `compress(File source, File archive)` | Compress a file or directory tree |
| `compress(File source, OutputStream out)` | Same to an output stream |
| `supportsDirectories()` | Return `true` if directories (not just single files) are supported |

### 4. Declare the service

Create the file `META-INF/services/be.stef.arcana.plugin.ArcanaPlugin` with one fully qualified class name per line:

```
io.github.example.arcana.plugin.foo.FooPlugin
```

### 5. Package: classes and sources in one JAR

The JAR must contain both the compiled classes and the `.java` source files. A minimal build script:

With plain `javac` and `jar` (the manifest must contain the `Arcana-Plugin-*` attributes if the plugin does not declare them):

```
javac -source 8 -target 8 -cp Arcana-v1.0.0.jar -d classes src/io/github/example/arcana/plugin/foo/*.java
cp -r src/. classes/                    (Windows: xcopy /E /Y src\. classes\)
cp -r META-INF classes/                 (Windows: xcopy /E /Y META-INF\. classes\META-INF\)
jar cfm arcana-plugin-foo.jar META-INF/MANIFEST.MF -C classes .
```

Inside the Arcana repository, `build.bat plugin-foo` / `./build.sh plugin-foo` does all of this for `plugins/arcana-plugin-foo/` (directories `src/` and `META-INF/`).

Alternatively, place the source under `src/` inside the JAR: `src/io/github/example/arcana/plugin/foo/FooPlugin.java` is also accepted.

---

## Writing an analyzer plugin

An analyzer inspects any file and reports its type, version and details without extracting anything. Unlike a format plugin, it is not tied to one archive format: it can recognize executables, images, databases, and so on.

Built-in analyzers already identify PE / ELF / Mach-O executables, .NET single-file bundles, archive formats, images (PNG / JPEG / GIF / BMP / TIFF / WebP with dimensions), PDF, SQLite, OLE2 documents, fonts and media containers.

### Implement `be.stef.arcana.analyze.ArcanaAnalyzer`

```java
package io.github.example.arcana.analyzer;

import be.stef.arcana.analyze.ArcanaAnalyzer;
import be.stef.arcana.analyze.Identification;
import be.stef.arcana.formats.carve.ByteSource;
import java.io.IOException;

public final class MyAnalyzer implements ArcanaAnalyzer {

    public String getId()        { return "io.github.example.myformat"; }
    public String getSourceUrl() { return "https://github.com/example/arcana-plugin-foo"; }
    public String getLicense()   { return "Apache-2.0"; }

    public Identification analyze(ByteSource s, String fileName) throws IOException {
        if (s.length() < 2 || s.u8(0) != 'M' || s.u8(1) != 'Y') return null; // not my format
        return Identification.of("document", "MYFMT")
            .version("2")
            .description("My format v2")
            .build();
    }
}
```

Declare it in `META-INF/services/be.stef.arcana.analyze.ArcanaAnalyzer`. A single JAR may hold both a format plugin and an analyzer. Analyzers are consulted from highest `getPriority()` to lowest; the first that returns a non-null result wins. When none matches, `arcana i` falls back to the format detection.

---

## Installing a plugin

Copy the plugin JAR into one of these directories:

- `<user home>/.arcana/plugins/`
- `plugins/` next to the Arcana JAR
- `plugins/` in the working directory

or set `-Darcana.plugins.dir=<dir1><path separator><dir2>...` (replaces the default directories).

Check with `arcana plugins`, then use the format like any built-in one:

```
arcana l  game.foo
arcana x  game.foo  ./out
arcana x  data.bin  ./out  -f foo          # force the plugin: id or extension
arcana c  ./dir     game.foo               # if the plugin has a compressor
```

From Java:

```java
Arcana.extractTo(file, dest);                              // auto-detect
Arcana.withPlugin("io.github.example.foo", null).extract(stream, dest); // forced
```

---

## Detection order

1. Plugins with `getPriority() > 0`, highest priority first.
2. Arcana's built-in formats recognized by their content (magic bytes, ISO signature).
3. All other plugins in load order: first whose `matches()` returns true.
4. Arcana's built-in detection by file extension, then the self-extracting archive search.

A plugin at default priority (0) therefore cannot hijack a built-in format. A plugin with a higher priority can, intentionally, and `arcana formats` / `arcana plugins` will show it.

The format names given to `-f` / `-t` follow the same order: priority plugins, built-in names (`zip`, `tar.gz`, `tgz`...), then other plugins (id or extension). For `arcana c` without `-t`, the longest known extension of the archive name is used (`backup.tar.gz` gives `tar.gz`).

A plugin that throws in `matches()` is silently ignored for that file.

---

## Testing during development

Plugins found on the application class path (through `META-INF/services`) are loaded **without** the source check: useful to test from the IDE in the same project as Arcana.

A plugin can also be registered by code:

```java
PluginManager.get().register(new FooPlugin());
```

The source check and namespace check only apply to plugin JARs loaded from the plugin directories. This is the distribution mechanism, not the development one.

---

## Getting your plugin listed

The known plugins are listed at the end of the [README](README.md#known-plugins).
To have yours added, follow [Submit your plugin](README.md#submit-your-plugin): a public repository with the source code is required.
