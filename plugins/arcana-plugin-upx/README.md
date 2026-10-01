# Arcana UPX plugin 0.3.0 (Java 8)

This pure Java plugin extracts supported UPX executables through Arcana 1.3+.
It never runs the input executable and does not offer compression.

## Output and supported formats

* A supported PE32 or PE32+ file produces `name.unpacked.exe` (or `.dll` / `.sys`).
  The plugin rebuilds the NT header, sections, imports, relocations, resources,
  and overlay. It reverses UPX x86/x64 filters `0x26` and `0x49`.
* A standard x86-64 ELF64 `ET_EXEC` can be reassembled. Other supported ELF
  variants produce concatenated decoded blocks in `name.upx-decoded.bin` for
  static analysis; that output is not a restored executable.
* NRV2B, NRV2D, and NRV2E are supported in their `_LE32`, `_8`, and `_LE16`
  variants. UPX LZMA (method 14) uses Arcana's bundled raw LZMA decoder;
  the plugin reads UPX's two-byte properties and supplies the known output
  size. The UPX header, bounds, and compressed/decoded Adler-32 checksums are
  verified. Output is limited to 256 MiB, and each ELF block to 64 MiB.

PE filters other than `0x26` and `0x49`, modified UPX variants, and some PE
layouts or icon resource transformations remain unsupported. The
plugin reports an error for an unsupported layout. Windows execution was not
tested in the Linux development environment.

## Installation

With a JDK 8+ and the Arcana 1.3+ JAR:

```sh
./build.sh /path/to/arcana.jar
mkdir -p "$HOME/.arcana/plugins"
cp arcana-plugin-upx.jar "$HOME/.arcana/plugins/"
arcana plugins
arcana l packed.exe
arcana x packed.exe ./output
```

On Windows, use `build.bat C:\path\to\arcana.jar`. The JAR also contains the
matching `.java` files, as required by Arcana's external plugin loader.

## Verification

UPX 5.2.1 was built from its official source. The output of this plugin is
byte-for-byte identical to `upx -d` for six independently packed NRV PE32/PE64
samples (four with default filters, two with `--no-filter`) and for the
user-supplied NRV PE32 sample containing both compressed and uncompressed
resources. This last sample exposed and fixed the resource handling error in
0.2.0. Two more PE samples (PE32 and PE64) packed with `--lzma` also match
`upx -d` byte-for-byte. A reconstructed ELF64 `ET_EXEC` matched its original
in two NRV modes and one LZMA mode.
All nine NRV variants passed synthetic decoder checks; damaged input was
rejected. The supplied executable is used only for verification and is not
included in the plugin or source archive.

Checksums prove that the compressed blocks decoded as expected. Comparison
with `upx -d` also validates PE reconstruction for the tested samples. It
does not prove that an arbitrary program will run in its target environment.

## Source and license

GPL-3.0-or-later. The NRV decoder and reconstruction routines are adapted
from UPX 5.2.1, notably `vendor/ucl/src/n2{b,d,e}_d.c`, `src/pefile.cpp`,
`src/packer_r.cpp`, and `src/filter/{cto,ctok}.h`, available under
GPL-2.0-or-later. See `LICENSE` and the source headers. Arcana's Apache-2.0
code is not included in the plugin JAR.

`getSourceUrl()` and `manifest.mf` currently reference the UPX repository
used as the source of the algorithms. Replace that URL with the public
repository for this Java plugin before publishing it.
