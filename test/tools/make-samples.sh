#!/bin/bash
# Optional Linux tool: rebuilds the test samples (test/samples) with the
# official tools of each format, from a small generated payload. The samples
# are committed, so this script is only needed to add or rebuild samples; the
# regression tests themselves (build.sh test / build.bat test) never need it.
#
# Usage: test/tools/make-samples.sh [output folder]   (default: test/samples)
# Build first (./build.sh test): the hand-made samples come from test/bin.
#
# Tools: zip, 7zz (or 7z), rar, tar, gzip, bzip2, xz, lz4, zstd, brotli,
# compress, arj, gcab, cpio, genisoimage, wimlib-imagex, mksquashfs, ar,
# dpkg-deb, rpmbuild, xar, wixl, chmcmd, gcc, upx, java. A missing tool only
# skips its samples. RAR, XAR, SEVENZ and UPX may point to the binaries.
#
# The payload and the hand-made samples (crafted or patched files: SZDD, PAK,
# SFX, damaged files, WinZip AES variants, Zstandard skippable frames, LZX
# uncompressed block...) come from be.stef.arcana.test.SampleGenerator (pure
# Java, test/src; it also runs on Windows). No Python is needed.
# test/samples/cab/arcana-created.cab is made by Arcana itself (arcana c) and
# is not rebuilt here.
#
# After a rebuild: java ... RegressionRunner --update, then check the diff.

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ ! -f "$ROOT/test/bin/be/stef/arcana/test/SampleGenerator.class" ]; then
    echo "build first: ./build.sh test"
    exit 1
fi
GEN=(java -cp "$ROOT/bin:$ROOT/test/bin" be.stef.arcana.test.SampleGenerator)
OUT="${1:-$ROOT/test/samples}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SEVENZ="${SEVENZ:-$(command -v 7zz || command -v 7z || true)}"
RAR="${RAR:-$(command -v rar || true)}"
XAR="${XAR:-$(command -v xar || true)}"
export TZ=UTC
STAMP="2024-01-02 03:04:05"
PASSWORD="secret"

have() { [ -n "$1" ] && command -v "$1" >/dev/null 2>&1; }
skip() { echo "skipped: $*"; }
mk() { mkdir -p "$OUT/$1"; }

# ---------------------------------------------------------------------------
# Payload: text, compressible text, random bytes, empty file, deep tree, empty folder
# ---------------------------------------------------------------------------
P="$WORK/payload"
"${GEN[@]}" payload "$P" || exit 1
N="$WORK/names"
mkdir -p "$N"
printf 'accented name\n' > "$N/$(printf 'caf\xc3\xa9 \xc3\xa0 la cr\xc3\xa8me.txt')"
printf 'long name\n' > "$N/$(printf 'a%.0s' $(seq 1 120)).txt"
find "$WORK" -exec touch -h -d "$STAMP" {} +
cd "$P"

# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------
mk zip
rm -f "$OUT"/zip/*.zip
zip -q -X -r -0 "$OUT/zip/store.zip" .
zip -q -X -r -9 "$OUT/zip/deflate.zip" .
zip -q -X -r -P "$PASSWORD" "$OUT/zip/zipcrypto.zip" .
(cd "$N" && zip -q -X -r "$OUT/zip/names-utf8.zip" .)
if have "$SEVENZ"; then
    "$SEVENZ" a -bso0 -tzip -mm=BZip2 "$OUT/zip/bzip2.zip" . >/dev/null
    "$SEVENZ" a -bso0 -tzip -mm=LZMA "$OUT/zip/lzma.zip" . >/dev/null
    "$SEVENZ" a -bso0 -tzip -mm=Deflate64 "$OUT/zip/deflate64.zip" . >/dev/null
    "$SEVENZ" a -bso0 -tzip -mem=AES256 -p"$PASSWORD" "$OUT/zip/aes256.zip" . >/dev/null
else skip "zip (7-Zip methods)"; fi
# WinZip AES: tampered data (only the authentication code detects it) and a UTF-8 password
# (7-Zip refuses non-ASCII passwords when it creates a ZIP: written by SampleGenerator)
[ -f "$OUT/zip/aes256.zip" ] && "${GEN[@]}" zip-aes-tampered "$OUT" || skip "zip aes256-tampered"
"${GEN[@]}" zip-aes-utf8 "$P" "$OUT/zip/aes256-utf8-password.zip" || skip "zip aes256-utf8-password"

# ---------------------------------------------------------------------------
# 7z
# ---------------------------------------------------------------------------
if have "$SEVENZ"; then
    mk 7z
    rm -f "$OUT"/7z/*.7z
    "$SEVENZ" a -bso0 -m0=LZMA2 "$OUT/7z/lzma2.7z" . >/dev/null
    "$SEVENZ" a -bso0 -m0=LZMA "$OUT/7z/lzma.7z" . >/dev/null
    "$SEVENZ" a -bso0 -m0=PPMd "$OUT/7z/ppmd.7z" . >/dev/null
    "$SEVENZ" a -bso0 -m0=BZip2 "$OUT/7z/bzip2.7z" . >/dev/null
    "$SEVENZ" a -bso0 -m0=Deflate "$OUT/7z/deflate.7z" . >/dev/null
    "$SEVENZ" a -bso0 -m0=Copy "$OUT/7z/copy.7z" . >/dev/null
    "$SEVENZ" a -bso0 -ms=off "$OUT/7z/not-solid.7z" . >/dev/null
    "$SEVENZ" a -bso0 -mf=Delta:4 "$OUT/7z/delta.7z" . >/dev/null
    "$SEVENZ" a -bso0 -p"$PASSWORD" "$OUT/7z/encrypted.7z" . >/dev/null
    "$SEVENZ" a -bso0 -p"$PASSWORD" -mhe=on "$OUT/7z/encrypted-headers.7z" . >/dev/null
    (cd "$N" && "$SEVENZ" a -bso0 "$OUT/7z/names-utf8.7z" . >/dev/null)
else skip "7z"; fi

# ---------------------------------------------------------------------------
# RAR (rar 5+; -ma4 = RAR 4 format)
# ---------------------------------------------------------------------------
if have "$RAR"; then
    mk rar
    rm -rf "$OUT"/rar/*
    "$RAR" a -idq -r -tsm- -tsc- -tsa- "$OUT/rar/rar5.rar" . >/dev/null
    "$RAR" a -idq -r -s "$OUT/rar/rar5-solid.rar" . >/dev/null
    "$RAR" a -idq -r -p"$PASSWORD" "$OUT/rar/rar5-encrypted.rar" . >/dev/null
    "$RAR" a -idq -r -hp"$PASSWORD" "$OUT/rar/rar5-encrypted-headers.rar" . >/dev/null
    "$RAR" a -idq -r -ma4 "$OUT/rar/rar4.rar" . >/dev/null
    "$RAR" a -idq -r -ma4 -s "$OUT/rar/rar4-solid.rar" . >/dev/null
    "$RAR" a -idq -r -ma4 -p"$PASSWORD" "$OUT/rar/rar4-encrypted.rar" . >/dev/null
    "$RAR" a -idq -r -ma4 -hp"$PASSWORD" "$OUT/rar/rar4-encrypted-headers.rar" . >/dev/null
    mkdir -p "$OUT/rar/volumes"
    "$RAR" a -idq -r -m0 -v8k "$OUT/rar/volumes/rar5-volumes.rar" . >/dev/null
    (cd "$N" && "$RAR" a -idq -r "$OUT/rar/names-utf8.rar" . >/dev/null)
else skip "rar"; fi

# ---------------------------------------------------------------------------
# TAR and compressed streams
# ---------------------------------------------------------------------------
mk tar
TAROPT=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="$STAMP")
tar "${TAROPT[@]}" --format=ustar -cf "$OUT/tar/ustar.tar" .
tar "${TAROPT[@]}" --format=gnu -cf "$OUT/tar/gnu.tar" -C "$N" .
tar "${TAROPT[@]}" --format=pax -cf "$OUT/tar/pax.tar" -C "$N" .
tar "${TAROPT[@]}" -cf - . | gzip -n -9 > "$OUT/tar/payload.tar.gz"
tar "${TAROPT[@]}" -cf - . | bzip2 -9 > "$OUT/tar/payload.tar.bz2"
tar "${TAROPT[@]}" -cf - . | xz -6 > "$OUT/tar/payload.tar.xz"
have zstd && tar "${TAROPT[@]}" -cf - . | zstd -q -19 > "$OUT/tar/payload.tar.zst"
have lz4 && tar "${TAROPT[@]}" -cf - . | lz4 -q -9 > "$OUT/tar/payload.tar.lz4"
have brotli && tar "${TAROPT[@]}" -cf - . | brotli -c > "$OUT/tar/payload.tar.br"

mk stream
F="$P/docs/notes.txt"
gzip -n -9 -c "$F" > "$OUT/stream/notes.txt.gz"
bzip2 -9 -c "$F" > "$OUT/stream/notes.txt.bz2"
xz -c "$F" > "$OUT/stream/notes.txt.xz"
xz --format=lzma -c "$F" > "$OUT/stream/notes.txt.lzma"
have zstd && zstd -q -c "$F" > "$OUT/stream/notes.txt.zst"
have lz4 && lz4 -q -c "$F" > "$OUT/stream/notes.txt.lz4"
have brotli && brotli -c "$F" > "$OUT/stream/notes.txt.br"
have compress && compress -c "$F" > "$OUT/stream/notes.txt.Z"
have compress && seq 1 10000 | compress -b 12 -c > "$OUT/stream/seq-b12.txt.Z"
# Zstandard: frames without content size larger than the window (small window
# forced with wlog=10), concatenated frames, skippable frames, detection by content
if have zstd; then
    tar "${TAROPT[@]}" -cf - . | zstd -q -19 --zstd=wlog=10 > "$OUT/tar/payload-pipe.tar.zst"
    seq 1 12000 | zstd -q -19 --zstd=wlog=10 > "$OUT/stream/seq-nosize.txt.zst"
    { zstd -q -c "$F"; zstd -q -c < "$F"; } > "$OUT/stream/two-frames.txt.zst"
    zstd -q -c --zstd=wlog=10 < "$F" > "$WORK/notes-pipe.zst"
    "${GEN[@]}" zstd-skippable "$WORK/notes-pipe.zst" "$OUT/stream/skippable.txt.zst"
    cp "$OUT/stream/notes.txt.zst" "$OUT/stream/zstd-no-extension.bin"
else skip "zstd (window, frames)"; fi

# ---------------------------------------------------------------------------
# ARJ, CAB, CPIO, AR / DEB
# ---------------------------------------------------------------------------
if have arj; then
    mk arj
    rm -f "$OUT"/arj/*.arj
    for m in 0 1 4; do arj a -r -y -m$m "$OUT/arj/method$m.arj" readme.txt docs/notes.txt bin/random.bin >/dev/null; done
    arj a -r -y -g"$PASSWORD" "$OUT/arj/garbled.arj" readme.txt docs/notes.txt >/dev/null
else skip "arj"; fi

if have gcab; then
    mk cab
    rm -f "$OUT"/cab/stored.cab "$OUT"/cab/mszip.cab
    gcab -c "$OUT/cab/stored.cab" readme.txt docs/notes.txt bin/random.bin
    gcab -c -z "$OUT/cab/mszip.cab" readme.txt docs/notes.txt bin/random.bin
else skip "cab"; fi

mk cpio
for f in newc odc crc bin; do find . | sort | cpio -o -H $f --quiet > "$OUT/cpio/$f.cpio"; done

mk ar
rm -f "$OUT/ar/files.a"
ar rcD "$OUT/ar/files.a" readme.txt docs/notes.txt bin/random.bin
if have dpkg-deb; then
    D="$WORK/deb"
    mkdir -p "$D/DEBIAN" "$D/usr/share/arcana-test"
    printf 'Package: arcana-test\nVersion: 1.0\nArchitecture: all\nMaintainer: Arcana <test@example.org>\nDescription: Arcana regression sample\n' > "$D/DEBIAN/control"
    cp -r . "$D/usr/share/arcana-test/"
    find "$D" -exec touch -h -d "$STAMP" {} +
    SOURCE_DATE_EPOCH=1704164645 dpkg-deb --root-owner-group -Zxz -b "$D" "$OUT/ar/arcana-test.deb" >/dev/null
fi

# ---------------------------------------------------------------------------
# RPM
# ---------------------------------------------------------------------------
if have rpmbuild; then
    mk rpm
    R="$WORK/rpm"
    mkdir -p "$R/SPECS"
    cat > "$R/SPECS/t.spec" <<SPEC
Name: arcana-test
Version: 1.0
Release: 1
Summary: Arcana regression sample
License: Apache-2.0
BuildArch: noarch
%description
Arcana regression sample.
%install
mkdir -p %{buildroot}/usr/share/arcana-test
cp -r $P/. %{buildroot}/usr/share/arcana-test/
%files
/usr/share/arcana-test
SPEC
    for z in gzdio bzdio xzdio zstdio; do
        rm -rf "$R/RPMS"
        SOURCE_DATE_EPOCH=1704164645 rpmbuild -bb --quiet --define "_topdir $R" --define "_binary_payload w9.$z" "$R/SPECS/t.spec" >/dev/null 2>&1 && cp "$R"/RPMS/noarch/*.rpm "$OUT/rpm/payload-${z%dio}.rpm" || skip "rpm $z (rpmbuild failed)"
    done
else skip "rpm"; fi

# ---------------------------------------------------------------------------
# Disk images and file systems
# ---------------------------------------------------------------------------
if have genisoimage; then
    mk iso
    genisoimage -quiet -o "$OUT/iso/joliet-rr.iso" -J -R -V ARCANA . 2>/dev/null
    genisoimage -quiet -o "$OUT/iso/level1.iso" -V ARCANA . 2>/dev/null
    genisoimage -quiet -o "$OUT/iso/udf-bridge.iso" -udf -J -R -V ARCANA . 2>/dev/null
    D="$WORK/rr-deep"
    mkdir -p "$D/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10"
    printf 'top\n' > "$D/top.txt"
    printf 'mid\n' > "$D/d1/d2/d3/d4/d5/d6/d7/d8/mid.txt"
    printf 'leaf\n' > "$D/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/leaf.txt"
    find "$D" -exec touch -h -d "$STAMP" {} +
    genisoimage -quiet -o "$OUT/iso/rr-deep.iso" -R -V ARCANA "$D" 2>/dev/null
else skip "iso"; fi

if have wimlib-imagex; then
    mk wim
    rm -f "$OUT"/wim/*.wim
    for c in none xpress lzx lzms; do wimlib-imagex capture . "$OUT/wim/$c.wim" "Arcana" --compress=$c >/dev/null; done
    wimlib-imagex capture . "$OUT/wim/solid-lzms.wim" "Arcana" --solid >/dev/null
    # LZX chunks with an uncompressed block (wimlib never writes one)
    "${GEN[@]}" wim-lzx-uncompressed "$WORK" "$OUT/wim/lzx-uncompressed-block.wim"
else skip "wim"; fi

if have mksquashfs; then
    mk squashfs
    for c in gzip xz zstd lz4; do mksquashfs . "$OUT/squashfs/$c.sqfs" -comp $c -noappend -quiet -all-root -mkfs-time 1704164645 -all-time 1704164645 >/dev/null 2>&1 || skip "squashfs $c"; done
else skip "squashfs"; fi

# ---------------------------------------------------------------------------
# XAR, MSI, CHM, SZDD
# ---------------------------------------------------------------------------
if have "$XAR"; then
    mk xar
    "$XAR" -cf "$OUT/xar/gzip.xar" . 2>/dev/null
    "$XAR" -cf "$OUT/xar/bzip2.xar" --compression=bzip2 . 2>/dev/null
    "$XAR" -cf "$OUT/xar/none.xar" --compression=none . 2>/dev/null
else skip "xar"; fi

if have wixl; then
    mk msi
    W="$WORK/msi"
    mkdir -p "$W"
    cp readme.txt docs/notes.txt bin/random.bin "$W/"
    cat > "$W/t.wxs" <<'WXS'
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="11111111-0000-0000-0000-000000000001" Name="ArcanaTest" Language="1033" Version="1.0.0" Manufacturer="Arcana" UpgradeCode="12345678-1234-1234-1234-123456789012">
    <Package InstallerVersion="200" Compressed="yes" />
    <Media Id="1" Cabinet="data.cab" EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLDIR" Name="ArcanaTest">
          <Component Id="C1" Guid="11111111-2222-3333-4444-555555555555">
            <File Id="F1" Source="readme.txt" />
            <File Id="F2" Source="random.bin" />
            <File Id="F3" Source="notes.txt" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="C1" /></Feature>
  </Product>
</Wix>
WXS
    (cd "$W" && wixl -o "$OUT/msi/package.msi" t.wxs) || skip "msi (wixl failed)"
else skip "msi"; fi

if have chmcmd; then
    mk chm
    C="$WORK/chm"
    mkdir -p "$C/pages"
    printf '<html><head><title>Index</title></head><body><a href="pages/p1.html">p1</a></body></html>\n' > "$C/index.html"
    for i in 1 2 3; do sed "s/^/<p>/" "$P/docs/notes.txt" | sed "1i <html><body><h1>Page $i</h1>" > "$C/pages/p$i.html"; done
    printf '[OPTIONS]\nCompiled file=help.chm\nDefault topic=index.html\nTitle=Arcana\n\n[FILES]\nindex.html\npages/p1.html\npages/p2.html\npages/p3.html\n' > "$C/t.hhp"
    (cd "$C" && chmcmd t.hhp >/dev/null 2>&1 && cp help.chm "$OUT/chm/help.chm") || skip "chm (chmcmd failed)"
else skip "chm"; fi

mk szdd
# SZDD (Microsoft COMPRESS.EXE): LZSS, 4 KiB window starting at 4096-16 filled with spaces
"${GEN[@]}" szdd "$P/docs/notes.txt" "$OUT/szdd/notes.tx_"
cp "$OUT/szdd/notes.tx_" "$OUT/szdd/UPPER.TX_"

# ---------------------------------------------------------------------------
# SFX: minimal PE whose section holds a ZIP that does not end at the end of the file
# ---------------------------------------------------------------------------
mk sfx
"${GEN[@]}" sfx-zip-inside "$P" "$OUT/sfx/zip-inside-image.exe"

# ---------------------------------------------------------------------------
# Plugins: Quake PAK, UPX (needs gcc and upx; UPX=path of the upx binary)
# ---------------------------------------------------------------------------
mk plugins/pak
"${GEN[@]}" pak "$P" "$OUT/plugins/pak/payload.pak"
UPX="${UPX:-$(command -v upx || true)}"
if have "$UPX" && have gcc; then
    mk plugins/upx
    rm -f "$OUT"/plugins/upx/*.upx
    printf '#include <stdio.h>\nint main(void){puts("Arcana UPX sample");return 0;}\n' > "$WORK/hello.c"
    gcc -static -Os -s -o "$WORK/hello" "$WORK/hello.c" && "$UPX" -q --best -o "$OUT/plugins/upx/hello-elf.upx" "$WORK/hello" >/dev/null && "$UPX" -q --lzma -o "$OUT/plugins/upx/hello-elf-lzma.upx" "$WORK/hello" >/dev/null || skip "upx (build failed)"
else skip "upx"; fi

# ---------------------------------------------------------------------------
# Damaged samples: Arcana must report an error, never hang or crash
# ---------------------------------------------------------------------------
mk damaged
# flipped and truncated copies of the samples above, empty.zip, garbage.bin, crafted ISO images
"${GEN[@]}" damaged "$OUT"
cp "$OUT/rar/rar5-encrypted-headers.rar" "$OUT/damaged/wrong-password-rar5.rar" 2>/dev/null || skip "wrong-password-rar5.rar"
cp "$OUT/rar/rar4-encrypted-headers.rar" "$OUT/damaged/wrong-password-rar4.rar" 2>/dev/null || skip "wrong-password-rar4.rar"
if have "$SEVENZ"; then
    rm -f "$WORK/aes-rounds.7z"
    "$SEVENZ" a -bso0 -p"$PASSWORD" -mhc=off "$WORK/aes-rounds.7z" readme.txt >/dev/null
    "${GEN[@]}" 7z-aes-rounds "$WORK/aes-rounds.7z" "$OUT/damaged/7z-aes-rounds.7z"
else skip "7z-aes-rounds.7z"; fi

echo "Samples written to $OUT"
