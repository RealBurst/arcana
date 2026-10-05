#!/bin/bash
# Builds the committed test samples (test/samples) with the official tools of
# each format, from a small generated payload. Run on Linux; the samples are
# committed, so this script is only needed to add or rebuild samples.
#
# Usage: test/tools/make-samples.sh [output folder]   (default: test/samples)
#
# Tools: zip, 7zz (or 7z), rar, tar, gzip, bzip2, xz, lz4, zstd, brotli,
# compress, arj, gcab, cpio, genisoimage, wimlib-imagex, mksquashfs, ar,
# dpkg-deb, rpmbuild, xar, wixl, chmcmd, python3. A missing tool only skips
# its samples. RAR, XAR and SEVENZ may point to the binaries.
#
# After a rebuild: java ... RegressionRunner --update, then check the diff.

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
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
python3 - "$P" <<'PY'
import os, random, sys
p = sys.argv[1]
os.makedirs(p + "/docs", exist_ok=True)
os.makedirs(p + "/bin", exist_ok=True)
os.makedirs(p + "/deep/a/b/c", exist_ok=True)
os.makedirs(p + "/empty-dir", exist_ok=True)
open(p + "/readme.txt", "w", newline="\n").write("Arcana regression payload.\nEvery archive of test/samples holds these files.\n" * 20)
lines = ["%05d The quick brown fox jumps over the lazy dog, line %d of the notes.\n" % (i, i) for i in range(400)]
open(p + "/docs/notes.txt", "w", newline="\n").write("".join(lines))
open(p + "/docs/empty.txt", "w").close()
r = random.Random(20240102)
open(p + "/bin/random.bin", "wb").write(bytes(r.getrandbits(8) for _ in range(4096)))
open(p + "/deep/a/b/c/leaf.txt", "w", newline="\n").write("leaf\n")
PY
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
    rm -f "$OUT"/cab/*.cab
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
else skip "iso"; fi

if have wimlib-imagex; then
    mk wim
    rm -f "$OUT"/wim/*.wim
    for c in none xpress lzx lzms; do wimlib-imagex capture . "$OUT/wim/$c.wim" "Arcana" --compress=$c >/dev/null; done
    wimlib-imagex capture . "$OUT/wim/solid-lzms.wim" "Arcana" --solid >/dev/null
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
python3 - "$P/docs/notes.txt" "$OUT/szdd/notes.tx_" <<'PY'
# SZDD (Microsoft COMPRESS.EXE): LZSS, 4 KiB window starting at 4096-16 filled with spaces
import sys
data = open(sys.argv[1], "rb").read()
win = bytearray(b" " * 4096)
pos = 4096 - 16
out = bytearray(b"SZDD\x88\xf0\x27\x33A" + b"t" + len(data).to_bytes(4, "little"))
i = 0
heads = {}
while i < len(data):
    flags, chunk = 0, bytearray()
    for bit in range(8):
        if i >= len(data):
            break
        best_len, best_off = 0, 0
        for j in reversed(heads.get(data[i:i + 3], [])[-32:]):
            back = i - j
            if back > 4096 - 18:
                break
            n = 0
            while n < 18 and i + n < len(data) and data[j + n] == data[i + n]:
                n += 1
            if n > best_len:
                best_len, best_off = n, (pos - back) & 0xFFF
                if n == 18:
                    break
        if best_len >= 3:
            chunk += bytes([best_off & 0xFF, ((best_off >> 4) & 0xF0) | (best_len - 3)])
            step = best_len
        else:
            flags |= 1 << bit
            chunk.append(data[i])
            step = 1
        for k in range(step):
            heads.setdefault(data[i + k:i + k + 3], []).append(i + k)
            win[pos] = data[i + k]
            pos = (pos + 1) & 0xFFF
        i += step
    out.append(flags)
    out += chunk
open(sys.argv[2], "wb").write(out)
PY

# ---------------------------------------------------------------------------
# Plugins: Quake PAK, UPX (needs gcc and upx; UPX=path of the upx binary)
# ---------------------------------------------------------------------------
mk plugins/pak
python3 - "$P" "$OUT/plugins/pak/payload.pak" <<'PY'
# PACK, directory offset, directory length; entries of 64 bytes: name (56), offset, size
import os, sys
root, out = sys.argv[1], sys.argv[2]
files = []
for d, _, names in sorted(os.walk(root)):
    for n in sorted(names):
        full = os.path.join(d, n)
        files.append((os.path.relpath(full, root).replace(os.sep, "/"), open(full, "rb").read()))
body, entries, pos = bytearray(), bytearray(), 12
for name, data in files:
    entries += name.encode("ascii").ljust(56, b"\0") + pos.to_bytes(4, "little") + len(data).to_bytes(4, "little")
    body += data
    pos += len(data)
open(out, "wb").write(b"PACK" + pos.to_bytes(4, "little") + len(entries).to_bytes(4, "little") + body + entries)
PY
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
python3 - "$OUT" <<'PY'
import os, sys
out = sys.argv[1]
def src(p):
    p = os.path.join(out, p)
    return open(p, "rb").read() if os.path.exists(p) else None
def put(name, data):
    if data is not None:
        open(os.path.join(out, "damaged", name), "wb").write(data)
def flip(d, at):
    if d is None: return None
    b = bytearray(d); b[at % len(b)] ^= 0x55; return bytes(b)
z = src("zip/deflate.zip"); put("truncated.zip", z[: len(z) // 2] if z else None); put("bad-crc.zip", flip(z, 1000))
s = src("7z/lzma2.7z"); put("flipped.7z", flip(s, 64)); put("truncated.7z", s[: len(s) - 40] if s else None)
r = src("rar/rar5.rar"); put("flipped.rar", flip(r, len(r) // 2) if r else None)
r4 = src("rar/rar4.rar"); put("truncated-rar4.rar", r4[: len(r4) * 2 // 3] if r4 else None)
g = src("stream/notes.txt.gz"); put("bad-crc.gz", flip(g, len(g) - 6) if g else None)
x = src("stream/notes.txt.xz"); put("flipped.xz", flip(x, len(x) // 2) if x else None)
b = src("stream/notes.txt.bz2"); put("flipped.bz2", flip(b, len(b) // 2) if b else None)
t = src("tar/ustar.tar"); put("truncated.tar", t[:2560] if t else None)
c = src("cab/mszip.cab"); put("truncated.cab", c[: len(c) // 2] if c else None)
w = src("wim/lzx.wim"); put("flipped.wim", flip(w, 1000) if w else None)
q = src("squashfs/xz.sqfs"); put("flipped.sqfs", flip(q, 300) if q else None)
put("empty.zip", b"")
put("garbage.bin", bytes((i * 37 + 11) & 0xFF for i in range(3000)))
PY

echo "Samples written to $OUT"
