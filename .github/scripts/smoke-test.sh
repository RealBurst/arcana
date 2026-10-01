#!/bin/bash
# Smoke test of the built Arcana JAR, run by .github/workflows/build.yml (can also be run by hand from the
# repository root after "./build.sh all"):
#   - the version printed by the JAR matches the VERSION file;
#   - compress then extract a small directory with every compression format, plain and encrypted;
#   - compress then extract a single file with the single-file formats;
#   - every plugin JAR built from plugins/ is loaded without being refused.

set -u
cd "$(dirname "$0")/../.."

VERSION="$(head -n 1 VERSION | tr -d ' \t\r\n')"
JAR="jar/Arcana-v$VERSION.jar"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
PLUGDIR="$T/plugins"
mkdir -p "$PLUGDIR" "$T/src/sub"
echo hello > "$T/src/a.txt"
echo world > "$T/src/sub/b.txt"
FAIL=0

arcana() { java -Darcana.plugins.dir="$PLUGDIR" -jar "$JAR" "$@"; }
ok()     { echo "OK    $1"; }
ko()     { echo "FAIL  $1"; FAIL=1; }

# $1 = extraction directory, $2 = label: a.txt and b.txt must be found with their content
check_tree() {
    local a b
    a="$(find "$1" -name a.txt 2>/dev/null | head -n 1)"
    b="$(find "$1" -name b.txt 2>/dev/null | head -n 1)"
    if [ -n "$a" ] && [ -n "$b" ] && [ "$(cat "$a")" = "hello" ] && [ "$(cat "$b")" = "world" ]; then ok "$2"; else ko "$2"; fi
}

# $1 = extraction directory, $2 = label: a single file containing "hello" must be found
check_file() {
    if grep -rqx hello "$1" 2>/dev/null; then ok "$2"; else ko "$2"; fi
}

[ -f "$JAR" ] || { echo "FAIL  $JAR not found (run build.sh all first)"; exit 1; }

# 1. Version
V="$(arcana version 2>/dev/null)"
if [ "$V" = "Arcana v$VERSION" ]; then ok "version: $V"; else ko "version: expected 'Arcana v$VERSION', got '$V'"; fi

# 2. Directory round trip, every compression format
for f in zip 7z tar tar.gz tar.bz2 tar.xz tar.lz4 lzh cab; do
    if arcana c "$T/src" "$T/test.$f" > /dev/null 2>&1 && arcana x "$T/test.$f" -o "$T/out-$f" > /dev/null 2>&1; then check_tree "$T/out-$f" "round trip $f"; else ko "round trip $f (command failed)"; fi
done

# 3. Encrypted archives, 7z at the highest level
for f in zip 7z; do
    if arcana c "$T/src" "$T/secure.$f" -p "s3cret" -l 9 > /dev/null 2>&1 && arcana x "$T/secure.$f" -o "$T/sec-$f" -p "s3cret" > /dev/null 2>&1; then check_tree "$T/sec-$f" "encrypted $f (-l 9)"; else ko "encrypted $f (command failed)"; fi
done

# 4. Single-file formats
for f in gz bz2 xz; do
    if arcana c "$T/src/a.txt" "$T/single.$f" > /dev/null 2>&1 && arcana x "$T/single.$f" -o "$T/one-$f" > /dev/null 2>&1; then check_file "$T/one-$f" "single file $f"; else ko "single file $f (command failed)"; fi
done

# 5. Plugins built from plugins/: all must load
set -- plugins/*/jar/*.jar
if [ -e "$1" ]; then
    cp plugins/*/jar/*.jar "$PLUGDIR/"
    OUT="$(arcana plugins 2>&1)"
    echo "$OUT" | grep -E "^\[(LOADED|REFUSED)\]" | sed 's/^/      /'
    if echo "$OUT" | grep -q "REFUSED"; then ko "plugins: at least one plugin is refused"; else ok "plugins: $# JAR(s) loaded"; fi
else
    echo "SKIP  plugins: no plugin JAR built"
fi

echo
if [ "$FAIL" -ne 0 ]; then echo "Smoke test FAILED"; exit 1; fi
echo "Smoke test passed"
