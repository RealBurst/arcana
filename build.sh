#!/bin/bash
# Build script for Arcana and its plugins.
# Usage: ./build.sh [arcana | plugin-pak | plugin-upx | all | test [runner options]]

ROOT="$(cd "$(dirname "$0")" && pwd)"
ARCANA_VERSION=""
[ -f "$ROOT/VERSION" ] && ARCANA_VERSION="$(head -n 1 "$ROOT/VERSION" | tr -d ' \t\r\n')"
if [ -z "$ARCANA_VERSION" ]; then
    echo "ERROR: file \"$ROOT/VERSION\" missing or empty (expected content: 1.0.0)"
    exit 1
fi
ARCANA_JAR="$ROOT/jar/Arcana-v$ARCANA_VERSION.jar"
TMPDIR_BUILD="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_BUILD"' EXIT

usage() {
    echo "Usage: build.sh [arcana | plugin-pak | plugin-upx | all | test [runner options]]"
    echo "  test: builds Arcana and the plugins, then runs the regression tests"
    echo "        (options: --update, --corpus DIR, filter; see test/README.md)"
    exit 1
}

# Write the list of .java files of a source directory to a javac @file.
# Each path is quoted so that directories containing spaces are supported.
write_sources() {
    local srcdir="$1" listfile="$2"
    : > "$listfile"
    find "$srcdir" -name "*.java" -print0 | while IFS= read -r -d '' f; do
        printf '"%s"\n' "$f" >> "$listfile"
    done
    if [ ! -s "$listfile" ]; then
        echo "ERROR: no .java file found in $srcdir"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Build arcana.jar from src/ into bin/
# ---------------------------------------------------------------------------
do_build_arcana() {
    echo "Building Arcana v$ARCANA_VERSION..."
    local bin="$ROOT/bin"
    local list="$TMPDIR_BUILD/arcana_sources.txt"
    local manifest="$TMPDIR_BUILD/arcana_manifest.txt"
    rm -rf "$bin" && mkdir -p "$bin" || return 1
    write_sources "$ROOT/src" "$list" || return 1
    javac -Xlint:-options -source 8 -target 8 -d "$bin" @"$list" || return 1
    mkdir -p "$ROOT/jar"
    {
        echo "Main-Class: be.stef.arcana.Arcana"
        echo "Implementation-Title: Arcana"
        echo "Implementation-Version: $ARCANA_VERSION"
        echo "Implementation-Vendor: Stephane Bury"
    } > "$manifest"
    jar cfm "$ARCANA_JAR" "$manifest" -C "$bin" . || return 1
    echo "Done: $ARCANA_JAR"
    return 0
}

# ---------------------------------------------------------------------------
# Build one plugin: $1 = plugin directory, $2 = plugin name
# ---------------------------------------------------------------------------
do_build_plugin() {
    local pdir="${1%/}" pname="$2"
    local pbin="$pdir/bin" pjar="$pdir/jar/$pname.jar"
    local list="$TMPDIR_BUILD/plugin_sources.txt"
    local cp=""
    echo "Building $pname..."

    if [ -f "$ROOT/bin/be/stef/arcana/Arcana.class" ]; then
        cp="$ROOT/bin"
    elif [ -f "$ARCANA_JAR" ]; then
        cp="$ARCANA_JAR"
    else
        echo "ERROR: Arcana classes not found. Expected \"$ROOT/bin\" or \"$ARCANA_JAR\"."
        return 1
    fi
    echo "Classpath: $cp"

    rm -rf "$pbin" && mkdir -p "$pbin" || return 1
    write_sources "$pdir/src" "$list" || return 1
    javac -Xlint:-options -source 8 -target 8 -cp "$cp" -d "$pbin" @"$list" || return 1

    cp -r "$pdir/src/." "$pbin/" || return 1
    if [ -d "$pdir/META-INF" ]; then
        mkdir -p "$pbin/META-INF"
        cp -r "$pdir/META-INF/." "$pbin/META-INF/" || return 1
    fi
    mkdir -p "$pdir/jar"
    if [ -f "$pbin/META-INF/MANIFEST.MF" ]; then
        jar cfm "$pjar" "$pbin/META-INF/MANIFEST.MF" -C "$pbin" . || return 1
    else
        jar cf "$pjar" -C "$pbin" . || return 1
    fi
    echo "Done: $pjar"
    return 0
}

# ---------------------------------------------------------------------------
# Regression tests: build everything, compile test/src, run the runner
# ---------------------------------------------------------------------------
do_test() {
    do_build_arcana || return 1
    local d
    for d in "$ROOT/plugins/arcana-plugin-"*/; do
        [ -d "$d" ] || continue
        do_build_plugin "$d" "$(basename "$d")" || return 1
    done
    local tbin="$ROOT/test/bin" list="$TMPDIR_BUILD/test_sources.txt"
    rm -rf "$tbin" && mkdir -p "$tbin" || return 1
    write_sources "$ROOT/test/src" "$list" || return 1
    javac -Xlint:-options -source 8 -target 8 -cp "$ROOT/bin" -d "$tbin" @"$list" || return 1
    echo
    (cd "$ROOT" && LC_ALL=C.UTF-8 java -cp "$ROOT/bin:$tbin" be.stef.arcana.test.RegressionRunner --root "$ROOT" "$@")
}

[ -z "$1" ] && usage
arg="$(echo "$1" | tr '[:upper:]' '[:lower:]')"

case "$arg" in
    arcana)
        do_build_arcana || exit 1
        ;;
    test)
        shift
        do_test "$@"
        exit $?
        ;;
    all)
        do_build_arcana || exit 1
        rc=0
        for d in "$ROOT/plugins/arcana-plugin-"*/; do
            [ -d "$d" ] || continue
            do_build_plugin "$d" "$(basename "$d")" || rc=1
        done
        exit $rc
        ;;
    plugin-*)
        PLUGIN_DIR="$ROOT/plugins/arcana-$arg"
        if [ ! -d "$PLUGIN_DIR" ]; then
            echo "ERROR: plugin directory not found: $PLUGIN_DIR"
            exit 1
        fi
        do_build_plugin "$PLUGIN_DIR" "arcana-$arg" || exit 1
        ;;
    *)
        usage
        ;;
esac
