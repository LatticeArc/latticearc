#!/usr/bin/env bash
# Builds the host library, generates the JVM flavour of the Kotlin bindings,
# compiles them with latticearc-ffi/samples/kotlin/Main.kt and runs the sample
# on the JVM through JNA. Exit status is the sample's: non-zero if any check
# fails.
#
#   JNA_JAR=/path/to/jna-5.19.1.jar scripts/ffi/run-kotlin-sample.sh
#
# Environment:
#   JNA_JAR   path to the JNA jar (required; net.java.dev.jna:jna)
#   KOTLINC   kotlinc binary (default: kotlinc on PATH)
#   JAVA      java binary (default: java on PATH)

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

: "${JNA_JAR:?set JNA_JAR to the path of the JNA jar}"
: "${KOTLINC:=kotlinc}"
: "${JAVA:=java}"
if [ ! -f "$JNA_JAR" ]; then
    echo "error: JNA_JAR=$JNA_JAR does not exist" >&2
    exit 1
fi

bindings="$FFI_OUT/bindings"
build="$FFI_OUT/kotlin-sample"
libdir="$(dirname "$(ffi_host_cdylib)")"

"$FFI_REPO_ROOT/scripts/ffi/generate-bindings.sh" "$bindings"
rm -rf "$build"
mkdir -p "$build"

echo "compiling the bindings and the sample"
"$KOTLINC" -Werror -include-runtime \
    -classpath "$JNA_JAR" \
    -d "$build/latticearc-sample.jar" \
    "$bindings"/kotlin/com/latticearc/ffi/*.kt \
    "$FFI_CRATE/samples/kotlin/Main.kt"

echo "running the sample"
"$JAVA" -ea --enable-native-access=ALL-UNNAMED -cp "$build/latticearc-sample.jar:$JNA_JAR" \
    "-Djna.library.path=$libdir" MainKt
