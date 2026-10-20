#!/usr/bin/env bash
# Builds the host library, generates the Swift bindings, compiles them into a
# `LatticeArc` module, builds latticearc-ffi/samples/swift/main.swift against
# it and runs the sample. macOS only (CryptoKit, Swift toolchain). Exit status
# is the sample's: non-zero if any check fails.
#
#   scripts/ffi/run-swift-sample.sh

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: the Swift sample needs macOS" >&2
    exit 1
fi

bindings="$FFI_OUT/bindings"
build="$FFI_OUT/swift-sample"
libdir="$(dirname "$(ffi_host_cdylib)")"

"$FFI_REPO_ROOT/scripts/ffi/generate-bindings.sh" "$bindings"
rm -rf "$build"
mkdir -p "$build"

modulemap="$bindings/swift/$FFI_SWIFT_FFI_MODULE.modulemap"

echo "compiling the $FFI_SWIFT_MODULE module"
(cd "$build" && swiftc \
    -module-cache-path "$build/ModuleCache" \
    -emit-module -emit-module-path "$build/$FFI_SWIFT_MODULE.swiftmodule" \
    -emit-library -o "$build/lib$FFI_SWIFT_MODULE.dylib" \
    -module-name "$FFI_SWIFT_MODULE" \
    -Xcc -fmodule-map-file="$modulemap" \
    -I "$bindings/swift" -L "$libdir" "-l$FFI_LIB_NAME" \
    "$bindings/swift/$FFI_SWIFT_MODULE.swift")

echo "compiling the sample"
(cd "$build" && swiftc \
    -module-cache-path "$build/ModuleCache" \
    -o "$build/sample" \
    -Xcc -fmodule-map-file="$modulemap" \
    -I "$build" -I "$bindings/swift" \
    -L "$build" "-l$FFI_SWIFT_MODULE" -L "$libdir" "-l$FFI_LIB_NAME" \
    "$FFI_CRATE/samples/swift/main.swift")

echo "running the sample"
DYLD_LIBRARY_PATH="$build:$libdir" "$build/sample"
