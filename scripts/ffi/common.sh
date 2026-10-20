#!/usr/bin/env bash
# Shared helpers for the latticearc-ffi scripts. Source this file; do not run it.
#
# Every script builds the host `cdylib` with the exact `uniffi` version pinned
# in latticearc-ffi/Cargo.toml and generates bindings with the `uniffi-bindgen`
# binary compiled from that same crate, so the Swift and Kotlin sources can
# never drift from the Rust library they load.

set -euo pipefail

FFI_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FFI_CRATE="$FFI_REPO_ROOT/latticearc-ffi"
FFI_TARGET="${CARGO_TARGET_DIR:-$FFI_REPO_ROOT/target}"
# Generated bindings, sample binaries and packaged artifacts land here.
FFI_OUT="${FFI_OUT_DIR:-$FFI_TARGET/ffi}"
FFI_LIB_NAME="latticearc_ffi"
FFI_SWIFT_MODULE="LatticeArc"
FFI_SWIFT_FFI_MODULE="LatticeArcFFI"

# Path of the host cdylib produced by `ffi_build_host`.
ffi_host_cdylib() {
    case "$(uname -s)" in
        Darwin) echo "$FFI_TARGET/release/lib$FFI_LIB_NAME.dylib" ;;
        Linux) echo "$FFI_TARGET/release/lib$FFI_LIB_NAME.so" ;;
        *) echo "error: unsupported host $(uname -s)" >&2; return 1 ;;
    esac
}

# The host library is both the input for binding generation and the library
# the samples load. UniFFI's library mode reads its metadata from the symbol
# table, which the workspace release profile strips (`strip = true`): on
# Linux that leaves "No UniFFI metadata found", on macOS the exported symbols
# happen to survive. The host build therefore keeps its symbols; the shipped
# iOS and Android libraries are built separately and stay stripped.
ffi_build_host() {
    (cd "$FFI_REPO_ROOT" && CARGO_PROFILE_RELEASE_STRIP=none cargo build --locked -p latticearc-ffi --release)
}

# Runs the crate's own `uniffi-bindgen` (generic, Swift + Kotlin).
ffi_bindgen() {
    (cd "$FFI_REPO_ROOT" && cargo run --locked -q -p latticearc-ffi --release \
        --features bindgen --bin uniffi-bindgen -- "$@")
}

# Runs the crate's own `uniffi-bindgen-swift` (headers, modulemap, sources).
ffi_bindgen_swift() {
    (cd "$FFI_REPO_ROOT" && cargo run --locked -q -p latticearc-ffi --release \
        --features bindgen --bin uniffi-bindgen-swift -- "$@")
}

# Generates Swift and Kotlin bindings from `$1` (a cdylib or staticlib) into
# `$2/swift` and `$2/kotlin`. Pass `android` as `$3` for the Android flavour of
# the Kotlin bindings (uses android.system.SystemCleaner); the default flavour
# runs on a plain JVM.
ffi_generate_bindings() {
    local lib="$1" out="$2" flavour="${3:-jvm}"
    mkdir -p "$out/swift" "$out/kotlin"
    ffi_bindgen generate --no-format --language swift --out-dir "$out/swift" "$lib"
    local config=()
    if [ "$flavour" = "android" ]; then
        config=(--config "$FFI_REPO_ROOT/scripts/ffi/uniffi-android.toml")
    fi
    ffi_bindgen generate --no-format --language kotlin --out-dir "$out/kotlin" ${config[@]+"${config[@]}"} "$lib"
}
