#!/usr/bin/env bash
# Builds the host latticearc-ffi library and generates the Swift and Kotlin
# bindings from it.
#
#   scripts/ffi/generate-bindings.sh [--android] [OUT_DIR]
#
# OUT_DIR defaults to target/ffi/bindings. `--android` selects the Android
# flavour of the Kotlin bindings (see scripts/ffi/uniffi-android.toml).

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

flavour=jvm
if [ "${1:-}" = "--android" ]; then
    flavour=android
    shift
fi
out="${1:-$FFI_OUT/bindings}"

ffi_build_host
lib="$(ffi_host_cdylib)"
ffi_generate_bindings "$lib" "$out" "$flavour"
echo "bindings written to $out (kotlin flavour: $flavour)"
