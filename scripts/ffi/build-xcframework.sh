#!/usr/bin/env bash
# Builds LatticeArcFFI.xcframework (iOS device + iOS simulator static
# libraries with the UniFFI C header and module map) and the matching Swift
# source, ready to ship as a local Swift package:
#
#   target/ffi/xcframework/LatticeArcFFI.xcframework
#   target/ffi/xcframework/swift/LatticeArc.swift
#
# Needs Xcode (iOS SDKs) and the rustup targets aarch64-apple-ios and
# aarch64-apple-ios-sim. The link flags come from the workspace release
# profile; nothing here depends on cargo-swift or other third-party tooling,
# so a reproducible-build manifest can pin every flag.
#
#   scripts/ffi/build-xcframework.sh

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: building an XCFramework needs macOS with Xcode" >&2
    exit 1
fi

targets=(aarch64-apple-ios aarch64-apple-ios-sim)
out="$FFI_OUT/xcframework"
rm -rf "$out"
mkdir -p "$out/headers" "$out/swift"

for t in "${targets[@]}"; do
    echo "building latticearc-ffi for $t"
    (cd "$FFI_REPO_ROOT" && cargo build --locked -p latticearc-ffi --release --target "$t")
done

# Metadata is read from the host library: the exported API, and therefore
# the generated header and sources, are identical for every target.
ffi_build_host
host_lib="$(ffi_host_cdylib)"
ffi_bindgen_swift --headers --modulemap --xcframework \
    --module-name "$FFI_SWIFT_FFI_MODULE" --modulemap-filename module.modulemap \
    "$host_lib" "$out/headers"
ffi_bindgen_swift --swift-sources "$host_lib" "$out/swift"

args=()
for t in "${targets[@]}"; do
    args+=(-library "$FFI_TARGET/$t/release/lib$FFI_LIB_NAME.a" -headers "$out/headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$out/$FFI_SWIFT_FFI_MODULE.xcframework"

echo "wrote $out/$FFI_SWIFT_FFI_MODULE.xcframework and $out/swift/$FFI_SWIFT_MODULE.swift"
du -sh "$out/$FFI_SWIFT_FFI_MODULE.xcframework"
