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

# Minimum iOS for the static libraries. Rust defaults to iOS 10, but the C
# objects aws-lc-sys compiles take the SDK's default (the Xcode version's
# iOS), and the mismatch leaves linker-only symbols such as ___chkstk_darwin
# unresolved. One value for both compilers; override with the environment.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"

for t in "${targets[@]}"; do
    echo "building latticearc-ffi (staticlib) for $t, iOS >= $IPHONEOS_DEPLOYMENT_TARGET"
    # Only the static library goes into the XCFramework; `cargo rustc
    # --crate-type staticlib` skips the cdylib link the crate also declares,
    # which is meaningless on iOS.
    (cd "$FFI_REPO_ROOT" && cargo rustc --locked -p latticearc-ffi --release --target "$t" --crate-type staticlib)
done

# Metadata is read from the host library: the exported API, and therefore
# the generated header and sources, are identical for every target.
ffi_build_host
host_lib="$(ffi_host_cdylib)"
# A plain `module` map, not `--xcframework`'s `framework module`: the slices
# are bare static libraries with a Headers directory, and clang only resolves
# a framework module inside a .framework bundle (the import would succeed but
# define no types).
ffi_bindgen_swift --headers --modulemap \
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
