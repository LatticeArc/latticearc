#!/usr/bin/env bash
# Builds the Android shared libraries and the Android flavour of the Kotlin
# bindings, laid out for an Android library module:
#
#   target/ffi/android/jniLibs/arm64-v8a/liblatticearc_ffi.so
#   target/ffi/android/jniLibs/x86_64/liblatticearc_ffi.so
#   target/ffi/android/kotlin/com/latticearc/ffi/latticearc_ffi.kt
#
# Copy `jniLibs` into the module's `src/main/jniLibs` and the Kotlin source
# into `src/main/kotlin`, add `net.java.dev.jna:jna:<version>@aar`, and the
# module's `assembleRelease` produces the AAR. See docs/FFI.md.
#
# Needs ANDROID_NDK_HOME (NDK r27 or newer) and the rustup targets
# aarch64-linux-android and x86_64-linux-android. The toolchain wiring is the
# one .github/workflows/mobile.yml uses.
#
#   ANDROID_NDK_HOME=... scripts/ffi/build-android.sh

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the NDK root}"
: "${ANDROID_API_LEVEL:=28}"

case "$(uname -s)" in
    Linux) host_tag=linux-x86_64 ;;
    Darwin) host_tag=darwin-x86_64 ;;  # the NDK ships x86_64 binaries for every Mac
    *) echo "error: unsupported host $(uname -s)" >&2; exit 1 ;;
esac
ndk_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host_tag/bin"

# Rust target triple -> Android ABI directory. Plain arrays and `tr` keep the
# script runnable under macOS's bash 3.2 as well as Linux's bash 5.
triples=(aarch64-linux-android x86_64-linux-android)
abis=(arm64-v8a x86_64)
out="$FFI_OUT/android"
rm -rf "$out"
mkdir -p "$out/jniLibs"

for i in 0 1; do
    triple="${triples[$i]}"
    abi="${abis[$i]}"
    clang="$ndk_bin/${triple}${ANDROID_API_LEVEL}-clang"
    test -x "$clang" || { echo "error: $clang not found" >&2; exit 1; }
    var="$(printf '%s' "$triple" | tr '-' '_')"
    upper="$(printf '%s' "$var" | tr '[:lower:]' '[:upper:]')"
    echo "building latticearc-ffi for $triple"
    (cd "$FFI_REPO_ROOT" && env \
        "CC_${var}=$clang" "CXX_${var}=${clang}++" \
        "AR_${var}=$ndk_bin/llvm-ar" "RANLIB_${var}=$ndk_bin/llvm-ranlib" \
        "CARGO_TARGET_${upper}_LINKER=$clang" \
        cargo build --locked -p latticearc-ffi --release --target "$triple")
    mkdir -p "$out/jniLibs/$abi"
    cp "$FFI_TARGET/$triple/release/lib$FFI_LIB_NAME.so" "$out/jniLibs/$abi/"
done

ffi_build_host
mkdir -p "$out/kotlin"
ffi_bindgen generate --no-format --language kotlin --out-dir "$out/kotlin" \
    --config "$FFI_REPO_ROOT/scripts/ffi/uniffi-android.toml" "$(ffi_host_cdylib)"

echo "wrote $out/jniLibs and $out/kotlin"
du -sh "$out"/jniLibs/*/lib$FFI_LIB_NAME.so
