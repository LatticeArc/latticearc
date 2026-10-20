# Building LatticeArc for iOS and Android

LatticeArc builds for four mobile targets. CI (`.github/workflows/mobile.yml`) builds all four.
It runs the `latticearc` and `latticearc-tests` test binaries, including the KAT and CAVP suites,
on an iOS simulator and an x86_64 Android emulator.

| Target | Use | CI |
|---|---|---|
| `aarch64-apple-ios` | iPhone / iPad devices | Built; test binaries linked |
| `aarch64-apple-ios-sim` | iOS simulator on Apple silicon | Built; tests run on a simulator |
| `aarch64-linux-android` | Android arm64 devices | Built; test binaries linked |
| `x86_64-linux-android` | Android x86_64 emulator | Built; tests run on an API 28 emulator |

## No FIPS on mobile

The `fips` feature (and anything that enables it, such as `latticearc-tests/fips`) is not
available on these targets. aws-lc-rs supports iOS and Android only with its non-FIPS
`aws-lc-sys` backend, which ships pre-generated bindings and needs only a C compiler. See the
[aws-lc-rs platform support table](https://aws.github.io/aws-lc-rs/platform_support.html).
`ComplianceMode::Fips140_3` and `Cnsa2_0` therefore cannot be used in a mobile build.

## Toolchain

The Rust toolchain is pinned by `rust-toolchain.toml`. From the repository root, add the targets
to that toolchain:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
rustup target add aarch64-linux-android x86_64-linux-android
```

## iOS

You need a full Xcode installation with the iOS SDK. Command Line Tools alone are not enough:
aws-lc-sys's build script runs `xcrun --show-sdk-path --sdk iphoneos` (or `iphonesimulator`),
which fails without Xcode. Check with:

```bash
xcrun --sdk iphoneos --show-sdk-path
xcrun --sdk iphonesimulator --show-sdk-path
```

Set the deployment target to the app's minimum iOS version. rustc and the `cc` crate (which
compiles AWS-LC) both read it, for device and simulator builds alike:

```bash
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cargo build -p latticearc --release --target aarch64-apple-ios
cargo build -p latticearc --release --target aarch64-apple-ios-sim
```

To run the test suite on a simulator the way CI does, build the test binaries and hand the list
to the runner script. It creates and boots an iPhone simulator, then runs each binary with
`xcrun simctl spawn`:

```bash
cargo test -p latticearc -p latticearc-tests --release --target aarch64-apple-ios-sim \
  --no-run --message-format=json-render-diagnostics \
  | python3 scripts/ci/list-test-binaries.py > /tmp/ios-test-bins.txt
scripts/ci/ios-simulator-run-tests.sh /tmp/ios-test-bins.txt
```

## Android

You need the Android NDK r27 (CI uses 27.3.13750724, the default NDK on GitHub's Ubuntu 24.04
runners). The app's minSdk is 28, so build against API level 28.

The simplest local route is [cargo-ndk](https://github.com/bbqsrc/cargo-ndk). It finds the NDK
through `ANDROID_NDK_HOME` and sets the compiler, archiver and linker for you:

```bash
cargo install cargo-ndk --version 4.1.2 --locked
export ANDROID_NDK_HOME=/path/to/android-sdk/ndk/27.3.13750724
CARGO_NDK_PLATFORM=28 cargo ndk -t arm64-v8a -t x86_64 build -p latticearc --release
```

CI sets the same variables by hand, without cargo-ndk. This is useful when another tool drives
cargo:

```bash
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"  # darwin-x86_64 on macOS
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android28-clang"
export CC_x86_64_linux_android="$NDK_BIN/x86_64-linux-android28-clang"
export AR_x86_64_linux_android="$NDK_BIN/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_BIN/x86_64-linux-android28-clang"
cargo build -p latticearc --release --target aarch64-linux-android
cargo build -p latticearc --release --target x86_64-linux-android
```

To run the tests on a connected emulator or device, build the x86_64 (emulator) or arm64
(device) test binaries the same way. Then pass the list to
`scripts/ci/android-emulator-run-tests.sh`. It pushes each binary to `/data/local/tmp`, runs
it with `adb shell` and removes it again.

## `secret-mlock` on Android

With the `secret-mlock` feature, each `SecretVec` tries to `mlock(2)` its buffer. If locking
fails, the `SecretVec` is still returned, unlocked: it is still zeroized on drop, but it is no
longer protected from swap or core dumps.

On Android this limit is reached quickly. Android's `init` sets `RLIMIT_MEMLOCK` to 64 KiB
(soft and hard) for the processes it starts. App processes are forked from zygote, which `init`
starts. See `setrlimit memlock 65536 65536` in [`system/core/rootdir/init.rc`][init-rc].
`mlock` locks whole pages, so only the first few SecretVec buffers in a process are locked;
later ones fall back to unlocked memory. Do not rely on `secret-mlock` for protection on
Android.

## Size

The CI jobs print the size of `liblatticearc.rlib` for each target. They do not enforce a
budget yet. The planned 9 MB per-architecture budget applies to the final app-facing cdylib,
which does not exist yet. An rlib also contains crate metadata and LTO bitcode, so it overstates
what the linked library will add.

[init-rc]: https://android.googlesource.com/platform/system/core/+/refs/heads/main/rootdir/init.rc
