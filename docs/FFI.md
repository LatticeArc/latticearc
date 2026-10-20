# Swift and Kotlin bindings (`latticearc-ffi`)

`latticearc-ffi` exposes the LatticeArc mobile-core APIs to Swift and Kotlin
through [UniFFI](https://mozilla.github.io/uniffi-rs/) 0.32. The Rust crate is
the single source of truth: its proc-macro attributes define the C ABI, and
the `uniffi-bindgen` binary built from the same crate generates the Swift and
Kotlin sources, so bindings and library can never disagree on a signature or
checksum.

| What | Where |
| --- | --- |
| Rust crate | [`latticearc-ffi/`](../latticearc-ffi/) |
| Swift sample (every API, macOS/iOS) | [`latticearc-ffi/samples/swift/main.swift`](../latticearc-ffi/samples/swift/main.swift) |
| Kotlin sample (every API, JVM/Android) | [`latticearc-ffi/samples/kotlin/Main.kt`](../latticearc-ffi/samples/kotlin/Main.kt) |
| Build and packaging scripts | [`scripts/ffi/`](../scripts/ffi/) |
| Fuzz target over the whole surface | [`fuzz/fuzz_targets/fuzz_ffi_surface.rs`](../fuzz/fuzz_targets/fuzz_ffi_surface.rs) |
| CI | `ffi-swift-sample`, `ffi-kotlin-sample` and the packaging steps in [`.github/workflows/mobile.yml`](../.github/workflows/mobile.yml) |

## Rules the surface follows

1. **Secrets are handles.** Derived keys, unwrapped keys, shared secrets and
   signing keys live in Rust memory as opaque objects (`SecretBytes`,
   `HybridKemSecretKey`, `HybridSigningKey`, `MlDsaSigningKey`), zeroized on
   drop and locked against swapping where the OS allows. Secret bytes cross
   the language boundary only through methods whose names start with
   `export` (`exportBytes`, `exportParts`, `exportSecretKey`). Inputs that are
   secrets (passwords, seeds, keys) are passed in as `SecretBytes` built with
   `SecretBytes.import(...)` or `SecretBytes.random(...)`.
2. **Errors are typed.** Every fallible call throws `LatticeArcError` (Swift)
   or `LatticeArcException` (Kotlin) with one case per variant:
   `InvalidInput`, `InvalidContext`, `InvalidParams`, `ResourceLimit`,
   `AuthenticationFailed`, `StreamExhausted`, `WireFormat`, `KeyGeneration`,
   `Internal`. Nothing panics across the boundary; the fuzz target enforces
   that. Failures an attacker can trigger with forged data (wrong key,
   tampered ciphertext, wrong context or `aad`) in the key-wrap, streaming
   and hybrid-encryption paths are the payload-free `AuthenticationFailed`;
   a signature that does not match returns `false`. `decapsulate` is the one
   exception: ML-KEM uses implicit rejection, so a wrong key or context
   yields a *different* secret with no error, and key confirmation comes from
   the authenticated step that uses the secret (`decryptHybrid`, an AEAD).
   Misconfigured HashML-DSA calls (hash not allowed at the parameter set,
   wrong digest length, bad context) are typed errors, never `false`.
3. **Contexts are mandatory.** Every call that takes a `context` (and the
   streaming `aad`) rejects an empty one with `InvalidContext`, matching the
   Rust `*_with_context` APIs. The one exception is plain ML-DSA
   `sign` / `verify`, which accept an empty context because FIPS 204 does;
   HashML-DSA requires one.
4. **Public values use the wire format.** Public keys, encapsulated keys,
   hybrid ciphertexts and hybrid signatures are the versioned `LA` encoding
   of [`WIRE_FORMAT.md`](WIRE_FORMAT.md), so bytes written on one platform
   parse on every other. ML-DSA keys and signatures use their FIPS 204
   encodings.

## API map

Rust names on the left; Swift uses `lowerCamelCase` members and `.enumCase`,
Kotlin uses `lowerCamelCase` members and `ENUM_CASE`. `Data` / `ByteArray`
stand for `Vec<u8>`.

| Area | Rust | Swift | Kotlin |
| --- | --- | --- | --- |
| Status | `version()`, `memory_lock_status()` | `version()`, `memoryLockStatus()` | `version()`, `memoryLockStatus()` |
| Secrets | `SecretBytes::{import, random}`, `.len/.is_empty/.is_locked/.export_bytes` | `SecretBytes.import(bytes:)`, `.random(len:)`, `.exportBytes()` | `SecretBytes.import(bytes)`, `.random(len)`, `.exportBytes()` |
| Argon2id | `argon2_default_params`, `argon2_calibrate(target_ms, max_memory_kib)`, `argon2id(password, salt, params)` | `argon2DefaultParams()`, `argon2Calibrate(targetMs:maxMemoryKib:)`, `argon2id(password:salt:params:)` | `argon2DefaultParams()`, `argon2Calibrate(targetMs, maxMemoryKib)`, `argon2id(password, salt, params)` |
| KDF | `hkdf(ikm, salt?, context, length)`, `counter_kdf(key, label, context, length)` | `hkdf(ikm:salt:context:length:)`, `counterKdf(key:label:context:length:)` | `hkdf(ikm, salt, context, length)`, `counterKdf(key, label, context, length)` |
| Key wrap | `wrap_key(kek, key, context)`, `wrap_key_padded(.., total_len)`, `unwrap_key(kek, wrapped, context)` | `wrapKey(kek:key:context:)`, `wrapKeyPadded(..totalLen:)`, `unwrapKey(kek:wrapped:context:)` | `wrapKey(kek, key, context)`, `wrapKeyPadded(.., totalLen)`, `unwrapKey(kek, wrapped, context)` |
| Streaming AEAD | `StreamEncryptor::new(key, aad, segment_size)`: `header`, `seal_segment`, `finish`, sizes; `StreamDecryptor::new(key, aad, header)`: `open_segment(index, segment, is_last)`, `open_next`, `is_finished` | `StreamEncryptor(key:aad:segmentSize:)`, `StreamDecryptor(key:aad:header:)` | `StreamEncryptor(key, aad, segmentSize)`, `StreamDecryptor(key, aad, header)` |
| Hybrid KEM | `HybridKemSecretKey::{generate(level), from_parts}`, `.public_key/.export_parts`; `HybridKemPublicKey::{from_wire}`, `.to_wire`; `encapsulate(pk, context)` → `Encapsulation{encapsulated_key, shared_secret}`; `decapsulate(sk, encapsulated_key, context)` | `HybridKemSecretKey.generate(level:)`, `encapsulate(publicKey:context:)`, `decapsulate(secretKey:encapsulatedKey:context:)` | `HybridKemSecretKey.generate(level)`, `encapsulate(publicKey, context)`, `decapsulate(secretKey, encapsulatedKey, context)` |
| Hybrid encryption | `encrypt_hybrid(pk, plaintext, aad?)`, `decrypt_hybrid(sk, ciphertext, aad?)` | `encryptHybrid(publicKey:plaintext:aad:)`, `decryptHybrid(secretKey:ciphertext:aad:)` | `encryptHybrid(publicKey, plaintext, aad)`, `decryptHybrid(secretKey, ciphertext, aad)` |
| Hybrid signatures | `HybridSigningKey::{generate(set), from_seed(seed, set), from_parts}`, `.sign(message, context)`, `.sign_prehashed(sha512_digest, context)`, `.public_key/.export_parts`; `HybridSigPublicKey::{from_wire}`, `.to_wire`; `verify(pk, message, signature, context)`, `verify_prehashed(pk, digest, signature, context)` | `HybridSigningKey.fromSeed(seed:parameterSet:)`, `verify(publicKey:message:signature:context:)`, `verifyPrehashed(...)` | `HybridSigningKey.fromSeed(seed, parameterSet)`, `verify(publicKey, message, signature, context)`, `verifyPrehashed(...)` |
| ML-DSA | `MlDsaSigningKey::{generate, from_seed, from_parts(secret_key, public_key, set)}`, `.sign`, `.sign_prehashed(digest, hash, context)`, `.export_secret_key`; `MlDsaPublicKey::{from_bytes}`, `.to_bytes`, `.verify`, `.verify_prehashed` | `MlDsaSigningKey.fromSeed(seed:parameterSet:)`, `MlDsaPublicKey.fromBytes(bytes:parameterSet:)` | `MlDsaSigningKey.fromSeed(seed, parameterSet)`, `MlDsaPublicKey.fromBytes(bytes, parameterSet)` |
| Enums | `MlKemSecurityLevel::{MlKem512, MlKem768, MlKem1024}`, `MlDsaParameterSet::{MlDsa44, MlDsa65, MlDsa87}`, `PrehashAlgorithm::{Sha256, Sha512, Shake128, Shake256}` | `.mlKem768`, `.mlDsa65`, `.sha512` | `ML_KEM768`, `ML_DSA65`, `SHA512` |
| Records | `Argon2Params`, `MemoryLockStatus`, `Encapsulation`, `HybridKemSecretKeyParts`, `HybridSigningKeyParts` | structs | data classes |

Notes that trip people up:

- The first streaming segment carries `firstPlaintextSegmentSize` bytes of
  plaintext and is 40 bytes shorter on the wire than `segmentSize`; every
  later segment carries `plaintextSegmentSize`. The last segment (any length
  up to the capacity, including empty) goes through `finish` / `isLast =
  true`.
- `hybrid` pre-hashed signing takes the caller's **SHA-512** digest (64 bytes).
  ML-DSA pre-hashed signing takes the digest plus the `PrehashAlgorithm` used;
  SHA-256 and SHAKE128 are only allowed at ML-DSA-44 and are reported through
  the opaque signing error.
- A `HybridSigningKey` made with `fromSeed` is identical on every platform for
  the same seed; persist the seed (wrapped) rather than the exported parts.
- `memoryLockStatus().failedBuffers > 0` is normal on Android, where the
  per-process lock limit is usually 64 KiB. Show it; do not treat it as an
  error.
- `argon2id` and `argon2Calibrate` are synchronous and take a noticeable
  fraction of a second at the default profile (up to `targetMs` for
  calibration). Call them off the UI thread.
- `exportParts` records are plain byte strings the caller owns: clear them
  after persisting, and store the public and secret halves together, since
  `fromParts` checks lengths only.
- `hkdf` and `counterKdf` outputs are capped at 8160 bytes.

## Building

All scripts build the host `cdylib` first and generate the bindings from it;
`uniffi-bindgen` is compiled from `latticearc-ffi` with its `bindgen` feature,
so no separate UniFFI install is needed.

```bash
# Bindings only (target/ffi/bindings/{swift,kotlin}); --android for the
# Android flavour of the Kotlin sources
scripts/ffi/generate-bindings.sh [--android] [OUT_DIR]

# Run the samples against the host library
scripts/ffi/run-swift-sample.sh                    # macOS
JNA_JAR=/path/to/jna-5.19.1.jar scripts/ffi/run-kotlin-sample.sh   # any host with kotlinc + a JDK

# iOS: LatticeArcFFI.xcframework (device + simulator) and LatticeArc.swift
scripts/ffi/build-xcframework.sh                   # macOS with Xcode

# Android: jniLibs/{arm64-v8a,x86_64}/liblatticearc_ffi.so and the Kotlin source
ANDROID_NDK_HOME=... scripts/ffi/build-android.sh
```

### iOS integration

`scripts/ffi/build-xcframework.sh` writes `target/ffi/xcframework/`. Ship it
as a local Swift package:

```
LatticeArcKit/
  Package.swift
  Sources/LatticeArc/LatticeArc.swift        <- target/ffi/xcframework/swift/LatticeArc.swift
  LatticeArcFFI.xcframework                   <- target/ffi/xcframework/LatticeArcFFI.xcframework
```

```swift
// Package.swift
let package = Package(
    name: "LatticeArcKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "LatticeArc", targets: ["LatticeArc"])],
    targets: [
        .binaryTarget(name: "LatticeArcFFI", path: "LatticeArcFFI.xcframework"),
        .target(name: "LatticeArc", dependencies: ["LatticeArcFFI"]),
    ]
)
```

The XCFramework holds static libraries; nothing is loaded at runtime. The
release profile builds with `panic = "abort"` and symbols stripped. The
script builds for iOS 17.0 and newer (`IPHONEOS_DEPLOYMENT_TARGET` overrides
it) so the Rust and the aws-lc C objects agree on a minimum version. The
layout above was verified by building this package for the simulator and the
device and running the sample on an iOS 27.1 simulator.

### Android integration

`scripts/ffi/build-android.sh` writes `target/ffi/android/`. In an Android
library module:

```
mylib/src/main/jniLibs/arm64-v8a/liblatticearc_ffi.so   <- target/ffi/android/jniLibs/...
mylib/src/main/jniLibs/x86_64/liblatticearc_ffi.so
mylib/src/main/kotlin/com/latticearc/ffi/latticearc_ffi.kt <- target/ffi/android/kotlin/...
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation("androidx.annotation:annotation:1.9.1")   // @RequiresApi in the generated source
}
```

`assembleRelease` of that module produces the AAR. The Android flavour of the
bindings (generated with `scripts/ffi/uniffi-android.toml`) frees objects
through `android.system.SystemCleaner` on API 33 and newer and through JNA's
cleaner below that; the JVM flavour the host sample uses always takes the JNA
cleaner. Nothing else differs.

Both builds are exercised in CI (`mobile.yml`: `ios-build` uploads the
XCFramework, `android-build` uploads the Android layout) but cannot run on a
machine without Xcode or the NDK; the host sample jobs are what verify the
bindings.

## Threading and lifetimes

Every object is `Send + Sync` and may be used from any thread. `StreamEncryptor`
and `StreamDecryptor` serialise their calls internally; `finish` consumes the
encryptor, after which every method raises `StreamExhausted`. Objects are
freed when the last Swift reference or Kotlin `close()` / cleaner runs; secret
contents are zeroized at that point. Kotlin objects implement `AutoCloseable`,
so `use { }` blocks release secrets deterministically.

## API freeze

The surface above is frozen for the 0.13 line. Additions are allowed; a
rename, removal or change of a parameter list requires a new minor version
and a changelog entry, because UniFFI checksums every function signature and
a stale binding fails at load time rather than at the call.

## Threat model notes

- The boundary adds no cryptography: every call forwards to the audited
  `latticearc` function with the same arguments.
- Copies made by the foreign runtime (`Data`, `ByteArray`) are outside Rust's
  zeroization. The surface keeps those copies to public values and to the
  explicit `export*` results, which the caller owns.
- Panics are compile-time excluded from the hand-written FFI source by the
  workspace lints and run-time excluded by the fuzz target; the release
  profile's `panic = "abort"` is the backstop.
- The generated C ABI is UniFFI's; `latticearc-ffi/tests/no_unsafe.rs` keeps
  the hand-written half free of `unsafe`.
