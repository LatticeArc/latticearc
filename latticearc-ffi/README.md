# latticearc-ffi

Swift and Kotlin bindings for [LatticeArc](https://github.com/latticearc/latticearc),
generated with [UniFFI](https://mozilla.github.io/uniffi-rs/) from this crate.

The surface is the LatticeArc 0.13 mobile core: Argon2id, HKDF and SP 800-108
with required contexts, committing key wrap, streaming AEAD with random
access, hybrid ML-KEM + X25519 encapsulation and encryption, hybrid
ML-DSA + Ed25519 and plain ML-DSA signatures (context-bound, pre-hashed and
seed-derived), the LatticeArc wire format for public values, and the
memory-lock status.

Three rules hold everywhere: secrets are opaque handles that leave Rust only
through `export*` methods, every failure is a typed error (no panics cross the
boundary), and every domain-separation context is mandatory.

See [`docs/FFI.md`](../docs/FFI.md) for the API map, the build scripts and
the iOS / Android integration steps. `samples/swift/main.swift` and
`samples/kotlin/Main.kt` round-trip every function and double as the binding
tests in CI.

```bash
scripts/ffi/run-swift-sample.sh                                     # macOS
JNA_JAR=/path/to/jna.jar scripts/ffi/run-kotlin-sample.sh           # kotlinc + JDK
scripts/ffi/build-xcframework.sh                                    # Xcode
ANDROID_NDK_HOME=... scripts/ffi/build-android.sh                   # NDK
```

License: Apache-2.0, like the rest of the workspace. UniFFI itself is MPL-2.0.
