# Dimension 11: Cross-Crate Integration

**Last audited:** 2026-02-15
**Auditor:** Agent a0044cc + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

None.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| **Re-export Completeness** | | | |
| Core unified API (5) | `latticearc/src/lib.rs` | 252 | encrypt, decrypt, sign_with_key, verify, generate_signing_keypair |
| Hybrid encryption (5+) | `latticearc/src/lib.rs` | 255-258 | All hybrid encryption functions |
| Hybrid signatures (6) | `latticearc/src/lib.rs` | 261-264 | All hybrid signature functions |
| Keygen (11) | `latticearc/src/lib.rs` | 267-273 | All keygen functions including FN-DSA, ML-DSA, ML-KEM, SLH-DSA (2026-02-15 fix) |
| Hashing/KDF (7) | `latticearc/src/lib.rs` | 270-273 | hash/HMAC/KDF functions |
| Low-level primitives | `latticearc/src/lib.rs` | 276-297 | AES-GCM, Ed25519, ML-KEM, ML-DSA, SLH-DSA, FN-DSA |
| Unverified variants (44+) | `latticearc/src/lib.rs` | 304-349 | All `_unverified` functions |
| TLS utilities | `latticearc/src/lib.rs` | 386-389 | TlsConfig, tls_connect, tls_accept |
| **Feature Flag Propagation** | | | |
| fips: latticearc → arc-core | `latticearc/Cargo.toml` | 52-53 | `fips = ["arc-core/fips", "arc-primitives/fips"]` |
| fips: arc-core → arc-primitives | `arc-core/Cargo.toml` | 20 | `fips = ["arc-primitives/fips", "fips-self-test"]` |
| fips: arc-primitives | `arc-primitives/Cargo.toml` | 21 | `fips = ["fips-self-test"]` |
| **Dependency Direction** | | | |
| No circular deps | workspace | — | `cargo tree --duplicates` clean |
| Base: arc-prelude, arc-validation | — | — | Leaf dependencies |
| Primitives → prelude | — | — | Correct direction |
| Core → primitives, prelude | — | — | Correct direction |
| Extensions → core/primitives | — | — | Correct direction |
| Facade → all | — | — | Correct direction |
| **Version Consistency** | | | |
| All crates v0.1.0 | `Cargo.toml` | 19-21 | `version.workspace = true` |
| Edition 2024 | `Cargo.toml` | 20 | `edition.workspace = true` |
| MSRV 1.93 | `Cargo.toml` | 21 | `rust-version.workspace = true` |
