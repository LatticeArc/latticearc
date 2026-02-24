# LatticeArc Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.1] - 2026-02-24

### Fixed

- **Documentation**: Removed all enterprise/proprietary references from published crate docs
- **Documentation**: Replaced old crate names (`arc-types`, `arc-core`, `arc-primitives`, `arc-hybrid`, `arc-tls`, `arc-zkp`, `arc-validation`) with correct module paths across 20 files
- **Documentation**: Fixed "this crate" → "this module" in 7 module-level docs
- **Documentation**: Removed stale "Backend Selection (Future)" section from ML-DSA docs (aws-lc-rs 1.16.0 already ships ML-DSA)
- **Documentation**: Removed non-existent `perf` feature flag from `perf` module docs
- **Documentation**: Fixed hardcoded `version = "0.2"` in FIPS error message
- **Documentation**: Removed broken relative `../docs/` links from README (broken on docs.rs)
- **Documentation**: Removed reference to non-existent `docs/FIPS_CERTIFICATION_PATH.md`
- **CI**: Use `macos-15-intel` for x86_64-apple-darwin release builds (matches aws-lc-rs upstream)
- **CI**: Make publish step idempotent for workflow re-runs

---

## [0.3.0] - 2026-02-22

### Security Audit Fixes (44 findings)

- **Critical (14)**: Fixed constant-time comparison violations in hybrid KEM/signature verification, HKDF salt handling, AES-GCM nonce reuse risk, error oracle information leaks, ECDH output validation, PCT validation gaps, resource limit enforcement, README/docs stale API examples, Kani CI frequency claims, DESIGN.md wrong feature flags, ChaCha20 test coverage gap, CI debug-mode test execution
- **High (13)**: Fixed FIPS self-test integrity key hardcoding (documented limitation), ZKP thread_rng usage (replaced with OsRng), secret key zeroization in hybrid decapsulation/key generation, error severity classifications for crypto failures, TLS recovery error handling, ML-KEM decapsulation key serialization validation
- **Medium (8)**: Documented FN-DSA upstream zeroization limitation, added SignatureScheme enum tracking comment, removed 5 dead workspace dependencies, strengthened error severity for RandomError/SerializationError, added error context to TLS recovery paths
- **Low (9)**: Cleaned deny.toml (added nix ban), fixed DESIGN.md algorithm table (added PBKDF2/BN254/X25519), corrected "30 Kani proofs" → "29", replaced TODO comments with NOT WIRED, added ed25519 to sign_with_key dispatch

### Changed

- **Version bump**: 0.2.0 → 0.3.0
- **CI**: Added `--release` to 7 integration/compliance/security test commands
- **Documentation**: Updated all code examples to v0.2.0+ unified API (`EncryptKey`/`DecryptKey` enums)
- **DESIGN_PATTERNS.md**: Promoted from internal to tracked doc

---

## [0.2.0] - 2026-02-21

### Added

- **Type-safe unified encryption API**: New `EncryptKey`/`DecryptKey` enums, `EncryptionScheme` enum, and `EncryptedOutput` struct eliminate silent degradation
  - `EncryptKey::Symmetric(&[u8])` for AES-256-GCM/ChaCha20Poly1305
  - `EncryptKey::Hybrid(&HybridPublicKey)` for ML-KEM-768 + X25519 hybrid encryption
  - `EncryptionScheme` enum replaces string-based scheme dispatch (5 variants)
  - `EncryptedOutput` unifies `EncryptedData` and `HybridEncryptionResult` into a single type
  - `CryptoPolicyEngine::validate_key_matches_scheme()` returns `Err` on mismatch — no silent fallback
  - Key-scheme mismatch tests verify all invalid combinations are rejected
- **Serialization for `EncryptedOutput`**: V2 format with `HybridComponents` support and backward-compatible V1 deserialization
- **Kani Formal Verification Expansion (16 → 29 proofs)**: Added 13 new bounded model checking proofs across 7 files in `latticearc::types`
  - `config.rs` (6 proofs): CoreConfig bi-conditional validation over all 96 combinations, factory presets, encryption compression/integrity, signature chain/timestamp
  - `types.rs` (3 proofs): ComplianceMode `requires_fips()` and `allows_hybrid()` exhaustive, PerformancePreference default is Balanced
  - `selector.rs` (2 proofs): Hybrid/general encryption and signature selection succeeds for all SecurityLevels
  - `domains.rs` (1 proof): All 4 HKDF domain constants are pairwise distinct (collision = key reuse across protocols)
  - `traits.rs` (1 proof): `is_verified()` returns true IFF VerificationStatus is Verified
  - `zero_trust.rs` (1 proof): `is_fully_trusted()` returns true IFF TrustLevel is FullyTrusted
  - Added `kani::Arbitrary` derives for ComplianceMode, PerformancePreference, ProofComplexity, VerificationStatus
  - Added manual `kani::Arbitrary` impl for CoreConfig (96 combinations)

### Changed

- **Unified `encrypt()`/`decrypt()` signatures**: Now take `EncryptKey<'_>`/`DecryptKey<'_>` instead of `&[u8]`, enabling type-safe hybrid encryption through the same API
- **`CryptoPolicyEngine` returns `EncryptionScheme` enum**: `select_encryption_scheme()`, `recommend_scheme()`, and `select_for_security_level()` return typed enums instead of `String`
- **Workspace Consolidation**: Merged 8 sub-crates into single `latticearc` crate for crates.io publishing
  - `arc-types`, `arc-prelude`, `arc-primitives`, `arc-hybrid`, `arc-core`, `arc-tls`, `arc-zkp`, `arc-perf` are now internal modules
  - Merged `arc-tests` and `arc-validation` into a single `latticearc-tests` crate (unpublished)
  - Workspace reduced from 11 crates to 3: `latticearc` (published), `tests` (dev-only), `fuzz` (excluded)
  - All public APIs remain identical — `use latticearc::*` works the same
  - Module paths available: `latticearc::types`, `latticearc::primitives`, `latticearc::hybrid`, `latticearc::unified_api`, `latticearc::tls`, `latticearc::zkp`, `latticearc::perf`, `latticearc::prelude`
  - Simplified release process: single `cargo publish -p latticearc` instead of 10-step layered publish
  - CI workflows updated to reference new crate structure

### Removed

- **Hybrid convenience functions**: Removed `encrypt_hybrid`, `decrypt_hybrid`, and all `_with_config`/`_unverified` variants — use `encrypt(data, EncryptKey::Hybrid(&pk), config)` instead
- **`HybridEncryptionResult`**: Replaced by `EncryptedOutput` with `hybrid_data: Option<HybridComponents>`
- **Silent degradation paths**: All 8 `warn!()` fallback paths eliminated — key-scheme mismatches now return `Err`

### Fixed

- **Critical: Silent degradation to AES-GCM**: All 22 `UseCase` variants recommended hybrid PQ schemes, but `encrypt()` silently fell back to AES-256-GCM because it only accepted `&[u8]` (symmetric keys). Now correctly dispatches to hybrid encryption when `EncryptKey::Hybrid` is provided
- **CNSA 2.0 roundtrip**: Encrypt stored "aes-256-gcm" in `EncryptedData.scheme` while CNSA compliance validated against the hybrid scheme name — decrypt rejected the mismatch. Now uses `EncryptionScheme` enum (always truthful)
- **Audit Warning Fixes (17 → 14 warnings)**: Resolved 3 warnings from 13-dimension code audit
  - Dim 3.7: Removed "secret key" from error format strings in `ml_kem.rs` and `pq_kem.rs` (key material leak false positive)
  - Dim 13a.2: Replaced direct array indexing with `from_array()` in SIMD basemul (neon.rs, avx2.rs) and `get_mut()` in NTT butterfly (ntt_processor.rs)
  - Dim 12.2: Replaced aspirational language in ALGORITHM_SELECTION.md
  - Dim 13c.27: Added descriptive messages to ~37 bare test assertions in fips_kat_loaders_tests.rs and fips_coverage_validation_summary_tests.rs

### Documentation

- Updated FORMAL_VERIFICATION.md with all 29 Kani proofs (was 12)
- Updated README.md verification section with expanded proof details
- Updated SECURITY.md Kani section from 12 to 29 proofs
- Updated DESIGN.md architecture notes with current proof count

---

## [0.1.2] - 2026-02-18

### Added

- **AES-GCM with Additional Authenticated Data (AAD)**: New functions for binding context to ciphertext
  - `encrypt_aes_gcm_with_aad()` / `decrypt_aes_gcm_with_aad()` with `SecurityMode` support
  - `_unverified` convenience variants for use without Zero Trust sessions
  - AAD is authenticated but not encrypted — enables protocol-level binding (headers, session IDs, etc.)
  - Re-exported through `arc-core` and `latticearc` facades
- **HKDF with Custom Info String**: Key derivation with caller-supplied domain separation
  - `derive_key_with_info()` / `derive_key_with_info_unverified()` for HKDF-SHA256 with custom info parameter
  - Enables domain-specific key derivation (different info → cryptographically independent keys)
  - Uses FIPS-validated `aws-lc-rs` HKDF implementation
  - Compatible with existing `derive_key()` when info is `b"latticearc"`
  - Re-exported through `arc-core` and `latticearc` facades
- **Formal Verification Documentation**: Comprehensive documentation for Kani proofs
  - New `docs/FORMAL_VERIFICATION.md` with 155 lines of detailed verification documentation
  - README.md section explaining 9 Kani proofs and verification schedule
  - SECURITY.md expanded with proof details table and verification approach
  - Clear disclosure: proofs run on schedule (nightly/weekly), not every commit
  - Follows AWS-LC model for cost-effective formal verification (~30 min for full suite)
- **FIPS 140-3 Integrity Test**: Implemented Section 9.2.2 Software/Firmware Load Test
  - `integrity_test()` with HMAC-SHA256 module verification
  - `build.rs` for production HMAC generation
  - Development mode prints HMAC, production mode verifies against PRODUCTION_HMAC.txt
  - Power-up test integration (runs before any crypto operations)
  - Constant-time comparison using `subtle::ConstantTimeEq`
- **Dependabot Auto-Merge**: GitHub Actions updates auto-merge after CI passes
  - Configured in `.github/dependabot.yml` with grouped updates
  - `.github/workflows/dependabot-automerge.yml` workflow
  - Reduces PR noise from weekly dependency updates
- **Documentation**: 7 comprehensive review and analysis documents
  - API Design Review (0 critical issues)
  - Security Guidance Review (9.3/10 score)
  - CI Workflow Status and Analysis
  - Dependency Cleanup summary
  - RUSTSEC Advisories documentation
  - aws-lc-rs PR #1029 merge update
- **Hybrid Signature Convenience API**: New dedicated functions for hybrid signatures (ML-DSA-65 + Ed25519)
  - `generate_hybrid_signing_keypair()` / `sign_hybrid()` / `verify_hybrid_signature()` with `SecurityMode` support
  - `_with_config` variants for configuration validation
  - `_unverified` variants for use without Zero Trust sessions
  - Wraps `arc-hybrid::sig_hybrid` with proper error mapping and resource limit validation
  - Re-exported through `arc-core` and `latticearc` facades

### Changed

- **Dependencies**: Upgraded `aws-lc-rs` from 1.15.4 to 1.16.0
  - Full ML-KEM `DecapsulationKey` serialization/deserialization now available
  - Enables complete ML-KEM encrypt/decrypt roundtrip (resolves #16)
  - Our upstream PRs #1029 and #1034 shipped in this release
- **CI/CD**: Fixed misleading Kani formal verification claims
  - Removed `--only-codegen` check from ci.yml (was not running actual proofs)
  - Enabled kani.yml schedule: nightly (3 AM UTC) + weekly (Sunday 5 AM UTC)
  - Added path filters to run proofs only when formal verification code changes
  - Badge now reflects actual proof execution status, not fake checks
  - Follows AWS-LC model: scheduled runs will be enabled once the library is stable
- **Documentation**: Clarified constant-time comparison approach in SECURITY.md
  - Documented use of `subtle` crate (22.7M downloads/month, battle-tested)
  - Acknowledged `subtle` is not formally verified (no alternative exists for Rust custom types)
  - Explained trade-off: aws-lc-rs SAW verification for primitives, `subtle` for API layer
  - Added usage statistics and security track record (zero RustSec advisories)
- **API Improvements**: Enhanced parameter ergonomics
  - `KeyLifecycle::add_approver()` now accepts `impl Into<String>`
  - `logging::set_correlation_id()` now accepts `impl Into<String>`
  - `CorrelationGuard::with_id()` now accepts `impl Into<String>`
  - Allows passing `&str` without `.to_string()` allocation
- **Dependencies**: Updated aws-lc-rs from 1.15.0 to 1.15.4 (security patches)
- **CI Matrix**: Added `fail-fast: false` to test job for complete platform coverage
- **Documentation**: Enhanced HKDF and AES-GCM security warnings
  - HKDF: Added comprehensive salt usage guidance (random > zero salt)
  - AES-GCM: Documented key truncation behavior (>32 bytes silently truncated)
- **API Refactoring**: Removed broken `sign()` function, replaced with `generate_signing_keypair()` + `sign_with_key()`
  - Old `sign(message, config)` generated new keypair on every call (broken behavior)
  - New pattern: `generate_signing_keypair(config)` → `sign_with_key(message, &sk, &pk, config)` → `verify(&signed, config)`
  - Keypairs are now reusable across multiple signing operations
- **Hybrid Encryption API Renamed**: Simplified naming for hybrid functions
  - `encrypt_true_hybrid()` → `encrypt_hybrid()`
  - `decrypt_true_hybrid()` → `decrypt_hybrid()`
  - `generate_true_hybrid_keypair()` → `generate_hybrid_keypair()`
  - `TrueHybridEncryptionResult` → `HybridEncryptionResult`
  - Old functions removed (breaking change)
- **Doctests**: Converted all 67 `ignore` doctests to `no_run` (compile-checked but not executed)
  - Fixes API rot: ignored doctests silently break when function signatures change
  - Fixed hidden boilerplate: import paths, `ZeroizedBytes` `.as_ref()`, error types
  - Added `pub fn tag()` getters to `Cmac128`/`Cmac192`/`Cmac256` (fields were private)
  - Added `ZeroTrustSession::generate_proof()` public method (was only accessible via `pub(crate)` field)
  - 0 doctests remain ignored; 2 unit `#[ignore]` tests unchanged (fips204 validation, fn-dsa zeroization)
- **Stale limitation references removed**: Cleaned up docs, tests, and fuzz targets referencing
  now-resolved aws-lc-rs ML-KEM limitations (DecapsulationKey serialization)

### Removed

- **ctgrind constant-time tests**: Removed arc-primitives/tests/constant_time.rs
  - Tests verified `subtle` crate, not our code
  - Required unsafe blocks that violated workspace lint policy
  - aws-lc-rs primitives already have SAW formal verification
  - Removed ctgrind dependency
- **Unused Dependencies**: Removed 5 workspace dependencies (attack surface reduction)
  - `bytes` (not used in any .rs files)
  - `url` (not used in any .rs files)
  - `futures` (not used in any .rs files)
  - `crossbeam-utils` (declared but never imported)
  - `generic-array` (not used in apache codebase)
  - Also removed from arc-core and latticearc member crates
- **Removed `sign()` function**: Use `generate_signing_keypair()` + `sign_with_key()` instead
- **Removed `generate_keypair()` ECDH bug**: Function no longer calls deprecated broken ECDH
- **Removed `diffie_hellman()` function**: Use hybrid KEM or direct X25519 primitives instead
- **Dead code**: Removed unused data characteristics computation in `selector.rs`

### Security

- **RUSTSEC Advisories**: Documented all 4 ignored advisories (LOW risk)
  - RUSTSEC-2023-0052: webpki DoS (transitive, waiting rustls update)
  - RUSTSEC-2021-0139: ansi_term unmaintained (informational only)
  - RUSTSEC-2024-0375: atty unmaintained (informational only)
  - RUSTSEC-2021-0145: atty unsound on Windows (theoretical, requires custom allocator)
  - All are transitive dependencies from dev tools (clap/criterion)
  - Overall risk assessment: LOW and acceptable
  - See `RUSTSEC_ADVISORIES_IGNORED.md` for full details

### Upstream

- **aws-lc-rs v1.16.0 released** — our PRs shipped
  - PR #1029: ML-KEM `DecapsulationKey` serialization (merged Feb 10, 2026)
  - PR #1034: ML-DSA seed-based deterministic keygen (merged Feb 13, 2026)
  - Upgraded LatticeArc to aws-lc-rs 1.16.0, enabling full ML-KEM roundtrip
  - Closes issue #16

### Documentation

- Updated all READMEs with new signing API pattern
- Added hybrid signature convenience API examples to all docs
- Updated API_DOCUMENTATION.md with correct function signatures
- Updated UNIFIED_API_GUIDE.md with hybrid encryption examples
- Added "Runnable Examples" section to main README
- All documentation now uses `latticearc::*` imports (not `quantumshield::*`)

---

## [0.1.1] - 2026-02-16

### Added

- **Property-based tests (40+ tests in 6 files)**: Comprehensive proptest coverage in `arc-tests`:
  - `proptest_hybrid_kem.rs` — ML-KEM-768 + X25519 roundtrip, key independence, wrong-key rejection
  - `proptest_hybrid_encrypt.rs` — hybrid encryption roundtrip, non-malleability, AAD integrity
  - `proptest_hybrid_sig.rs` — ML-DSA-65 + Ed25519 roundtrip, determinism, size validation
  - `proptest_unified_api.rs` — unified API AEAD + signing across all security levels
  - `proptest_pq_kem.rs` — ML-KEM-512/768/1024 roundtrip, FIPS 203 key/ciphertext sizes
  - `proptest_selector.rs` — CryptoPolicyEngine determinism, monotonicity, exhaustiveness
- **`arc-types` crate**: Pure-Rust domain types, traits, config, policy engine, and key lifecycle
  management extracted from `arc-core`. Zero FFI dependencies, enabling Kani formal verification.
- **Kani proofs expanded (2 → 12)**: Formal verification now covers all major `arc-types` modules:
  - `key_lifecycle.rs`: 5 proofs — state machine immutability, forward-only transitions, API consistency
  - `zero_trust.rs`: 3 proofs — trust level ordering, `is_trusted()` correctness, minimum bound
  - `types.rs`: 1 proof — default `SecurityLevel` is `High` (NIST Level 3)
  - `selector.rs`: 3 proofs — `force_scheme` completeness, PQ encryption/signature coverage for all levels
- **Kani CI for `arc-types`**: Verified tier now targets `arc-types` (pure Rust) instead of
  `arc-core` (FFI-dependent). All 12 proofs run nightly/weekly via CI schedule.
- **Kani Proofs badge**: Added to README, linking to the `arc-types` verification workflow.
- **True Hybrid Encryption** (commit `9973d0c`): Fixed critical issue where arc-core's hybrid encryption used ML-KEM only (no X25519, no HKDF)
  - Added `encrypt_true_hybrid()` / `decrypt_true_hybrid()` / `generate_true_hybrid_keypair()` API
  - Delegates to arc-hybrid's real ML-KEM-768 + X25519 + HKDF + AES-256-GCM combiner
  - New types: `TrueHybridEncryptionResult`, re-exports `KemHybridPublicKey` / `KemHybridSecretKey`
  - Added `X25519StaticKeyPair` with real ECDH via aws-lc-rs `PrivateKey::agree()`
  - Added `MlKemDecapsulationKeyPair` with real aws-lc-rs `DecapsulationKey`
  - Old ML-KEM-only functions retained for backward compatibility
- **Unified API Tests**: Comprehensive test coverage for the unified encryption API
  - `test_unified_api_aes_gcm_roundtrip` - AES-GCM symmetric encryption roundtrip
  - `test_unified_api_rejects_symmetric_key_for_hybrid_schemes` - Validates API correctly rejects 32-byte keys for hybrid PQ schemes
  - `test_hybrid_encryption_only` - Tests hybrid encryption works
  - `test_scheme_selection_for_security_levels` - Verifies CryptoPolicyEngine selects correct ML-KEM variant
  - `test_encrypted_data_contains_scheme_metadata` - Verifies scheme metadata storage
  - `test_decrypt_honors_scheme_from_encrypted_data` - Confirms decrypt() dispatches based on scheme field

### Fixed

- **Wildcard error suppression**: `ed25519.rs` verification now logs original error before returning
  `VerificationFailed`; recovery strategy failures now logged before `continue`.
- **Hybrid Signature Verification**: Fixed bug where hybrid signatures (ML-DSA + Ed25519) failed verification due to incorrect public key storage
  - `sign()` now stores combined public key (ML-DSA + Ed25519) for hybrid schemes
  - `verify()` correctly splits combined key for each algorithm
  - Added missing verify case for `hybrid-ml-dsa-87-ed25519`

### Removed

- **Fake Kani proofs in `arc-hybrid`**: Deleted `formal_verification.rs` (7 proofs that called FFI
  crypto and could never execute under Kani; silently swallowed all errors with `Err(_) => {}`).
  Replaced by property-based tests in `arc-tests` that cover the same properties.
- **`formal-verification` feature flag** from `arc-hybrid`.
- **Kani experimental CI tier** (`kani-experimental` job in `kani.yml`) — no longer needed.
- **Fuzzing badge** from README (schedule disabled, badge was stale).
- **Hardcoded test count badge** (8,079 was incorrect; replaced with self-updating workflow).
- **Dead Code Cleanup**: Removed ~11,500 lines of unreachable code from `latticearc` crate
  - Deleted `latticearc/src/unified_api/` directory (32 files) which was shadowed by an inline module definition and never compiled
  - Removed vestigial `unified_api` re-export module from `lib.rs`
- **Dead hardware stubs** (commit `de47ebb`): Removed `HardwareRouter`, `CpuAccelerator`, `GpuAccelerator`, `FpgaAccelerator`, `SgxAccelerator`, `TpmAccelerator` from arc-core
  - Retained trait definitions (`HardwareAccelerator`, `HardwareAware`, `HardwareCapabilities`, `HardwareInfo`, `HardwareType`)
  - Real hardware detection is in enterprise `arc-enterprise-perf` crate

### Changed

- **Kani badge renamed** to "Kani: type invariants" — honestly scoped to what it verifies.
- **FIPS badge** changed from "ready" to "ML-KEM validated" — accurate scope.
- **Self-updating test count badge**: Replaced Gist-based approach (secrets not configured)
  with `shields.io/endpoint` reading from `.github/badges/test-count.json`.
- **`arc-core` refactored**: Types, traits, config, selector, key_lifecycle, and zero_trust modules
  now re-export from `arc-types` instead of defining inline. No public API changes.
- **Workspace version**: Bumped to 0.1.1 across all crates.
- **SecurityLevel Redesign**: Simplified security levels to four clear options
  - `Standard` - NIST Level 1 (128-bit), hybrid mode
  - `High` - NIST Level 3 (192-bit), hybrid mode (default)
  - `Maximum` - NIST Level 5 (256-bit), hybrid mode
  - `Quantum` - NIST Level 5 (256-bit), PQ-only mode (CNSA 2.0)
  - Removed `Medium` and `Low` levels
  - Classic TLS now only accessible via use cases (`IoT`, `LegacyIntegration`)
- **Architecture: Dependency graph cleanup** (breaking inverted dependencies).

  **Before (0.1.0):**
  ```
  arc-prelude (errors + testing infra, 6.7K lines)
  │  deps: aws-lc-rs, ed25519-dalek, k256
  ▼
  arc-validation (CAVP/NIST, 24.3K)     arc-primitives (algorithms, 22.2K)
  │  deps: arc-prelude            ◄────── deps: arc-prelude, arc-validation
  │                                        │
  arc-hybrid (hybrid, 4K)                  │
  │  deps: arc-primitives          ◄───────┘
  │
  arc-core (API, 17.6K)
  │  deps: arc-types, arc-primitives, arc-hybrid,
  │        arc-prelude, arc-validation
  │
  ├── arc-tls    ├── arc-tests    ├── fuzz
  ▼
  latticearc (facade)
    deps: ALL crates + pub use prelude::*
  ```

  **After (0.1.1):**
  ```
  arc-types (Layer 0: zero FFI, Kani-verifiable)
  │  + resource_limits (from arc-validation)
  │  + domains (from arc-prelude)
  │  NO external deps (pure Rust)
  ▼
  arc-primitives (Layer 1: algorithms)     arc-prelude (errors)
  │  deps: arc-types, arc-prelude          │
  │  arc-validation → dev-deps only        ▼
  ▼                                        arc-validation (CAVP/NIST)
  arc-hybrid (Layer 2: hybrid)               deps: arc-prelude, arc-types
  │  deps: arc-primitives
  ▼
  arc-core (Layer 3: unified API)
  │  deps: arc-types, arc-primitives, arc-hybrid
  │  REMOVED: arc-prelude, arc-validation
  ▼
  latticearc (facade)
  │  deps: arc-core, arc-primitives, arc-hybrid,
  │        arc-tls, arc-zkp, arc-perf
  │  REMOVED: 14 unused deps, glob export
  │  Only re-exports: LatticeArcError
  │
  arc-tests (all integration tests)
    deps: latticearc, arc-core, arc-primitives, arc-types
    37 test files consolidated from arc-core + latticearc
  ```

  - `resource_limits` module moved from `arc-validation` to `arc-types` (pure Rust, zero FFI)
  - `domains` constants moved from `arc-prelude` to `arc-types`
  - Both original modules replaced with re-exports for backward compatibility
  - `arc-primitives` no longer depends on `arc-validation` in production (moved to dev-deps)
  - `arc-core` no longer depends on `arc-validation` or `arc-prelude` in production
  - `arc-tests` no longer depends on `arc-prelude` (was unused)
- **Architecture: Public API cleanup**:
  - `latticearc` no longer glob-exports `arc-prelude::*` (was leaking testing infrastructure
    into public namespace). Only `LatticeArcError` explicitly re-exported.
  - 14 unused direct dependencies removed from `latticearc` (all transitive via arc-core)
  - 3 unused dependencies removed from `arc-core` (`k256`, `async-trait`, `anyhow`)
  - `criterion` and `tempfile` moved from production to dev-deps in `arc-tls`
- **Test consolidation into `arc-tests`**:
  - 30 integration test files moved from `arc-core/tests/` to `arc-tests/tests/`
  - 7 integration test files + `nist_kat/` directory moved from `latticearc/tests/` to `arc-tests/tests/`
  - All dev-dependencies removed from `latticearc` (tests no longer in-crate)
  - `fips` feature added to `arc-tests` to propagate FIPS gating for KAT tests
  - `arc-tests` is now the single location for all integration and regression tests
- **Documentation**: Updated all docs to clarify hardware detection is enterprise-only
  - Removed references to `HardwareRouter`, `detect_hardware()`, `HardwarePreference` from all Apache docs
  - Clarified Apache vs Enterprise feature scope in DESIGN.md

---

## [0.1.0] - 2026-01-29

### Initial Release

First public release of LatticeArc, an enterprise-grade post-quantum cryptography library for Rust.

### Features

#### Post-Quantum Cryptography (NIST Standards)
- **ML-KEM** (FIPS 203) - Key encapsulation mechanism
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204) - Digital signatures
  - ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205) - Hash-based signatures
  - SLH-DSA-SHA2-128s/f, SLH-DSA-SHAKE-128s/f
- **FN-DSA** (FIPS 206 Draft) - Lattice signatures
  - FN-DSA-512, FN-DSA-1024

#### Classical Cryptography
- AES-256-GCM (FIPS 197)
- ChaCha20-Poly1305 (RFC 8439)
- ECDH P-256 (FIPS 186-5)
- ECDSA P-256 (FIPS 186-5)
- Ed25519 signatures
- X25519 key exchange

#### Hybrid Cryptography
- Hybrid KEM (ML-KEM + ECDH)
- Hybrid Signatures (ML-DSA + ECDSA)
- Hybrid Encryption (post-quantum + classical)

#### Security Features
- **Zero Trust Enforcement**: Type-based API with `SecurityMode`
- **Memory Safety**: Zeroization of sensitive data
- **Constant-Time Operations**: Side-channel resistant implementations
- **No Unsafe Code**: Pure safe Rust in production paths

#### Developer Experience
- Unified API for all cryptographic operations
- Comprehensive error handling (no panics)
- Extensive documentation and examples

### Crate Structure (v0.1.x — consolidated into single `latticearc` crate in v0.2.0)

| Crate | Description |
|-------|-------------|
| `latticearc` | Main facade crate |
| `arc-core` | Unified API layer |
| `arc-primitives` | Core cryptographic primitives |
| `arc-prelude` | Common types and errors |
| `arc-hybrid` | Hybrid encryption |
| `arc-tls` | Post-quantum TLS |
| `arc-validation` | NIST test vectors |
| `arc-zkp` | Zero-knowledge proofs |

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
