# LatticeArc Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.3] - 2026-02-07

### Fixed

- **True Hybrid Encryption** (commit `9973d0c`): Fixed critical issue where arc-core's hybrid encryption used ML-KEM only (no X25519, no HKDF)
  - Added `encrypt_true_hybrid()` / `decrypt_true_hybrid()` / `generate_true_hybrid_keypair()` API
  - Delegates to arc-hybrid's real ML-KEM-768 + X25519 + HKDF + AES-256-GCM combiner
  - New types: `TrueHybridEncryptionResult`, re-exports `KemHybridPublicKey` / `KemHybridSecretKey`
  - Added `X25519StaticKeyPair` with real ECDH via aws-lc-rs `PrivateKey::agree()`
  - Added `MlKemDecapsulationKeyPair` with real aws-lc-rs `DecapsulationKey`
  - Old ML-KEM-only functions retained for backward compatibility

### Changed

- **Hardware Cleanup** (commit `de47ebb`): Removed dead hardware stub implementations from arc-core
  - Removed `HardwareRouter`, `CpuAccelerator`, `GpuAccelerator`, `FpgaAccelerator`, `SgxAccelerator`, `TpmAccelerator`
  - Retained trait definitions (`HardwareAccelerator`, `HardwareAware`, `HardwareCapabilities`, `HardwareInfo`, `HardwareType`)
  - Real hardware detection is in enterprise `arc-enterprise-perf` crate
  - `aws-lc-rs` handles AES-NI/SHA/SIMD acceleration at the C level
- **Documentation**: Updated all docs to clarify hardware detection is enterprise-only
  - Removed references to `HardwareRouter`, `detect_hardware()`, `HardwarePreference` from all Apache docs
  - Updated DESIGN.md, arc-core/README.md, latticearc/README.md, API_DOCUMENTATION.md, FAQ.md, unified_api docs

---

## [0.1.2] - 2026-01-30

### Removed

- **Dead Code Cleanup**: Removed ~11,500 lines of unreachable code from `latticearc` crate
  - Deleted `latticearc/src/unified_api/` directory (32 files) which was shadowed by an inline module definition and never compiled
  - Removed vestigial `unified_api` re-export module from `lib.rs`
  - This was technical debt from an earlier architecture that was superseded by `arc-core`

### Added

- **Unified API Tests**: Added comprehensive test coverage for the unified encryption API
  - `test_unified_api_aes_gcm_roundtrip` - AES-GCM symmetric encryption roundtrip
  - `test_unified_api_rejects_symmetric_key_for_hybrid_schemes` - Validates API correctly rejects 32-byte keys for hybrid PQ schemes
  - `test_hybrid_encryption_only` - Tests hybrid encryption works (documents aws-lc-rs limitation)
  - `test_scheme_selection_for_security_levels` - Verifies CryptoPolicyEngine selects correct ML-KEM variant
  - `test_encrypted_data_contains_scheme_metadata` - Verifies scheme metadata storage
  - `test_decrypt_honors_scheme_from_encrypted_data` - Confirms decrypt() dispatches based on scheme field

### Changed

- **Documentation**: Clarified Apache vs Enterprise feature scope in DESIGN.md
  - Added comparison table showing which features are in Apache (open source) vs Enterprise (proprietary)
  - Clarified that hardware traits are in Apache (types only), but detection and adaptive routing are Enterprise-only
  - Updated Zero Trust section to distinguish framework (Apache) from enforcement (Enterprise)

### Notes

- The removed `unified_api/` directory contained duplicate implementations that were never used:
  - Duplicate `encrypt`/`decrypt` functions with a latent bug (decrypt always used AES-GCM)
  - Duplicate type definitions, traits, and configuration
  - PHI masking stubs (enterprise feature properly lives in proprietary repo)
  - DID resolution stubs (enterprise feature properly lives in proprietary repo)
- All functionality is properly implemented in `arc-core` which is re-exported by `latticearc`

---

## [0.1.1] - 2026-01-30

### Fixed

- **Hybrid Signature Verification**: Fixed bug where hybrid signatures (ML-DSA + Ed25519) failed verification due to incorrect public key storage
  - `sign()` now stores combined public key (ML-DSA + Ed25519) for hybrid schemes
  - `verify()` correctly splits combined key for each algorithm
  - Added missing verify case for `hybrid-ml-dsa-87-ed25519`

### Changed

- **SecurityLevel Redesign**: Simplified security levels to four clear options
  - `Standard` - NIST Level 1 (128-bit), hybrid mode
  - `High` - NIST Level 3 (192-bit), hybrid mode (default)
  - `Maximum` - NIST Level 5 (256-bit), hybrid mode
  - `Quantum` - NIST Level 5 (256-bit), PQ-only mode (CNSA 2.0)
  - Removed `Medium` and `Low` levels
  - Classic TLS now only accessible via use cases (`IoT`, `LegacyIntegration`)

### Documentation

- Updated all README files with new SecurityLevel table
- Updated `UNIFIED_API_GUIDE.md` with detailed level descriptions
- Clarified hybrid vs PQ-only mode distinction

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

### Crate Structure

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
