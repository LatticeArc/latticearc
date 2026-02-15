# FIPS 140-3 Security Policy

**Module Name**: LatticeArc Cryptographic Module
**Module Version**: 0.1.0
**Module Type**: Software (FIPS 140-3 Level 1)
**Date**: 2026-02-15
**Status**: Pre-submission draft — not yet CMVP validated

---

## 1. Module Identification

| Field | Value |
|-------|-------|
| Module Name | LatticeArc Cryptographic Module |
| Module Version | 0.1.0 |
| Module Type | Software library |
| Security Level | Level 1 (overall) |
| Language | Rust (edition 2024, MSRV 1.93) |
| Platforms | Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64 |
| Underlying Crypto | aws-lc-rs (FIPS validated), fips204, fips205, fn-dsa |

---

## 2. Cryptographic Module Boundary

The FIPS cryptographic boundary is defined by the `fips` feature flag in `arc-primitives/Cargo.toml`. When `fips` is enabled:

- **Included**: All FIPS-approved algorithms (see Section 3)
- **Excluded**: Non-approved algorithms gated by `#[cfg(not(feature = "fips"))]`:
  - Ed25519 (not FIPS-approved)
  - Secp256k1 (not FIPS-approved)
  - ChaCha20-Poly1305 (not FIPS-approved)
  - X25519 ECDH (not FIPS-approved)
  - ZKP operations (not FIPS-approved)

### Boundary Crates

| Crate | In Boundary | Role |
|-------|-------------|------|
| `arc-primitives` | Yes | Core cryptographic implementations |
| `arc-core` | Yes | Unified API layer |
| `arc-validation` | Yes | FIPS validation and self-tests |
| `latticearc` | Yes | Public API facade |
| `arc-prelude` | Yes | Error types, common utilities |
| `arc-hybrid` | Partial | Hybrid KEM (ML-KEM + X25519 gated) |
| `arc-tls` | No | TLS integration (outside boundary) |
| `arc-zkp` | No | ZKP (non-FIPS) |
| `arc-perf` | No | Benchmarking (non-cryptographic) |

---

## 3. Approved Algorithms

| Algorithm | Standard | Implementation | Service |
|-----------|----------|----------------|---------|
| ML-KEM-512/768/1024 | FIPS 203 | aws-lc-rs | Key encapsulation |
| ML-DSA-44/65/87 | FIPS 204 | fips204 crate | Digital signatures |
| SLH-DSA-SHAKE-128s/f, 192s/f, 256s/f | FIPS 205 | fips205 crate | Hash-based signatures |
| FN-DSA-512/1024 | FIPS 206 (draft) | fn-dsa crate | Lattice signatures |
| AES-256-GCM | SP 800-38D | aws-lc-rs | Authenticated encryption |
| SHA-256 | FIPS 180-4 | aws-lc-rs | Hashing |
| SHA3-256 | FIPS 202 | sha3 crate | Hashing |
| HMAC-SHA256 | FIPS 198-1 | hmac + sha2 | Message authentication |
| HKDF-SHA256 | SP 800-56C | hkdf crate | Key derivation |

### Non-Approved Algorithms (excluded when `fips` enabled)

| Algorithm | Gate |
|-----------|------|
| Ed25519 | `#[cfg(not(feature = "fips"))]` |
| Secp256k1 ECDSA | `#[cfg(not(feature = "fips"))]` |
| X25519 ECDH | `#[cfg(not(feature = "fips"))]` |
| ChaCha20-Poly1305 | `#[cfg(not(feature = "fips"))]` |

---

## 4. Modes of Operation

### FIPS Mode (Approved)

Enabled via `--features fips` at compile time. In this mode:
- Only FIPS-approved algorithms are available
- Power-up self-tests run before any crypto operation
- Self-test failure calls `std::process::abort()` — no recovery
- Module integrity verification via HMAC-SHA256 of binary
- Pairwise Consistency Tests (PCT) run after every key generation

### Non-FIPS Mode (Default)

Default build without `fips` feature. All algorithms available including non-approved. Self-tests can be optionally enabled via `fips-self-test` feature.

---

## 5. Self-Tests

### 5.1 Power-Up Self-Tests

Executed automatically on first cryptographic operation (lazy initialization via `std::sync::Once`). Located in `arc-primitives/src/self_test.rs`.

| Test | Type | Algorithm | Requirement |
|------|------|-----------|-------------|
| Module Integrity | Integrity | HMAC-SHA256 | FIPS 140-3 §9.2.2 |
| SHA-256 KAT | Known Answer | SHA-256 | FIPS 140-3 §9.1 |
| SHA3-256 KAT | Known Answer | SHA3-256 | FIPS 140-3 §9.1 |
| HMAC-SHA256 KAT | Known Answer | HMAC-SHA256 | FIPS 140-3 §9.1 |
| HKDF-SHA256 KAT | Known Answer | HKDF-SHA256 | FIPS 140-3 §9.1 |
| AES-256-GCM KAT | Known Answer | AES-256-GCM | FIPS 140-3 §9.1 |
| ML-KEM-768 KAT | Known Answer | ML-KEM | FIPS 140-3 §9.1 |
| ML-DSA-44 KAT | Known Answer | ML-DSA | FIPS 140-3 §9.1 |
| SLH-DSA KAT | Known Answer | SLH-DSA | FIPS 140-3 §9.1 |
| FN-DSA-512 KAT | Known Answer | FN-DSA | FIPS 140-3 §9.1 |

### 5.2 Conditional Self-Tests

| Test | Trigger | Algorithm |
|------|---------|-----------|
| Pairwise Consistency Test | After keygen | ML-DSA, SLH-DSA, FN-DSA |
| Pairwise Consistency Test | After keygen | Ed25519, Secp256k1 (non-FIPS) |

PCT implementation: Sign fixed message `b"FIPS PCT test"` with generated private key, verify with corresponding public key. Failure enters error state.

### 5.3 Module Integrity Test

1. `build.rs` generates `integrity_hmac.rs` containing expected HMAC:
   - Production: reads from `PRODUCTION_HMAC.txt` (externally generated)
   - Development: sets expected HMAC to `None`
2. At runtime, `integrity_test()` computes HMAC-SHA256 over the current binary
3. Compares against expected value
4. Debug builds: warn and continue if no expected HMAC
5. Release builds: fail if no expected HMAC configured

### 5.4 Self-Test Failure Behavior

On any self-test failure:
- `std::process::abort()` is called immediately
- No crypto operations are permitted
- No recovery path (FIPS 140-3 compliant)
- Error state transitions: Power-up → Self-test → **Abort** (on failure) or Operational (on success)

---

## 6. Cryptographic Key Management

### 6.1 Key Types (Critical Security Parameters)

| CSP | Algorithm | Generation | Storage | Zeroization |
|-----|-----------|------------|---------|-------------|
| ML-KEM Decapsulation Key | ML-KEM | `aws-lc-rs` RNG | In-memory only | `ZeroizeOnDrop` |
| ML-KEM Shared Secret | ML-KEM | Encapsulation | In-memory only | `Zeroize` on drop |
| ML-DSA Signing Key | ML-DSA | `fips204` RNG | `Zeroizing<Vec<u8>>` | Auto-zeroized |
| SLH-DSA Signing Key | SLH-DSA | `fips205` RNG | `Zeroizing<Vec<u8>>` | Auto-zeroized |
| FN-DSA Signing Key | FN-DSA | `fn-dsa` RNG | `Zeroizing<Vec<u8>>` | Auto-zeroized |
| AES-256-GCM Key | AES-256-GCM | HKDF or user-provided | In-memory | `Zeroize` on drop |
| HMAC Key | HMAC-SHA256 | User-provided | In-memory | Caller responsibility |

### 6.2 Key Generation

- All key generation uses `OsRng` (operating system CSPRNG)
- No `thread_rng()` in production code
- PCT runs automatically after PQC key generation

### 6.3 Key Zeroization

- Secret types derive `Zeroize` and `ZeroizeOnDrop`
- Secret types do NOT implement `Clone`, `Debug`, or `Serialize`
- `Zeroizing<Vec<u8>>` wrapper used for secret key byte vectors
- Memory zeroization occurs on `Drop`

### 6.4 Key Storage

- No persistent key storage in the module
- Keys exist only in volatile memory during process lifetime
- ML-KEM `DecapsulationKey` cannot be serialized (aws-lc-rs security design)
- Applications must implement their own key persistence using HSM/KMS

---

## 7. Access Control

### Level 1 Software Module

As a Level 1 software module, access control is delegated to the operating system:
- Process isolation via OS memory protection
- No hardware security boundary
- File system permissions for module binary

### API Access Tiers

| Tier | API | FIPS Guard |
|------|-----|------------|
| Unified (recommended) | `encrypt()`, `decrypt()`, `sign_with_key()`, `verify()` | `fips_verify_operational()` enforced |
| Expert | `sign_pq_ml_dsa()`, `encrypt_aes_gcm()`, etc. | Caller responsibility |

---

## 8. Physical Security

Not applicable — software-only module (FIPS 140-3 Level 1).

---

## 9. Operational Environment

| Requirement | Implementation |
|-------------|----------------|
| Operating System | General-purpose OS (Linux, macOS, Windows) |
| Rust Version | 1.93+ (edition 2024) |
| Unsafe Code | Forbidden (`unsafe_code = "forbid"` workspace-wide) |
| Memory Safety | Guaranteed by Rust type system + `zeroize` |
| Side-Channel Mitigation | `subtle` crate for constant-time comparisons |

---

## 10. Mitigation of Other Attacks

| Attack | Mitigation |
|--------|------------|
| Timing side-channels | `subtle::ConstantTimeEq` for secret comparisons |
| Memory disclosure | `Zeroize`/`ZeroizeOnDrop` on all CSPs |
| Key oracle | Generic error messages (no upstream key validation details) |
| Binary tampering | HMAC-SHA256 integrity test at power-up |
| Algorithm downgrade | Feature flag gating, no runtime algorithm negotiation in FIPS mode |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-02-15 | Initial draft |
