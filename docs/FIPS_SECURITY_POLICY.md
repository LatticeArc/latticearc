# LatticeArc Cryptographic Module Security Policy

**Document Version:** 1.0
**Module Version:** 0.1.0
**FIPS 140-3 Target Level:** Level 2 (Software Module)
**Date:** January 2026

## 1. Introduction

### 1.1 Purpose

This Security Policy describes the LatticeArc Cryptographic Module, a software-only cryptographic module implementing NIST post-quantum cryptography standards (FIPS 203-206) and classical cryptographic algorithms for secure data protection.

### 1.2 Module Overview

| Property | Value |
|----------|-------|
| Module Name | LatticeArc Cryptographic Module |
| Module Version | 0.1.0 |
| Module Type | Software |
| FIPS 140-3 Level | Level 2 |
| Operational Environment | General Purpose Computer (GPC) |
| Programming Language | Rust (2024 Edition) |

### 1.3 Cryptographic Boundary

The cryptographic boundary encompasses all software components within the `arc-primitives` crate, including:

- Key Encapsulation Mechanisms (KEM)
- Digital Signature Algorithms
- Authenticated Encryption with Associated Data (AEAD)
- Hash Functions
- Key Derivation Functions (KDF)
- Random Number Generation interfaces

```
┌─────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC BOUNDARY                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    arc-primitives                          │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐      │  │
│  │  │   KEM   │  │   SIG   │  │  AEAD   │  │  HASH   │      │  │
│  │  │ ML-KEM  │  │ ML-DSA  │  │ AES-GCM │  │ SHA-2/3 │      │  │
│  │  │         │  │ SLH-DSA │  │         │  │         │      │  │
│  │  │         │  │ FN-DSA  │  │         │  │         │      │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘      │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                   │  │
│  │  │   KDF   │  │   RNG   │  │ SELF-   │                   │  │
│  │  │  HKDF   │  │ Health  │  │ TEST    │                   │  │
│  │  │ PBKDF2  │  │ Tests   │  │         │                   │  │
│  │  └─────────┘  └─────────┘  └─────────┘                   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  External Dependencies (FIPS Validated):                         │
│  - aws-lc-rs (FIPS 140-3 Cert #4631, #4759, #4816)             │
└─────────────────────────────────────────────────────────────────┘
```

## 2. Approved Algorithms

### 2.1 FIPS-Approved Algorithms

| Algorithm | Standard | Parameter Sets | Key Sizes | Use |
|-----------|----------|----------------|-----------|-----|
| ML-KEM | FIPS 203 | 512, 768, 1024 | 800-1568 bytes (PK) | Key Encapsulation |
| ML-DSA | FIPS 204 | 44, 65, 87 | 1312-2592 bytes (PK) | Digital Signatures |
| SLH-DSA | FIPS 205 | SHAKE-128s/f, 192s/f, 256s/f | Variable | Digital Signatures |
| FN-DSA | FIPS 206 | 512, 1024 | 897-1793 bytes (PK) | Digital Signatures |
| AES-GCM | FIPS 197 / SP 800-38D | 128, 256 | 128, 256 bits | AEAD Encryption |
| SHA-2 | FIPS 180-4 | SHA-256, SHA-384, SHA-512 | N/A | Hashing |
| SHA-3 | FIPS 202 | SHA3-256, SHA3-384, SHA3-512 | N/A | Hashing |
| HMAC | FIPS 198-1 | HMAC-SHA256, HMAC-SHA384 | 256, 384 bits | MAC |
| HKDF | SP 800-56C | HKDF-SHA256 | Variable | Key Derivation |
| PBKDF2 | SP 800-132 | PBKDF2-HMAC-SHA256 | Variable | Key Derivation |

### 2.2 Non-Approved Algorithms (Excluded from FIPS Mode)

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ChaCha20-Poly1305 | RFC 8439 | Non-FIPS (disabled in FIPS builds) |
| Ed25519 | RFC 8032 | Non-FIPS (used only in hybrid mode) |
| X25519 | RFC 7748 | Non-FIPS (used only in hybrid mode) |

### 2.3 Algorithm Implementation Status

| Algorithm | Implementation | FIPS Validated |
|-----------|----------------|----------------|
| ML-KEM | aws-lc-rs | Yes (Cert #4631, #4759, #4816) |
| ML-DSA | fips204 crate | No (awaiting aws-lc-rs API) |
| SLH-DSA | fips205 crate | Audited |
| FN-DSA | fn-dsa crate | Partial |
| AES-GCM | aws-lc-rs | Yes |
| SHA-2 | aws-lc-rs | Yes |
| SHA-3 | sha3 crate | Audited |

## 3. Security Levels

### 3.1 NIST Security Level Mapping

| NIST Level | Classical Equivalent | LatticeArc Algorithms |
|------------|---------------------|----------------------|
| Level 1 | AES-128 | ML-KEM-512, ML-DSA-44, SLH-DSA-128 |
| Level 2 | SHA-256 collision | ML-DSA-44 |
| Level 3 | AES-192 | ML-KEM-768, ML-DSA-65, SLH-DSA-192 |
| Level 4 | SHA-384 collision | ML-DSA-65 |
| Level 5 | AES-256 | ML-KEM-1024, ML-DSA-87, SLH-DSA-256 |

### 3.2 Module Security Level

The module targets FIPS 140-3 Security Level 2:

| Security Area | Level | Implementation |
|---------------|-------|----------------|
| Cryptographic Module Specification | 2 | This document |
| Cryptographic Module Interfaces | 2 | Defined API boundaries |
| Roles, Services, and Authentication | 2 | Role-based access |
| Software/Firmware Security | 2 | Rust memory safety |
| Operational Environment | 2 | GPC with approved OS |
| Physical Security | N/A | Software module |
| Non-Invasive Security | N/A | Software module |
| Sensitive Security Parameter Management | 2 | Zeroization on drop |
| Self-Tests | 2 | Power-up and conditional |
| Life-Cycle Assurance | 2 | Documented SDLC |
| Mitigation of Other Attacks | 2 | Constant-time operations |

## 4. Roles and Services

### 4.1 Roles

| Role | Description | Authentication |
|------|-------------|----------------|
| Crypto Officer | Administers module, manages keys | Implicit (process owner) |
| User | Performs cryptographic operations | Implicit (API caller) |

### 4.2 Services

#### 4.2.1 Crypto Officer Services

| Service | Description | Input | Output |
|---------|-------------|-------|--------|
| Module Initialize | Initialize module, run self-tests | None | Status |
| Key Generation | Generate cryptographic key pairs | Algorithm, Parameters | Key Pair |
| Key Import | Import external keys | Key material | Status |
| Key Zeroization | Securely destroy keys | Key handle | Status |
| Self-Test | Execute self-tests on demand | Test type | Results |
| Status Query | Query module operational status | None | Status |

#### 4.2.2 User Services

| Service | Description | Input | Output |
|---------|-------------|-------|--------|
| Encrypt | Encrypt data | Plaintext, Key | Ciphertext |
| Decrypt | Decrypt data | Ciphertext, Key | Plaintext |
| Sign | Generate digital signature | Message, Private Key | Signature |
| Verify | Verify digital signature | Message, Signature, Public Key | Valid/Invalid |
| Hash | Compute hash digest | Data | Digest |
| MAC | Compute/verify MAC | Data, Key | MAC |
| KDF | Derive keys | Input material, Parameters | Derived key |
| Encapsulate | ML-KEM encapsulation | Public Key | Shared Secret, Ciphertext |
| Decapsulate | ML-KEM decapsulation | Ciphertext, Private Key | Shared Secret |

### 4.3 Service Access Control

| Service | Crypto Officer | User |
|---------|---------------|------|
| Module Initialize | Yes | No |
| Key Generation | Yes | Yes |
| Key Import | Yes | No |
| Key Zeroization | Yes | Yes (own keys) |
| Self-Test | Yes | No |
| Status Query | Yes | Yes |
| Encrypt/Decrypt | Yes | Yes |
| Sign/Verify | Yes | Yes |
| Hash | Yes | Yes |
| MAC | Yes | Yes |
| KDF | Yes | Yes |
| Encapsulate/Decapsulate | Yes | Yes |

## 5. Sensitive Security Parameters (SSP)

### 5.1 SSP Inventory

| SSP | Type | Generation | Storage | Zeroization |
|-----|------|------------|---------|-------------|
| ML-KEM Private Key | Secret | Internal DRBG | RAM (ZeroizeOnDrop) | Automatic on drop |
| ML-DSA Private Key | Secret | Internal DRBG | RAM (ZeroizeOnDrop) | Automatic on drop |
| SLH-DSA Private Key | Secret | Internal DRBG | RAM (ZeroizeOnDrop) | Automatic on drop |
| FN-DSA Private Key | Secret | Internal DRBG | RAM (ZeroizeOnDrop) | Automatic on drop |
| AES Key | Secret | Internal DRBG or derived | RAM (ZeroizeOnDrop) | Automatic on drop |
| HMAC Key | Secret | Internal DRBG or derived | RAM (ZeroizeOnDrop) | Automatic on drop |
| Shared Secret (KEM) | Secret | Encapsulation | RAM (ZeroizeOnDrop) | Automatic on drop |
| HKDF PRK | Secret | Extraction | RAM (ZeroizeOnDrop) | Automatic on drop |

### 5.2 SSP Protection

All SSPs are protected using Rust's ownership system and the `zeroize` crate:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: Vec<u8>,
}
```

- **In Memory**: SSPs exist only in process memory
- **On Drop**: Automatic zeroization when SSP goes out of scope
- **No Persistence**: SSPs are never written to disk by the module
- **No Export**: Private keys cannot be exported in plaintext

### 5.3 Key Establishment

| Method | Description | Standard |
|--------|-------------|----------|
| ML-KEM | Post-quantum key encapsulation | FIPS 203 |
| HKDF | Key derivation from shared secret | SP 800-56C |
| Hybrid | ML-KEM + X25519 combined | Defense in depth |

## 6. Self-Tests

### 6.1 Power-Up Self-Tests

Executed automatically when the module initializes:

| Test | Algorithm | Type | Action on Failure |
|------|-----------|------|-------------------|
| SHA-256 KAT | SHA-256 | Known Answer | Module enters error state |
| AES-GCM KAT | AES-256-GCM | Known Answer | Module enters error state |
| ML-KEM KAT | ML-KEM-768 | Known Answer | Module enters error state |
| HKDF KAT | HKDF-SHA256 | Known Answer | Module enters error state |
| Software Integrity | Module | Integrity | Module enters error state |

### 6.2 Conditional Self-Tests

Executed when specific conditions are met:

| Test | Trigger | Type | Action on Failure |
|------|---------|------|-------------------|
| ML-DSA PCT | Key generation | Pairwise Consistency | Key generation fails |
| SLH-DSA PCT | Key generation | Pairwise Consistency | Key generation fails |
| FN-DSA PCT | Key generation | Pairwise Consistency | Key generation fails |
| Entropy Health | RNG output | Statistical | RNG operation fails |

### 6.3 Entropy Health Tests (SP 800-90B)

| Test | Description | Threshold |
|------|-------------|-----------|
| Repetition | Consecutive identical values | Max 5 consecutive |
| Frequency | Byte value distribution | Max 1.5x expected |
| Monobit | Bit balance (0s vs 1s) | 40-60% ones |
| Runs | Consecutive bit sequences | ±30% of expected |
| Longest Run | Maximum consecutive bits | log2(n) + margin |
| Adaptive Proportion | Value proportion in window | Max 40% single value |

### 6.4 Self-Test Implementation

```rust
// Power-up self-tests (automatic on module init)
pub fn run_power_up_self_tests() -> Result<SelfTestReport>;

// Conditional self-tests
pub fn pct_ml_dsa(pk: &PublicKey, sk: &SecretKey) -> Result<()>;
pub fn pct_slh_dsa(vk: &VerifyingKey, sk: &SigningKey) -> Result<()>;
pub fn pct_fn_dsa(vk: &VerifyingKey, sk: &SigningKey) -> Result<()>;

// Entropy health tests
pub fn run_entropy_health_tests() -> Result<()>;
```

## 7. Module States

### 7.1 Operational States

| State | Description | Allowed Operations |
|-------|-------------|-------------------|
| Uninitialized | Module loaded but not initialized | None |
| Self-Test | Running power-up self-tests | None |
| Operational | Normal operation | All services |
| Error | Self-test or critical failure | Status query only |
| Zeroization | Destroying all SSPs | None |

### 7.2 State Transitions

See [FIPS_FINITE_STATE_MODEL.md](FIPS_FINITE_STATE_MODEL.md) for detailed state diagrams.

## 8. Physical Security

As a software-only module, physical security is provided by the operational environment:

- **Operational Environment**: General Purpose Computer
- **Operating Systems**: Linux (x86_64, aarch64), macOS, Windows
- **Memory Protection**: OS-provided process isolation
- **No Physical Ports**: Software module has no physical interfaces

## 9. Mitigation of Other Attacks

### 9.1 Timing Attack Mitigation

All cryptographic operations use constant-time implementations:

- **Comparison**: `subtle::ConstantTimeEq` for secret comparisons
- **Selection**: `subtle::ConditionallySelectable` for branching on secrets
- **Memory Access**: No secret-dependent memory access patterns

### 9.2 Memory Safety

- **No Unsafe Code**: `#![deny(unsafe_code)]` enforced
- **Bounds Checking**: All array accesses use `.get()` or are bounds-checked
- **No Panics**: `#![deny(clippy::unwrap_used, clippy::panic)]`
- **Automatic Zeroization**: `ZeroizeOnDrop` trait on all secrets

### 9.3 Side-Channel Mitigation

| Attack | Mitigation |
|--------|------------|
| Timing | Constant-time operations |
| Cache | Avoid secret-dependent access patterns |
| Power | (Hardware responsibility) |
| EM | (Hardware responsibility) |

## 10. Operational Environment

### 10.1 Approved Operating Systems

| OS | Architecture | Notes |
|----|--------------|-------|
| Linux | x86_64, aarch64 | Kernel 5.x+ |
| macOS | x86_64, aarch64 | 12.0+ |
| Windows | x86_64 | 10/11, Server 2019+ |

### 10.2 Requirements

- Rust 1.93+ (MSRV)
- ASLR enabled
- DEP/NX enabled
- Process isolation

## 11. Documentation References

| Document | Description |
|----------|-------------|
| FIPS_FINITE_STATE_MODEL.md | Detailed state machine |
| NIST_COMPLIANCE.md | Algorithm compliance status |
| ML_KEM_KEY_PERSISTENCE.md | Key persistence workarounds |
| DEPENDENCIES.md | Supply chain security |

## 12. Revision History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | January 2026 | Initial release |

---

**END OF SECURITY POLICY DOCUMENT**
