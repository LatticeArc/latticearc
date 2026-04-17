# latticearc

[![crates.io](https://img.shields.io/crates/v/latticearc.svg)](https://crates.io/crates/latticearc)
[![docs.rs](https://docs.rs/latticearc/badge.svg)](https://docs.rs/latticearc)
[![CI](https://github.com/LatticeArc/latticearc/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeArc/latticearc/actions/workflows/ci.yml)
[![FIPS 203-206](https://img.shields.io/badge/FIPS_203--206-implemented-blue)](https://docs.rs/latticearc)
[![codecov](https://codecov.io/gh/LatticeArc/latticearc/branch/main/graph/badge.svg)](https://codecov.io/gh/LatticeArc/latticearc)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

LatticeArc is a post-quantum cryptography library for Rust that implements all four NIST PQC standards (FIPS 203–206). It ships as one library crate with a use-case-driven API — you describe what you're protecting, the library selects the right algorithm, security level, and compliance mode automatically. Hybrid (PQ + classical) by default for defense-in-depth, with PQ-only mode available for CNSA 2.0.

Opt-in FIPS routing (`--features fips`) sends AES-GCM, ML-KEM, HKDF, and SHA-2 through a CMVP-validated aws-lc-rs build; the PQ signature algorithms use NIST-conformant but non-validated crates. LatticeArc itself is not a CMVP-certified cryptographic module — see [What's Included](#whats-included) for the per-algorithm scope.

## Why LatticeArc?

| Without LatticeArc | With LatticeArc |
|---------------------|-----------------|
| ~50 lines for hybrid encryption | 3 lines |
| Research 4 NIST standards, 11 parameter sets | `UseCase::HealthcareRecords` auto-selects |
| Wire up ML-KEM + X25519 + HKDF + AES-GCM | `EncryptKey::Hybrid(&pk)` |
| Manual secret zeroization, constant-time comparisons | Automatic via `Zeroize` + `subtle` |
| Read CNSA 2.0 to know when hybrid vs PQ-only | `CryptoMode::Hybrid` / `CryptoMode::PqOnly` |

## When to Use / When Not To

**Use LatticeArc when you want:**

- Hybrid PQ+classical encrypt/decrypt without wiring ML-KEM + X25519 + HKDF + AES-GCM yourself
- Use-case-driven algorithm selection (22 workloads, 3 compliance modes)
- A CLI backed by the same library code
- Opt-in FIPS routing with no code changes

**Reach for something else when you need:**

- A single low-level primitive — use `aws-lc-rs`, `fips204`, `fips205`, or `fn-dsa` directly
- End-to-end CMVP-certified module — no CMVP backend exists for PQ signatures yet
- Cross-language bindings — `liboqs` covers C, Python, Go, Java
- `no_std` / embedded — `wolfCrypt` leads for embedded PQ
- A TLS stack — use `rustls`, OpenSSL 3.5, or wolfSSL

> Detailed comparison: [Ecosystem Map](../docs/ECOSYSTEM.md)

## Quick Start

```toml
[dependencies]
latticearc = "0.6"
```

**Hybrid encryption** (default — PQ + classical):

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, EncryptKey, DecryptKey};

let (pk, sk) = latticearc::generate_hybrid_keypair()?;
let encrypted = encrypt(b"patient records", EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
// ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM — selected automatically
```

**Digital signatures** (ML-DSA-65 + Ed25519 hybrid):

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

let config = CryptoConfig::new();
let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;
let signed = sign_with_key(b"contract.pdf", &sk, &pk, config.clone())?;
assert!(verify(&signed, config)?);
```

## Configuration

Two orthogonal axes control algorithm selection:

```rust
CryptoConfig::new()
    .use_case(UseCase::FileStorage)       // what you're protecting (22 use cases)
    .crypto_mode(CryptoMode::PqOnly)      // hybrid or PQ-only
    .security_level(SecurityLevel::High)  // NIST level 1/3/5
    .compliance(ComplianceMode::Fips140_3) // regulatory requirements
    .session(&session)                    // optional zero-trust verification
```

### Security Levels

| Level | NIST Level | Encryption (Hybrid) | Encryption (PQ-only) |
|-------|------------|---------------------|----------------------|
| `Maximum` | 5 | ML-KEM-1024 + X25519 + AES-256-GCM | ML-KEM-1024 + AES-256-GCM |
| `High` (default) | 3 | ML-KEM-768 + X25519 + AES-256-GCM | ML-KEM-768 + AES-256-GCM |
| `Standard` | 1 | ML-KEM-512 + X25519 + AES-256-GCM | ML-KEM-512 + AES-256-GCM |

### Compliance Modes

`ComplianceMode` is a **runtime** algorithm constraint — it restricts which
algorithms the library will select. It is separate from the `fips` Cargo
feature, which controls the **compile-time** backend. See [What's Included](#whats-included).

| Mode | Hybrid Allowed | Use Case |
|------|----------------|----------|
| `Default` | Yes | Development, general use |
| `Fips140_3` | Yes | Restricts selection to FIPS 203–206 algorithms |
| `Cnsa2_0` | No | NSA CNSA 2.0 — requires `CryptoMode::PqOnly` |

## What's Included

**Algorithm conformance ≠ module validation.** LatticeArc implements the NIST
algorithm specs (FIPS 203 / 204 / 205 / 206) by delegating to audited third-party
crates. Separately, `--features fips` switches the aws-lc-rs dependency to its
CMVP-validated FIPS build; at that point AES-GCM, ML-KEM, HKDF, and SHA-2 run
through a validated module. PQ signatures (ML-DSA, SLH-DSA, FN-DSA) always use
non-validated crates — there is no CMVP-certified backend for them yet. The
LatticeArc library as a whole is **not** a CMVP-certified cryptographic module.

The table below is the source of truth for which algorithms go through a
validated module:

| Category | Algorithms | Backend |
|----------|-----------|---------|
| **PQ Key Encapsulation** | ML-KEM-512/768/1024 (FIPS 203) | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
| **PQ Signatures** | ML-DSA-44/65/87 (FIPS 204) | fips204 — NIST-conformant, not CMVP-validated |
| **PQ Hash Signatures** | SLH-DSA (FIPS 205) | fips205 — NIST-conformant, not CMVP-validated |
| **PQ Lattice Signatures** | FN-DSA-512/1024 (draft FIPS 206) | fn-dsa — NIST-conformant, not CMVP-validated |
| **Classical Signatures** | Ed25519 | ed25519-dalek — audited |
| **Classical Key Exchange** | X25519 | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
| **Symmetric Encryption** | AES-256-GCM | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
| **Symmetric Encryption** | ChaCha20-Poly1305 | chacha20poly1305 crate — non-FIPS |
| **Hash** | SHA-2 (256/384/512) | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
| **Hash** | SHA-3, BLAKE2 | sha3 / blake2 crates — non-FIPS |
| **KDF** | HKDF-SHA256 | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
| **Hybrid Encryption** | ML-KEM + X25519 + HKDF + AES-GCM | Composite |
| **PQ-Only Encryption** | ML-KEM + HKDF + AES-GCM | Composite |

## CLI

A companion CLI tool is available for key generation, signing, encryption, and hashing — no code required:

```bash
cargo install --path latticearc-cli

# Use-case-driven signing
latticearc-cli keygen --use-case legal-documents --output ./keys
latticearc-cli sign --input contract.pdf \
  --key keys/hybrid-ml-dsa-87-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-87-ed25519.pub.json

# PQ-only encryption
latticearc-cli keygen --algorithm ml-kem768 --output ./keys
latticearc-cli encrypt --mode pq-only --key keys/ml-kem-768.pub.json --input secret.pdf
```

See [`latticearc-cli/README.md`](../latticearc-cli/README.md) for the full command reference.

## Key Format

Keys use the **LatticeArc Portable Key (LPK)** format — dual JSON + CBOR, identified by use case or security level:

```rust
let (pk, sk) = latticearc::generate_hybrid_keypair()?;
let (portable_pk, portable_sk) =
    PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk)?;

let json = portable_pk.to_json()?;   // human-readable
let cbor = portable_pk.to_cbor()?;   // compact binary
```

See [`docs/KEY_FORMAT.md`](../docs/KEY_FORMAT.md) for the full specification.

## Security

- `#![forbid(unsafe_code)]` at workspace level
- Constant-time comparisons via `subtle` — validated by 3-way gate (DudeCT + ctgrind + Criterion)
- Automatic secret zeroization via `Zeroize`
- 30 Kani formal verification proofs (18 PR-blocking) + SAW-verified C primitives via aws-lc-rs
- Cross-impl differential testing against independent reference crates (ML-KEM, ML-DSA, SLH-DSA)
- 31 fuzz targets + mutation testing at 80% PR-blocking floor
- Opaque AEAD error messages (SP 800-38D)

Per-algorithm validation status: see [What's Included](#whats-included).

### Limitations

- **Not a CMVP-certified cryptographic module.** LatticeArc itself has not
  undergone CMVP certification, and no CMVP-certified backend exists for the
  PQ signature algorithms (ML-DSA, SLH-DSA, FN-DSA). Workloads that strictly
  require module validation should use `--features fips` for the subset that
  routes through aws-lc-rs and a separately-certified module for the rest.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `fips` | Routes AES-GCM, ML-KEM, HKDF, and SHA-2 through the CMVP-validated aws-lc-rs FIPS build. PQ signatures remain on non-validated crates. Requires CMake + Go. |
| `fips-self-test` | Power-up KAT self-tests for FIPS-boundary algorithms |
| `zkp-serde` | Serialization support for ZKP types |

## Documentation

- [API Reference](https://docs.rs/latticearc)
- [CLI Reference](../latticearc-cli/README.md)
- [Unified API Guide](../docs/UNIFIED_API_GUIDE.md)
- [Key Format Specification](../docs/KEY_FORMAT.md)
- [Architecture](../docs/DESIGN.md)
- [Security Guide](../docs/SECURITY_GUIDE.md)
- [NIST Compliance](../docs/NIST_COMPLIANCE.md)

## License

Apache-2.0
