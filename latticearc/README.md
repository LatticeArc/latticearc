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

## When to Use LatticeArc

Most PQ deployment today is TLS hybrid key exchange. LatticeArc targets **application-layer PQ crypto** — encrypting records, signing documents, protecting keys at rest.

**Use it when you want:**

- **Hybrid composition without the wiring.** General-purpose hybrid encrypt/decrypt (ML-KEM + X25519 + HKDF + AES-GCM as a complete AEAD pipeline) is DIY in every other library. LatticeArc ships the full pipeline as the default mode.
- **Use-case-driven selection.** `UseCase::HealthcareRecords` auto-selects algorithm, security level, and compliance mode. 22 workload types, two compliance modes. No other library or CLI offers this.
- **A CLI from the same trust boundary.** Ops teams get keygen, encrypt, sign, verify, and hash without writing Rust. Non-Rust teams can evaluate PQC through the CLI before committing to the SDK.
- **Opt-in FIPS routing.** `--features fips` routes AES-GCM, ML-KEM, HKDF, and SHA-2 through CMVP-validated aws-lc-rs — no code changes.

**Reach for something else when:**

- **You need a single primitive.** `aws-lc-rs`, `fips204`, `fips205`, `fn-dsa` are smaller dependencies. LatticeArc's value is the composition.
- **You need a CMVP-certified module end-to-end.** No CMVP-validated backend exists for PQ signatures today. See [What's Included](#whats-included).
- **You need cross-language bindings.** LatticeArc is Rust-only. liboqs provides C, Python, Go, Java, and Rust.
- **You target `no_std` or embedded.** LatticeArc is `std`-only. wolfCrypt leads for embedded PQ.
- **You need a TLS stack.** Use rustls, OpenSSL 3.5, or wolfSSL.

> For a detailed comparison with other PQC libraries, CLIs, and managed services across languages, see the [Ecosystem Map](../docs/ECOSYSTEM.md).

## Quick Start

```toml
[dependencies]
latticearc = "0.6"
```

### Hybrid Encryption (Recommended)

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, EncryptKey, DecryptKey};

// ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM — selected automatically
let (pk, sk) = latticearc::generate_hybrid_keypair()?;
let encrypted = encrypt(b"patient records", EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
```

### PQ-Only Encryption (CNSA 2.0)

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, CryptoMode, EncryptKey, DecryptKey};

// ML-KEM-768 + HKDF-SHA256 + AES-256-GCM — no classical component
let (pk, sk) = latticearc::generate_pq_keypair()
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
let config = CryptoConfig::new().crypto_mode(CryptoMode::PqOnly);
let encrypted = encrypt(b"classified", EncryptKey::PqOnly(&pk), config.clone())?;
let decrypted = decrypt(&encrypted, DecryptKey::PqOnly(&sk), config)?;
```

### Digital Signatures

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

// ML-DSA-65 + Ed25519 hybrid signature
let config = CryptoConfig::new();
let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;
let signed = sign_with_key(b"contract.pdf", &sk, &pk, config.clone())?;
assert!(verify(&signed, config)?);
```

### Use Case Selection

```rust
use latticearc::{encrypt, CryptoConfig, UseCase, EncryptKey};

// Library selects ML-KEM-1024 + X25519 for government classified data
let (pk, _sk) = latticearc::generate_hybrid_keypair()?;
let encrypted = encrypt(b"data", EncryptKey::Hybrid(&pk),
    CryptoConfig::new().use_case(UseCase::GovernmentClassified))?;
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
| **Hash** | SHA-2 (256/384/512) | aws-lc-rs — routed through FIPS 140-3 validated module with `--features fips` |
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

- Zero `unsafe` code
- Constant-time comparisons via `subtle`
- Automatic secret zeroization via `Zeroize`
- CAVP test vector validation
- 27 Kani formal verification proofs
- Opaque AEAD error messages (SP 800-38D)

For the per-algorithm validation status (what's CMVP-validated, what's only
NIST-conformant), see [What's Included](#whats-included) above.

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
