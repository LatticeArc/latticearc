# latticearc

[![crates.io](https://img.shields.io/crates/v/latticearc.svg)](https://crates.io/crates/latticearc)
[![docs.rs](https://docs.rs/latticearc/badge.svg)](https://docs.rs/latticearc)
[![CI](https://github.com/LatticeArc/latticearc/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeArc/latticearc/actions/workflows/ci.yml)
[![FIPS 203-206](https://img.shields.io/badge/FIPS_203--206-implemented-blue)](https://docs.rs/latticearc)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Post-quantum cryptography for Rust. Implements all four NIST PQC standards (FIPS 203–206) behind a use-case-driven API — describe what you're protecting, the library picks the algorithm, security level, and compliance mode. Hybrid (PQ + classical) by default; PQ-only mode for CNSA 2.0.

## Install

```toml
[dependencies]
latticearc = "0.8"
```

Requires Rust 1.93+ and a C/C++ compiler. For FIPS-validated routing also CMake + Go (`--features fips`).

## Quick Start

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, EncryptKey, DecryptKey};

let (pk, sk) = latticearc::generate_hybrid_keypair()?;
let encrypted = encrypt(b"secret data", EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
// ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM — selected automatically
```

## CLI

A companion command-line tool — `latticearc-cli` — exposes the same library so ops and CI workflows can use PQ crypto without writing Rust:

```bash
cargo install --git https://github.com/LatticeArc/latticearc latticearc-cli

# Sign a legal document (ML-DSA-87 + Ed25519 hybrid, selected by use case)
latticearc-cli keygen --use-case legal-documents --output ./keys
latticearc-cli sign   --input contract.pdf \
  --key keys/hybrid-ml-dsa-87-ed25519.sec.json \
  --public-key keys/hybrid-ml-dsa-87-ed25519.pub.json

# Encrypt healthcare records (AES-256-GCM, FIPS 203 backend)
latticearc-cli keygen  --algorithm aes256 --output ./keys
latticearc-cli encrypt --use-case healthcare-records \
  --input patient.json --output patient.enc.json --key keys/aes256.key.json
```

22 use cases · 12 algorithms · hybrid + PQ-only modes. Full reference: [`latticearc-cli` README](https://github.com/LatticeArc/latticearc/tree/main/latticearc-cli).

## What's Inside

| Category | Algorithms | Backend |
|----------|-----------|---------|
| PQ KEM | ML-KEM-512/768/1024 (FIPS 203) | aws-lc-rs — FIPS-validatable |
| PQ Signatures | ML-DSA, SLH-DSA, FN-DSA (FIPS 204/205/206) | fips204 / fips205 / fn-dsa |
| Classical | X25519, Ed25519, AES-256-GCM, SHA-2/3, BLAKE2, HKDF | aws-lc-rs / RustCrypto |

`--features fips` routes AES-GCM, ML-KEM, X25519, and HKDF through the CMVP-validated aws-lc-rs build. PQ signatures use NIST-conformant but non-validated crates. LatticeArc itself is **not** a CMVP-certified cryptographic module.

## Security

- `#![forbid(unsafe_code)]`, constant-time comparisons via `subtle`, automatic secret zeroization
- 30 Kani proofs (18 PR-blocking) + cross-impl differential testing + 31 fuzz targets + Wycheproof + mutation testing at 80% floor
- Pre-1.0: API may change between minor versions; see [CHANGELOG.md](https://github.com/LatticeArc/latticearc/blob/main/CHANGELOG.md)

## More

- **[GitHub repo](https://github.com/LatticeArc/latticearc)** — full README, architecture, design docs, verification details
- **[docs.rs/latticearc](https://docs.rs/latticearc)** — API reference
- **[SECURITY.md](https://github.com/LatticeArc/latticearc/blob/main/SECURITY.md)** — reporting vulnerabilities, supported versions

## License

Apache-2.0
