# latticearc

Post-quantum cryptography library for Rust with unified API.

## Why LatticeArc?

| Manual Implementation | LatticeArc |
|----------------------|------------|
| ~50 lines for hybrid signing | 2 lines |
| Manage 4 separate key vectors | Single `SignedData` struct |
| Research NIST parameter sets | `UseCase::*` auto-selects |
| Manual memory zeroization | Automatic via `Zeroize` |

## Overview

LatticeArc provides post-quantum cryptographic primitives implementing NIST FIPS 203-206 standards:

- **ML-KEM** (FIPS 203) - Key encapsulation
- **ML-DSA** (FIPS 204) - Digital signatures
- **SLH-DSA** (FIPS 205) - Hash-based signatures
- **FN-DSA** (FIPS 206) - Lattice signatures
- **Hybrid encryption** - PQC + classical for defense-in-depth
- **TLS 1.3** - Post-quantum TLS integration

## Unified API

LatticeArc uses a **consistent builder pattern** across all APIs:

```rust
// Crypto operations use CryptoConfig
CryptoConfig::new()
    .use_case(UseCase::FileStorage)
    .session(&session)

// TLS configuration uses TlsConfig
TlsConfig::new()
    .use_case(TlsUseCase::WebServer)
    .with_fallback(true)
```

Both APIs share the same intuitive pattern:
- `::new()` creates defaults
- `.use_case()` selects algorithm by scenario
- `.security_level()` selects algorithm by security level

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
latticearc = "0.1"
```

### Digital Signatures

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

// Generate signing keypair (defaults: ML-DSA-65 + Ed25519)
let config = CryptoConfig::new();
let (pk, sk) = generate_signing_keypair(&config)?;

// Sign
let signed = sign_with_key(b"important document", &sk, &pk, &config)?;

// Verify
let is_valid = verify(&signed, &config)?;
```

### Encryption

```rust
use latticearc::{encrypt, decrypt, CryptoConfig};

let key = [0u8; 32];  // 256-bit key
let encrypted = encrypt(b"secret message", &key, CryptoConfig::new())?;
let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())?;
```

### With Use Case Selection

```rust
use latticearc::{generate_signing_keypair, sign_with_key, CryptoConfig, UseCase};

// Library auto-selects optimal algorithm
let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
let (pk, sk) = generate_signing_keypair(&config)?;
let signed = sign_with_key(b"financial data", &sk, &pk, &config)?;
```

### With Security Level

```rust
use latticearc::{generate_signing_keypair, sign_with_key, CryptoConfig, SecurityLevel};

// Maximum security (ML-DSA-87 + Ed25519)
let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
let (pk, sk) = generate_signing_keypair(&config)?;
let signed = sign_with_key(b"classified", &sk, &pk, &config)?;
```

### Key Generation

```rust
use latticearc::generate_keypair;

// Generate Ed25519 keypair
let (public_key, private_key) = generate_keypair()?;
```

### Hybrid Encryption

```rust
use latticearc::{generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid, SecurityMode};

// Generate hybrid keypair (ML-KEM-768 + X25519)
let (pk, sk) = generate_hybrid_keypair()?;

// Encrypt using hybrid KEM (ML-KEM + X25519 + HKDF + AES-256-GCM)
let encrypted = encrypt_hybrid(b"sensitive data", &pk, SecurityMode::Unverified)?;

// Decrypt
let plaintext = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
```

### Hybrid Signatures

```rust
use latticearc::{generate_hybrid_signing_keypair, sign_hybrid, verify_hybrid_signature, SecurityMode};

// Generate hybrid signing keypair (ML-DSA-65 + Ed25519)
let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;

// Sign (both ML-DSA and Ed25519)
let signature = sign_hybrid(b"document", &sk, SecurityMode::Unverified)?;

// Verify (both must pass)
let valid = verify_hybrid_signature(b"document", &signature, &pk, SecurityMode::Unverified)?;
```

### With Zero Trust Session

For enterprise security with session-based verification:

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, generate_keypair, CryptoConfig, VerifiedSession};

// Establish verified session
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// Operations with session verification
let config = CryptoConfig::new().session(&session);
let (pk, sk) = generate_signing_keypair(&config)?;
let signed = sign_with_key(b"authenticated message", &sk, &pk, &config)?;
let is_valid = verify(&signed, &config)?;
```

### Post-Quantum TLS

```rust
use arc_tls::{TlsConfig, TlsUseCase};
use arc_core::SecurityLevel;

// Default: Hybrid mode (X25519 + ML-KEM)
let config = TlsConfig::new();

// By use case
let config = TlsConfig::new().use_case(TlsUseCase::WebServer);

// By security level
let config = TlsConfig::new().security_level(SecurityLevel::Maximum);
```

### Low-Level Primitives

For direct access to NIST algorithms:

```rust
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use rand::rngs::OsRng;

let mut rng = OsRng;
let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;
let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &pk)?;
let recovered = MlKem::decapsulate(&sk, &ciphertext)?;
```

## Included Features

All features are included by default:

- Post-quantum KEM (ML-KEM-512/768/1024)
- Post-quantum signatures (ML-DSA, SLH-DSA, FN-DSA)
- Hybrid encryption (PQC + classical)
- Zero-knowledge proofs (Schnorr, Pedersen)
- TLS 1.3 integration
- Use case-based scheme selection

## Algorithm Selection

### By Use Case

| Use Case | Encryption | Signatures |
|----------|------------|------------|
| `SecureMessaging` | ML-KEM-768 + AES-256-GCM | ML-DSA-65 + Ed25519 |
| `FileStorage` | ML-KEM-1024 + AES-256-GCM | ML-DSA-87 + Ed25519 |
| `FinancialTransactions` | N/A | ML-DSA-65 + Ed25519 |
| `IoTDevice` | ML-KEM-512 + AES-256-GCM | ML-DSA-44 + Ed25519 |

### By Security Level

| Level | Mode | Encryption | Signatures |
|-------|------|------------|------------|
| `Quantum` | PQ-only | ML-KEM-1024 + AES-256-GCM | ML-DSA-87 |
| `Maximum` | Hybrid | ML-KEM-1024 + AES-256-GCM | ML-DSA-87 + Ed25519 |
| `High` (default) | Hybrid | ML-KEM-768 + AES-256-GCM | ML-DSA-65 + Ed25519 |
| `Standard` | Hybrid | ML-KEM-512 + AES-256-GCM | ML-DSA-44 + Ed25519 |

> For complete security level documentation, see [docs/UNIFIED_API_GUIDE.md](../docs/UNIFIED_API_GUIDE.md).

## Runnable Examples

The `latticearc` crate includes comprehensive examples:

- `basic_encryption.rs` - Simple symmetric encryption with AES-256-GCM
- `digital_signatures.rs` - Digital signatures with ML-DSA and hybrid modes
- `hybrid_encryption.rs` - Hybrid encryption (ML-KEM + X25519 + HKDF)
- `post_quantum_signatures.rs` - Post-quantum signature schemes
- `complete_secure_workflow.rs` - End-to-end secure workflow with Zero Trust
- `zero_knowledge_proofs.rs` - Zero-knowledge proof demonstrations

Run an example with:
```bash
cargo run --example basic_encryption
cargo run --example digital_signatures
```

## Security

- No unsafe code
- Constant-time operations
- Automatic secret zeroization
- CAVP test vector validation

## Documentation

- [API Reference](https://docs.rs/latticearc)
- [Unified API Guide](../docs/UNIFIED_API_GUIDE.md)
- [Security Guide](../docs/SECURITY_GUIDE.md)
- [NIST Compliance](../docs/NIST_COMPLIANCE.md)

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md)
