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
use latticearc::{sign, verify, CryptoConfig};

// Sign with defaults (ML-DSA-65 + Ed25519)
let signed = sign(b"important document", CryptoConfig::new())?;

// Verify
let is_valid = verify(&signed, CryptoConfig::new())?;
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
use latticearc::{sign, CryptoConfig, UseCase};

// Library auto-selects optimal algorithm
let signed = sign(b"financial data", CryptoConfig::new()
    .use_case(UseCase::FinancialTransactions))?;
```

### With Security Level

```rust
use latticearc::{sign, CryptoConfig, SecurityLevel};

// Maximum security (ML-DSA-87)
let signed = sign(b"classified", CryptoConfig::new()
    .security_level(SecurityLevel::Maximum))?;
```

### Key Generation

```rust
use latticearc::generate_keypair;

// Generate Ed25519 keypair
let (public_key, private_key) = generate_keypair()?;
```

### With Zero Trust Session

For enterprise security with session-based verification:

```rust
use latticearc::{sign, verify, generate_keypair, CryptoConfig, VerifiedSession};

// Establish verified session
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// Operations with session verification
let signed = sign(b"authenticated message", CryptoConfig::new()
    .session(&session))?;

let is_valid = verify(&signed, CryptoConfig::new()
    .session(&session))?;
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
- Hardware-aware scheme selection

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
