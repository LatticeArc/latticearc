# latticearc

Post-quantum cryptography library for Rust with simple API.

## Overview

LatticeArc provides post-quantum cryptographic primitives implementing NIST FIPS 203-206 standards:

- **ML-KEM** (FIPS 203) - Key encapsulation
- **ML-DSA** (FIPS 204) - Digital signatures
- **SLH-DSA** (FIPS 205) - Hash-based signatures
- **FN-DSA** (FIPS 206) - Lattice signatures
- **Hybrid encryption** - PQC + classical for defense-in-depth
- **TLS 1.3** - Post-quantum TLS integration

## API Options

| Crate | Session Required | Zero Trust |
|-------|-----------------|------------|
| `latticearc` | No | Optional |
| `arc-core` | Yes (`VerifiedSession`) | Enforced |

The `latticearc` crate provides a simpler API without session requirements.
For Zero Trust enforcement, use `arc-core` directly with `VerifiedSession`.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
latticearc = "0.1"
```

### Simple Encryption & Decryption

```rust
use latticearc::{encrypt, decrypt};

// Auto-selects best hybrid scheme (ML-KEM + AES-256-GCM)
// No session required - simple API
let key = [0u8; 32];
let encrypted = encrypt(b"secret message", &key)?;
let decrypted = decrypt(&encrypted, &key)?;
```

### Digital Signatures

```rust
use latticearc::{sign, verify};

// Auto-selects hybrid signature scheme (ML-DSA + Ed25519)
let signed = sign(b"important document")?;
let is_valid = verify(&signed)?;
```

### Key Generation

```rust
use latticearc::generate_keypair;

// Generate hybrid keypair
let keypair = generate_keypair()?;
```

### Zero Trust API (arc-core)

For enterprise security with Zero Trust enforcement:

```rust
use arc_core::{VerifiedSession, encrypt, decrypt, generate_keypair};

// Establish verified session
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// All operations require the session
let key = [0u8; 32];
let encrypted = encrypt(&session, b"secret message", &key)?;
let decrypted = decrypt(&session, &encrypted, &key)?;
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

| Use Case | Recommended |
|----------|-------------|
| General purpose | ML-KEM-768, ML-DSA-65 |
| Maximum security | ML-KEM-1024, ML-DSA-87 |
| Constrained | ML-KEM-512, SLH-DSA-SHAKE-128f |

## Security

- No unsafe code
- Constant-time operations
- Automatic secret zeroization
- CAVP test vector validation

## Documentation

- [API Reference](https://docs.rs/latticearc)
- [Security Guide](docs/SECURITY_GUIDE.md)
- [NIST Compliance](docs/NIST_COMPLIANCE.md)

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md)
