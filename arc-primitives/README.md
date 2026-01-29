# arc-primitives

Core cryptographic primitives for LatticeArc.

## Overview

`arc-primitives` implements the low-level cryptographic operations:

- **Key Encapsulation** - ML-KEM (FIPS 203)
- **Digital Signatures** - ML-DSA (FIPS 204), SLH-DSA (FIPS 205), FN-DSA (FIPS 206)
- **AEAD** - AES-256-GCM, ChaCha20-Poly1305
- **KDF** - HKDF, PBKDF2, SP 800-108
- **Hash** - SHA-2, SHA-3, SHAKE
- **MAC** - HMAC, CMAC
- **EC** - Ed25519, X25519, secp256k1, BLS12-381

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-primitives = "0.1"
```

### ML-KEM (Key Encapsulation)

```rust
use arc_primitives::kem::*;

// Generate key pair
let (pk, sk) = MlKem::generate_keypair(MlKemVariant::MlKem768)?;

// Encapsulate (sender)
let (shared_secret, ciphertext) = MlKem::encapsulate(&pk)?;

// Decapsulate (receiver)
let shared_secret = MlKem::decapsulate(&ciphertext, &sk)?;
```

### ML-DSA (Digital Signatures)

```rust
use arc_primitives::sig::*;

// Generate key pair
let (vk, sk) = MlDsa::generate_keypair(MlDsaVariant::MlDsa65)?;

// Sign
let signature = MlDsa::sign(&message, &sk)?;

// Verify
let is_valid = MlDsa::verify(&message, &signature, &vk)?;
```

### AES-GCM Encryption

```rust
use arc_primitives::aead::*;

let cipher = AesGcm::new(&key)?;
let ciphertext = cipher.encrypt(&nonce, &plaintext, &aad)?;
let plaintext = cipher.decrypt(&nonce, &ciphertext, &aad)?;
```

### Key Derivation

```rust
use arc_primitives::kdf::*;

// HKDF
let derived = hkdf_sha256(&ikm, &salt, &info, 32)?;

// PBKDF2
let key = pbkdf2_sha256(&password, &salt, 600_000, 32)?;
```

## Modules

| Module | Description |
|--------|-------------|
| `kem` | Key Encapsulation Mechanisms |
| `sig` | Digital Signature Algorithms |
| `aead` | Authenticated Encryption |
| `kdf` | Key Derivation Functions |
| `hash` | Hash Functions |
| `mac` | Message Authentication Codes |
| `ec` | Elliptic Curve Operations |
| `keys` | Key Types and Utilities |

## Algorithm Support

### Key Encapsulation (FIPS 203)

| Algorithm | Security Level | Public Key | Ciphertext |
|-----------|---------------|------------|------------|
| ML-KEM-512 | 1 | 800 B | 768 B |
| ML-KEM-768 | 3 | 1184 B | 1088 B |
| ML-KEM-1024 | 5 | 1568 B | 1568 B |

### Digital Signatures (FIPS 204)

| Algorithm | Security Level | Public Key | Signature |
|-----------|---------------|------------|-----------|
| ML-DSA-44 | 2 | 1312 B | 2420 B |
| ML-DSA-65 | 3 | 1952 B | 3309 B |
| ML-DSA-87 | 5 | 2592 B | 4627 B |

### Hash-Based Signatures (FIPS 205)

| Algorithm | Security Level | Signature |
|-----------|---------------|-----------|
| SLH-DSA-SHAKE-128f | 1 | 17,088 B |
| SLH-DSA-SHAKE-128s | 1 | 7,856 B |
| SLH-DSA-SHAKE-256f | 5 | 49,856 B |
| SLH-DSA-SHAKE-256s | 5 | 29,792 B |

## Security

- No unsafe code (`#![forbid(unsafe_code)]`)
- Constant-time operations via `subtle` crate
- Automatic zeroization via `zeroize` crate
- CAVP test vector validation

## License

Apache-2.0
