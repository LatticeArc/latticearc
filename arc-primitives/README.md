# arc-primitives

Core cryptographic primitives for LatticeArc.

## Overview

`arc-primitives` implements the low-level cryptographic operations:

- **Key Encapsulation** - ML-KEM (FIPS 203) via aws-lc-rs
- **Digital Signatures** - ML-DSA (FIPS 204) via fips204, SLH-DSA (FIPS 205) via fips205, FN-DSA (FIPS 206) via fn-dsa
- **AEAD** - AES-128-GCM, AES-256-GCM via aws-lc-rs; ChaCha20-Poly1305 via chacha20poly1305
- **KDF** - HKDF, PBKDF2, SP 800-108 Counter KDF
- **Hash** - SHA-2, SHA-3
- **MAC** - HMAC, CMAC
- **EC** - Ed25519, X25519, secp256k1, BLS12-381, BN254

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-primitives = "0.1"
```

### ML-KEM (Key Encapsulation)

```rust,ignore
use arc_primitives::kem::ml_kem::*;

// Generate key pair
let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)?;

// Encapsulate (sender) — returns (MlKemSharedSecret, MlKemCiphertext)
let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &pk)?;

// Decapsulate (receiver)
let shared_secret = sk.decapsulate(&ciphertext)?;
```

### AES-GCM Encryption

```rust,ignore
use arc_primitives::aead::aes_gcm::AesGcm256;

// Create cipher with a 256-bit key
let cipher = AesGcm256::new(&key)?;

// Encrypt with nonce and optional AAD
let ciphertext = cipher.encrypt(&nonce, &plaintext, &aad)?;

// Decrypt
let plaintext = cipher.decrypt(&nonce, &ciphertext, &aad)?;
```

### Key Derivation

```rust,ignore
use arc_primitives::kdf::hkdf;

// HKDF extract-then-expand
let result = hkdf::hkdf(Some(&salt), &ikm, Some(&info), 32)?;
let derived_key = result.key();

// Simple HKDF (no salt, no info)
let result = hkdf::hkdf_simple(&ikm, 32)?;
```

## Modules

| Module | Description |
|--------|-------------|
| `kem` | Key Encapsulation Mechanisms (ML-KEM, X25519, ECDH) |
| `sig` | Digital Signature Algorithms (ML-DSA, SLH-DSA, FN-DSA) |
| `aead` | Authenticated Encryption (AES-GCM, ChaCha20-Poly1305) |
| `kdf` | Key Derivation Functions (HKDF, PBKDF2, SP 800-108) |
| `hash` | Hash Functions (SHA-2, SHA-3) |
| `mac` | Message Authentication Codes (HMAC, CMAC) |
| `ec` | Elliptic Curve Operations (Ed25519, secp256k1, BLS12-381, BN254) |
| `keys` | Key Types and Utilities |
| `self_test` | FIPS 140-3 power-up self-tests (behind `fips-self-test` feature) |

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

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `fips` | FIPS 140-3 mode (enables self-tests) | No |
| `fips-self-test` | Power-up self-test module | No |

## Security

- No unsafe code (`#![deny(unsafe_code)]`)
- Constant-time operations via `subtle` crate
- Automatic zeroization via `zeroize` crate
- CAVP test vector validation

## License

Apache-2.0
