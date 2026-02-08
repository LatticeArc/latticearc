# arc-hybrid

Hybrid cryptography combining post-quantum and classical algorithms.

## Overview

`arc-hybrid` provides defense-in-depth by combining:

- **Post-quantum algorithms** - Secure against quantum computers
- **Classical algorithms** - Proven security, backup if PQC has issues

The combined scheme is secure if **either** component remains secure.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-hybrid = "0.1"
```

### Hybrid KEM (ML-KEM-768 + X25519 + HKDF)

```rust
use arc_hybrid::kem_hybrid;

let mut rng = rand::rngs::OsRng;

// Generate hybrid key pair (ML-KEM-768 + X25519)
let (pk, sk) = kem_hybrid::generate_keypair(&mut rng)?;

// Encapsulate — combines ML-KEM + X25519 shared secrets via HKDF
let (encapsulated_key, shared_secret) = kem_hybrid::encapsulate(&mut rng, &pk)?;

// Decapsulate
let shared_secret = kem_hybrid::decapsulate(&sk, &encapsulated_key)?;
```

### Hybrid Signatures (ML-DSA-65 + Ed25519)

```rust
use arc_hybrid::sig_hybrid;

let mut rng = rand::rngs::OsRng;

// Generate hybrid key pair
let (pk, sk) = sig_hybrid::generate_keypair(&mut rng)?;

// Sign (produces both ML-DSA + Ed25519 signatures)
let signature = sig_hybrid::sign(&sk, b"message")?;

// Verify (both must pass)
let is_valid = sig_hybrid::verify(&pk, b"message", &signature)?;
```

### Hybrid Encryption (KEM + AES-256-GCM)

```rust
use arc_hybrid::encrypt_hybrid::{encrypt_hybrid, decrypt_hybrid};
use arc_hybrid::kem_hybrid;

let mut rng = rand::rngs::OsRng;
let (pk, sk) = kem_hybrid::generate_keypair(&mut rng)?;

// Encrypt: KEM encapsulate + HKDF + AES-256-GCM
let ciphertext = encrypt_hybrid(&mut rng, &pk, b"secret data", None)?;

// Decrypt: KEM decapsulate + HKDF + AES-256-GCM verify+decrypt
let plaintext = decrypt_hybrid(&sk, &ciphertext, None)?;
```

## Why Hybrid?

During the transition to post-quantum cryptography (2024-2035+):

| Scenario | Protection |
|----------|------------|
| PQC has unknown weakness | Classical provides backup |
| Classical broken by quantum | PQC provides protection |
| Both secure | Maximum security |

Recommended for any data requiring long-term confidentiality.

## Algorithm Combinations

| Hybrid Scheme | Post-Quantum | Classical | Key Combination |
|--------------|--------------|-----------|-----------------|
| `kem_hybrid` | ML-KEM-768 | X25519 | HKDF-SHA256 |
| `sig_hybrid` | ML-DSA-65 | Ed25519 | Concatenated |
| `encrypt_hybrid` | ML-KEM-768 + AES-256-GCM | X25519 + AES-256-GCM | HKDF-SHA256 |

## Security Properties

- **IND-CCA2** for hybrid KEM (if either component is IND-CCA2)
- **EUF-CMA** for hybrid signatures (if either component is EUF-CMA)
- Key combination via HKDF with domain separation

See `docs/SECURITY_PROOFS.md` for formal analysis.

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library | Yes |
| `ml-kem-768` | Use ML-KEM-768 | Yes |
| `ml-kem-1024` | Use ML-KEM-1024 | No |

## Security

- No unsafe code
- Constant-time key combination
- Automatic secret zeroization
- Formal security proofs documented

## License

Apache-2.0
