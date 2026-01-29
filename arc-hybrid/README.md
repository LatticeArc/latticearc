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

### Hybrid KEM (ML-KEM + X25519)

```rust
use arc_hybrid::*;

// Generate hybrid key pair
let (pk, sk) = HybridKem::generate_keypair()?;

// Encapsulate (combines both algorithms)
let (shared_secret, ciphertext) = HybridKem::encapsulate(&pk)?;

// Decapsulate
let shared_secret = HybridKem::decapsulate(&ciphertext, &sk)?;
```

### Hybrid Signatures (ML-DSA + Ed25519)

```rust
use arc_hybrid::*;

// Generate hybrid key pair
let (vk, sk) = HybridSig::generate_keypair()?;

// Sign (produces both signatures)
let signature = HybridSig::sign(&message, &sk)?;

// Verify (both must pass)
let is_valid = HybridSig::verify(&message, &signature, &vk)?;
```

### Hybrid Encryption

```rust
use arc_hybrid::*;

// Full encryption (KEM + symmetric)
let ciphertext = hybrid_encrypt(&plaintext, &recipient_pk)?;
let plaintext = hybrid_decrypt(&ciphertext, &recipient_sk)?;
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

| Hybrid Scheme | Post-Quantum | Classical |
|--------------|--------------|-----------|
| HybridKem | ML-KEM-768 | X25519 |
| HybridSig | ML-DSA-65 | Ed25519 |
| HybridEncrypt | ML-KEM + AES-GCM | X25519 + AES-GCM |

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
