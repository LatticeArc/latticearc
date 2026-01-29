# ML-KEM Key Persistence Guide

This document provides guidance for applications that need ML-KEM key persistence,
addressing the limitation that aws-lc-rs does not expose secret key serialization.

## The Challenge

The aws-lc-rs library, which provides FIPS 140-3 validated ML-KEM (FIPS 203),
intentionally does **not** expose ML-KEM secret key (decapsulation key) serialization.
This is a deliberate security decision by AWS-LC to prevent accidental exposure of
secret key material.

### What Works

| Operation | Supported | Notes |
|-----------|-----------|-------|
| Generate keypair | Yes | Returns `(MlKemPublicKey, MlKemSecretKey)` |
| Serialize public key | Yes | `pk.to_bytes()` / `MlKemPublicKey::from_bytes()` |
| Encapsulate (with public key) | Yes | `MlKem::encapsulate(&mut rng, &pk)` |
| Store/restore public key | Yes | Public keys can be freely serialized |

### What Does NOT Work

| Operation | Supported | Reason |
|-----------|-----------|--------|
| Serialize secret key | No | aws-lc-rs does not expose `DecapsulationKey` bytes |
| Restore secret key from bytes | No | Cannot reconstruct `DecapsulationKey` from raw bytes |
| Decapsulate with restored key | No | Requires original `DecapsulationKey` object |

## Recommended Patterns

### Pattern 1: Ephemeral Keys (Simplest)

Use ML-KEM for session key establishment only. Generate new keypairs for each
session and keep the `DecapsulationKey` alive for the session duration.

**When to use:**
- Key exchange protocols (TLS, QUIC)
- Session establishment
- Short-lived connections

**Example Architecture:**

```
Session Start:
  1. Generate ML-KEM keypair
  2. Send public key to peer
  3. Keep DecapsulationKey in memory

Session Active:
  4. Receive ciphertext from peer
  5. Decapsulate using in-memory DecapsulationKey
  6. Use shared secret for session encryption

Session End:
  7. DecapsulationKey is dropped and zeroized
```

**Code Example:**

```rust
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel, MlKemPublicKey};
use rand::rngs::OsRng;

struct Session {
    // Public key can be serialized and shared
    public_key_bytes: Vec<u8>,
    // In a real implementation, you would store the aws-lc-rs DecapsulationKey
    // directly, not the MlKemSecretKey wrapper
}

impl Session {
    fn new(level: MlKemSecurityLevel) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)?;

        Ok(Self {
            public_key_bytes: pk.to_bytes(),
        })
    }

    fn public_key(&self, level: MlKemSecurityLevel) -> Result<MlKemPublicKey, Box<dyn std::error::Error>> {
        Ok(MlKemPublicKey::from_bytes(&self.public_key_bytes, level)?)
    }
}
```

### Pattern 2: Hybrid with X25519 (Recommended for Long-Term)

Combine X25519 (which supports serialization) for long-term identity with ML-KEM
for post-quantum protection. This provides both:
- Key persistence via X25519
- Post-quantum security via ML-KEM

**When to use:**
- Long-term identity keys
- Applications requiring key backup
- Migration to post-quantum while maintaining classical security

**Architecture:**

```
Key Generation (Once):
  1. Generate X25519 keypair
  2. Serialize and store X25519 secret key securely

Per-Session:
  3. Load X25519 secret key
  4. Generate ephemeral ML-KEM keypair
  5. Perform both key exchanges
  6. Combine shared secrets using HKDF

Result:
  - Session key is secure even if either classical OR quantum is broken
  - Only X25519 key needs persistence
```

**Code Example:**

```rust
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use rand::rngs::OsRng;

/// Hybrid key pair with persistent X25519 and ephemeral ML-KEM
struct HybridSession {
    /// X25519 secret key bytes (can be stored)
    x25519_secret: [u8; 32],
    /// X25519 public key bytes (can be shared)
    x25519_public: [u8; 32],
    /// ML-KEM public key bytes (ephemeral, can be shared)
    mlkem_public: Vec<u8>,
    // ML-KEM DecapsulationKey would be stored here (not the wrapper)
}

impl HybridSession {
    fn combine_secrets(
        x25519_shared: &[u8; 32],
        mlkem_shared: &[u8; 32],
    ) -> [u8; 32] {
        // Use HKDF to combine both shared secrets
        // This ensures security even if one primitive is broken
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"hybrid-kem-v1");
        hasher.update(x25519_shared);
        hasher.update(mlkem_shared);
        let result = hasher.finalize();

        let mut combined = [0u8; 32];
        combined.copy_from_slice(&result);
        combined
    }
}
```

### Pattern 3: HSM/KMS Integration

Store keys in a hardware security module (HSM) or Key Management Service (KMS)
that supports ML-KEM natively. The HSM manages key persistence internally.

**When to use:**
- Enterprise deployments
- Regulatory compliance requirements
- High-security environments

**Supported Platforms:**
- AWS CloudHSM (check for ML-KEM support)
- Azure Managed HSM (check for ML-KEM support)
- Thales Luna HSM
- Custom PKCS#11 implementations

**Architecture:**

```
Key Generation:
  1. HSM generates ML-KEM keypair internally
  2. HSM returns key handle (not raw bytes)
  3. Store key handle for future use

Operations:
  4. Request encapsulation: HSM uses stored key
  5. Request decapsulation: HSM uses stored key
  6. Key material never leaves HSM boundary
```

### Pattern 4: Deterministic Key Derivation (Advanced)

Derive ML-KEM keys deterministically from a master secret using a KDF.
This allows "regenerating" the same key from the master secret.

**CAUTION:** This pattern has security implications:
- Master secret must be stored securely
- Compromising master secret compromises all derived keys
- Not all ML-KEM implementations support deterministic generation

**When to use:**
- Key recovery scenarios
- Hierarchical key structures
- When you have a secure master key storage solution

**Code Example:**

```rust
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

/// Derive a consistent keypair from a master secret and purpose string
fn derive_mlkem_keypair(
    master_secret: &[u8; 32],
    purpose: &str,
    level: MlKemSecurityLevel,
) -> Result<(Vec<u8>, ()), Box<dyn std::error::Error>> {
    use sha2::{Sha256, Digest};

    // Derive seed from master secret and purpose
    let mut hasher = Sha256::new();
    hasher.update(b"mlkem-key-derivation-v1");
    hasher.update(master_secret);
    hasher.update(purpose.as_bytes());
    let seed = hasher.finalize();

    let seed_array: [u8; 32] = seed.into();

    // Generate keypair from seed
    // Note: This returns the same keypair for the same inputs
    let (pk, _sk) = MlKem::generate_keypair_with_seed(&seed_array, level)?;

    // Return public key bytes (can be stored)
    // Secret key must be re-derived when needed
    Ok((pk.to_bytes(), ()))
}
```

## Anti-Patterns to Avoid

### DO NOT: Store decapsulation keys in plaintext files

```rust
// WRONG - Never do this
let (pk, sk) = MlKem::generate_keypair(&mut rng, level)?;
std::fs::write("secret_key.bin", sk.as_bytes())?;  // Contains only zeros!
```

The `MlKemSecretKey` wrapper contains placeholder bytes, not actual secret key
material. Even if it contained real bytes, storing them in plaintext would be
a security risk.

### DO NOT: Attempt to extract key bytes from memory

```rust
// WRONG - Don't try to circumvent the API
let decaps_key: DecapsulationKey = /* ... */;
let ptr = &decaps_key as *const _ as *const u8;
// This is undefined behavior and won't give you the key bytes
```

Attempting to extract bytes through pointer manipulation is undefined behavior
and will not work.

### DO NOT: Use non-FIPS implementations just for serialization

```rust
// WRONG - Mixing implementations breaks security guarantees
// Generate with pqcrypto-mlkem (non-FIPS)
let (pk_pq, sk_pq) = pqcrypto_mlkem::kem_keypair();
// Encapsulate with aws-lc-rs (FIPS)
// This won't work and defeats the purpose of FIPS validation
```

Different implementations may have subtle differences that cause interoperability
issues or security problems.

### DO NOT: Rely on `MlKemSecretKey` for decapsulation

```rust
// WRONG - This will fail at runtime
let (pk, sk) = MlKem::generate_keypair(&mut rng, level)?;
let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk)?;
let ss_dec = MlKem::decapsulate(&sk, &ct)?;  // Returns error!
```

The current API cannot perform decapsulation because aws-lc-rs doesn't expose
secret key deserialization.

## Migration Guidance

### From Non-FIPS to FIPS ML-KEM

If you're migrating from a library that supports secret key serialization:

1. **Audit existing key usage**: Identify all locations where ML-KEM secret keys
   are stored or transmitted.

2. **Choose a persistence pattern**: Select one of the recommended patterns above
   based on your requirements.

3. **Implement hybrid if needed**: If you must maintain backward compatibility,
   use Pattern 2 (Hybrid with X25519).

4. **Update key rotation procedures**: Ephemeral keys simplify rotation since
   new keys are generated per-session.

### From Static to Ephemeral Keys

If transitioning from static ML-KEM keys to ephemeral keys:

1. **Identify key lifetime requirements**: Determine if you truly need long-lived
   ML-KEM keys or if ephemeral is sufficient.

2. **Update protocol design**: Modify key exchange protocols to support ephemeral
   ML-KEM keypairs.

3. **Consider caching**: For performance, you might cache keypairs for a short
   duration (e.g., 5 minutes) rather than generating per-connection.

## FAQ

### Q: Will aws-lc-rs ever support secret key serialization?

This is unlikely. The decision to not expose secret key bytes is intentional and
aligned with AWS-LC's security philosophy. The library prioritizes preventing
accidental key exposure over convenience.

### Q: Can I use a different ML-KEM implementation?

Yes, but with tradeoffs:
- `pqcrypto-mlkem`: Supports serialization but is NOT FIPS 140-3 validated
- `fips203` crate: Check current status for serialization support
- Custom implementations: Not recommended due to implementation risks

### Q: What about key backup and recovery?

For key backup/recovery needs:
1. Use Pattern 2 (Hybrid) and back up the X25519 key
2. Use Pattern 3 (HSM/KMS) with the HSM's backup mechanisms
3. Use Pattern 4 (Deterministic) and back up the master secret

### Q: How does this affect TLS implementations?

TLS key exchange is ephemeral by design, so this limitation has minimal impact.
Each TLS connection generates fresh ML-KEM keypairs, and the DecapsulationKey
only needs to live for the handshake duration.

## References

- [FIPS 203 Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [aws-lc-rs Documentation](https://docs.rs/aws-lc-rs)
- [ML-KEM Key Sizes](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
