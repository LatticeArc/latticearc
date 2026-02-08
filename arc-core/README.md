# arc-core

Unified API layer for LatticeArc post-quantum cryptography with intelligent scheme selection and zero-trust authentication.

## Features

- **Zero-Trust Enforcement** - All crypto ops require verified session
- **Convenience API** - Simple encrypt/decrypt/sign/verify functions
- **Smart Selection** - CryptoPolicyEngine for automatic scheme selection
- **Use Case Templates** - 20+ predefined use cases with optimized schemes

## Quick Start

```rust
use arc_core::{VerifiedSession, encrypt, decrypt, sign, verify, generate_keypair};

// Establish verified session (required for Zero Trust)
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// Simple encryption (auto-selects hybrid PQ scheme)
let key = [0u8; 32];
let encrypted = encrypt(&session, b"secret message", &key)?;
let decrypted = decrypt(&session, &encrypted, &key)?;

// Simple signing (auto-selects hybrid signature scheme)
let signed = sign(&session, b"document")?;
let is_valid = verify(&session, &signed)?;
```

## Zero Trust Enforcement

All cryptographic operations require a `VerifiedSession` to enforce Zero Trust at the API level.

### Verified API (Default)

```rust
use arc_core::{VerifiedSession, encrypt};

let session = VerifiedSession::establish(&public_key, &private_key)?;
let encrypted = encrypt(&session, data, &key)?;
```

### Unverified API (Opt-Out)

`_unverified` variants for scenarios without session management:

```rust
use arc_core::encrypt_unverified;

let encrypted = encrypt_unverified(data, &key)?;
```

### Trust Levels

```rust
use arc_core::TrustLevel;

match session.trust_level() {
    TrustLevel::Untrusted => { /* Initial state */ }
    TrustLevel::Partial => { /* First verification passed */ }
    TrustLevel::Trusted => { /* Multiple verifications */ }
    TrustLevel::FullyTrusted => { /* Continuous verification */ }
}
```

## Modules

| Module | Purpose |
|--------|---------|
| `convenience` | High-level encrypt/decrypt/sign/verify, true hybrid (ML-KEM+X25519+HKDF) |
| `selector` | CryptoPolicyEngine |
| `zero_trust` | VerifiedSession, TrustLevel, ZeroTrustAuth, Challenge, ZKP |
| `hardware` | Hardware trait re-exports (types only — detection is in enterprise) |
| `config` | CoreConfig, ZeroTrustConfig |
| `types` | UseCase, SecurityLevel, PerformancePreference |
| `error` | CoreError including SessionExpired, AuthenticationRequired |

## Cryptographic Modes

Three modes are supported for all operations:

| Mode | Encryption | Signatures |
|------|------------|------------|
| **Hybrid** (default) | ML-KEM + X25519 + AES-256-GCM | ML-DSA + Ed25519 |
| **PQ-Only** | ML-KEM + AES-256-GCM | ML-DSA |
| **Classical** | X25519 + AES-256-GCM | Ed25519 |

## Scheme Selection

The `CryptoPolicyEngine` uses a priority-based selection algorithm:

```
┌─────────────────────────────────────────────────────────────┐
│                    Selection Priority                        │
├─────────────────────────────────────────────────────────────┤
│  1. Explicit UseCase override                               │
│     └─> UseCase::FileStorage → hybrid-ml-kem-1024           │
│                                                             │
│  2. Context-aware (data + security level)                   │
│     └─> SecurityLevel::Maximum → hybrid-ml-kem-1024         │
│     └─> SecurityLevel::High → hybrid-ml-kem-768             │
│                                                             │
│  3. PQ-only mode:                                           │
│     └─> SecurityLevel::Quantum → pq-ml-kem-1024             │
│                                                             │
│  4. Lightweight hybrid (for constrained devices):           │
│     └─> SecurityLevel::Standard → hybrid-ml-kem-512         │
│                                                             │
│  5. Default: hybrid-ml-kem-768-aes-256-gcm                  │
└─────────────────────────────────────────────────────────────┘
```

### Use Case-Based Selection

```rust
use arc_core::selector::CryptoPolicyEngine;
use arc_core::config::CoreConfig;
use arc_core::types::UseCase;

let config = CoreConfig::default();

// Use case-based selection
let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
// -> "hybrid-ml-kem-768-aes-256-gcm"

let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::FileStorage, &config)?;
// -> "hybrid-ml-kem-1024-aes-256-gcm" (stronger for long-term storage)
```

### Data-Aware Selection

```rust
// Analyze data and select optimal scheme
let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;

// Get data characteristics
let chars = CryptoPolicyEngine::analyze_data_characteristics(data);
println!("Size: {} bytes", chars.size);
println!("Entropy: {:.2} bits/byte", chars.entropy);
println!("Pattern: {:?}", chars.pattern_type);
```

**PatternType Detection:**
- `Random` - entropy > 7.5 (already encrypted/compressed)
- `Text` - ASCII printable, entropy > 4.0
- `Structured` - JSON/XML markers or entropy < 6.0
- `Repetitive` - 8-byte repeating cycles
- `Binary` - everything else

### PQ-Only and Classical Modes

```rust
// Force PQ-only encryption scheme
let pq_scheme = CryptoPolicyEngine::select_pq_encryption_scheme(&config)?;
// -> "pq-ml-kem-768-aes-256-gcm"

// Force PQ-only signature scheme
let pq_sig = CryptoPolicyEngine::select_pq_signature_scheme(&config)?;
// -> "pq-ml-dsa-65"

// Force specific scheme type
let forced = CryptoPolicyEngine::force_scheme(CryptoScheme::HybridKem);
```

### Security Level Mappings

| SecurityLevel | Mode | Encryption Scheme | Signature Scheme |
|---------------|------|-------------------|------------------|
| Quantum | PQ-only | pq-ml-kem-1024-aes-256-gcm | ml-dsa-87 |
| Maximum | Hybrid | hybrid-ml-kem-1024-aes-256-gcm | ml-dsa-87-ed25519 |
| High (default) | Hybrid | hybrid-ml-kem-768-aes-256-gcm | ml-dsa-65-ed25519 |
| Standard | Hybrid | hybrid-ml-kem-512-aes-256-gcm | ml-dsa-44-ed25519 |

> **Note:** `Quantum` mode uses PQ-only algorithms for CNSA 2.0 compliance.

## Zero-Trust Authentication

### Quick Session Establishment

```rust
use arc_core::{VerifiedSession, generate_keypair};

// One-line session establishment
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// Session is now ready for crypto operations
```

### Manual Challenge-Response

```rust
use arc_core::zero_trust::{ZeroTrustAuth, ZeroTrustSession};
use arc_core::config::ZeroTrustConfig;

// Create auth with keypair
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Generate challenge
let challenge = auth.generate_challenge()?;

// Generate zero-knowledge proof
let proof = auth.generate_proof(&challenge.data)?;

// Verify (uses public key only)
let is_valid = auth.verify_proof(&proof, &challenge.data)?;

// Session management
let mut session = ZeroTrustSession::new(auth);
let challenge = session.initiate_authentication()?;
// ... generate proof ...
let proof = session.auth.generate_proof(&challenge.data)?;
session.verify_response(&proof)?;

// Convert to VerifiedSession for crypto operations
let verified_session = session.into_verified()?;
```

## True Hybrid Encryption

For true hybrid key encapsulation (ML-KEM-768 + X25519 combined via HKDF):

```rust
use arc_core::{
    generate_true_hybrid_keypair, encrypt_true_hybrid, decrypt_true_hybrid,
    SecurityMode,
};

// Generate hybrid keypair
let (pk, sk) = generate_true_hybrid_keypair()?;

// Encrypt — ML-KEM + X25519 + HKDF + AES-256-GCM
let encrypted = encrypt_true_hybrid(data, &pk, SecurityMode::Unverified)?;

// Decrypt
let plaintext = decrypt_true_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
```

Security holds if **either** ML-KEM or X25519 remains secure.

## Hardware

The `hardware` module provides **trait definitions only** (`HardwareAccelerator`, `HardwareAware`, `HardwareCapabilities`, `HardwareInfo`, `HardwareType`). These define the interface contract for hardware-aware operations.

Hardware detection, adaptive routing, and performance-based algorithm selection are available in the enterprise `arc-enterprise-perf` crate. The underlying crypto library (`aws-lc-rs`) handles AES-NI and SIMD acceleration automatically at the C level.

## Configuration

```rust
use arc_core::config::CoreConfig;
use arc_core::types::{SecurityLevel, PerformancePreference};

let config = CoreConfig::builder()
    .security_level(SecurityLevel::High)
    .performance_preference(PerformancePreference::Balanced)
    .build()?;
```

## UseCase Mappings

| UseCase | Scheme |
|---------|--------|
| `SecureMessaging` | hybrid-ml-kem-768-aes-256-gcm |
| `FileStorage` | hybrid-ml-kem-1024-aes-256-gcm |
| `DatabaseEncryption` | hybrid-ml-kem-768-aes-256-gcm |
| `KeyExchange` | hybrid-ml-kem-1024-x25519 |
| `FinancialTransactions` | hybrid-ml-dsa-65-ed25519 |
| `Authentication` | hybrid-ml-dsa-87-ed25519 |

## Security

- `#![forbid(unsafe_code)]` - No unsafe Rust
- `#![deny(clippy::unwrap_used)]` - No panics
- Constant-time operations via `subtle`
- Automatic zeroization via `zeroize`

## License

Apache-2.0
