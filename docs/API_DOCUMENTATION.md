# LatticeArc API Documentation

**Version**: 0.1.3
**Last Updated**: February 7, 2026
**License**: Apache 2.0

---

## Table of Contents

1. [Overview](#overview)
2. [Core API](#core-api)
3. [Unified API](#unified-api)
4. [Primitives API](#primitives-api)
5. [Hybrid API](#hybrid-api)
6. [Error Handling](#error-handling)
7. [Type Reference](#type-reference)
8. [Examples](#examples)
9. [Migration Guide](#migration-guide)

---

## Overview

LatticeArc provides three levels of API abstraction:

| API Level | Description | Use Case |
|-----------|-------------|----------|
| **Unified API** | Simple, high-level interface | Quick integration, developers new to crypto |
| **Core API** | Mid-level abstraction | Production applications, custom configurations |
| **Primitives API** | Low-level, fine-grained control | Cryptographic experts, performance optimization |

### API Hierarchy

```
Unified API (High-Level)
    ↓ Auto-selection
Core API (Mid-Level)
    ↓ Direct usage
Primitives API (Low-Level)
    ↓ Direct implementation
Audited Crates (fips203, fips204, fips205, etc.)
```

---

## Core API

### Configuration

```rust
use latticearc::{CryptoConfig, SecurityLevel};

// Default configuration
let config = CryptoConfig::new();

// Security level configuration
let config = CryptoConfig::new()
    .security_level(SecurityLevel::High);
```

### Encryption

```rust
use latticearc::{encrypt, decrypt, CryptoConfig};

let key = [0u8; 32];  // 256-bit key for AES-256-GCM
let plaintext = b"Secret message";

let encrypted = encrypt(plaintext, &key, CryptoConfig::new())?;
let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())?;
assert_eq!(plaintext, decrypted.as_slice());
```

### Signatures

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

// Generate signing keypair (returns public key, secret key, and scheme name)
let config = CryptoConfig::new();
let (public_key, secret_key, _scheme) = generate_signing_keypair(config.clone())?;

// Sign message
let message = b"Important document";
let signed_data = sign_with_key(message, &secret_key, &public_key, config.clone())?;

// Verify signature
let is_valid = verify(&signed_data, config)?;
assert!(is_valid);
```

### Configuration API

#### CryptoConfig

```rust
use latticearc::{CryptoConfig, SecurityLevel};

let config = CryptoConfig::new()
    .security_level(SecurityLevel::High);
```

#### Configuration Options

| Option | Type | Default | Description |
|--------|------|----------|-------------|
| `security_level` | `SecurityLevel` | `High` | Security strength level |
| `performance_preference` | `PerformancePreference` | `Balanced` | Performance vs security trade-off |
| `compliance_mode` | `bool` | `false` | Enable compliance checks |
| `enable_zeroization` | `bool` | `true` | Auto-zeroize sensitive data |
| `audit_logging` | `bool` | `false` | Enable audit logging |

---

## Unified API

### Convenience Functions

The Unified API provides simple functions for common operations.

#### Encryption

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, UseCase, SecurityLevel};

// Simple encryption with default config
let key = [0u8; 32];
let encrypted = encrypt(data, &key, CryptoConfig::new())?;

// Encryption with use case selection
let encrypted = encrypt(data, &key, CryptoConfig::new()
    .use_case(UseCase::FileStorage))?;

// Encryption with security level
let encrypted = encrypt(data, &key, CryptoConfig::new()
    .security_level(SecurityLevel::Maximum))?;

// Decryption
let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())?;
```

#### Signatures

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

// Generate keys and sign data
let config = CryptoConfig::new();
let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;
let signed_data = sign_with_key(data, &sk, &pk, config.clone())?;

// Verify signature
let is_valid = verify(&signed_data, config)?;
assert!(is_valid);
```

#### Key Generation

```rust
use latticearc::generate_keypair;

// Generate Ed25519 keypair
let (public_key, private_key) = generate_keypair()?;
```

### Zero-Trust Authentication

```rust
use latticearc::{VerifiedSession, generate_keypair};

// Initialize zero-trust authentication
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Generate challenge
let challenge = auth.generate_challenge();

// Generate proof
let proof = auth.generate_proof(&challenge)?;

// Verify proof
let verified = auth.verify_proof(&proof, &challenge)?;
```

### Auto-Selection Engine

```rust
use arc_core::selector::CryptoPolicyEngine;

// Recommend scheme for use case
let scheme = CryptoPolicyEngine::recommend_scheme(
    &UseCase::SecureMessaging,
    &config
)?;

// Analyze data characteristics
let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);

// Select encryption scheme
let selected = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
```

---

## Primitives API

### ML-KEM (Key Encapsulation Mechanism)

```rust
use arc_primitives::kem::ml_kem::*;

// Generate keypair
let keypair = MlKem1024KeyPair::generate()?;

// Encapsulate
let encapsulated = keypair.public_key.encapsulate()?;
let shared_secret = encapsulated.shared_secret;

// Decapsulate
let decapsulated = keypair.private_key.decapsulate(&encapsulated.ciphertext)?;
assert_eq!(shared_secret, decapsulated);
```

### ML-DSA (Digital Signature Algorithm)

```rust
use arc_primitives::sig::ml_dsa::*;

// Generate keypair
let keypair = MlDsa65KeyPair::generate()?;

// Sign
let message = b"Important message";
let signature = keypair.private_key.sign(message)?;

// Verify
let verified = keypair.public_key.verify(message, &signature)?;
assert!(verified.into());
```

### SLH-DSA (Stateless Hash-Based Signatures)

```rust
use arc_primitives::sig::slh_dsa::*;

// Generate keypair
let keypair = SlhDsaSha2128KeyPair::generate()?;

// Sign
let signature = keypair.private_key.sign(message)?;

// Verify
let verified = keypair.public_key.verify(message, &signature)?;
```

### AES-GCM (AEAD Encryption)

```rust
use arc_primitives::aead::aes_gcm::*;

// Generate key
let key = Aes256GcmKey::generate()?;

// Encrypt
let nonce = AesGcmNonce::generate();
let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, aad)?;

// Decrypt
let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, aad)?;
```

### ChaCha20-Poly1305

```rust
use arc_primitives::aead::chacha20poly1305::*;

// Generate key
let key = ChaCha20Poly1305Key::generate()?;

// Encrypt
let nonce = ChaCha20Poly1305Nonce::generate();
let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad)?;

// Decrypt
let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad)?;
```

---

## Hybrid API

### Hybrid Encryption

Combines post-quantum and classical encryption for quantum-safe hybrid security.

```rust
use latticearc::{generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid, SecurityMode};

// Generate hybrid keypair (ML-KEM-768 + X25519)
let (pk, sk) = generate_hybrid_keypair()?;

// Hybrid encryption (ML-KEM + X25519 + HKDF + AES-256-GCM)
let plaintext = b"Sensitive data";
let encrypted = encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified)?;

// Hybrid decryption
let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
```

### Hybrid Signatures

#### Via Unified API (returns `SignedData`)

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig, SecurityLevel};

// Generate hybrid signature keypair (ML-DSA + Ed25519)
let config = CryptoConfig::new().security_level(SecurityLevel::High);
let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;

// Sign
let message = b"Important data";
let signed_data = sign_with_key(message, &sk, &pk, config.clone())?;

// Verify
let is_valid = verify(&signed_data, config)?;
```

#### Direct Hybrid Signature API

For direct access to ML-DSA-65 + Ed25519 AND-composition signatures:

```rust
use latticearc::{generate_hybrid_signing_keypair, sign_hybrid, verify_hybrid_signature, SecurityMode};

// Generate hybrid signing keypair
let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;

// Sign (both ML-DSA and Ed25519 signatures are generated)
let signature = sign_hybrid(b"important message", &sk, SecurityMode::Unverified)?;

// Verify (both signatures must verify)
let valid = verify_hybrid_signature(b"important message", &signature, &pk, SecurityMode::Unverified)?;
```

---

## Error Handling

### Error Types

```rust
use latticearc::CoreError;

match operation() {
    Ok(result) => println!("Success: {:?}", result),
    Err(CoreError::InvalidKeyLength { expected, actual }) => {
        eprintln!("Invalid key length: expected {}, got {}", expected, actual);
    }
    Err(CoreError::EncryptionFailed(msg)) => {
        eprintln!("Encryption failed: {}", msg);
    }
    Err(CoreError::DecryptionFailed(msg)) => {
        eprintln!("Decryption failed: {}", msg);
    }
    Err(CoreError::VerificationFailed) => {
        eprintln!("Signature verification failed");
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

### Error Variants

| Error | Description | Common Causes |
|--------|-------------|----------------|
| `InvalidKeyLength` | Key length mismatch | Wrong key size for algorithm |
| `EncryptionFailed` | Encryption operation failed | Invalid input, algorithm error |
| `DecryptionFailed` | Decryption operation failed | Wrong key, corrupted ciphertext |
| `VerificationFailed` | Signature verification failed | Wrong key, tampered data |
| `InvalidInput` | Input validation failed | Empty input, invalid format |
| `HardwareError` | Hardware accelerator error (enterprise only) | Device unavailable, driver issue |
| `ConfigurationError` | Invalid configuration | Conflicting settings, invalid parameters |

---

## Type Reference

### Security Levels

```rust
pub enum SecurityLevel {
    Standard, // NIST Level 1 (128-bit equivalent), hybrid mode
    High,     // NIST Level 3 (192-bit equivalent), hybrid mode (default)
    Maximum,  // NIST Level 5 (256-bit equivalent), hybrid mode
    Quantum,  // NIST Level 5, PQ-only (no classical fallback)
}
```

### Crypto Schemes

```rust
pub enum CryptoScheme {
    Hybrid,       // PQC + classical for defense in depth
    Symmetric,    // Symmetric encryption (e.g., AES-GCM)
    Asymmetric,   // Classical asymmetric (e.g., Ed25519)
    Homomorphic,  // Homomorphic encryption schemes
    PostQuantum,  // Pure post-quantum without classical fallback
}
```

### Use Cases

```rust
pub enum UseCase {
    SecureMessaging,
    EmailEncryption,
    VpnTunnel,
    ApiSecurity,
    FileStorage,
    DatabaseEncryption,
    CloudStorage,
    BackupArchive,
    ConfigSecrets,
    Authentication,
    SessionToken,
    DigitalCertificate,
    KeyExchange,
    FinancialTransactions,
    LegalDocuments,
    BlockchainTransaction,
    HealthcareRecords,
    GovernmentClassified,
    PaymentCard,
    IoTDevice,
    FirmwareSigning,
    SearchableEncryption,
    HomomorphicComputation,
    AuditLog,
}
```

---

## Examples

### Example 1: Simple Encryption

```rust
use latticearc::{encrypt, decrypt, CryptoConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0u8; 32];
    let message = b"Hello, LatticeArc!";

    // Encrypt
    let encrypted = encrypt(message, &key, CryptoConfig::new())?;

    // Decrypt
    let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())?;

    assert_eq!(message, decrypted.as_slice());
    println!("✅ Encryption/Decryption successful!");

    Ok(())
}
```

### Example 2: Digital Signatures

```rust
use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = CryptoConfig::new();
    let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;

    let document = b"Important document";
    let signed_data = sign_with_key(document, &sk, &pk, config.clone())?;

    let is_valid = verify(&signed_data, config)?;
    assert!(is_valid);

    println!("✅ Signature verified!");
    Ok(())
}
```

### Example 3: Hybrid Encryption

```rust
use latticearc::{generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid, SecurityMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate hybrid keypair
    let (pk, sk) = generate_hybrid_keypair()?;

    // Encrypt
    let plaintext = b"Quantum-safe data";
    let encrypted = encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified)?;

    // Decrypt
    let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("✅ Hybrid encryption successful!");

    Ok(())
}
```

### Example 4: Zero-Trust Authentication

```rust
use latticearc::{generate_keypair, VerifiedSession, generate_signing_keypair,
                 sign_with_key, verify, CryptoConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let (public_key, private_key) = generate_keypair()?;

    // Establish verified session
    let session = VerifiedSession::establish(&public_key, &private_key)?;

    // Use session for crypto operations
    let config = CryptoConfig::new().session(&session);
    let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;
    let signed = sign_with_key(b"authenticated message", &sk, &pk, config.clone())?;
    let is_valid = verify(&signed, config)?;

    assert!(is_valid);
    println!("✅ Zero-trust authentication successful!");

    Ok(())
}
```

---

## Migration Guide

### From OpenSSL

**Before (OpenSSL):**
```c
EVP_PKEY *key = EVP_PKEY_new();
EVP_PKEY_assign_RSA(key, RSA_generate_key(2048, 65537, NULL, NULL));

unsigned char *encrypted = malloc(256);
int encrypted_len = RSA_public_encrypt(
    data_len, data, encrypted,
    EVP_PKEY_get0_RSA(key), RSA_PKCS1_OAEP_PADDING
);
```

**After (LatticeArc):**
```rust
use latticearc::{encrypt, CryptoConfig};

let key = [0u8; 32];
let encrypted = encrypt(data, &key, CryptoConfig::new())?;
```

### From Sodium

**Before (libsodium):**
```c
unsigned char public_key[crypto_box_PUBLICKEYBYTES];
unsigned char secret_key[crypto_box_SECRETKEYBYTES];
crypto_box_keypair(public_key, secret_key);

unsigned char encrypted[crypto_box_MACBYTES + msg_len];
crypto_box_easy(encrypted, msg, msg_len,
                nonce, public_key, secret_key);
```

**After (LatticeArc):**
```rust
use latticearc::{generate_hybrid_keypair, encrypt_hybrid, SecurityMode};

let (pk, sk) = generate_hybrid_keypair()?;
let encrypted = encrypt_hybrid(data, &pk, SecurityMode::Unverified)?;
```

### From Bouncy Castle

**Before (Java/Bouncy Castle):**
```java
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
keyGen.initialize(256);
KeyPair keyPair = keyGen.generateKeyPair();

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
byte[] encrypted = cipher.doFinal(plaintext);
```

**After (LatticeArc):**
```rust
use latticearc::{encrypt, CryptoConfig};

let key = [0u8; 32];
let encrypted = encrypt(data, &key, CryptoConfig::new())?;
```

---

## Further Reading

- [Unified API Guide](unified_api/README.md)
- [Primitives Documentation](primitives/README.md)
- [Security Guide](docs/SECURITY_GUIDE.md)
- [NIST Compliance](docs/NIST_COMPLIANCE.md)

---

## Support

- **Documentation**: https://docs.rs/latticearc
- **GitHub Issues**: https://github.com/latticearc/latticearc/issues
- **Security**: security@latticearc.com

---

**Document Version**: 0.1.3
**Last Updated**: February 7, 2026
**Maintained By**: LatticeArc Documentation Team
