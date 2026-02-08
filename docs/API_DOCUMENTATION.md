# QuantumShield API Documentation

**Version**: 1.0.0
**Last Updated**: January 13, 2026
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

QuantumShield provides three levels of API abstraction:

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

### QuantumShield Struct

The main entry point for QuantumShield cryptographic operations.

#### Initialization

```rust
use quantumshield::QuantumShield;

// Default configuration
let qs = QuantumShield::new()?;

// Custom configuration
let qs = QuantumShield::with_config(config)?;

// Security level configuration
let qs = QuantumShield::with_security_level(
    quantumshield::SecurityLevel::High
)?;
```

#### Key Generation

```rust
// Generate keypair
let keypair = qs.generate_keypair()?;

// Key generation with specific scheme
let keypair = qs.generate_keypair_with_scheme(
    quantumshield::CryptoScheme::HybridPq
)?;

// Get public/private keys
let public_key = keypair.public_key();
let private_key = keypair.secret_key();
```

#### Encryption

```rust
// Encrypt with public key
let plaintext = b"Secret message";
let encrypted = qs.encrypt(public_key, plaintext)?;

// Encrypt with context
let context = quantumshield::CryptoContext {
    associated_data: Some(b"metadata".to_vec()),
    ..Default::default()
};
let encrypted = qs.encrypt_with_context(public_key, plaintext, &context)?;
```

#### Decryption

```rust
// Decrypt with private key
let decrypted = qs.decrypt(private_key, &encrypted)?;

// Verify decryption
assert_eq!(plaintext, decrypted.as_slice());
```

#### Signatures

```rust
// Sign message
let message = b"Important document";
let signature = qs.sign(private_key, message)?;

// Verify signature
let verified = qs.verify(public_key, message, &signature)?;
assert!(verified.into());
```

### Configuration API

#### CryptoConfig

```rust
use quantumshield::CryptoConfig;
use quantumshield::SecurityLevel;
use quantumshield::PerformancePreference;

let config = CryptoConfig::new()
    .with_security_level(SecurityLevel::High)
    .with_performance_preference(PerformancePreference::Speed)
    .with_compliance_mode(true)
    .validate()?;
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
use quantumshield::unified_api::*;

// Simple encryption
let encrypted = encrypt(sensitive_data)?;

// Encryption with scheme selection
let encrypted = encrypt_with_scheme(
    data,
    CryptoScheme::HybridPq
)?;

// Encryption with configuration
let config = CryptoConfig::new().with_security_level(SecurityLevel::High);
let encrypted = encrypt_with_config(data, &config)?;
```

#### Decryption

```rust
// Simple decryption
let decrypted = decrypt(&encrypted)?;

// Verify decryption
assert_eq!(data, decrypted.as_slice());
```

#### Signatures

```rust
// Sign data
let signature = sign(data)?;

// Verify signature
let verified = verify(data, &signature)?;
assert!(verified);
```

#### Key Generation

```rust
// Generate keypair
let (public_key, private_key) = generate_keypair()?;

// Generate with specific scheme
let (public_key, private_key) = generate_keypair_with_scheme(
    CryptoScheme::HybridPq
)?;
```

### Zero-Trust Authentication

```rust
use quantumshield::unified_api::ZeroTrustAuth;

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
use quantumshield::unified_api::CryptoSelector;

// Recommend scheme for use case
let scheme = CryptoSelector::recommend_scheme(
    UseCase::SecureMessaging,
    &config
)?;

// Analyze data characteristics
let characteristics = CryptoSelector::analyze_data_characteristics(data);

// Select encryption scheme
let selected = CryptoSelector::select_encryption_scheme(data, &config)?;
```

---

## Primitives API

### ML-KEM (Key Encapsulation Mechanism)

```rust
use quantumshield_primitives::kem::ml_kem::*;

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
use quantumshield_primitives::sig::ml_dsa::*;

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
use quantumshield_primitives::sig::slh_dsa::*;

// Generate keypair
let keypair = SlhDsaSha2128KeyPair::generate()?;

// Sign
let signature = keypair.private_key.sign(message)?;

// Verify
let verified = keypair.public_key.verify(message, &signature)?;
```

### AES-GCM (AEAD Encryption)

```rust
use quantumshield_primitives::aead::aes_gcm::*;

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
use quantumshield_primitives::aead::chacha20poly1305::*;

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
use quantumshield::hybrid::*;

// Generate hybrid keypair
let keypair = HybridKeyPair::generate()?;

// Hybrid encryption
let plaintext = b"Sensitive data";
let encrypted = hybrid_encrypt(keypair.public_key(), plaintext)?;

// Hybrid decryption
let decrypted = hybrid_decrypt(keypair.secret_key(), &encrypted)?;
```

### Hybrid Signatures

```rust
use quantumshield::hybrid::*;

// Generate hybrid keypair
let keypair = HybridSigKeyPair::generate()?;

// Sign
let signature = hybrid_sign(keypair.secret_key(), plaintext)?;

// Verify
let verified = hybrid_verify(keypair.public_key(), plaintext, &signature)?;
```

---

## Error Handling

### Error Types

```rust
use quantumshield::CryptoError;

match operation() {
    Ok(result) => println!("Success: {:?}", result),
    Err(CryptoError::InvalidKeyLength { expected, actual }) => {
        eprintln!("Invalid key length: expected {}, got {}", expected, actual);
    }
    Err(CryptoError::EncryptionFailed(msg)) => {
        eprintln!("Encryption failed: {}", msg);
    }
    Err(CryptoError::DecryptionFailed(msg)) => {
        eprintln!("Decryption failed: {}", msg);
    }
    Err(CryptoError::VerificationFailed) => {
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
    Low,      // 128-bit security
    Medium,   // 192-bit security
    High,     // 256-bit security (default)
    Maximum,  // 512-bit security (maximum security)
}
```

### Crypto Schemes

```rust
pub enum CryptoScheme {
    // Post-quantum schemes
    MlKem1024,
    MlKem768,
    MlKem512,
    MlDsa65,
    MlDsa44,
    SlhDsaSha2128,
    SlhDsaShake128,

    // Classical schemes
    Aes256Gcm,
    ChaCha20Poly1305,
    EcdsaP256,
    EcdhP256,

    // Hybrid schemes
    HybridPq,          // Post-quantum + Classical
    HybridDsa,         // Hybrid signatures

    // Advanced schemes
    Homomorphic(HomomorphicScheme),
    Threshold(ThresholdScheme),
}
```

### Use Cases

```rust
pub enum UseCase {
    SecureMessaging,
    DatabaseEncryption,
    FileEncryption,
    SecureCommunication,
    DataAtRest,
    DataInTransit,
    FinancialTransactions,
    HealthcareRecords,
}
```

---

## Examples

### Example 1: Simple Encryption

```rust
use quantumshield::QuantumShield;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let qs = QuantumShield::new()?;

    // Generate keys
    let keypair = qs.generate_keypair()?;

    // Encrypt
    let message = b"Hello, QuantumShield!";
    let encrypted = qs.encrypt(keypair.public_key(), message)?;

    // Decrypt
    let decrypted = qs.decrypt(keypair.secret_key(), &encrypted)?;

    assert_eq!(message, decrypted.as_slice());
    println!("✅ Encryption/Decryption successful!");

    Ok(())
}
```

### Example 2: Digital Signatures

```rust
use quantumshield::QuantumShield;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let qs = QuantumShield::new()?;
    let keypair = qs.generate_keypair()?;

    let document = b"Important document";
    let signature = qs.sign(keypair.secret_key(), document)?;

    let verified = qs.verify(keypair.public_key(), document, &signature)?;
    assert!(verified.into());

    println!("✅ Signature verified!");
    Ok(())
}
```

### Example 3: Hybrid Encryption

```rust
use quantumshield::hybrid::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate hybrid keypair
    let keypair = HybridKeyPair::generate()?;

    // Encrypt
    let plaintext = b"Quantum-safe data";
    let encrypted = hybrid_encrypt(keypair.public_key(), plaintext)?;

    // Decrypt
    let decrypted = hybrid_decrypt(keypair.secret_key(), &encrypted)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("✅ Hybrid encryption successful!");

    Ok(())
}
```

### Example 4: Zero-Trust Authentication

```rust
use quantumshield::unified_api::{ZeroTrustAuth, generate_keypair};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let (public_key, private_key) = generate_keypair()?;

    // Initialize zero-trust
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    // Challenge-response
    let challenge = auth.generate_challenge();
    let proof = auth.generate_proof(&challenge)?;
    let verified = auth.verify_proof(&proof, &challenge)?;

    assert!(verified.into());
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

**After (QuantumShield):**
```rust
let keypair = QuantumShield::new()?.generate_keypair()?;
let encrypted = encrypt(&keypair.public_key, data)?;
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

**After (QuantumShield):**
```rust
let (public_key, private_key) = generate_keypair()?;
let encrypted = encrypt_with_keypair(public_key, private_key, data)?;
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

**After (QuantumShield):**
```rust
let keypair = QuantumShield::new()?.generate_keypair()?;
let encrypted = encrypt(&keypair.public_key, data)?;
```

---

## Further Reading

- [Unified API Guide](unified_api/README.md)
- [Primitives Documentation](primitives/README.md)
- [Security Guide](docs/SECURITY_GUIDE.md)
- [NIST Compliance](docs/NIST_COMPLIANCE.md)

---

## Support

- **Documentation**: https://docs.quantumshield.io
- **GitHub Issues**: https://github.com/quantumshield/quantumshield/issues
- **Security**: security@quantumshield.io

---

**Document Version**: 1.0.0
**Last Updated**: January 13, 2026
**Maintained By**: QuantumShield Documentation Team
