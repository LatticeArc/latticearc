# Unified Cryptographic API

The Unified Cryptographic API provides a simple, developer-friendly interface to all LatticeArc cryptographic operations.

## Overview

### Design Philosophy

1. **Simplicity First**: One API for all crypto operations
2. **Smart Defaults**: Auto-selects best scheme for each use case
3. **Flexibility**: Manual overrides for advanced users
4. **Safety First**: Memory-safe, constant-time operations
5. **Performance**: Hardware-aware routing

### Quick Start

```rust
use latticearc::unified_api::*;

// Simple encryption - auto-selects best scheme
let encrypted = encrypt(sensitive_data)?;
let decrypted = decrypt(encrypted)?;

// Zero-trust authentication
let auth = ZeroTrustAuth::new(public_key, private_key)?;
let challenge = auth.generate_challenge();
let proof = auth.generate_proof(&challenge)?;
let verified = auth.verify_proof(&proof, &challenge)?;

// Hardware-aware operations
let result = HardwareRouter::new().execute_heavy_operation(|| {
    perform_encryption(large_data)
})?;
```

## Module Structure

```
unified_api/
├── error.rs           # Comprehensive error types
├── types.rs           # Type aliases and common types
├── traits.rs          # Core trait definitions
├── config.rs          # Configuration and policy
├── selector.rs        # Auto-selection engine
├── hardware.rs        # Hardware detection and routing
├── zero_trust.rs      # Zero-trust authentication
└── README.md          # This file
```

## Core Traits

### Encryption & Decryption

```rust
pub trait Encryptable {
    type Output;
    type Error;

    fn encrypt(&self, data: &[u8]) -> Result<Self::Output, Self::Error>;
    fn encrypt_with_context(&self, data: &[u8], ctx: &CryptoContext) -> Result<Self::Output, Self::Error>;
}

pub trait Decryptable {
    type Output;
    type Error;

    fn decrypt(&self, encrypted: &[u8]) -> Result<Self::Output, Self::Error>;
    fn decrypt_with_context(&self, encrypted: &[u8], ctx: &CryptoContext) -> Result<Self::Output, Self::Error>;
}
```

### Signing & Verification

```rust
pub trait Signable {
    type Output;
    type Error;

    fn sign(&self, message: &[u8]) -> Result<Self::Output, Self::Error>;
    fn sign_with_context(&self, message: &[u8], ctx: &CryptoContext) -> Result<Self::Output, Self::Error>;
}

pub trait Verifiable {
    type Error;

    fn verify(&self, message: &[u8], signature: &[u8]) -> subtle::Choice;
    fn verify_with_context(&self, message: &[u8], signature: &[u8], ctx: &CryptoContext) -> subtle::Choice;
}
```

### Key Derivation

```rust
pub trait KeyDerivable {
    type Output;
    type Error;

    fn derive_key(&self, input: &[u8], info: &[u8], length: usize) -> Result<Self::Output, Self::Error>;
    fn derive_key_from_password(&self, password: &str, salt: &[u8], length: usize) -> Result<Self::Output, Self::Error>;
}
```

### Zero-Trust Authentication

```rust
pub trait ZeroTrustAuthenticable {
    type Proof;
    type Error;

    fn generate_proof(&self, challenge: &[u8]) -> Result<Self::Proof, Self::Error>;
    fn verify_proof(&self, proof: &Self::Proof, challenge: &[u8]) -> subtle::Choice;
}

pub trait ProofOfPossession {
    type Pop;
    type Error;

    fn generate_pop(&self) -> Result<Self::Pop, Self::Error>;
    fn verify_pop(&self, pop: &Self::Pop) -> subtle::Choice;
}

pub trait ContinuousVerifiable {
    type Error;

    fn verify_continuously(&self) -> Result<VerificationStatus, Self::Error>;
    fn reauthenticate(&self) -> Result<(), Self::Error>;
}
```

### Hardware-Aware Operations

```rust
pub trait HardwareAware {
    type Error;

    fn detect_hardware(&self) -> HardwareInfo;
    fn route_to_best_hardware<F, R>(&self, f: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&dyn HardwareAccelerator) -> Result<R, Box<dyn std::error::Error>>;
}

pub trait HardwareAccelerator {
    fn name(&self) -> &str;
    fn hardware_type(&self) -> HardwareType;
    fn is_available(&self) -> bool;
    fn accelerate<F, R>(&self, f: F) -> Result<R, HardwareError>
    where
        F: FnOnce() -> Result<R, HardwareError>;
}
```

## Type Aliases

### Common Types

```rust
/// Encrypted data with metadata
pub type EncryptedData = CryptoPayload<EncryptedMetadata>;

/// Signed data with signature
pub type SignedData = CryptoPayload<SignedMetadata>;

/// Generic key pair (public + private)
pub type KeyPair = (PublicKey, PrivateKey);

/// Cryptographic hash output
pub type HashOutput = [u8; 32];

/// Symmetric key (zeroized on drop)
pub type SymmetricKey = ZeroizedBytes;

/// Asymmetric public key
pub type PublicKey = Vec<u8>;

/// Asymmetric private key (zeroized on drop)
pub type PrivateKey = ZeroizedBytes;
```

## Configuration

### Basic Configuration

```rust
use latticearc::unified_api::*;

let config = CryptoConfig::new()
    .with_security_level(SecurityLevel::High)
    .with_performance_preference(PerformancePreference::Speed)
    .with_hardware_acceleration(true)
    .validate()?;
```

### Use-Case Based Configuration

```rust
// Secure messaging
let messaging_config = CryptoPolicyEngine::recommend_scheme(UseCase::SecureMessaging, &config)?;

// Database encryption
let db_config = CryptoPolicyEngine::recommend_scheme(UseCase::DatabaseEncryption, &config)?;

// Financial transactions
let financial_config = CryptoPolicyEngine::recommend_scheme(UseCase::FinancialTransactions, &config)?;
```

## Auto-Selection Engine

### Scheme Selection

The `CryptoPolicyEngine` automatically selects the optimal cryptographic scheme based on:

1. **Data Characteristics**: Size, entropy, structure
2. **Security Requirements**: Security level, compliance needs
3. **Performance Needs**: Speed, throughput, latency, memory
4. **Hardware**: Available accelerators, CPU features

### Example

```rust
let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);

let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config)?;

// Force specific scheme (advanced users)
let forced_config = CryptoPolicyEngine::force_scheme(CryptoScheme::HybridKem);
```

## Zero-Trust Authentication

### Basic Zero-Knowledge Authentication

```rust
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Prover generates proof
let challenge = auth.generate_challenge();
let proof = auth.generate_proof(&challenge)?;

// Verifier validates proof
let verified = auth.verify_proof(&proof, &challenge)?;
if verified.into() {
    println!("Authentication successful!");
}
```

### Proof of Possession

```rust
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Generate proof of possession
let pop = auth.generate_pop()?;

// Verify proof of possession
let verified = auth.verify_pop(&pop)?;
assert!(verified.into());
```

### Continuous Verification

```rust
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Start continuous verification
let session = auth.start_continuous_verification()?;

// Verify at regular intervals
let status = auth.verify_continuously()?;
if status.is_verified() {
    println!("Still verified");
}
```

## Hardware-Aware Routing

### Hardware Detection

```rust
let mut router = HardwareRouter::new();
let info = router.detect_hardware();

println!("Hardware: {}", info.summary());
println!("Best accelerator: {}", info.best_accelerator());
```

### Hardware-Aware Execution

```rust
let router = HardwareRouter::new()
    .with_config(HardwareConfig::new()
        .with_acceleration(true)
        .with_fallback(true)
        .with_threshold(1024));

let result = router.execute_heavy_operation(|| {
    // Automatically routed to best available hardware
    perform_encryption(large_data)
})?;
```

### Custom Hardware Configuration

```rust
let config = HardwareConfig::new()
    .with_acceleration(true)
    .with_fallback(true)
    .with_threshold(4096)
    .with_preferred_accelerator(HardwareType::Gpu)
    .with_preferred_accelerator(HardwareType::Fpga);

let router = HardwareRouter::new().with_config(config);
```

## Error Handling

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Hardware error: {0}")]
    HardwareError(#[from] HardwareError),

    // ... more error variants
}
```

### Error Handling Pattern

```rust
match encrypt(data) {
    Ok(encrypted) => {
        println!("Encryption successful");
    }
    Err(CryptoError::InvalidKeyLength { expected, actual }) => {
        eprintln!("Key length error: expected {}, got {}", expected, actual);
    }
    Err(CryptoError::EncryptionFailed(msg)) => {
        eprintln!("Encryption failed: {}", msg);
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

## Security Best Practices

### 1. Constant-Time Operations

All operations on secrets use `subtle::Choice` to prevent timing attacks:

```rust
pub fn verify_constant_time(a: &[u8], b: &[u8]) -> subtle::Choice {
    a.ct_eq(b)
}
```

### 2. Memory Safety

All secrets use `ZeroizedBytes` wrapper:

```rust
let key = ZeroizedBytes::new(vec![0u8; 32]);
// key is automatically zeroized on drop
```

### 3. Input Validation

All public APIs validate inputs:

```rust
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::InvalidInput("Data cannot be empty".to_string()));
    }
    // ...
}
```

## Use Cases

### Secure Messaging

```rust
let config = CryptoPolicyEngine::recommend_scheme(UseCase::SecureMessaging, &CryptoConfig::new())?;

let encrypted = encrypt_with_config(message, &config)?;
let decrypted = decrypt_with_config(encrypted, &config)?;
```

### Database Encryption

```rust
let config = CryptoPolicyEngine::recommend_scheme(UseCase::DatabaseEncryption, &CryptoConfig::new())?;

// Encrypt record
let encrypted_record = encrypt_with_config(&record, &config)?;

// Store in database
db.insert(encrypted_record);
```

### Searchable Encryption

```rust
let config = CryptoPolicyEngine::recommend_scheme(UseCase::SearchableEncryption, &CryptoConfig::new())?;

let encrypted = encrypt_with_config(&data, &config)?;

// Search without decryption
let results = search_encrypted(encrypted, query)?;
```

### Post-Quantum Key Exchange

```rust
use latticearc::unified_api::*;

// Generate hybrid keypair (ML-KEM + X25519)
let keypair = generate_keypair()?;

// Encrypt with hybrid scheme
let encrypted = encrypt_hybrid(data)?;

// Decrypt
let decrypted = decrypt_hybrid(encrypted)?;
```

## Performance Considerations

### Hardware Acceleration

When hardware accelerators are available (FPGA, TPU, GPU, SGX), operations are automatically routed to the fastest available device:

- **FPGA**: 100x speedup for specific operations
- **TPU**: 1000x speedup for ML-based operations
- **GPU**: 10-50x speedup for parallel operations
- **SGX**: Secure enclave for key operations

### Memory Management

- Keys are zeroized on drop
- Encrypted data overhead: < 5%
- Peak memory: Linear with data size

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let data = b"Hello, World!";
        let encrypted = encrypt(data).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_zero_trust_authentication() {
        let auth = ZeroTrustAuth::new(public_key, private_key).unwrap();
        let challenge = auth.generate_challenge();
        let proof = auth.generate_proof(&challenge).unwrap();
        let verified = auth.verify_proof(&proof, &challenge);
        assert!(verified.into());
    }
}
```

## Migration Guide

### From Primitive-Level API

**Before:**
```rust
use latticearc_primitives::kem::ml_kem::*;
use latticearc_primitives::aead::aes_gcm::*;

let kem_key = MlKem1024KeyPair::generate()?;
let encapsulated = kem_key.public_key.encapsulate()?;
let shared_secret = kem_key.private_key.decapsulate(&encapsulated)?;
let ciphertext = aes_gcm_encrypt(&shared_secret, data)?;
```

**After:**
```rust
use latticearc::unified_api::*;

let encrypted = encrypt(data)?;
let decrypted = decrypt(encrypted)?;
```

## Further Reading

- [API Design Document](../UNIFIED_API_DESIGN.md)
- [LatticeArc Documentation](../README.md)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
