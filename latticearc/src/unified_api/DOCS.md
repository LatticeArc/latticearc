# Unified API Module Documentation

Complete documentation for LatticeArc's Unified Cryptographic API module.

## Overview

The `unified_api` module provides a simplified, developer-friendly interface to all cryptographic operations in LatticeArc. It abstracts away the complexity of choosing algorithms, managing keys, and orchestrating cryptographic primitives.

### Design Philosophy

1. **Simplicity First**: One function call does what you need
2. **Smart Defaults**: Pre-optimized for common use cases
3. **Auto-Selection**: Automatically chooses best algorithms
4. **Zero-Trust**: Built-in security best practices
5. **Hardware-Aware**: Automatic hardware detection and routing
6. **Flexible**: Advanced users can customize everything

### Module Structure

```
unified_api/
├── mod.rs              # Module exports
├── convenience.rs       # Simple convenience functions
├── config.rs           # Configuration types
├── selector.rs         # Auto-selection engine
├── types.rs            # Common types
├── traits.rs           # Core traits
├── error.rs            # Error types
├── zero_trust.rs       # Zero-trust primitives
├── hardware.rs         # Hardware detection and routing
└── smart_defaults.rs      # Smart templates
```

## Core Concepts

### 1. Auto-Selection

The auto-selection engine analyzes input data and context to choose the optimal cryptographic scheme:

```rust
use latticearc::unified_api::*;

// Different data characteristics trigger different schemes
let small_msg = b"Hi!";              // → Fast classical crypto
let large_data = vec![0u8; 1_000_000]; // → Efficient AEAD
let structured = br#"{"key": "val"}"#;  // → Hybrid PQ

// Auto-selection handles it all
let enc1 = encrypt(small_msg);
let enc2 = encrypt(&large_data);
let enc3 = encrypt(structured);
```

**Factors analyzed:**
- Data size (small, medium, large)
- Data entropy (random, structured)
- Data structure (text, numeric, binary, JSON)
- Security level requirements
- Performance preferences
- Use case context

### 2. CryptoContext

Context that guides cryptographic operations:

```rust
pub struct CryptoContext {
    pub security_level: SecurityLevel,      // Security requirement
    pub performance_preference: PerformancePreference, // Optimization goal
    pub hardware_preference: HardwarePreference,     // Hardware selection
    pub custom_params: Option<Vec<(String, Vec<u8>)>>, // Custom parameters
}
```

**Security Levels:**
- `Standard` - 128-bit security (NIST Level 1)
- `High` - 192-bit security (NIST Level 3)
- `Maximum` - 256-bit security (NIST Level 5)
- `Custom { security_bits }` - Custom security level

**Performance Preferences:**
- `Speed` - Minimize latency (best for small data)
- `Throughput` - Maximize throughput (best for large data)
- `Latency` - Same as Speed
- `Memory` - Minimize memory usage
- `Balanced` - Balance all factors (default)

**Hardware Preferences:**
- `Auto` - Auto-detect best hardware (default)
- `CpuOnly` - CPU only (most compatible)
- `GpuPreferred` - Prefer GPU acceleration
- `FpgaPreferred` - Prefer FPGA acceleration
- `TpuPreferred` - Prefer TPU acceleration
- `SgxPreferred` - Prefer SGX enclaves

### 3. CryptoScheme

Enumeration of all supported cryptographic schemes:

```rust
pub enum CryptoScheme {
    // Homomorphic encryption
    Homomorphic(HomomorphicScheme),  // Paillier, BFV, CKKS, TFHE

    // Multi-party computation
    MultiParty(MpcScheme),          // FROST, SPDZ, Yao

    // Order-revealing encryption
    OrderRevealing(OreScheme),      // Basic, Optimized

    // Searchable encryption
    Searchable(SseScheme),          // Deterministic, Dynamic, Verifiable

    // Hybrid post-quantum
    HybridPq,                       // ML-KEM + AEAD

    // Classical cryptography
    Classical(ClassicalScheme),       // AES-GCM, ChaCha20-Poly1305, etc.
}
```

### 4. Use Cases

Pre-defined use cases for common scenarios:

```rust
pub enum UseCase {
    Messaging,              // End-to-end encrypted messaging
    Database,               // At-rest database encryption
    Searchable,             // Searchable encrypted data
    MachineLearning,        // Homomorphic computation for ML
    MultiPartyComputation,  // Secure multi-party computation
    SecureAnalytics,        // Analytics on encrypted data
    HighSecurity,           // High-security applications
    PerformanceCritical,    // Performance-critical applications
}
```

Each use case has an associated optimized template that selects the best scheme and parameters.

## Modules

### Convenience (`convenience.rs`)

Simple, one-line functions for common operations.

**Public Functions:**
- `encrypt(data: &[u8]) -> Result<EncryptedData, CryptoError>`
- `decrypt(encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError>`
- `sign(message: &[u8]) -> Result<SignedData, CryptoError>`
- `verify(signed: &SignedData) -> Result<bool, CryptoError>`
- `generate_keypair() -> Result<(PublicKey, PrivateKey), CryptoError>`
- `derive_key(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>, CryptoError>`

**Example:**
```rust
use latticearc::unified_api::*;

// One-line encryption
let encrypted = encrypt(b"Hello, World!")?;

// One-line decryption
let decrypted = decrypt(&encrypted)?;

// One-line signing
let signed = sign(b"Important message")?;

// One-line verification
let verified = verify(&signed)?;
```

### Selector (`selector.rs`)

Auto-selection engine that chooses optimal cryptographic scheme.

**Public Functions:**
- `select_encryption_scheme(data: &[u8], config: &EncryptionConfig, use_case: Option<UseCase>) -> Result<CryptoScheme, CryptoError>`
- `select_signature_scheme(config: &CryptoConfig) -> Result<CryptoScheme, CryptoError>`
- `select_hash_scheme(config: &CryptoConfig) -> Result<CryptoScheme, CryptoError>`
- `analyze_data_characteristics(data: &[u8]) -> DataCharacteristics`

**Example:**
```rust
use latticearc::unified_api::*;

let config = EncryptionConfig::default();
let data = b"Hello, World!";

// Let selector choose best scheme
let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;
println!("Selected scheme: {:?}", scheme);

// Force specific use case
let scheme = CryptoPolicyEngine::select_encryption_scheme(
    data,
    &config,
    Some(UseCase::Messaging),
)?;
```

### Config (`config.rs`)

Configuration types for customizing cryptographic operations.

**Public Types:**
- `CryptoConfig` - Main configuration
- `EncryptionConfig` - Encryption-specific configuration
- `SignatureConfig` - Signature-specific configuration
- `KeyDerivationConfig` - Key derivation configuration
- `HardwareConfig` - Hardware configuration
- `ZeroTrustConfig` - Zero-trust configuration

**Example:**
```rust
use latticearc::unified_api::*;

let config = CryptoConfig::new()
    .with_security_level(SecurityLevel::High)
    .with_performance_preference(PerformancePreference::Speed)
    .with_hardware_preference(HardwarePreference::Auto);

let enc_config = EncryptionConfig::default()
    .with_base(config)
    .with_aead(true)
    .with_nonce_strategy(NonceStrategy::Random);
```

### Types (`types.rs`)

Common types used across the module.

**Public Types:**
- `EncryptedData` - Encrypted data with metadata
- `SignedData` - Signed data with metadata
- `PublicKey` - Public key
- `PrivateKey` - Private key (zeroized on drop)
- `SymmetricKey` - Symmetric key (zeroized on drop)
- `CryptoContext` - Context for cryptographic operations
- `ZeroizedBytes` - Bytes that zeroize on drop

**Example:**
```rust
use latticearc::unified_api::*;

// Encrypt returns EncryptedData
let encrypted = encrypt(b"Hello")?;
println!("Scheme: {:?}", encrypted.scheme);
println!("Timestamp: {}", encrypted.timestamp);

// Sign returns SignedData
let signed = sign(b"Hello")?;
println!("Signature algorithm: {:?}", signed.metadata.signature_algorithm);

// Keys are automatically zeroized
let (public_key, private_key) = generate_keypair()?;
// private_key is zeroized when dropped
```

### Error (`error.rs`)

Error types for the module.

**Public Types:**
- `CryptoError` - General cryptographic errors
- `VerificationError` - Verification-specific errors
- `HardwareError` - Hardware-specific errors

**Example:**
```rust
use latticearc::unified_api::*;

match encrypt(data) {
    Ok(encrypted) => { /* success */ }
    Err(CryptoError::EncryptionFailed(msg)) => {
        eprintln!("Encryption failed: {}", msg);
    }
    Err(CryptoError::HardwareError(hw_err)) => {
        eprintln!("Hardware error: {}", hw_err);
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

### Zero Trust (`zero_trust.rs`)

Zero-knowledge authentication primitives.

**Public Types:**
- `ZeroTrustAuth` - Zero-trust authenticator
- `ZeroKnowledgeProof` - Zero-knowledge proof
- `ProofOfPossessionToken` - Proof of possession token
- `AuthenticationRequest` - Authentication request
- `AuthenticationResponse` - Authentication response
- `VerificationSession` - Verification session

**Public Functions:**
- `generate_challenge(&self, client_id: &str) -> Result<Vec<u8>, CryptoError>`
- `generate_zkp(&self, secret: &[u8], challenge: &[u8]) -> Result<ZeroKnowledgeProof, CryptoError>`
- `verify_zkp(&self, proof: &ZeroKnowledgeProof, challenge: &[u8], public_key: &[u8]) -> Result<bool, CryptoError>`

**Example:**
```rust
use latticearc::unified_api::*;

let auth = ZeroTrustAuth::new(CryptoScheme::HybridPq)?;

// Server: Generate challenge
let challenge = auth.generate_challenge("client123")?;

// Client: Generate proof
let secret = b"my_secret_key";
let proof = auth.generate_zkp(secret, &challenge)?;

// Server: Verify proof
let public_key = b"my_public_key";
let verified = auth.verify_zkp(&proof, &challenge, public_key)?;
```

### Hardware (`hardware.rs`)

Hardware detection and routing.

**Public Types:**
- `HardwareRouter` - Routes operations to best hardware
- `HardwareCapabilities` - Hardware capabilities
- `CpuFeatures` - CPU features
- `HardwareAccelerator` - Hardware accelerator trait
- `CpuAccelerator` - CPU accelerator implementation

**Public Functions:**
- `HardwareCapabilities::detect() -> HardwareCapabilities`
- `CpuFeatures::detect() -> CpuFeatures`
- `route_encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>`
- `route_decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>`

**Example:**
```rust
use latticearc::unified_api::*;

let router = HardwareRouter::new(HardwarePreference::Auto)?;

let capabilities = router.get_capabilities();
println!("CPU AES-NI: {}", capabilities.cpu_features.aes_ni);
println!("CPU AVX2: {}", capabilities.cpu_features.avx2);

let encrypted = router.route_encrypt(b"Hello", b"key")?;
let decrypted = router.route_decrypt(&encrypted, b"key")?;
```

### Smart Defaults (`smart_defaults.rs`)

Smart templates for common use cases.

**Public Types:**
- `SmartDefaults` - Smart defaults manager
- `OptimizedTemplate` - Optimized template
- `TemplateRegistry` - Template registry
- `UseCaseDetector` - Use case detector
- `AlgorithmParams` - Algorithm parameters

**Public Functions:**
- `recommend_template(&self, data: &[u8]) -> Result<OptimizedTemplate, CryptoError>`
- `get_template(&self, use_case: UseCase) -> Option<OptimizedTemplate>`
- `get_template_for_context(&self, context: &str) -> Result<OptimizedTemplate, CryptoError>`

**Example:**
```rust
use latticearc::unified_api::*;

let smart_defaults = SmartDefaults::new()?;

// Get template for specific use case
let template = smart_defaults.get_template(UseCase::Messaging)?;
println!("Template: {}", template.name);

// Get recommended template based on data
let data = br#"{"key": "value"}"#;
let template = smart_defaults.recommend_template(data)?;
println!("Recommended: {}", template.name);
```

## Security Best Practices

### 1. Always Verify Signatures

```rust
// Good: Verify signature
let verified = verify(&signed)?;
if verified {
    // Use data
}

// Bad: Trust signed data without verification
let data = signed.data; // DANGEROUS!
```

### 2. Zeroize Sensitive Data

```rust
// Good: Use ZeroizedBytes (auto-zeroizes)
let key = PrivateKey::new(vec![0u8; 32]);

// Good: Manual zeroization
use zeroize::Zeroize;
let mut key = vec![0u8; 32];
key.zeroize();

// Bad: Leave sensitive data in memory
let key = vec![0u8; 32];
// Key stays in memory until GC
```

### 3. Use Constant-Time Operations

```rust
// Good: Use constant-time comparison
use subtle::ConstantTimeEq;
if public_key.ct_eq(&expected).into() {
    // Match
}

// Bad: Use regular comparison (timing attack)
if public_key == expected {
    // Match - VULNERABLE!
}
```

### 4. Validate All Inputs

```rust
// Good: Validate input
if data.is_empty() {
    return Err(CryptoError::InvalidInput("Data cannot be empty".to_string()));
}
if data.len() > MAX_SIZE {
    return Err(CryptoError::InvalidInput("Data too large".to_string()));
}

// Bad: No validation
encrypt(data)? // Could panic or behave unexpectedly
```

### 5. Use Secure Random Numbers

```rust
// Good: Use crypto-secure random
let mut nonce = vec![0u8; 12];
rand::thread_rng().fill_bytes(&mut nonce);

// Bad: Use predictable random
let nonce = b"predictable"; // DANGEROUS!
```

## Performance Considerations

### 1. Data Size Matters

The auto-selection engine optimizes for data size:

```rust
// Small data (< 1KB) → Fast algorithms
let small = encrypt(b"Hi")?; // ChaCha20-Poly1305

// Medium data (1KB - 1MB) → Balanced algorithms
let medium = encrypt(&vec![0u8; 100_000])?; // AES-GCM

// Large data (> 1MB) → Throughput-optimized
let large = encrypt(&vec![0u8; 10_000_000])?; // Hybrid PQ
```

### 2. Hardware Acceleration

Enable hardware acceleration for better performance:

```rust
let config = CryptoConfig::default()
    .with_hardware_preference(HardwarePreference::Auto);
```

Hardware acceleration benefits:
- CPU AES-NI: 2-3x faster for AES-GCM
- CPU AVX2: 1.5-2x faster for hash operations
- GPU: 10-100x faster for homomorphic encryption
- FPGA: 5-50x faster for ML-KEM

### 3. Key Caching

Cache keys for repeated operations:

```rust
let config = CryptoConfig::default()
    .with_key_caching(true);
```

Key caching benefits:
- Faster key generation (no re-derivation)
- Reduced CPU usage
- Better performance for repeated operations

### 4. Compression

Enable compression for highly compressible data:

```rust
let config = EncryptionConfig::default()
    .with_compression(true);
```

Compression benefits:
- Smaller ciphertext size (30-70% reduction)
- Faster transmission (less data to send)
- Lower storage costs

## Common Pitfalls

### 1. Reusing Nonces

```rust
// Bad: Reusing nonce
let nonce = vec![0u8; 12];
let enc1 = encrypt_with_nonce(data1, &nonce)?;
let enc2 = encrypt_with_nonce(data2, &nonce)?; // DANGEROUS!

// Good: Generate new nonce each time
let enc1 = encrypt(data1)?;
let enc2 = encrypt(data2)?;
```

### 2. Hardcoding Keys

```rust
// Bad: Hardcoded key
let key = b"secret_key_16b";

// Good: Generate key securely
let key = derive_key(b"password", b"salt", 16)?;
```

### 3. Ignoring Errors

```rust
// Bad: Ignoring error
let encrypted = encrypt(data).unwrap();

// Good: Handle error properly
match encrypt(data) {
    Ok(encrypted) => { /* use it */ }
    Err(e) => { /* handle error */ }
}
```

### 4. Using Insecure Schemes

```rust
// Bad: Using insecure scheme
let config = CryptoConfig::default()
    .with_scheme(CryptoScheme::Classical(ClassicalScheme::ChaCha20Poly1305));

// Good: Use secure default (HybridPq)
let config = CryptoConfig::default();
```

## Thread Safety

### Safe Usage

The module is designed to be thread-safe:

```rust
use std::thread;
use latticearc::unified_api::*;

let data = vec![0u8; 1000];

// Multiple threads can encrypt independently
let handles: Vec<_> = (0..10).map(|i| {
    let data = data.clone();
    thread::spawn(move || {
        encrypt(&data)
    })
}).collect();

for handle in handles {
    let encrypted = handle.join().unwrap()?;
    // Use encrypted data
}
```

### Shared State

Use `Arc` for shared authenticators:

```rust
use std::sync::Arc;
use latticearc::unified_api::*;

let auth = Arc::new(ZeroTrustAuth::new(CryptoScheme::HybridPq)?);
let auth1 = Arc::clone(&auth);

thread::spawn(move || {
    let challenge = auth1.generate_challenge("client1")?;
    // ...
});
```

## Testing

### Unit Tests

The module includes comprehensive unit tests:

```bash
# Run all tests
cargo test --package latticearc --lib unified_api

# Run specific test
cargo test --package latticearc --lib test_encrypt_decrypt
```

### Integration Tests

Integration tests verify end-to-end functionality:

```bash
# Run integration tests
cargo test --test integration
```

### Fuzz Testing

Fuzz testing finds edge cases and bugs:

```bash
# Run fuzz tests
cd fuzz
cargo fuzz run encrypt_fuzzer
```

## Additional Resources

- [Unified API Guide](../../UNIFIED_API_GUIDE.md)
- [API Reference](https://docs.rs/latticearc)
- [Examples](../../examples/)
- [Source Code](../../latticearc/src/unified_api/)
