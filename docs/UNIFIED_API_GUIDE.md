# LatticeArc Unified API Guide

A high-level, intelligent cryptographic API with automatic algorithm selection, zero-trust authentication, and hardware acceleration.

## Overview

The Unified API provides three levels of abstraction:

1. **Simple Functions** - One-line encryption/signing with smart defaults
2. **Use Case-Based Selection** - Automatic scheme selection for common scenarios
3. **Context-Aware Selection** - Data analysis and runtime-adaptive optimization

```rust
use arc_core::convenience::*;
use arc_core::selector::{CryptoPolicyEngine, CryptoPolicyEngine};
use arc_core::types::UseCase;

// Level 1: Simple (hybrid PQ by default)
let encrypted = encrypt(data, &key)?;

// Level 2: Use case-based (automatic scheme selection)
let scheme = CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;

// Level 3: Context-aware (analyzes data characteristics)
let selector = CryptoPolicyEngine::new();
let scheme = selector.select_for_context(data, &config)?;
```

## Quick Start

### With Zero Trust (arc-core)

```rust
use arc_core::{VerifiedSession, encrypt, decrypt, sign, verify, generate_keypair};
use arc_core::config::CoreConfig;
use arc_core::types::{SecurityLevel, PerformancePreference};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Establish verified session (required for Zero Trust)
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(&public_key, &private_key)?;

    // Configure security preferences
    let config = CoreConfig::builder()
        .security_level(SecurityLevel::High)
        .performance_preference(PerformancePreference::Balanced)
        .build()?;

    // Encrypt with automatic hybrid PQ scheme (session required)
    let key = [0u8; 32];
    let encrypted = encrypt(&session, b"secret message", &key)?;
    let decrypted = decrypt(&session, &encrypted, &key)?;

    // Sign with hybrid ML-DSA + Ed25519 (session required)
    let signed = sign(&session, b"document")?;
    let is_valid = verify(&session, &signed)?;

    Ok(())
}
```

### Simple API (latticearc)

For simpler usage without Zero Trust sessions:

```rust
use latticearc::{encrypt, decrypt, sign, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No session required - uses _unverified variants internally
    let key = [0u8; 32];
    let encrypted = encrypt(b"secret message", &key)?;
    let decrypted = decrypt(&encrypted, &key)?;

    let signed = sign(b"document")?;
    let is_valid = verify(&signed)?;

    Ok(())
}
```

## Smart Defaults and Auto-Selection

### CryptoPolicyEngine - Data-Aware Selection

Analyzes data characteristics to select optimal schemes:

```rust
use arc_core::selector::CryptoPolicyEngine;
use arc_core::config::CoreConfig;

let config = CoreConfig::default();

// Analyzes entropy, size, and pattern type
let scheme = CryptoPolicyEngine::select_encryption_scheme(data, &config, None)?;

// Get data characteristics
let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
println!("Entropy: {:.2} bits/byte", characteristics.entropy);
println!("Pattern: {:?}", characteristics.pattern_type);
println!("Size: {} bytes", characteristics.size);
```

**Pattern Types Detected:**
- `Random` - High entropy (>7.5 bits/byte), encrypted or compressed data
- `Text` - ASCII printable with moderate entropy (>4.0)
- `Repetitive` - Repeating patterns detected
- `Structured` - Sequential or structured data
- `Binary` - Other binary data

### UseCase-Based Selection

8 predefined use cases with optimized scheme mappings:

```rust
use arc_core::selector::CryptoPolicyEngine;
use arc_core::types::UseCase;

// Encryption use cases
CryptoPolicyEngine::recommend_scheme(&UseCase::SecureMessaging, &config)?;
// -> "hybrid-ml-kem-768-aes-256-gcm"

CryptoPolicyEngine::recommend_scheme(&UseCase::FileStorage, &config)?;
// -> "hybrid-ml-kem-1024-aes-256-gcm"

CryptoPolicyEngine::recommend_scheme(&UseCase::DatabaseEncryption, &config)?;
// -> "hybrid-ml-kem-768-aes-256-gcm"

CryptoPolicyEngine::recommend_scheme(&UseCase::KeyExchange, &config)?;
// -> "hybrid-ml-kem-1024-x25519"

// Signature use cases
CryptoPolicyEngine::recommend_scheme(&UseCase::FinancialTransactions, &config)?;
// -> "hybrid-ml-dsa-65-ed25519"

CryptoPolicyEngine::recommend_scheme(&UseCase::Authentication, &config)?;
// -> "hybrid-ml-dsa-87-ed25519"
```

| Use Case | Recommended Scheme | Notes |
|----------|-------------------|-------|
| `SecureMessaging` | hybrid-ml-kem-768-aes-256-gcm | Real-time communication |
| `FileStorage` | hybrid-ml-kem-1024-aes-256-gcm | Long-term storage |
| `DatabaseEncryption` | hybrid-ml-kem-768-aes-256-gcm | Balanced performance |
| `KeyExchange` | hybrid-ml-kem-1024-x25519 | Key agreement |
| `FinancialTransactions` | hybrid-ml-dsa-65-ed25519 | Transaction signing |
| `Authentication` | hybrid-ml-dsa-87-ed25519 | Maximum security |
| `SearchableEncryption` | hybrid-ml-kem-768-aes-256-gcm | Searchable cipher |
| `HomomorphicComputation` | hybrid-ml-kem-768-aes-256-gcm | Computation on encrypted |

### CryptoPolicyEngine - Runtime Adaptive

Adapts based on runtime performance metrics:

```rust
use arc_core::selector::{CryptoPolicyEngine, PerformanceMetrics};

let selector = CryptoPolicyEngine::new();

// Basic context-aware selection
let scheme = selector.select_for_context(data, &config)?;

// Adaptive selection with runtime metrics
let metrics = PerformanceMetrics {
    encryption_speed_ms: 150.0,
    decryption_speed_ms: 75.0,
    memory_usage_mb: 256.0,
    cpu_usage_percent: 45.0,
};
let scheme = selector.adaptive_selection(data, &metrics, &config)?;
```

**Adaptation Rules:**
- High memory pressure (>500MB) + Memory preference → Downgrade to ML-KEM-768
- Slow encryption (>1000ms) + Speed preference + Repetitive data → Classical fallback
- Maximum security → Always use strongest hybrid (ML-KEM-1024)

## Zero-Trust Authentication

### VerifiedSession (Recommended)

The simplest way to use Zero Trust is through `VerifiedSession::establish()`:

```rust
use arc_core::{VerifiedSession, TrustLevel, encrypt, generate_keypair};

// Quick session establishment (one-line)
let (public_key, private_key) = generate_keypair()?;
let session = VerifiedSession::establish(&public_key, &private_key)?;

// Check trust level
assert_eq!(session.trust_level(), TrustLevel::Trusted);

// Use for all crypto operations
let encrypted = encrypt(&session, data, &key)?;
```

### Manual Challenge-Response

For more control, use the full challenge-response flow:

```rust
use arc_core::zero_trust::{
    ZeroTrustAuth, ZeroTrustSession, Challenge, ZeroKnowledgeProof
};
use arc_core::config::ZeroTrustConfig;

// Create authentication handler
let auth = ZeroTrustAuth::new(public_key, private_key)?;

// Generate challenge
let challenge = auth.generate_challenge()?;

// Generate zero-knowledge proof (proves key ownership without revealing key)
let proof = auth.generate_proof(&challenge.data)?;

// Verify proof using only public key
let is_valid = auth.verify_proof(&proof, &challenge.data)?;

// Convert to VerifiedSession for crypto operations
let mut zt_session = ZeroTrustSession::new(auth);
let challenge = zt_session.initiate_authentication()?;
let proof = zt_session.auth.generate_proof(&challenge.data)?;
zt_session.verify_response(&proof)?;
let session = zt_session.into_verified()?;
```

### Zero-Trust Session Management

```rust
use arc_core::zero_trust::ZeroTrustSession;

// Create session
let mut session = ZeroTrustSession::new(auth);

// Initiate authentication
let challenge = session.initiate_authentication()?;

// Verify response
let proof = generate_proof_externally(&challenge);
let authenticated = session.verify_response(&proof)?;

// Check session status
if session.is_authenticated() {
    let age_ms = session.session_age_ms()?;
    println!("Session age: {}ms", age_ms);
}
```

### Proof of Possession

```rust
use arc_core::traits::ProofOfPossession;

// Generate proof that you possess the private key
let pop = auth.generate_pop()?;

// Verify possession (timestamp-bound)
let is_valid = auth.verify_pop(&pop)?;
```

### Continuous Verification

```rust
use arc_core::traits::{ContinuousVerifiable, VerificationStatus};

// Start continuous session
let session = auth.start_continuous_verification();

// Check verification status periodically
match auth.verify_continuously()? {
    VerificationStatus::Verified => { /* Session valid */ }
    VerificationStatus::Pending => { /* Re-verification needed */ }
    VerificationStatus::Expired => { /* Session expired */ }
}

// Re-authenticate if needed
auth.reauthenticate()?;
```

### Zero-Trust Configuration

```rust
use arc_core::config::{ZeroTrustConfig, ProofComplexity};

let config = ZeroTrustConfig {
    challenge_timeout_ms: 30_000,      // 30 second challenge timeout
    proof_complexity: ProofComplexity::High,  // Include timestamp + key binding
    continuous_verification: true,
    verification_interval_ms: 60_000,  // Re-verify every minute
    ..Default::default()
};

let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
```

**Proof Complexity Levels:**
- `Low` - Sign challenge only (32-byte challenge)
- `Medium` - Sign challenge + timestamp (64-byte challenge, replay protection)
- `High` - Sign challenge + timestamp + public key binding (128-byte challenge)

## Hardware Detection and Routing

Automatic hardware acceleration detection and routing:

```rust
use arc_core::hardware::HardwareRouter;

let router = HardwareRouter::new();

// Detect available hardware
let info = router.detect_hardware();
println!("Available: {:?}", info.available_accelerators);
println!("Preferred: {:?}", info.preferred_accelerator);
println!("Capabilities:");
println!("  SIMD: {}", info.capabilities.simd_support);
println!("  AES-NI: {}", info.capabilities.aes_ni);
println!("  Threads: {}", info.capabilities.threads);

// Route operation to best hardware
let result = router.route_to_best_hardware(|| {
    encrypt(data, &key)
})?;
```

**Supported Accelerators:**
- `Cpu` - CPU with SIMD/AES-NI
- `Gpu` - NVIDIA GPU (CUDA)
- `Fpga` - Xilinx/Altera FPGA
- `Tpm` - Trusted Platform Module
- `Sgx` - Intel SGX enclaves

## Configuration

### SecurityLevel

```rust
use arc_core::types::SecurityLevel;

// Classical equivalent security bits
SecurityLevel::Low      // 128-bit (ML-KEM-512, ML-DSA-44)
SecurityLevel::Medium   // 192-bit (ML-KEM-768, ML-DSA-65)
SecurityLevel::High     // 256-bit (ML-KEM-768, ML-DSA-65)
SecurityLevel::Maximum  // 256+ bit (ML-KEM-1024, ML-DSA-87)
```

### PerformancePreference

```rust
use arc_core::types::PerformancePreference;

PerformancePreference::Speed     // Minimize latency
PerformancePreference::Memory    // Minimize memory usage
PerformancePreference::Balanced  // Balance all factors
```

### CoreConfig Builder

```rust
use arc_core::config::CoreConfig;

let config = CoreConfig::builder()
    .security_level(SecurityLevel::High)
    .performance_preference(PerformancePreference::Balanced)
    .hardware_acceleration(true)
    .fallback_enabled(true)
    .strict_validation(true)
    .build()?;
```

## Encryption Functions

### Basic Encryption

```rust
// Default hybrid scheme
let encrypted = encrypt(data, &key)?;
let decrypted = decrypt(&encrypted, &key)?;

// With configuration
let config = EncryptionConfig::default();
let encrypted = encrypt_with_config(data, &config, &key)?;
let decrypted = decrypt_with_config(&encrypted, &config, &key)?;
```

### Hybrid Encryption (Public Key)

```rust
// Encrypt for recipient's public key
let result = encrypt_hybrid(data, &recipient_public_key)?;
// result.ciphertext - encrypted data
// result.encapsulated_key - KEM ciphertext

// Recipient decrypts with private key
let plaintext = decrypt_hybrid(
    &result.ciphertext,
    &result.encapsulated_key,
    &recipient_secret_key
)?;
```

### Post-Quantum Specific

```rust
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

// ML-KEM encryption
let ciphertext = encrypt_pq_ml_kem(data, &pk, MlKemSecurityLevel::MlKem768)?;
let plaintext = decrypt_pq_ml_kem(&ciphertext, &sk, MlKemSecurityLevel::MlKem768)?;
```

## Signature Functions

### Basic Signing

```rust
// Sign with auto-generated keypair
let signed = sign(message)?;
let is_valid = verify(&signed)?;

// With configuration
let config = SignatureConfig::default();
let signed = sign_with_config(message, &config)?;
let is_valid = verify_with_config(message, &signed, &config)?;
```

### Post-Quantum Signatures

```rust
use arc_primitives::sig::ml_dsa::MlDsaParameterSet;

// ML-DSA (FIPS 204)
let signature = sign_pq_ml_dsa(message, &sk, MlDsaParameterSet::MLDSA65)?;
let valid = verify_pq_ml_dsa(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;

// SLH-DSA (FIPS 205)
let signature = sign_pq_slh_dsa(message, &sk, SecurityLevel::Shake128s)?;

// FN-DSA (FIPS 206)
let signature = sign_pq_fn_dsa(message, &sk)?;
```

## Key Generation

```rust
// Ed25519
let (pk, sk) = generate_keypair()?;

// ML-KEM (FIPS 203)
let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

// ML-DSA (FIPS 204)
let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

// SLH-DSA (FIPS 205)
let (pk, sk) = generate_slh_dsa_keypair(SecurityLevel::Shake128s)?;

// FN-DSA (FIPS 206)
let (pk, sk) = generate_fn_dsa_keypair()?;
```

## Hashing and KDF

```rust
// SHA-256 hash
let hash = hash_data(data)?;

// HKDF key derivation
let derived = derive_key(ikm, salt, info, 32)?;

// HMAC-SHA256
let mac = hmac(&key, data)?;
let valid = hmac_check(&key, data, &mac)?;
```

## Scheme Constants

```rust
use arc_core::selector::*;

// Hybrid schemes (default - PQ + classical)
DEFAULT_ENCRYPTION_SCHEME  // "hybrid-ml-kem-768-aes-256-gcm"
DEFAULT_SIGNATURE_SCHEME   // "hybrid-ml-dsa-65-ed25519"

HYBRID_ENCRYPTION_512      // "hybrid-ml-kem-512-aes-256-gcm"
HYBRID_ENCRYPTION_768      // "hybrid-ml-kem-768-aes-256-gcm"
HYBRID_ENCRYPTION_1024     // "hybrid-ml-kem-1024-aes-256-gcm"

HYBRID_SIGNATURE_44        // "hybrid-ml-dsa-44-ed25519"
HYBRID_SIGNATURE_65        // "hybrid-ml-dsa-65-ed25519"
HYBRID_SIGNATURE_87        // "hybrid-ml-dsa-87-ed25519"

// PQ-only schemes (pure post-quantum)
DEFAULT_PQ_ENCRYPTION_SCHEME  // "pq-ml-kem-768-aes-256-gcm"
DEFAULT_PQ_SIGNATURE_SCHEME   // "pq-ml-dsa-65"

// Classical schemes (legacy/compatibility)
CLASSICAL_AES_GCM   // "aes-256-gcm"
CLASSICAL_ED25519   // "ed25519"
```

## Error Handling

```rust
use arc_core::error::CoreError;

match encrypt(data, &key) {
    Ok(encrypted) => { /* success */ }
    Err(CoreError::InvalidKeyLength { expected, actual }) => {
        eprintln!("Key must be {} bytes, got {}", expected, actual);
    }
    Err(CoreError::AuthenticationFailed(msg)) => {
        eprintln!("Auth failed: {}", msg);
    }
    Err(CoreError::EntropyDepleted { message, action }) => {
        eprintln!("No entropy: {} - {}", message, action);
    }
    Err(CoreError::ConfigurationError(msg)) => {
        eprintln!("Config error: {}", msg);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Security Considerations

1. **Quantum Safety**: All defaults use hybrid schemes (PQ + classical) for defense-in-depth
2. **Key Zeroization**: Private keys use `ZeroizedBytes` for automatic memory clearing
3. **Constant-Time**: Zero-trust proofs use constant-time comparison
4. **Nonce Uniqueness**: Nonces are auto-generated using secure random
5. **Input Validation**: All inputs validated against resource limits

## Examples

See the `examples/` directory:
- `unified_api_quickstart.rs` - Basic usage
- `unified_api_encryption.rs` - Encryption patterns
- `unified_api_signatures.rs` - Signature patterns
- `unified_api_advanced.rs` - Advanced configuration
- `unified_api_smart_defaults.rs` - Auto-selection demo
- `unified_api_hardware.rs` - Hardware detection
- `unified_api_zero_trust.rs` - Zero-trust auth

```bash
cargo run --example unified_api_quickstart
cargo run --example unified_api_smart_defaults
cargo run --example unified_api_zero_trust
```
