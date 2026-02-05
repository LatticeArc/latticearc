# Security Guide

Security best practices for using LatticeArc in production applications.

## Threat Model

```mermaid
flowchart TB
    subgraph "Threats Mitigated"
        QC[Quantum Computer<br/>Attacks]
        CRYPTO[Classical<br/>Cryptanalysis]
        TIMING[Timing<br/>Side-Channels]
        MEM[Memory<br/>Disclosure]
        REPLAY[Replay<br/>Attacks]
    end

    subgraph "Defenses"
        HYBRID[Hybrid PQ+Classical]
        CONST[Constant-Time Ops]
        ZERO[Zeroization]
        ZT[Zero-Trust Auth]
        PROOF[ZK Proofs]
    end

    subgraph "Protection Level"
        FULL[Full Protection]
        BEST[Best Effort]
    end

    QC --> HYBRID --> FULL
    CRYPTO --> HYBRID --> FULL
    TIMING --> CONST --> BEST
    MEM --> ZERO --> BEST
    REPLAY --> ZT --> FULL
    REPLAY --> PROOF --> FULL

    classDef threat fill:#e74c3c,stroke:#333,color:#fff
    classDef defense fill:#3498db,stroke:#333,color:#fff
    classDef level fill:#27ae60,stroke:#333,color:#fff

    class QC,CRYPTO,TIMING,MEM,REPLAY threat
    class HYBRID,CONST,ZERO,ZT,PROOF defense
    class FULL,BEST level
```

### What LatticeArc Protects Against

| Threat | Protection | Mechanism |
|--------|------------|-----------|
| Quantum attacks | Full | FIPS 203-206 PQ algorithms |
| Classical cryptanalysis | Full | Hybrid PQ + classical |
| Timing side-channels | Best effort | `subtle` crate constant-time |
| Memory disclosure | Best effort | `zeroize` automatic clearing |
| Replay attacks | Full | ZeroTrustAuth + timestamps |
| Key compromise | Partial | Key rotation, continuous verification |

### What LatticeArc Does NOT Protect Against

- **Physical attacks**: Power analysis, EM emanations, fault injection
- **Compromised systems**: Malware, backdoored hardware
- **Implementation bugs**: Despite extensive testing, bugs may exist
- **Misuse**: Incorrect API usage voids security guarantees

## Zero-Trust Authentication

LatticeArc implements zero-trust authentication at the cryptographic operation level.

### Authentication Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant ZT as ZeroTrustAuth
    participant Crypto as Crypto Operations

    App->>ZT: Create auth with keypair
    ZT->>ZT: Validate configuration

    rect rgb(200, 230, 255)
        Note over App,Crypto: Authentication Phase
        App->>ZT: generate_challenge()
        ZT-->>App: Challenge (data, timeout, complexity)
        App->>ZT: generate_proof(challenge)
        Note right of ZT: Sign challenge with<br/>private key (ZKP)
        ZT-->>App: ZeroKnowledgeProof
        App->>ZT: verify_proof(proof, challenge)
        Note right of ZT: Verify using<br/>PUBLIC key only
        ZT-->>App: is_valid: bool
    end

    rect rgb(200, 255, 200)
        Note over App,Crypto: Continuous Verification
        loop Every verification_interval
            App->>ZT: verify_continuously()
            alt Status: Verified
                ZT-->>App: Continue operations
            else Status: Pending
                App->>ZT: reauthenticate()
            else Status: Expired
                App->>ZT: New session required
            end
        end
    end

    App->>Crypto: Perform crypto operation
    Crypto-->>App: Result
```

### Proof Complexity Levels

```mermaid
graph TD
    subgraph "Low - Basic Challenge"
        L1[Challenge<br/>32 bytes] --> L2[Ed25519 Sign]
        L2 --> L3[Signature<br/>64 bytes]
    end

    subgraph "Medium - Replay Protection"
        M1[Challenge<br/>64 bytes] --> M2[Concatenate]
        M1T[Timestamp<br/>8 bytes] --> M2
        M2 --> M3[Ed25519 Sign]
        M3 --> M4[Signature + Timestamp<br/>72 bytes]
    end

    subgraph "High - Key Binding"
        H1[Challenge<br/>128 bytes] --> H2[Concatenate]
        H1T[Timestamp<br/>8 bytes] --> H2
        H1K[Public Key] --> H2
        H2 --> H3[Ed25519 Sign]
        H3 --> H4[Signature + Timestamp<br/>72 bytes]
    end

    classDef input fill:#3498db,stroke:#333,color:#fff
    classDef process fill:#9b59b6,stroke:#333,color:#fff
    classDef output fill:#27ae60,stroke:#333,color:#fff

    class L1,M1,M1T,H1,H1T,H1K input
    class L2,M2,M3,H2,H3 process
    class L3,M4,H4 output
```

### Zero-Trust Configuration

```rust
use arc_core::config::{ZeroTrustConfig, ProofComplexity};
use arc_core::zero_trust::ZeroTrustAuth;

// High-security configuration using builder pattern
let config = ZeroTrustConfig::new()
    .with_timeout(30_000)                // 30s challenge timeout
    .with_complexity(ProofComplexity::High)
    .with_continuous_verification(true)
    .with_verification_interval(60_000); // Re-verify every 60s

let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
```

**Recommendations:**
- Use `ProofComplexity::High` for sensitive operations
- Enable continuous verification for long-running sessions
- Set appropriate challenge timeouts (15-60 seconds)
- Log authentication failures for security monitoring

## Secure Usage Patterns

### Key Generation

```rust
use arc_core::convenience::*;

// Generate post-quantum keypairs
let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
let (vk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

// Generate classical keypairs
let (pk, sk) = generate_keypair()?;  // Ed25519
```

**NEVER:**
- Generate keys from predictable seeds
- Reuse nonces across encryptions
- Store private keys in plaintext
- Log or expose key material

### Encryption

```mermaid
flowchart LR
    subgraph "Secure"
        S1[encrypt with<br/>hybrid scheme]
        S2[Auto-generated<br/>nonces]
        S3[Authenticated<br/>encryption]
    end

    subgraph "Insecure"
        I1[ECB mode]
        I2[Reused nonces]
        I3[Unauthenticated]
    end

    S1 --> OK[Safe]
    S2 --> OK
    S3 --> OK

    I1 --> BAD[Vulnerable]
    I2 --> BAD
    I3 --> BAD

    classDef secure fill:#27ae60,stroke:#333,color:#fff
    classDef insecure fill:#e74c3c,stroke:#333,color:#fff

    class S1,S2,S3,OK secure
    class I1,I2,I3,BAD insecure
```

```rust
use arc_core::convenience::*;

// Recommended: Hybrid encryption (default)
let encrypted = encrypt(data, &key)?;

// For long-term storage: ML-KEM-1024
let encrypted = encrypt_for_use_case(data, UseCase::FileStorage, &key)?;

// Hybrid public-key encryption
let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
let result = encrypt_hybrid(data, &pk)?;
let decrypted = decrypt_hybrid(&result.ciphertext, &result.encapsulated_key, &sk)?;
```

**Security constraints:**
- AES-GCM: Maximum 2^32 messages per key with random nonces
- ChaCha20-Poly1305: Maximum 2^64 messages per key
- Always verify decryption succeeded before using plaintext

### Signatures

```rust
use arc_core::convenience::*;
use arc_core::zero_trust::ZeroTrustAuth;

// Simple signing
let signed = sign(message)?;
let is_valid = verify(&signed)?;

// Post-quantum signatures
let signature = sign_pq_ml_dsa(message, &sk, MlDsaParameterSet::MLDSA65)?;
let is_valid = verify_pq_ml_dsa(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;

// Zero-trust authenticated signing
let auth = ZeroTrustAuth::new(public_key, private_key)?;
let challenge = auth.generate_challenge()?;
let proof = auth.generate_proof(&challenge.data)?;
if auth.verify_proof(&proof, &challenge.data)? {
    // Proceed with signing
}
```

**NEVER:**
- Ignore verification failures
- Sign attacker-controlled data without validation
- Use the same key for signing and encryption

### Memory Safety

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use arc_core::types::ZeroizedBytes;

// Automatic zeroization with ZeroizedBytes
let private_key = ZeroizedBytes::new(secret_bytes);
// Automatically zeroized when dropped

// Custom type with zeroization
#[derive(ZeroizeOnDrop)]
struct SecretData {
    key: [u8; 32],
    nonce: [u8; 12],
}

// Manual zeroization
let mut secret = [0u8; 32];
// ... use secret ...
secret.zeroize();
```

## Algorithm Selection

### Security Levels

```mermaid
graph LR
    subgraph "Security Levels"
        S[Standard<br/>128-bit]
        H[High<br/>192-bit]
        M[Maximum<br/>256-bit]
        Q[Quantum<br/>256-bit PQ-only]
    end

    subgraph "Use Cases"
        GEN[General Purpose]
        ENT[Enterprise]
        REG[Regulated]
        GOV[Government]
    end

    S --> GEN
    H --> ENT
    M --> REG
    Q --> GOV

    classDef level fill:#3498db,stroke:#333,color:#fff
    classDef use fill:#9b59b6,stroke:#333,color:#fff

    class S,H,M,Q level
    class GEN,ENT,REG,GOV use
```

| Level | Algorithms | Mode | NIST Level | Use Case |
|-------|-----------|------|------------|----------|
| `Standard` | ML-KEM-512, ML-DSA-44 | Hybrid | 1 | General purpose, IoT |
| `High` (default) | ML-KEM-768, ML-DSA-65 | Hybrid | 3 | Enterprise, sensitive data |
| `Maximum` | ML-KEM-1024, ML-DSA-87 | Hybrid | 5 | Financial, regulated |
| `Quantum` | ML-KEM-1024, ML-DSA-87 | PQ-only | 5 | Government (CNSA 2.0) |

### Recommendations

| Use Case | Recommended | Why |
|----------|-------------|-----|
| General purpose | ML-KEM-768, ML-DSA-65 | Balance of security and performance |
| Long-term secrets | ML-KEM-1024, ML-DSA-87 | Maximum post-quantum security |
| Embedded/constrained | ML-KEM-512, SLH-DSA-SHAKE-128f | Smaller keys/signatures |
| Regulatory compliance | Check specific requirements | May mandate specific algorithms |

### Hybrid Mode

```rust
use arc_core::selector::*;

// Default: Hybrid (recommended)
DEFAULT_ENCRYPTION_SCHEME  // hybrid-ml-kem-768-aes-256-gcm
DEFAULT_SIGNATURE_SCHEME   // hybrid-ml-dsa-65-ed25519

// Why hybrid?
// 1. If PQC has weaknesses → classical backup
// 2. If classical broken → PQC protection
// 3. Recommended during transition (2024-2035+)
```

## Error Handling

### Secure Error Handling

```rust
use arc_core::convenience::*;
use arc_core::error::CoreError;

fn process_data(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
    // Use ? to propagate errors - never ignore them
    let encrypted = EncryptedData::deserialize(ciphertext)?;
    let plaintext = decrypt(&encrypted, key)?;

    // Validate before use
    if plaintext.is_empty() {
        return Err(CoreError::InvalidInput("Empty plaintext".to_string()));
    }

    Ok(plaintext)
}
```

### What NOT to Do

```rust
// DANGEROUS: Ignoring errors
let plaintext = decrypt(&encrypted, &key).unwrap(); // May panic

// DANGEROUS: Logging sensitive data
tracing::debug!("Decrypted: {:?}", plaintext); // Leaks secrets

// DANGEROUS: Non-constant-time comparison
if signature == expected { ... } // Timing leak

// SECURE alternative:
use subtle::ConstantTimeEq;
if signature.ct_eq(&expected).into() { ... }
```

## Deployment Considerations

### Environment Variables

```bash
# DANGEROUS - Never store secrets in env vars
export SECRET_KEY="..."

# SECURE - Use secrets manager or encrypted config
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
```

### Logging Configuration

```rust
use tracing_subscriber::EnvFilter;

// Disable debug logging for crypto modules in production
let filter = EnvFilter::new("warn")
    .add_directive("arc_core=warn".parse().unwrap())
    .add_directive("arc_primitives=warn".parse().unwrap());

tracing_subscriber::fmt()
    .with_env_filter(filter)
    .init();
```

### Resource Limits

```rust
use std::sync::Semaphore;

// Limit concurrent crypto operations
static CRYPTO_SEMAPHORE: Semaphore = Semaphore::new(100);

async fn encrypt_with_limit(data: &[u8], key: &[u8; 32]) -> Result<EncryptedData, CoreError> {
    let _permit = CRYPTO_SEMAPHORE.acquire().await?;
    encrypt(data, key)
}
```

## Compliance Considerations

### FIPS 140-3

LatticeArc implements FIPS 203-206 algorithms but is **not** FIPS 140-3 validated.

For FIPS 140-3 compliance:
1. Use algorithms as specified (no modifications)
2. Implement power-up self-tests (see `arc-validation`)
3. Use approved random number generators
4. Consider validated modules for certification

### Common Criteria

For Common Criteria evaluations:
1. Document all cryptographic boundaries
2. Implement required self-tests
3. Maintain audit logging for cryptographic operations

## Incident Response

### Key Compromise

```mermaid
flowchart TD
    DETECT[Detect Compromise] --> STOP[Stop Using Key]
    STOP --> GENERATE[Generate New Keys]
    GENERATE --> REVOKE[Revoke Old Keys]
    REVOKE --> NOTIFY[Notify Affected Parties]
    NOTIFY --> ROTATE[Rotate All Systems]
    ROTATE --> AUDIT[Audit Logs]

    classDef action fill:#3498db,stroke:#333,color:#fff
    class DETECT,STOP,GENERATE,REVOKE,NOTIFY,ROTATE,AUDIT action
```

1. **Immediately**: Stop using the compromised key
2. **Generate**: Create new key pairs
3. **Revoke**: If using certificates, revoke the old certificate
4. **Notify**: Inform affected parties
5. **Rotate**: Update all systems using the old key
6. **Audit**: Review logs for unauthorized usage

### Vulnerability Reports

Report security vulnerabilities according to [SECURITY.md](../SECURITY.md):
- Do NOT open public issues for security vulnerabilities
- Expected response within 24 hours

## Security Checklist

Before deploying to production:

- [ ] Using recommended algorithm variants (Level 3+)
- [ ] Hybrid mode enabled for long-term security
- [ ] Zero-trust authentication configured
- [ ] Error handling verified (no unwrap/expect)
- [ ] Secrets not logged or exposed
- [ ] Memory zeroization verified
- [ ] Key rotation mechanism in place
- [ ] Incident response plan documented
- [ ] Dependencies audited (`cargo audit`)
- [ ] Fuzzing performed on custom integrations
- [ ] Continuous verification enabled for sessions

## Further Reading

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 206: FN-DSA](https://csrc.nist.gov/pubs/fips/206/final)
