# NIST Post-Quantum Cryptography Compliance

LatticeArc's compliance with NIST FIPS 203-206 post-quantum cryptography standards.

## Standards Overview

```mermaid
graph LR
    subgraph "Key Encapsulation"
        KEM[FIPS 203<br/>ML-KEM]
    end

    subgraph "Digital Signatures"
        DSA[FIPS 204<br/>ML-DSA]
        SLH[FIPS 205<br/>SLH-DSA]
        FN[FIPS 206<br/>FN-DSA]
    end

    subgraph "Implementation"
        AWSLC[aws-lc-rs<br/>FIPS Validated]
        F204[fips204 crate]
        F205[fips205 crate]
        FNDSA[fn-dsa crate]
    end

    KEM --> AWSLC
    DSA --> F204
    SLH --> F205
    FN --> FNDSA

    classDef standard fill:#3498db,stroke:#333,color:#fff
    classDef fips fill:#27ae60,stroke:#333,color:#fff
    classDef impl fill:#f5a623,stroke:#333,color:#fff

    class KEM,DSA,SLH,FN standard
    class AWSLC fips
    class F204,F205,FNDSA impl
```

| Standard | Algorithm | Implementation | FIPS Validated | Status |
|----------|-----------|----------------|----------------|--------|
| FIPS 203 | ML-KEM | `aws-lc-rs` | Yes (Cert #4631, #4759, #4816) | Complete |
| FIPS 204 | ML-DSA | `fips204` crate | No (awaiting aws-lc-rs) | Complete* |
| FIPS 205 | SLH-DSA | `fips205` crate | Audited | Complete |
| FIPS 206 | FN-DSA | `fn-dsa` crate | Partial | Complete |

*ML-DSA uses the `fips204` pure Rust crate. For FIPS 140-3 certification, migration to `aws-lc-rs` is required once the ML-DSA Rust API is exposed (tracking: aws/aws-lc-rs#773, our PR: aws/aws-lc-rs#1029 under review).

## FIPS 203: ML-KEM (Module-Lattice-Based Key Encapsulation)

### Algorithm Variants

| Parameter Set | Security Level | Public Key | Ciphertext | Shared Secret |
|--------------|----------------|------------|------------|---------------|
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | NIST Level 3 | 1184 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | NIST Level 5 | 1568 bytes | 1568 bytes | 32 bytes |

### Usage with LatticeArc API

```rust
use arc_core::convenience::*;
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

// Key generation (FIPS 203 Section 7.1)
let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

// Hybrid encryption using ML-KEM + AES-GCM
let result = encrypt_hybrid(plaintext, &pk)?;
// result.ciphertext - AES-GCM encrypted data
// result.encapsulated_key - ML-KEM ciphertext

// Decryption
let plaintext = decrypt_hybrid(
    &result.ciphertext,
    &result.encapsulated_key,
    &sk
)?;

// Direct PQ encryption
let ciphertext = encrypt_pq_ml_kem(data, &pk, MlKemSecurityLevel::MlKem768)?;
let plaintext = decrypt_pq_ml_kem(&ciphertext, &sk, MlKemSecurityLevel::MlKem768)?;
```

### CAVP Validation

- Test vectors from [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- All parameter sets tested (512, 768, 1024)
- Positive and negative test cases included

## FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature)

### Algorithm Variants

| Parameter Set | Security Level | Public Key | Secret Key | Signature |
|--------------|----------------|------------|------------|-----------|
| ML-DSA-44 | NIST Level 2 | 1312 bytes | 2560 bytes | 2420 bytes |
| ML-DSA-65 | NIST Level 3 | 1952 bytes | 4032 bytes | 3309 bytes |
| ML-DSA-87 | NIST Level 5 | 2592 bytes | 4896 bytes | 4627 bytes |

### Usage with LatticeArc API

```rust
use arc_core::convenience::*;
use arc_primitives::sig::ml_dsa::MlDsaParameterSet;

// Key generation (FIPS 204 Section 6.1)
let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

// Sign (FIPS 204 Section 6.2)
let signature = sign_pq_ml_dsa(message, &sk, MlDsaParameterSet::MLDSA65)?;

// Verify (FIPS 204 Section 6.3)
let is_valid = verify_pq_ml_dsa(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
```

### CAVP Validation

- Deterministic and randomized signing tested
- All parameter sets validated
- Edge cases for message lengths covered

## FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature)

### Algorithm Variants

| Parameter Set | Security | Signature Size | Performance |
|--------------|----------|----------------|-------------|
| SLH-DSA-SHAKE-128f | Level 1 | 17,088 bytes | Fast |
| SLH-DSA-SHAKE-128s | Level 1 | 7,856 bytes | Small |
| SLH-DSA-SHAKE-192f | Level 3 | 35,664 bytes | Fast |
| SLH-DSA-SHAKE-192s | Level 3 | 16,224 bytes | Small |
| SLH-DSA-SHAKE-256f | Level 5 | 49,856 bytes | Fast |
| SLH-DSA-SHAKE-256s | Level 5 | 29,792 bytes | Small |

### Usage with LatticeArc API

```rust
use arc_core::convenience::*;
use arc_primitives::sig::slh_dsa::SecurityLevel;

// Key generation (FIPS 205 Section 9.1)
let (pk, sk) = generate_slh_dsa_keypair(SecurityLevel::Shake128s)?;

// Sign (FIPS 205 Section 9.2)
let signature = sign_pq_slh_dsa(message, &sk, SecurityLevel::Shake128s)?;

// Verify (FIPS 205 Section 9.3)
let is_valid = verify_pq_slh_dsa(message, &signature, &pk, SecurityLevel::Shake128s)?;
```

## FIPS 206: FN-DSA (FFT over NTRU Lattice Digital Signature)

### Algorithm Variants

| Parameter Set | Security Level | Public Key | Signature |
|--------------|----------------|------------|-----------|
| FN-DSA-512 | NIST Level 1 | 897 bytes | ~666 bytes |
| FN-DSA-1024 | NIST Level 5 | 1793 bytes | ~1280 bytes |

### Usage with LatticeArc API

```rust
use arc_core::convenience::*;

// Key generation (FIPS 206 Section 6.1)
let (pk, sk) = generate_fn_dsa_keypair()?;

// Sign (FIPS 206 Section 6.2)
let signature = sign_pq_fn_dsa(message, &sk)?;

// Verify (FIPS 206 Section 6.3)
let is_valid = verify_pq_fn_dsa(message, &signature, &pk)?;
```

## Security Levels

```mermaid
graph TD
    subgraph "NIST Security Levels"
        L1[Level 1<br/>AES-128]
        L2[Level 2<br/>SHA-256]
        L3[Level 3<br/>AES-192]
        L4[Level 4<br/>SHA-384]
        L5[Level 5<br/>AES-256]
    end

    subgraph "LatticeArc Mapping"
        LOW[SecurityLevel::Low]
        MED[SecurityLevel::Medium]
        HIGH[SecurityLevel::High]
        MAX[SecurityLevel::Maximum]
    end

    L1 --> LOW
    L2 --> LOW
    L3 --> MED
    L3 --> HIGH
    L4 --> HIGH
    L5 --> MAX

    classDef nist fill:#3498db,stroke:#333,color:#fff
    classDef arc fill:#27ae60,stroke:#333,color:#fff

    class L1,L2,L3,L4,L5 nist
    class LOW,MED,HIGH,MAX arc
```

| Level | Description | Classical Equivalent |
|-------|-------------|---------------------|
| 1 | At least as hard as AES-128 key recovery | AES-128 |
| 2 | At least as hard as SHA-256 collision finding | SHA-256 |
| 3 | At least as hard as AES-192 key recovery | AES-192 |
| 4 | At least as hard as SHA-384 collision finding | SHA-384 |
| 5 | At least as hard as AES-256 key recovery | AES-256 |

### Recommendations

| Use Case | Recommended Level | Algorithms |
|----------|-------------------|------------|
| General purpose | 3 | ML-KEM-768, ML-DSA-65 |
| Maximum security | 5 | ML-KEM-1024, ML-DSA-87 |
| Constrained environments | 1 | ML-KEM-512, SLH-DSA-SHAKE-128f |
| Long-term protection | 5 | ML-KEM-1024, ML-DSA-87 |

## Validation Testing

### CAVP Test Vectors

```bash
# Run CAVP validation suite
cargo test --package arc-validation --all-features
```

Test categories:
- **AFT** (Algorithm Functional Test): Basic correctness
- **VAL** (Validation): Decapsulation/verification with known values
- **MCT** (Monte Carlo Test): Extended iteration tests

### Test Vector Sources

| Algorithm | Source |
|-----------|--------|
| ML-KEM | [NIST ML-KEM](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022) |
| ML-DSA | [NIST ML-DSA](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022) |
| SLH-DSA | [NIST SLH-DSA](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022) |
| FN-DSA | [NIST FN-DSA](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024) |

## FIPS 140-3 Considerations

LatticeArc implements FIPS 203-206 algorithms but is **NOT** FIPS 140-3 validated.

For FIPS 140-3 compliance:

1. **Use validated modules**: Consider validated hardware or software modules
2. **Implement self-tests**: Power-up and conditional self-tests
3. **Approved RNG**: Use DRBG per SP 800-90A
4. **Key management**: Follow SP 800-57 guidelines
5. **Audit trail**: Log cryptographic operations

### Self-Tests

```rust
use arc_validation::fips_validation::*;

// Run FIPS algorithm validation
let results = run_fips_validation()?;

// Check specific algorithms
assert!(results.ml_kem_valid);
assert!(results.ml_dsa_valid);
assert!(results.slh_dsa_valid);
```

## Hybrid Mode (Recommended)

```mermaid
flowchart LR
    subgraph "Hybrid Encryption"
        PQ[ML-KEM-768]
        CL[X25519]
        KDF[HKDF]
        AES[AES-256-GCM]
    end

    PQ --> KDF
    CL --> KDF
    KDF --> AES

    classDef pq fill:#9b59b6,stroke:#333,color:#fff
    classDef classical fill:#3498db,stroke:#333,color:#fff
    classDef derive fill:#f5a623,stroke:#333,color:#fff
    classDef aead fill:#27ae60,stroke:#333,color:#fff

    class PQ pq
    class CL classical
    class KDF derive
    class AES aead
```

During the transition period, use hybrid encryption:

```rust
use arc_core::convenience::*;
use arc_core::selector::*;

// Default schemes are hybrid
DEFAULT_ENCRYPTION_SCHEME  // "hybrid-ml-kem-768-aes-256-gcm"
DEFAULT_SIGNATURE_SCHEME   // "hybrid-ml-dsa-65-ed25519"

// Hybrid encryption
let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
let result = encrypt_hybrid(plaintext, &pk)?;
let decrypted = decrypt_hybrid(&result.ciphertext, &result.encapsulated_key, &sk)?;
```

### Timeline Recommendations

| Year | Recommendation |
|------|----------------|
| 2024-2026 | Hybrid mode mandatory for new systems |
| 2027-2030 | Begin migrating existing systems |
| 2030+ | PQC-only for most applications |

## Interoperability

### Wire Formats

LatticeArc uses standard encodings per FIPS specifications:

- **Keys**: Raw byte encoding
- **Ciphertexts**: Raw byte encoding
- **Signatures**: Raw byte encoding

### X.509 Certificate OIDs

| Algorithm | OID |
|-----------|-----|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 |
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 |

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 206: FN-DSA](https://csrc.nist.gov/pubs/fips/206/final)
- [SP 800-208: Hash-Based Signatures](https://csrc.nist.gov/pubs/sp/800/208/final)
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
