# LatticeArc Architecture

This document describes the architecture of LatticeArc, a post-quantum cryptography library with intelligent scheme selection, zero-trust authentication, and hardware acceleration.

## Design Principles

1. **Security First**: Defense-in-depth with hybrid PQ+classical, constant-time operations, memory safety
2. **Intelligent Defaults**: Auto-selection based on data, use case, and hardware
3. **Zero Trust**: Challenge-response authentication with ZKP at every operation
4. **Modularity**: Use only what you need, from high-level to low-level APIs
5. **FIPS Compliance**: NIST FIPS 203-206 compliant implementations

## Architecture Overview

```mermaid
graph TB
    subgraph "User Application"
        APP[Application Code]
    end

    subgraph "LatticeArc Public API"
        MAIN[latticearc<br/>Main Facade]
    end

    subgraph "High-Level APIs"
        CORE[arc-core<br/>Unified API]
        HYBRID[arc-hybrid<br/>Hybrid Crypto]
        TLS[arc-tls<br/>PQ TLS 1.3]
    end

    subgraph "Core Cryptography"
        PRIM[arc-primitives<br/>Crypto Primitives]
        ZKP[arc-zkp<br/>Zero-Knowledge]
    end

    subgraph "Foundation"
        PRELUDE[arc-prelude<br/>Types & Errors]
    end

    subgraph "Testing & Validation"
        VAL[arc-validation<br/>CAVP Tests]
        PERF[arc-perf<br/>Benchmarks]
        FUZZ[arc-fuzz<br/>Fuzzing]
    end

    APP --> MAIN
    MAIN --> CORE
    MAIN --> HYBRID
    MAIN --> TLS
    CORE --> PRIM
    CORE --> PRELUDE
    HYBRID --> PRIM
    HYBRID --> PRELUDE
    TLS --> PRIM
    TLS --> PRELUDE
    ZKP --> PRIM
    PRIM --> PRELUDE
    VAL --> PRIM
    PERF --> PRIM

    classDef facade fill:#4a90d9,stroke:#333,color:#fff
    classDef highlevel fill:#50c878,stroke:#333,color:#fff
    classDef core fill:#f5a623,stroke:#333,color:#fff
    classDef foundation fill:#9b59b6,stroke:#333,color:#fff
    classDef testing fill:#95a5a6,stroke:#333,color:#fff

    class MAIN facade
    class CORE,HYBRID,TLS highlevel
    class PRIM,ZKP core
    class PRELUDE foundation
    class VAL,PERF,FUZZ testing
```

## API Abstraction Levels

LatticeArc provides three abstraction levels:

```mermaid
graph LR
    subgraph "Level 1: Simple"
        L1[encrypt/decrypt<br/>sign/verify]
    end

    subgraph "Level 2: Use Case"
        L2[CryptoPolicyEngine<br/>recommend_scheme]
    end

    subgraph "Level 3: Context-Aware"
        L3[CryptoPolicyEngine<br/>adaptive_selection]
    end

    subgraph "Level 4: Primitives"
        L4[ML-KEM/ML-DSA<br/>AES-GCM/Ed25519]
    end

    L1 -->|"uses"| L2
    L2 -->|"uses"| L3
    L3 -->|"uses"| L4

    classDef simple fill:#4a90d9,stroke:#333,color:#fff
    classDef usecase fill:#50c878,stroke:#333,color:#fff
    classDef context fill:#f5a623,stroke:#333,color:#fff
    classDef primitive fill:#9b59b6,stroke:#333,color:#fff

    class L1 simple
    class L2 usecase
    class L3 context
    class L4 primitive
```

## Scheme Selection Flow

The CryptoPolicyEngine analyzes data and configuration to select optimal schemes:

```mermaid
flowchart TD
    START([Start]) --> INPUT[/"Input: data, config, use_case"/]
    INPUT --> USECASE{Use case<br/>specified?}

    USECASE -->|Yes| RECOMMEND[recommend_scheme<br/>for use case]
    USECASE -->|No| ANALYZE[analyze_data_characteristics]

    ANALYZE --> ENTROPY[Calculate entropy]
    ANALYZE --> PATTERN[Detect pattern type]
    ANALYZE --> SIZE[Measure size]

    ENTROPY --> CONTEXT{Security Level?}
    PATTERN --> CONTEXT
    SIZE --> CONTEXT

    CONTEXT -->|Maximum| MAX[hybrid-ml-kem-1024]
    CONTEXT -->|High| HIGH[hybrid-ml-kem-768]
    CONTEXT -->|Medium + Speed| MEDSPEED{Size < 4KB?}
    CONTEXT -->|Low + Speed| LOWSPEED[aes-256-gcm]
    CONTEXT -->|Default| DEFAULT[hybrid-ml-kem-768]

    MEDSPEED -->|Yes| CLASSICAL[aes-256-gcm]
    MEDSPEED -->|No| DEFAULT

    RECOMMEND --> OUTPUT[/"Selected Scheme"/]
    MAX --> OUTPUT
    HIGH --> OUTPUT
    CLASSICAL --> OUTPUT
    LOWSPEED --> OUTPUT
    DEFAULT --> OUTPUT

    OUTPUT --> END([End])

    classDef decision fill:#f5a623,stroke:#333,color:#000
    classDef process fill:#4a90d9,stroke:#333,color:#fff
    classDef terminal fill:#50c878,stroke:#333,color:#fff

    class USECASE,CONTEXT,MEDSPEED decision
    class ANALYZE,ENTROPY,PATTERN,SIZE,RECOMMEND,MAX,HIGH,CLASSICAL,LOWSPEED,DEFAULT process
    class START,END,INPUT,OUTPUT terminal
```

## Zero-Trust Authentication Flow

Challenge-response authentication with zero-knowledge proofs:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server (ZeroTrustAuth)
    participant V as Verifier

    Note over C,V: Session Initialization
    C->>S: Request authentication
    S->>S: generate_challenge()
    S-->>C: Challenge (data, complexity, timeout)

    Note over C,V: Proof Generation
    C->>C: generate_proof(challenge)
    Note right of C: Signs challenge with<br/>private key (ZKP)
    C->>S: ZeroKnowledgeProof

    Note over C,V: Verification
    S->>V: verify_proof(proof, challenge)
    Note right of V: Uses PUBLIC key only<br/>(true ZK verification)
    V-->>S: is_valid: bool

    alt Proof Valid
        S->>S: Update last_verification
        S-->>C: Session established

        Note over C,V: Continuous Verification
        loop Every verification_interval_ms
            S->>S: verify_continuously()
            alt Status == Pending
                S->>C: Reauthentication required
                C->>S: New proof
            end
        end
    else Proof Invalid
        S-->>C: Authentication failed
    end
```

## Proof Complexity Levels

```mermaid
graph TD
    subgraph "Low Complexity (32 bytes)"
        L_CH[Challenge] --> L_SIG[sign]
        L_SIG --> L_OUT[Signature]
    end

    subgraph "Medium Complexity (64 bytes)"
        M_CH[Challenge] --> M_CAT[concatenate]
        M_TS[Timestamp] --> M_CAT
        M_CAT --> M_SIG[sign]
        M_SIG --> M_OUT[Signature + Timestamp]
    end

    subgraph "High Complexity (128 bytes)"
        H_CH[Challenge] --> H_CAT[concatenate]
        H_TS[Timestamp] --> H_CAT
        H_PK[Public Key] --> H_CAT
        H_CAT --> H_SIG[sign]
        H_SIG --> H_OUT[Signature + Timestamp]
    end

    classDef input fill:#4a90d9,stroke:#333,color:#fff
    classDef process fill:#50c878,stroke:#333,color:#fff
    classDef output fill:#f5a623,stroke:#333,color:#fff

    class L_CH,M_CH,M_TS,H_CH,H_TS,H_PK input
    class L_SIG,M_CAT,M_SIG,H_CAT,H_SIG process
    class L_OUT,M_OUT,H_OUT output
```

## Hardware Detection and Routing

```mermaid
flowchart TD
    subgraph "HardwareRouter"
        DETECT[detect_hardware]
        CACHE[(Detection Cache)]
        SELECT[select_best_accelerator]
        ROUTE[route_to_best_hardware]
    end

    subgraph "Accelerators"
        CPU[CpuAccelerator<br/>SIMD + AES-NI]
        GPU[GpuAccelerator<br/>CUDA/OpenCL]
        FPGA[FpgaAccelerator<br/>Xilinx/Altera]
        TPM[TpmAccelerator<br/>Hardware Keys]
        SGX[SgxAccelerator<br/>Secure Enclave]
    end

    subgraph "Capabilities"
        CAPS[HardwareCapabilities]
        SIMD[simd_support]
        AESNI[aes_ni]
        THREADS[thread_count]
        MEM[memory]
    end

    DETECT --> CACHE
    CACHE --> SELECT
    SELECT --> CPU
    SELECT --> GPU
    SELECT --> FPGA
    SELECT --> TPM
    SELECT --> SGX

    CPU --> ROUTE
    GPU --> ROUTE
    FPGA --> ROUTE
    TPM --> ROUTE
    SGX --> ROUTE

    CAPS --> SIMD
    CAPS --> AESNI
    CAPS --> THREADS
    CAPS --> MEM

    classDef router fill:#4a90d9,stroke:#333,color:#fff
    classDef accel fill:#50c878,stroke:#333,color:#fff
    classDef caps fill:#f5a623,stroke:#333,color:#fff

    class DETECT,CACHE,SELECT,ROUTE router
    class CPU,GPU,FPGA,TPM,SGX accel
    class CAPS,SIMD,AESNI,THREADS,MEM caps
```

## Encryption Data Flow

```mermaid
flowchart LR
    subgraph "Input"
        DATA[Plaintext]
        KEY[Key]
        CFG[Config]
    end

    subgraph "Selection"
        SEL[CryptoPolicyEngine]
        SCHEME{Scheme?}
    end

    subgraph "Hybrid Path"
        KEM[ML-KEM<br/>Encapsulate]
        AEAD_H[AES-256-GCM<br/>Encrypt]
    end

    subgraph "Classical Path"
        AEAD_C[AES-256-GCM<br/>Encrypt]
    end

    subgraph "Output"
        CT[EncryptedData]
        META[Metadata<br/>nonce, tag, scheme]
    end

    DATA --> SEL
    KEY --> SEL
    CFG --> SEL
    SEL --> SCHEME

    SCHEME -->|Hybrid| KEM
    KEM --> AEAD_H
    AEAD_H --> CT

    SCHEME -->|Classical| AEAD_C
    AEAD_C --> CT

    CT --> META

    classDef input fill:#4a90d9,stroke:#333,color:#fff
    classDef select fill:#f5a623,stroke:#333,color:#fff
    classDef crypto fill:#50c878,stroke:#333,color:#fff
    classDef output fill:#9b59b6,stroke:#333,color:#fff

    class DATA,KEY,CFG input
    class SEL,SCHEME select
    class KEM,AEAD_H,AEAD_C crypto
    class CT,META output
```

## Crate Descriptions

### `latticearc` (Main Facade)

Re-exports all public APIs from the workspace.

```rust
use latticearc::prelude::*;
// Access to all crates via single import
```

### `arc-core`

The Unified API layer with intelligent features:

| Module | Purpose |
|--------|---------|
| `convenience` | Simple encrypt/decrypt/sign/verify functions |
| `selector` | CryptoPolicyEngine |
| `zero_trust` | ZeroTrustAuth, Challenge, ZeroKnowledgeProof |
| `hardware` | HardwareRouter, accelerator detection |
| `config` | CoreConfig, ZeroTrustConfig, SecurityLevel |
| `types` | UseCase, PerformancePreference, CryptoContext |

### `arc-primitives`

Low-level cryptographic primitives:

| Module | Algorithms |
|--------|-----------|
| `kem/` | ML-KEM-512/768/1024 (FIPS 203) |
| `sig/` | ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205), FN-DSA (FIPS 206) |
| `aead/` | AES-256-GCM, ChaCha20-Poly1305 |
| `kdf/` | HKDF-SHA256, PBKDF2, SP800-108 |
| `hash/` | SHA-2, SHA-3 |
| `mac/` | HMAC-SHA256, CMAC |
| `ec/` | Ed25519, X25519, secp256k1, BLS12-381 |

### `arc-hybrid`

Hybrid cryptography combining PQ + classical:

| Component | Combination |
|-----------|-------------|
| HybridKem | ML-KEM + X25519 |
| HybridSignature | ML-DSA + Ed25519 |
| HybridEncrypt | ML-KEM + AES-GCM |

### `arc-tls`

Post-quantum TLS 1.3 with rustls:

- PQ key exchange (ML-KEM)
- Hybrid mode support
- Session resumption
- Connection monitoring

### `arc-prelude`

Common types and error handling:

- `CryptoError` hierarchy
- Common traits
- Memory safety utilities

### `arc-validation`

CAVP/FIPS compliance testing:

- NIST test vectors
- Self-test infrastructure
- Timing analysis

### `arc-zkp`

Zero-knowledge proof systems:

- Schnorr proofs
- Sigma protocols
- Pedersen commitments

## Key Design Decisions

### 1. No Unsafe Code

```rust
#![forbid(unsafe_code)]
```

All cryptographic operations use safe Rust, eliminating memory safety vulnerabilities.

### 2. No Panics in Library Code

```rust
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
```

All operations return `Result<T, E>`. Callers must handle errors explicitly.

### 3. Constant-Time by Default

```rust
use subtle::ConstantTimeEq;

// All secret comparisons use constant-time operations
fn verify_mac(computed: &[u8], received: &[u8]) -> bool {
    computed.ct_eq(received).into()
}
```

### 4. Automatic Zeroization

```rust
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
struct SecretKey {
    data: [u8; 32],
}
// Automatically zeroized when dropped
```

### 5. Hybrid by Default

All default schemes are hybrid (PQ + classical) for defense-in-depth:

```
DEFAULT_ENCRYPTION_SCHEME = "hybrid-ml-kem-768-aes-256-gcm"
DEFAULT_SIGNATURE_SCHEME  = "hybrid-ml-dsa-65-ed25519"
```

## Error Handling

```mermaid
graph TD
    subgraph "arc-prelude"
        CE[CryptoError]
    end

    subgraph "Error Variants"
        IK[InvalidKey]
        II[InvalidInput]
        KL[InvalidKeyLength]
        EF[EncryptionError]
        AF[AuthenticationFailed]
        ED[EntropyDepleted]
        CF[ConfigurationError]
    end

    subgraph "Crate Errors"
        CORE_E[CoreError]
        PRIM_E[PrimitivesError]
        TLS_E[TlsError]
    end

    CE --> IK
    CE --> II
    CE --> KL
    CE --> EF
    CE --> AF
    CE --> ED
    CE --> CF

    CORE_E -->|"From"| CE
    PRIM_E -->|"From"| CE
    TLS_E -->|"From"| CE

    classDef base fill:#4a90d9,stroke:#333,color:#fff
    classDef variant fill:#50c878,stroke:#333,color:#fff
    classDef crate fill:#f5a623,stroke:#333,color:#fff

    class CE base
    class IK,II,KL,EF,AF,ED,CF variant
    class CORE_E,PRIM_E,TLS_E crate
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library | Yes |
| `alloc` | Heap allocation | Yes |
| `serde` | Serialization | No |
| `zeroize` | Memory clearing | Yes |

## Testing Strategy

```mermaid
graph LR
    subgraph "Test Types"
        UNIT[Unit Tests]
        INT[Integration Tests]
        PROP[Property Tests]
        CAVP[CAVP Vectors]
        FUZZ[Fuzz Tests]
        BENCH[Benchmarks]
    end

    subgraph "Coverage"
        COV[80% Minimum]
    end

    subgraph "CI/CD"
        CI[GitHub Actions]
    end

    UNIT --> COV
    INT --> COV
    PROP --> COV
    CAVP --> CI
    FUZZ --> CI
    BENCH --> CI
    COV --> CI

    classDef test fill:#4a90d9,stroke:#333,color:#fff
    classDef metric fill:#50c878,stroke:#333,color:#fff
    classDef ci fill:#f5a623,stroke:#333,color:#fff

    class UNIT,INT,PROP,CAVP,FUZZ,BENCH test
    class COV metric
    class CI ci
```

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 206: FN-DSA](https://csrc.nist.gov/pubs/fips/206/final)
- [Rustls](https://github.com/rustls/rustls)
