# LatticeArc Architecture

This document describes the architecture of LatticeArc, a post-quantum cryptography library with intelligent scheme selection and zero-trust authentication framework.

## Open Source vs Enterprise

LatticeArc is available in two editions:

| Feature | Apache (Open Source) | Enterprise |
|---------|---------------------|------------|
| Core PQC primitives (ML-KEM, ML-DSA, SLH-DSA, FN-DSA) | ✅ | ✅ |
| Hybrid encryption (PQ + Classical) | ✅ | ✅ |
| Post-quantum TLS 1.3 | ✅ | ✅ |
| Scheme selection by use case | ✅ | ✅ |
| Zero-trust authentication framework | ✅ | ✅ |
| Hardware type definitions (traits only) | ✅ | ✅ |
| **Hardware detection & adaptive routing** | ❌ | ✅ |
| **ML-based attack detection** | ❌ | ✅ |
| **Self-healing security (auto key rotation)** | ❌ | ✅ |
| **Continuous trust verification** | ❌ | ✅ |
| **Per-operation policy enforcement** | ❌ | ✅ |
| **Runtime performance optimization** | ❌ | ✅ |
| **Graceful degradation system** | ❌ | ✅ |

> **Note**: This document covers the Apache (open source) edition. Enterprise features are marked with 🔒.

## Design Principles

1. **Security First**: Defense-in-depth with hybrid PQ+classical, constant-time operations, memory safety
2. **Hybrid by Default**: All encryption uses PQ + classical algorithms—no classical-only paths exposed
3. **Zero Trust Framework**: Challenge-response authentication with ZKP support
4. **Modularity**: Use only what you need, from high-level to low-level APIs
5. **FIPS Compliance**: NIST FIPS 203-206 compliant implementations with `ComplianceMode` (Default, Fips140_3, Cnsa2_0) and `fips` feature flag

## Architecture Overview

```mermaid
graph TB
    subgraph "User Application"
        APP[Application Code]
    end

    subgraph "LatticeArc Public API"
        MAIN["latticearc (facade)<br/>re-exports: LatticeArcError"]
    end

    subgraph "High-Level APIs (Layer 3)"
        CORE[unified_api<br/>Unified API + Zero-Trust]
        TLS[tls<br/>PQ TLS 1.3]
    end

    subgraph "Hybrid Constructions (Layer 2)"
        HYBRID[hybrid<br/>PQ + Classical]
    end

    subgraph "Algorithms (Layer 1)"
        PRIM[primitives<br/>ML-KEM, ML-DSA, AES-GCM, ...]
        ZKP[zkp<br/>Zero-Knowledge Proofs]
    end

    subgraph "Domain Types (Layer 0)"
        TYPES["types<br/>Pure Rust · Zero FFI · Kani-verified<br/>types, traits, config, selector,<br/>key_lifecycle, zero_trust,<br/>resource_limits, domains"]
    end

    subgraph "Foundation"
        PRELUDE[prelude<br/>Errors + Testing Infra]
    end

    subgraph "Testing & Validation (dev-deps only)"
        TESTS["latticearc-tests<br/>CAVP, KAT, integration<br/>(consolidated)"]
        PERF[perf<br/>Benchmarks]
        FUZZ[fuzz<br/>Fuzzing]
    end

    APP --> MAIN
    MAIN --> CORE
    MAIN --> HYBRID
    MAIN --> TLS
    MAIN --> ZKP
    MAIN --> PERF
    CORE --> TYPES
    CORE --> PRIM
    CORE --> HYBRID
    HYBRID --> PRIM
    TLS --> PRIM
    TLS --> PRELUDE
    ZKP --> PRIM
    PRIM --> TYPES
    PRIM --> PRELUDE
    TESTS --> MAIN
    TESTS --> CORE
    TESTS --> PRIM
    TESTS --> TYPES

    classDef facade fill:#4a90d9,stroke:#333,color:#fff
    classDef highlevel fill:#50c878,stroke:#333,color:#fff
    classDef core fill:#f5a623,stroke:#333,color:#fff
    classDef types fill:#e74c3c,stroke:#333,color:#fff
    classDef foundation fill:#9b59b6,stroke:#333,color:#fff
    classDef testing fill:#95a5a6,stroke:#333,color:#fff

    class MAIN facade
    class CORE,TLS highlevel
    class HYBRID highlevel
    class TYPES types
    class PRIM,ZKP core
    class PRELUDE foundation
    class PERF,TESTS,FUZZ testing
```

**Key architectural properties (v0.2.0):**
- **`latticearc::types`** is Layer 0: zero FFI dependencies, enabling Kani formal verification (29 proofs)
- All modules consolidated into single `latticearc` crate (was 8 separate crates)
- **`latticearc-tests`** consolidates all integration tests, CAVP validation, and NIST KAT vectors

## API Abstraction Levels

LatticeArc provides multiple abstraction levels:

```mermaid
graph LR
    subgraph "Level 1: Simple (Apache)"
        L1[encrypt/decrypt<br/>sign/verify]
    end

    subgraph "Level 2: Use Case (Apache)"
        L2[CryptoPolicyEngine<br/>recommend_scheme]
    end

    subgraph "Level 3: Primitives (Apache)"
        L3[ML-KEM/ML-DSA<br/>AES-GCM/Ed25519]
    end

    L1 -->|"uses"| L2
    L2 -->|"uses"| L3

    classDef simple fill:#4a90d9,stroke:#333,color:#fff
    classDef usecase fill:#50c878,stroke:#333,color:#fff
    classDef primitive fill:#9b59b6,stroke:#333,color:#fff

    class L1 simple
    class L2 usecase
    class L3 primitive
```

| Level | Apache | Enterprise |
|-------|--------|------------|
| **Level 1: Simple** | `encrypt()`, `decrypt()`, `sign()`, `verify()` | Same + session-aware variants |
| **Level 2: Use Case** | `recommend_scheme()` by security level/use case | Same |
| **Level 3: Primitives** | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, AES-GCM | Same |
| **Level 4: Adaptive** | ❌ | 🔒 Runtime hardware detection, performance tracking, adaptive routing |
| **Level 5: Self-Healing** | ❌ | 🔒 Attack detection, auto key rotation, graceful degradation |

## Scheme Selection Flow

The CryptoPolicyEngine analyzes configuration to select optimal hybrid schemes:

```mermaid
flowchart TD
    START([Start]) --> INPUT[/"Input: data, config, use_case"/]
    INPUT --> USECASE{Use case<br/>specified?}

    USECASE -->|Yes| RECOMMEND[recommend_scheme<br/>for use case]
    USECASE -->|No| SECLEVEL{Security Level?}

    SECLEVEL -->|Maximum/Quantum| MAX[hybrid-ml-kem-1024]
    SECLEVEL -->|High| HIGH[hybrid-ml-kem-768]
    SECLEVEL -->|Standard| STD[hybrid-ml-kem-512]
    SECLEVEL -->|Default| DEFAULT[hybrid-ml-kem-768]

    RECOMMEND --> OUTPUT[/"Selected Hybrid Scheme"/]
    MAX --> OUTPUT
    HIGH --> OUTPUT
    STD --> OUTPUT
    DEFAULT --> OUTPUT

    OUTPUT --> END([End])

    classDef decision fill:#f5a623,stroke:#333,color:#000
    classDef process fill:#4a90d9,stroke:#333,color:#fff
    classDef terminal fill:#50c878,stroke:#333,color:#fff

    class USECASE,SECLEVEL decision
    class RECOMMEND,MAX,HIGH,STD,DEFAULT process
    class START,END,INPUT,OUTPUT terminal
```

> **Note**: All schemes are hybrid (PQ + Classical). Classical-only encryption is not exposed in the public API.
>
> 🔒 **Enterprise Feature**: Adaptive scheme selection based on data characteristics, entropy analysis, and runtime performance metrics is available in LatticeArc Enterprise.

## Zero-Trust Authentication Flow

Challenge-response authentication framework with zero-knowledge proofs:

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
    else Proof Invalid
        S-->>C: Authentication failed
    end
```

> **Apache Edition**: Provides the zero-trust authentication framework including challenge generation, proof creation, and verification. Applications integrate these primitives into their authentication flows.

🔒 **Enterprise Feature: Continuous Trust Verification**

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant P as Policy Engine
    participant A as Audit Log

    Note over C,A: Per-Operation Enforcement (Enterprise)
    C->>S: Crypto operation request
    S->>P: Check operation policy
    P->>P: Evaluate trust score
    alt Trust Score Sufficient
        P-->>S: Approved
        S->>S: Execute operation
        S->>A: Log operation
        S-->>C: Result
    else Trust Degraded
        P-->>S: Re-auth required
        S-->>C: Challenge
        C->>S: New proof
        S->>P: Update trust score
    end
```

Enterprise edition provides:
- **Per-operation policy enforcement**: Every crypto operation checked against access policies
- **Continuous trust verification**: Dynamic trust scoring with automatic reauthentication
- **W3C DID integration**: Decentralized identity resolution (did:key, did:web)
- **Cryptographic audit trails**: Compliance-ready operation logging

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

## Hardware Acceleration

The Apache edition provides **trait definitions only** for hardware-aware operations (`HardwareAccelerator`, `HardwareAware`, `HardwareCapabilities`, `HardwareInfo`, `HardwareType`). These define the interface contract but contain no detection or routing logic.

The underlying cryptography library (`aws-lc-rs`) handles AES-NI, SHA extensions, and SIMD acceleration automatically at the C level — no application-level hardware detection is needed for optimal performance.

> **Apache Edition**: Hardware acceleration traits only. No detection, no routing. The crypto primitives (`aws-lc-rs`) already use AES-NI and SIMD internally when available.

🔒 **Enterprise Feature: Hardware Detection & Adaptive Routing**

The enterprise `arc-enterprise-perf` crate provides real hardware detection and adaptive routing:

```mermaid
flowchart TD
    subgraph "AdaptiveSelector (Enterprise)"
        DETECT[detect_hardware]
        PERF[PerformanceTracker]
        RISK[RiskLevel]
        SELECT[select_optimal_scheme]
    end

    subgraph "Detected Hardware"
        CPU[CPU<br/>AES-NI / AVX-512]
        GPU[GPU<br/>CUDA/OpenCL]
        HSM[HSM/TPM<br/>Hardware Keys]
    end

    DETECT --> CPU
    DETECT --> GPU
    DETECT --> HSM

    CPU --> SELECT
    GPU --> SELECT
    HSM --> SELECT
    PERF --> SELECT
    RISK --> SELECT

    classDef router fill:#4a90d9,stroke:#333,color:#fff
    classDef accel fill:#50c878,stroke:#333,color:#fff

    class DETECT,PERF,RISK,SELECT router
    class CPU,GPU,HSM accel
```

Enterprise edition dynamically selects cryptographic algorithms based on:
- Runtime hardware capability detection (CPU features, GPU, HSM/TPM)
- Continuous performance metrics with feedback loop
- Risk-level scaling (Normal → Critical, with security multipliers)
- Data size and characteristics

## Encryption Data Flow

All encryption in LatticeArc uses hybrid mode (PQ + Classical) for defense-in-depth:

```mermaid
flowchart LR
    subgraph "Input"
        DATA[Plaintext]
        KEY[Key]
        CFG[Config]
    end

    subgraph "Selection"
        SEL[CryptoPolicyEngine]
        LEVEL{Security<br/>Level?}
    end

    subgraph "Hybrid Encryption"
        KEM[ML-KEM<br/>Encapsulate]
        AEAD[AES-256-GCM<br/>Encrypt]
    end

    subgraph "Output"
        CT[EncryptedData]
        META[Metadata<br/>nonce, tag, scheme]
    end

    DATA --> SEL
    KEY --> SEL
    CFG --> SEL
    SEL --> LEVEL

    LEVEL -->|Maximum| KEM
    LEVEL -->|High| KEM
    LEVEL -->|Standard| KEM

    KEM --> AEAD
    AEAD --> CT
    CT --> META

    classDef input fill:#4a90d9,stroke:#333,color:#fff
    classDef select fill:#f5a623,stroke:#333,color:#fff
    classDef crypto fill:#50c878,stroke:#333,color:#fff
    classDef output fill:#9b59b6,stroke:#333,color:#fff

    class DATA,KEY,CFG input
    class SEL,LEVEL select
    class KEM,AEAD crypto
    class CT,META output
```

> **Security Note**: LatticeArc does not expose classical-only encryption. All data is protected by both post-quantum (ML-KEM) and classical (AES-256-GCM) algorithms, ensuring security even if one algorithm is compromised.

## Crate Descriptions

### `latticearc` (Main Facade)

Re-exports public APIs from the workspace via explicit imports:

```rust
use latticearc::{encrypt, decrypt, CryptoConfig, SecurityLevel};
use latticearc::LatticeArcError; // From latticearc::prelude
```

> **Note**: As of v0.2.0, all modules are consolidated into a single `latticearc` crate.
> Use explicit imports from `latticearc` (e.g., `latticearc::primitives::*`, `latticearc::unified_api::*`).

### `latticearc::types` (Pure-Rust Domain Types)

Zero-FFI-dependency module containing all types, traits, and configuration that can be formally verified with Kani:

| Module | Purpose |
|--------|---------|
| `types` | `ZeroizedBytes`, `SecurityLevel`, `UseCase`, `CryptoScheme`, `CryptoContext`, `ComplianceMode`, `PerformancePreference` |
| `traits` | `Encryptable`, `Decryptable`, `Signable`, `Verifiable`, `SchemeSelector` |
| `config` | `CoreConfig`, `EncryptionConfig`, `SignatureConfig`, `ZeroTrustConfig` |
| `selector` | `CryptoPolicyEngine` and scheme constants |
| `key_lifecycle` | `KeyStateMachine`, `KeyLifecycleRecord` (with Kani proofs) |
| `zero_trust` | `TrustLevel` enum |
| `error` | `TypeError` for pure-Rust error conditions |

### `latticearc::unified_api`

The Unified API layer, re-exports types and adds cryptographic operations:

| Module | Purpose |
|--------|---------|
| `convenience` | Simple encrypt/decrypt/sign/verify functions |
| `selector` | Re-exports CryptoPolicyEngine from types |
| `zero_trust` | ZeroTrustAuth, Challenge, ZeroKnowledgeProof |
| `hardware` | Hardware trait re-exports (types only, no detection) |
| `config` | Re-exports CoreConfig from types, adds CryptoConfig |
| `types` | Re-exports from types, adds FFI-dependent types |

### `latticearc::primitives`

Low-level cryptographic primitives:

| Module | Algorithms |
|--------|-----------|
| `kem/` | ML-KEM-512/768/1024 (FIPS 203) |
| `sig/` | ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205), FN-DSA (FIPS 206) |
| `aead/` | AES-256-GCM, ChaCha20-Poly1305 |
| `kdf/` | HKDF-SHA256, SP800-108 |
| `hash/` | SHA-2, SHA-3 |
| `mac/` | HMAC-SHA256, CMAC |
| `ec/` | Ed25519, X25519, secp256k1, BLS12-381 |

### `latticearc::hybrid`

Hybrid cryptography combining PQ + classical:

| Component | Combination |
|-----------|-------------|
| HybridKem | ML-KEM + X25519 |
| HybridSignature | ML-DSA + Ed25519 |
| HybridEncrypt | ML-KEM + AES-GCM |

### `latticearc::tls`

Post-quantum TLS 1.3 with rustls:

- PQ key exchange (ML-KEM)
- Hybrid mode support
- Session resumption
- Connection monitoring

### `latticearc::prelude`

Common types and error handling:

- `LatticeArcError` hierarchy
- Error recovery (circuit breaker, graceful degradation)
- Testing infrastructure (CAVP compliance, property-based testing)

### `latticearc-tests`

Consolidated test suite (CAVP, KAT, integration, FIPS validation):

- Convenience API tests (encryption, signing, KEM, hybrid)
- NIST Known Answer Tests (ML-KEM, ML-DSA, SLH-DSA, AES-GCM, ChaCha20)
- Zero-trust and session tests
- API stability and serialization tests
- End-to-end workflows and cross-validation tests

### `latticearc::zkp`

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
    subgraph "latticearc::prelude"
        CE[LatticeArcError]
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

## 🔒 Enterprise Features

LatticeArc Enterprise extends the open source core with advanced security capabilities:

### Self-Healing Cryptographic Security

```mermaid
flowchart TD
    subgraph "Detection"
        MON[Runtime Monitor]
        ML[ML-based Anomaly Detection<br/>K-Means Clustering]
        CVE[CVE Database Integration<br/>NVD API]
    end

    subgraph "Response"
        ROTATE[Automatic Key Rotation]
        PATCH[Vulnerability Patching]
        DEGRADE[Graceful Degradation]
    end

    subgraph "Levels"
        FULL[Full Security]
        DEG[Degraded Mode]
        EMERG[Emergency Mode]
    end

    MON --> ML
    MON --> CVE
    ML -->|Anomaly| ROTATE
    CVE -->|Vulnerability| PATCH
    ROTATE --> DEGRADE
    PATCH --> DEGRADE
    DEGRADE --> FULL
    DEGRADE --> DEG
    DEGRADE --> EMERG

    classDef detect fill:#4a90d9,stroke:#333,color:#fff
    classDef respond fill:#e74c3c,stroke:#333,color:#fff
    classDef level fill:#50c878,stroke:#333,color:#fff

    class MON,ML,CVE detect
    class ROTATE,PATCH,DEGRADE respond
    class FULL,DEG,EMERG level
```

- **Attack Detection**: ML-based anomaly detection using K-Means clustering (< 100ms latency)
- **Auto-Remediation**: Automatic key rotation and algorithm switching on vulnerability detection
- **Graceful Degradation**: Multi-level fallback (Full → Degraded → Emergency) with security guarantees

### Runtime-Adaptive Algorithm Selection

The enterprise `AdaptiveSelector` performs runtime algorithm selection based on:

- **Hardware Detection**: CPU instruction sets (AES-NI, AVX-512), GPU, HSM/TPM availability
- **Performance Feedback**: Continuous measurement of algorithm latency and throughput
- **Risk-Level Scaling**: Dynamic security multipliers under active threat conditions

> **Note**: The Apache edition provides static `UseCase`-based scheme selection via `CryptoPolicyEngine` (a lookup table). Runtime-adaptive selection with hardware detection, performance feedback, and risk scaling is an enterprise-only feature.

### Zero-Trust at Operation Level

- **Per-Operation Policy**: Every cryptographic operation evaluated against access policies
- **W3C DID Integration**: Decentralized identity with did:key, did:web resolution
- **Continuous Verification**: Dynamic trust scoring with automatic reauthentication triggers
- **Compliance Audit Trails**: Cryptographic-level logging for regulatory compliance

### Performance Targets

| Metric | Target |
|--------|--------|
| Attack detection latency | < 100ms |
| Vulnerability patching | < 500ms |
| Threat prediction accuracy | > 85% |
| Degradation trigger | < 50ms |

For Enterprise licensing, contact: Enterprise@LatticeArc.com

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 206: FN-DSA (Draft)](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022)
- [Rustls](https://github.com/rustls/rustls)
