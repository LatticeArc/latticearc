# Algorithm Selection Guide

This document explains LatticeArc's algorithm choices, including what we include, what we skip, and why.

**Last Updated:** February 2026

---

## Table of Contents

- [Design Principles](#design-principles)
- [Included Algorithms](#included-algorithms)
- [Excluded Algorithms](#excluded-algorithms)
- [Backend Selection](#backend-selection)
- [Ecosystem Positioning](#ecosystem-positioning)
- [Performance Data](#performance-data)
- [Roadmap](#roadmap)

---

## Design Principles

LatticeArc's algorithm selection follows these principles:

1. **Standards-First** - Only NIST-standardized algorithms (FIPS 203-206, 186-5)
2. **Performance Matters** - Choose faster algorithms when security is equivalent
3. **Safety by Default** - Prefer misuse-resistant designs
4. **FIPS-Ready** - Use validated backends for certification path
5. **Rust Memory Safety** - Minimize unsafe C code where practical
6. **No Broken Crypto** - Exclude algorithms broken by cryptanalysis
7. **Future-Proof** - Follow NIST migration timeline

---

## Included Algorithms

### Post-Quantum Algorithms

#### ML-KEM (FIPS 203) - Key Encapsulation Mechanism

**Variants:** ML-KEM-512, ML-KEM-768, ML-KEM-1024

**Why included:**
- ✅ NIST-standardized (August 2024)
- ✅ FIPS 140-3 validated in aws-lc-rs
- ✅ Based on proven lattice mathematics (Module-LWE)
- ✅ All three security levels (128/192/256-bit equivalent)
- ✅ Production deployments by AWS, Google, Cloudflare

**Use cases:**
- `ML-KEM-512` - IoT devices, constrained environments (NIST Level 1)
- `ML-KEM-768` - Standard applications, TLS 1.3 default (NIST Level 3)
- `ML-KEM-1024` - Maximum security, long-term storage (NIST Level 5)

**Performance:**
- Keygen: ~0.05ms
- Encapsulation: ~0.07ms
- Decapsulation: ~0.08ms

---

#### ML-DSA (FIPS 204) - Digital Signature Algorithm

**Variants:** ML-DSA-44, ML-DSA-65, ML-DSA-87

**Why included:**
- ✅ NIST-standardized (August 2024)
- ✅ Based on proven lattice mathematics (Module-SIS)
- ✅ Smaller signatures than hash-based schemes
- ✅ Fast signing and verification

**Use cases:**
- `ML-DSA-44` - High-volume signing, IoT (NIST Level 2)
- `ML-DSA-65` - Standard applications (NIST Level 3)
- `ML-DSA-87` - Maximum security, long-term validity (NIST Level 5)

**Performance:**
- Sign: ~0.5ms (ML-DSA-65)
- Verify: ~0.4ms (ML-DSA-65)

**Trade-offs:**
- ✅ Smaller signatures than SLH-DSA
- ❌ Structured assumption (vs SLH-DSA's conservative hash-based security)

---

#### SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures

**Variants:** SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s

**Why included:**
- ✅ NIST-standardized (August 2024)
- ✅ Conservative security (hash-based, minimal assumptions)
- ✅ Stateless (no state management like XMSS)
- ✅ Long-term security confidence

**Use cases:**
- Firmware signing (infrequent updates, long validity)
- Root certificate authorities
- Systems requiring maximum conservatism

**Performance:**
- Sign: ~50ms (slower than ML-DSA)
- Verify: ~1ms

**Trade-offs:**
- ✅ Most conservative PQ signature scheme
- ❌ Much slower signing than ML-DSA
- ❌ Larger signatures

---

#### FN-DSA (FIPS 206) - Fast Lattice Signatures

**Variants:** FN-DSA-512, FN-DSA-1024

**Why included:**
- ✅ NIST-standardized (October 2024)
- ✅ Smaller keys than ML-DSA (same security)
- ✅ Fast verification
- ✅ Complement to ML-DSA

**Use cases:**
- Bandwidth-constrained environments
- Public key distribution (smaller keys)
- Applications prioritizing verification speed

**Performance:**
- Sign: ~1.2ms (FN-DSA-512)
- Verify: ~0.3ms (faster than ML-DSA)

**Trade-offs:**
- ✅ Smaller public keys (897 bytes vs 1952 for ML-DSA-65)
- ❌ Larger signatures than ML-DSA
- ⚠️ Newer standard (less deployment experience)

---

### Classical Algorithms (Hybrid Mode)

#### Ed25519 - Digital Signatures

**Why Ed25519 instead of P-256 ECDSA:**

| Criterion | Ed25519 | P-256 ECDSA | Winner |
|-----------|---------|-------------|--------|
| **Signing speed** | 16,000 ops/sec | 3,000 ops/sec | ✅ **Ed25519 (5x faster)** |
| **Verification speed** | 6,000 ops/sec | 1,200 ops/sec | ✅ **Ed25519 (5x faster)** |
| **Side-channel resistance** | Built-in constant-time | Requires careful impl | ✅ **Ed25519** |
| **Nonce generation** | Deterministic (safe) | Random (RNG failure = leak) | ✅ **Ed25519** |
| **Implementation complexity** | Simple, hard to misuse | Complex, easy to mess up | ✅ **Ed25519** |
| **FIPS 186-5 approved** | ✅ Yes (since 2023) | ✅ Yes | 🟰 **Tie** |
| **Key/signature size** | 32/64 bytes | 32/64 bytes | 🟰 **Tie** |
| **Protocol adoption** | SSH, Signal, WireGuard, Tor | TLS, legacy PKI | ✅ **Ed25519** |

**Real-world performance:**
```
Payment processing at 10,000 tx/sec:
- Ed25519: 62% of 1 CPU core
- P-256 ECDSA: 333% (requires 4 cores)
```

**Security advantage:**
- Ed25519 uses deterministic nonces (derived from message + private key)
- P-256 ECDSA uses random nonces (Sony PS3 hack was bad nonce reuse)
- Ed25519 is constant-time by design (no timing leaks)
- P-256 ECDSA has history of timing vulnerabilities (pre-2015 implementations)

**Why P-256 ECDSA exists:**
- Legacy HSM/TPM support (pre-2020 hardware)
- Regulatory inertia (outdated compliance requirements)
- Conservative institutional preference (20 years vs 10 years)

**Our decision:** Ed25519 is objectively better. P-256 available on request for legacy needs.

---

#### X25519 - Key Exchange

**Why X25519:**
- ✅ TLS 1.3 standard (RFC 8446)
- ✅ Fast (~0.05ms per operation)
- ✅ Simple, hard to misuse
- ✅ Production-proven (billions of TLS connections)

**Alternatives considered:**
- P-256 ECDH - Slower, more complex, same security level
- P-384/P-521 - Overkill (NIST Level 3/5 classical security not needed with ML-KEM)

---

#### AES-256-GCM - Authenticated Encryption

**Why AES-256-GCM:**
- ✅ FIPS 140-3 validated
- ✅ Hardware acceleration (AES-NI) - 10x faster than software
- ✅ Single-pass AEAD (encrypt + authenticate)
- ✅ Industry standard

**When ChaCha20-Poly1305 is used:**
- Systems without AES-NI (older CPUs, embedded)
- Software-only implementations
- ARM Cortex-M microcontrollers

---

#### HKDF-SHA256 - Key Derivation

**Why HKDF:**
- ✅ RFC 5869 standard
- ✅ Composable with hybrid schemes
- ✅ Provable security guarantees
- ✅ Widely deployed

**Used for:**
- Combining ML-KEM and X25519 shared secrets
- Deriving encryption keys from hybrid KEM output

---

## Excluded Algorithms

### Pre-Standard Algorithms (Deprecated)

#### CRYSTALS-Kyber → Superseded by ML-KEM

**Status:** AWS deprecating in 2026

**Why excluded:**
- ❌ Pre-standard version (NIST competition submission)
- ❌ Parameter changes in final FIPS 203
- ❌ Migration path exists (CRYSTALS-Kyber → ML-KEM)

**Migration timeline:**
- 2024: FIPS 203 (ML-KEM) published
- 2025: Coexistence period (both supported by vendors)
- 2026: CRYSTALS-Kyber removed from AWS endpoints

---

#### CRYSTALS-Dilithium → Superseded by ML-DSA

**Status:** Pre-standard, replaced by FIPS 204

**Why excluded:**
- ❌ Parameter differences from ML-DSA
- ❌ Not FIPS-standardized
- ❌ All vendors migrating to ML-DSA

---

#### SPHINCS+ → Superseded by SLH-DSA

**Status:** Pre-standard, replaced by FIPS 205

**Why excluded:**
- ❌ Parameter set changes in FIPS 205
- ❌ We support final SLH-DSA instead

---

### NIST Alternate Candidates

#### BIKE (Bit Flipping Key Encapsulation)

**Status:** Round 4 alternate candidate

**Why excluded:**
- ⚠️ Not standardized yet (may be in Round 5)
- ⚠️ Code-based cryptography (different security assumption)
- ⚠️ Smaller keys than Classic McEliece but larger than ML-KEM

**Future:** Will add if NIST standardizes in Round 5+

---

#### HQC (Hamming Quasi-Cyclic)

**Status:** Round 4 alternate candidate

**Why excluded:**
- ⚠️ Not standardized yet
- ⚠️ Code-based cryptography
- ⚠️ Performance similar to ML-KEM

**Future:** Will add if NIST standardizes

---

#### Classic McEliece

**Status:** Round 4 alternate candidate

**Why excluded:**
- ❌ Huge keys (260 KB public key)
- ❌ Impractical for most use cases
- ❌ Conservative but unwieldy

**Use case:** Extremely long-term security (100+ years) where size doesn't matter

**Future:** May add as optional feature if needed

---

### Legacy Classical Algorithms

#### RSA-2048/3072/4096

**Why excluded:**
- ❌ 50x slower than Ed25519
- ❌ Huge keys (2048-4096 bits vs 256 bits)
- ❌ Legacy algorithm (1977)
- ❌ Patent history (expired 2000, but long controversy)

**Performance comparison:**
```
Signature operations per second:
- Ed25519: 16,000 sign/sec
- RSA-2048: 500 sign/sec (32x slower)
- RSA-3072: 200 sign/sec (80x slower)
```

**When RSA still matters:**
- Existing PKI infrastructure (X.509 certificates)
- Legacy system interoperability
- Regulatory requirements (rare in 2026)

**Our position:** Not included. Use Ed25519 or ML-DSA instead.

---

#### P-256/P-384/P-521 ECDSA

**Why not default:**
- ❌ Slower than Ed25519 (5x for signing)
- ❌ Complex implementation (incomplete addition formulas)
- ❌ History of timing vulnerabilities
- ❌ NSA curve design (trust concerns)

**When P-256 ECDSA matters:**
- Legacy HSM support (pre-2020 hardware)
- Explicit regulatory requirements (outdated policies)
- FIPS 186-4 compliance (before 2023 update)

**Our position:** Ed25519 is default. P-256 available on request for legacy needs.

**How to request:** [Open an issue](https://github.com/latticearc/latticearc/issues) with your use case

---

#### DSA (Digital Signature Algorithm)

**Why excluded:**
- ❌ Deprecated in FIPS 186-5
- ❌ Superseded by ECDSA and EdDSA
- ❌ No reason to use in 2026

---

### Broken or Experimental Algorithms

#### SIKE (Supersingular Isogeny Key Encapsulation)

**Status:** Broken by cryptanalysis (2022)

**Why excluded:**
- ❌ Broken in 1 hour on single CPU
- ❌ Smallest PQC keys (220 bytes) don't matter if broken
- ❌ NIST removed from Round 4

---

#### Rainbow

**Status:** Broken by cryptanalysis (2022)

**Why excluded:**
- ❌ Multivariate signature scheme
- ❌ Broken faster than expected
- ❌ NIST removed from competition

---

#### secp256k1 (Bitcoin Curve)

**Status:** Not FIPS, Bitcoin-specific

**Why excluded:**
- ❌ Not FIPS-approved
- ❌ Niche use case (cryptocurrencies)
- ❌ No advantage over P-256 or Ed25519 for general use

**When it matters:** Bitcoin, Ethereum signature compatibility

**Our position:** Not included. Use Ed25519 for general-purpose signatures.

---

#### Ed448

**Status:** FIPS 186-5 approved, but rarely used

**Why excluded:**
- ❌ Ed25519 is standard (99% of EdDSA usage)
- ❌ Larger keys/signatures for minimal security gain
- ❌ Slower than Ed25519
- ❌ Not needed (Ed25519 + ML-DSA provides 256-bit hybrid security)

---

## Backend Selection

### Why aws-lc-rs for ML-KEM?

| Criterion | aws-lc-rs | liboqs | Winner |
|-----------|-----------|--------|--------|
| **FIPS 140-3 validated** | ✅ Yes (first with ML-KEM) | ❌ No | aws-lc-rs |
| **Production status** | ✅ Powers AWS KMS | ⚠️ "Prototyping only" | aws-lc-rs |
| **ML-KEM support** | ✅ FIPS 203 | ✅ FIPS 203 | Tie |
| **Memory safety** | ⚠️ C (via Rust FFI) | ⚠️ C | Tie |
| **Formal verification** | ⚠️ Partial | ⚠️ Partial | Tie |
| **AWS backing** | ✅ Yes | ❌ No (Linux Foundation) | aws-lc-rs |

**Decision:** aws-lc-rs for FIPS validation and production readiness.

**Future:** If FIPS-validated pure Rust ML-KEM emerges, we'll migrate for better memory safety.

---

### Why fips204 for ML-DSA?

**Current:** ML-DSA uses `fips204` crate (pure Rust, NIST-compliant)

**Why not aws-lc-rs ML-DSA?**
- ⚠️ ML-DSA in aws-lc-rs is `unstable::signature` (not stabilized as of v1.15.4)
- ⚠️ No public Rust API yet

**Migration plan:**
- Our PR [aws/aws-lc-rs#1034](https://github.com/aws/aws-lc-rs/pull/1034) for ML-DSA seed-based keygen was merged
- When aws-lc-rs stabilizes ML-DSA (v1.16+), we'll migrate
- Tracking: GitHub issue #17

---

### Upstream Contributions to aws-lc-rs

We actively contribute features to aws-lc-rs that benefit the entire Rust cryptography ecosystem:

#### PR #1029: ML-KEM DecapsulationKey Serialization (Merged ✅)

**Status:** Merged Feb 10, 2026
**Problem:** ML-KEM decapsulation keys couldn't be serialized for storage/transmission
**Solution:** Added `private_key_as_be_bytes()` and `DecapsulationKey::from_bytes()` methods
**Impact:** Enables key persistence for ML-KEM, unlocking key management scenarios
**Link:** https://github.com/aws/aws-lc-rs/pull/1029

**Why it matters:** Before this PR, applications couldn't store ML-KEM keys between sessions. This was a blocker for enterprise key management workflows.

**Related issues:**
- aws/aws-lc-rs#799 (DecapsulationKey serialization support)

#### PR #1034: ML-DSA Seed-Based Keygen (Merged ✅)

**Status:** Merged Feb 13, 2026
**Problem:** ML-DSA keygen is random-only, preventing deterministic key derivation
**Solution:** Added `PqdsaKeyPair::from_seed()` for RFC 5869 seed-based keygen
**Impact:** Enables HD wallets, test vectors, and deterministic keygen for ML-DSA
**Link:** https://github.com/aws/aws-lc-rs/pull/1034
**Tests:** 25 new tests (360 insertions, 3 files)

**Why it matters:** Deterministic keygen is critical for:
- Test vector reproducibility
- Hierarchical deterministic (HD) wallets
- Zero-downtime key rotation scenarios
- Compliance with deterministic keygen requirements

**Related issues:**
- aws/aws-lc-rs#964 (ML-DSA stabilization)
- aws/aws-lc-rs#773 (ML-DSA Rust API support)

---

### Backend Summary

| Algorithm | Backend | Version | Status |
|-----------|---------|---------|--------|
| **ML-KEM** | aws-lc-rs | 1.15.4 | ✅ FIPS 140-3 validated |
| **ML-DSA** | fips204 | 0.4.6 | ⚠️ Awaiting aws-lc-rs stabilization |
| **SLH-DSA** | fips205 | 0.4.1 | ✅ NIST-compliant |
| **FN-DSA** | fn-dsa | 0.3.0 | ✅ FIPS 206 compliant |
| **Ed25519** | ed25519-dalek | 2.1.1 | ✅ Audited, constant-time |
| **X25519** | aws-lc-rs | 1.15.4 | ✅ FIPS 140-3 validated |
| **AES-GCM** | aws-lc-rs | 1.15.4 | ✅ FIPS 140-3 validated |
| **ChaCha20-Poly1305** | chacha20poly1305 | 0.10.1 | ✅ RustCrypto audited |
| **HKDF** | hkdf | 0.12.4 | ✅ RustCrypto |

---

## Ecosystem Positioning

LatticeArc exists within a rich ecosystem of cryptographic libraries. Rather than competing, we **build on** and **complement** existing tools. Here's how we relate to other libraries:

### AWS-LC: Our Foundation

**Relationship:** We **use AWS-LC** as our cryptographic backend via the `aws-lc-rs` Rust bindings.

| Component | AWS-LC | LatticeArc |
|-----------|--------|------------|
| **ML-KEM** | ✅ FIPS 140-3 validated implementation | ✅ **Uses** aws-lc-rs |
| **X25519, AES-GCM** | ✅ FIPS 140-3 validated | ✅ **Uses** aws-lc-rs |
| **Hybrid Signatures** | ❌ Not in scope (KEM-only) | ✅ We add this layer |
| **Language** | C with Rust FFI | Pure Rust API |
| **API Level** | Low-level primitives | High-level builder pattern |

**How we complement AWS-LC:**
- We **depend on** their FIPS-validated ML-KEM, X25519, and AES-GCM
- We **add** hybrid signature API (ML-DSA + Ed25519)
- We **provide** high-level Rust API on top of their low-level C primitives
- We **integrate** multiple backends (aws-lc-rs + fips204 + ed25519-dalek)

**Credit:** AWS-LC's FIPS validation enables our compliance-ready approach.

---

### OpenSSL: Different API Layer

**Relationship:** Complementary - we target different developer experiences.

| Aspect | OpenSSL (+ oqs-provider) | LatticeArc |
|--------|--------------------------|------------|
| **Hybrid KEMs** | X25519MLKEM768 | ML-KEM-768 + X25519 + HKDF |
| **Hybrid Sigs** | ML-DSA + P-256 ECDSA | ML-DSA + Ed25519 |
| **FN-DSA** | ❌ Not available | ✅ FIPS 206 support |
| **Language** | C | Rust |
| **API Philosophy** | Low-level EVP (maximum control) | High-level builder (developer productivity) |
| **Use Case** | General-purpose C/C++ projects | Rust ecosystem, modern APIs |

**How we differ:**
- **Algorithm choice:** Ed25519 hybrids (5x faster) vs P-256 ECDSA
- **API level:** `encrypt(data, &key, config)?` vs `EVP_PKEY_encapsulate_init()`
- **Memory safety:** Rust compile-time guarantees vs C manual memory management
- **Target audience:** Rust developers wanting high-level API vs C developers needing low-level control

**Not competitors:** OpenSSL dominates C/C++ ecosystem (25 years, battle-tested). We serve Rust ecosystem with modern API.

---

### liboqs: Research Partner

**Relationship:** We learn from their research; they're explicitly for prototyping, not production.

| Aspect | liboqs | LatticeArc |
|--------|--------|------------|
| **Mission** | "Prototyping and experimenting" | Production deployment |
| **Algorithm Scope** | 50+ (including experimental) | NIST standards only |
| **FIPS Validation** | ❌ "Not for production use" | ✅ Via aws-lc-rs |
| **Hybrid Sigs** | ✅ ML-DSA + P-256/RSA (research) | ✅ ML-DSA + Ed25519 (production) |
| **Used By** | oqs-provider (OpenSSL), research projects | Rust production applications |

**How we complement liboqs:**
- We **study** their experimental algorithm implementations
- We **adopt** algorithms when they become NIST-standardized
- We **focus on** production readiness while they explore new algorithms
- We **integrate** their research findings into production-grade code

**Credit:** liboqs's work on hybrid signatures informed our API design.

---

### rustls: Integration Partner

**Relationship:** We **integrate with** rustls for TLS support.

| Component | rustls | LatticeArc |
|-----------|--------|------------|
| **Scope** | TLS 1.3 protocol | Broader crypto library |
| **Hybrid KEMs** | ✅ X25519MLKEM768 (TLS only) | ✅ Standalone + TLS via `arc-tls` |
| **Signatures** | ❌ No signature API | ✅ Hybrid signatures (ML-DSA + Ed25519) |
| **Non-TLS Crypto** | ❌ Out of scope | ✅ Encryption, signatures, ZKP |

**How we work together:**
- Our `arc-tls` crate **wraps** rustls with PQC extensions
- We **provide** standalone crypto operations (encrypt, sign) rustls doesn't
- We **reuse** their excellent TLS 1.3 implementation
- We **complement** by adding hybrid signatures and broader crypto API

---

### Bouncy Castle: Different Ecosystem

**Relationship:** Parallel efforts in different language ecosystems.

| Aspect | Bouncy Castle | LatticeArc |
|--------|---------------|------------|
| **Ecosystem** | Java/C# | Rust |
| **Maturity** | 25 years, v2.x | New, v0.1.0 |
| **Hybrid Sigs** | ✅ Composite sigs (X.509) | ✅ ML-DSA + Ed25519 |
| **Use Case** | Enterprise Java applications | Rust applications, systems programming |

**How we differ:**
- **Language:** JVM (GC, runtime safety) vs Rust (compile-time safety, no GC)
- **Performance:** JVM overhead vs native machine code
- **Target users:** Java/C# developers vs Rust developers

**Not competitors:** We serve entirely different language ecosystems. A Java shop uses Bouncy Castle; a Rust shop uses LatticeArc.

---

## Performance Data

### Signature Performance Comparison

| Algorithm | Sign (ops/sec) | Verify (ops/sec) | Use Case |
|-----------|----------------|------------------|----------|
| **Ed25519** | 16,000 | 6,000 | Fast classical baseline |
| **P-256 ECDSA** | 3,000 | 1,200 | Legacy NIST curves |
| **RSA-2048** | 500 | 20,000 | Legacy (slow sign, fast verify) |
| **ML-DSA-44** | 4,000 | 5,000 | IoT, high-volume |
| **ML-DSA-65** | 2,000 | 2,500 | Standard applications |
| **ML-DSA-87** | 1,000 | 1,500 | Maximum security |
| **SLH-DSA-128s** | 20 | 1,000 | Conservative (slow sign) |

**Source:** Benchmarks on Intel i7-1185G7 (Tiger Lake)

---

### Hybrid Signature Performance

| Combination | Sign (ops/sec) | Verify (ops/sec) | Notes |
|-------------|----------------|------------------|-------|
| **ML-DSA-65 + Ed25519** | 1,800 | 2,000 | Our default |
| **ML-DSA-65 + P-256 ECDSA** | 1,200 | 800 | OpenSSL oqs-provider |
| **ML-DSA-65 + RSA-3072** | 180 | 1,400 | Slowest signing |

**Winner:** Ed25519 hybrids are 50% faster than P-256 hybrids.

---

### Key and Signature Sizes

| Algorithm | Public Key | Signature | Notes |
|-----------|-----------|-----------|-------|
| **Ed25519** | 32 bytes | 64 bytes | Smallest classical |
| **P-256 ECDSA** | 32 bytes | 64 bytes | Same size as Ed25519 |
| **ML-DSA-44** | 1312 bytes | 2420 bytes | Smallest PQ sig |
| **ML-DSA-65** | 1952 bytes | 3309 bytes | Standard |
| **ML-DSA-87** | 2592 bytes | 4627 bytes | Largest |
| **FN-DSA-512** | 897 bytes | 666 bytes | Smaller key than ML-DSA |
| **SLH-DSA-128s** | 32 bytes | 7856 bytes | Huge signature |

**Hybrid ML-DSA-65 + Ed25519:**
- Public key: 1984 bytes (1952 + 32)
- Signature: 3373 bytes (3309 + 64)

---

## Roadmap

### Actively Planned

#### ML-DSA Migration to aws-lc-rs

**Status:** Waiting for upstream stabilization

**Priority:** High - enables FIPS-validated signatures

**Timeline:**
- aws-lc-rs v1.16.0 expected Mar-Jun 2026
- Will migrate when stable ML-DSA API is available
- Tracking: Issue #17, PRs aws/aws-lc-rs#1029 and #1034 (both merged)

**Benefit:** FIPS-validated ML-DSA (currently using fips204)

---

#### BIKE/HQC (If NIST Standardizes)

**Status:** Monitoring NIST Round 5

**Priority:** Medium - algorithmic diversity

**Condition:** Only if NIST standardizes in Round 5+

**Rationale:** Provide code-based alternatives to lattice-based schemes

---

### Available on Request (Not Proactively Building)

#### P-256/P-384/P-521 ECDSA Hybrids

**Status:** NOT planned unless users need it

**Our position:** Ed25519 is objectively better (5x faster, safer, FIPS 186-5 approved). We will NOT proactively add P-256 ECDSA.

**When we WOULD add it:**
- Multiple users request it for specific legacy constraints
- Real use case: Pre-2020 HSM that doesn't support Ed25519
- Real use case: Auditor requires P-256 despite FIPS 186-5 approving Ed25519

**How to request:**
[Open an issue](https://github.com/latticearc/latticearc/issues/new) with:
- Your specific legacy constraint
- Why Ed25519 won't work
- Evidence you can't upgrade/educate auditor

**Implementation IF requested:**
```rust
// Optional feature: ecdsa-hybrids (disabled by default)
#[cfg(feature = "ecdsa-hybrids")]
pub fn generate_p256_hybrid_signing_keypair() -> Result<...>;
```

**Default will always be:** Ed25519 hybrids for performance and safety

---

### Not Planned

#### Pre-Standard Algorithms

- ❌ CRYSTALS-Kyber (use ML-KEM instead)
- ❌ CRYSTALS-Dilithium (use ML-DSA instead)
- ❌ SPHINCS+ (use SLH-DSA instead)

**Rationale:** Follow NIST 2026 migration timeline.

---

#### Broken Algorithms

- ❌ SIKE (broken in 2022)
- ❌ Rainbow (broken in 2022)

**Rationale:** No security value.

---

#### Legacy Algorithms

- ❌ RSA-2048/3072/4096 (50x slower than Ed25519)
- ❌ DSA (deprecated in FIPS 186-5)

**Rationale:** Modern alternatives are faster and safer.

---

#### Exotic Algorithms

- ❌ secp256k1 (Bitcoin-specific, not general-purpose)
- ❌ Ed448 (Ed25519 is standard)
- ❌ Argon2/bcrypt (password hashing, not key derivation)

**Rationale:** Niche use cases, not core mission.

---

## Questions or Requests

### Need an algorithm we don't support?

1. Check our [GitHub issues](https://github.com/latticearc/latticearc/issues) for existing requests
2. [Open a new issue](https://github.com/latticearc/latticearc/issues/new) explaining:
   - Your use case
   - Why existing algorithms don't work
   - Regulatory/compliance constraints
3. We prioritize based on:
   - NIST standardization status
   - User demand
   - Implementation complexity

### Security concerns about algorithm choices?

See our [Security Policy](../SECURITY.md) or email Security@LatticeArc.com

---

## References

### NIST Standards
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA
- [FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd) - FN-DSA
- [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) - Digital Signature Standard (includes EdDSA)

### Performance Sources
- [EdDSA benchmarks](https://billatnapier.medium.com/benchmarking-digital-signatures-ed25519-eddsa-wins-for-signing-rsa-wins-for-verifying-316944a1d43d)
- [ECDSA vs EdDSA security](https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/)
- [SSH key comparison](https://goteleport.com/blog/comparing-ssh-keys/)

### AWS Migration Timeline
- [AWS PQC migration plan](https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/)
- [ML-KEM in AWS services](https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/)

---

**Last Updated:** February 11, 2026
**Document Version:** 1.0
