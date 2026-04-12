# Post-Quantum Cryptography Ecosystem Map

> **Last verified:** 2026-04-11
> **Versions checked:** OpenSSL 3.5.0, aws-lc-rs 1.16.2, pqcrypto 0.18.1, ml-kem 0.2.3,
> ml-dsa 0.0.4, slh-dsa 0.1.0, liboqs 0.14.0 / liboqs-rust 0.11.0, Go 1.24,
> pyca/cryptography 46.x, wolfSSL 5.7+, age 1.3.0, GnuPG 2.5, Sequoia PGP (pre-release),
> oqs-provider 0.10.0
>
> **Scope:** Libraries, CLIs, and managed services that implement NIST PQC standards
> (FIPS 203–206). Credit where due — every project here is advancing the ecosystem.
> This document maps capabilities so readers can choose the right tool, not to rank them.

## How to Read This Document

The tables below compare **capabilities**, not quality. A check mark means the feature
exists; a dash means it doesn't. "Partial" and footnotes explain nuance. The
[Where LatticeArc Fits](#where-latticearc-fits) section at the end summarizes our
positioning honestly.

---

## 1. Libraries

Libraries provide cryptographic primitives or higher-level APIs that developers integrate
into applications.

### 1.1 Rust

| Capability | LatticeArc | aws-lc-rs | pqcrypto | RustCrypto (ml-kem, ml-dsa, slh-dsa) | liboqs-rust |
|------------|:----------:|:---------:|:--------:|:------------------------------------:|:-----------:|
| **ML-KEM (FIPS 203)** | 512/768/1024 | 512/768/1024 | 512/768/1024 | 512/768/1024 | 512/768/1024 |
| **ML-DSA (FIPS 204)** | 44/65/87 | 44/65/87 ^1^ | 44/65/87 | 44/65/87 | 44/65/87 |
| **SLH-DSA (FIPS 205)** | All param sets | -- | SPHINCS+ variants | All param sets | SPHINCS+ variants |
| **FN-DSA (FIPS 206)** | 512/1024 | -- | Falcon variants | -- | Falcon variants |
| **Hybrid PQ+Classical** | Yes (default) | -- | -- | X-Wing KEM only ^2^ | -- |
| **AEAD composition** | Yes (ML-KEM + HKDF + AES-GCM) | AES-GCM standalone | -- | -- | -- |
| **Use-case selection** | 22 use cases | -- | -- | -- | -- |
| **CLI companion** | Yes (latticearc-cli) | -- | -- | -- | -- |
| **FIPS 140-3 backend** | Opt-in via `--features fips` ^3^ | Yes (CMVP validated) | -- | -- | -- |
| **Architecture** | Pure Rust + aws-lc-rs for FIPS | C (aws-lc) FFI | C (PQClean) FFI | Pure Rust | C (liboqs) FFI |

^1^ ML-DSA in aws-lc-rs was added in v1.13.0, initially behind the `unstable` feature flag. Stabilization was planned for v1.14.0+.
^2^ RustCrypto's `x-wing` crate implements the X-Wing hybrid KEM (ML-KEM-768 + X25519). It is a KEM-only composition, not a full encrypt/decrypt pipeline.
^3^ LatticeArc routes AES-GCM, ML-KEM, HKDF, and SHA-2 through the CMVP-validated aws-lc-rs FIPS build. PQ signatures always use non-validated crates. LatticeArc itself is not a CMVP-certified module.

### 1.2 C / C++

| Capability | OpenSSL 3.5 | aws-lc (C) | liboqs | wolfCrypt | BoringSSL |
|------------|:-----------:|:----------:|:------:|:---------:|:---------:|
| **ML-KEM (FIPS 203)** | 512/768/1024 | 512/768/1024 | 512/768/1024 | 512/768/1024 | 768 ^4^ |
| **ML-DSA (FIPS 204)** | 44/65/87 | 44/65/87 | 44/65/87 | 44/65/87 | 65/87 ^4^ |
| **SLH-DSA (FIPS 205)** | All param sets | -- | SPHINCS+ variants | -- | -- |
| **FN-DSA (FIPS 206)** | -- | -- | Falcon variants | -- | -- |
| **Hybrid TLS KEM** | X25519MLKEM768 (default) | X25519MLKEM768 | Multiple hybrids via oqs-provider | Yes | X25519MLKEM768 |
| **FIPS 140-3 validated** | Pending ^5^ | Yes (Certificate #4631+) | -- | In progress | -- |
| **Embedded / no_std** | No | No | No | Yes | No |

^4^ BoringSSL supports ML-KEM and ML-DSA in production (Chrome, Android) but the parameter set coverage is narrower and the API is not designed for general-purpose use outside Google.
^5^ OpenSSL 3.5's FIPS provider is undergoing CMVP testing; not yet certified as of April 2026.

### 1.3 Go

| Capability | Go stdlib (1.24+) | Cloudflare circl |
|------------|:-----------------:|:----------------:|
| **ML-KEM (FIPS 203)** | 768/1024 | 512/768/1024 |
| **ML-DSA (FIPS 204)** | Planned (Go 1.27 `crypto/mldsa`) ^6^ | 44/65/87 |
| **SLH-DSA (FIPS 205)** | -- | -- |
| **FN-DSA (FIPS 206)** | -- | -- |
| **Hybrid TLS** | X25519MLKEM768 (default in crypto/tls) | X25519MLKEM768 |
| **Hybrid general-purpose** | -- | -- |

^6^ Go has an internal `crypto/internal/fips140/mldsa` implementation as of 1.26. The public `crypto/mldsa` package is proposed for Go 1.27 (GitHub issue #77626).

### 1.4 Python

| Capability | pyca/cryptography | pqcrypto (PyPI) | quantcrypt |
|------------|:-----------------:|:---------------:|:----------:|
| **ML-KEM (FIPS 203)** | Planned (issue #12824, target H1 2026) | Via PQClean bindings | Via PQClean bindings |
| **ML-DSA (FIPS 204)** | Planned | Via PQClean bindings | Via PQClean bindings |
| **Hybrid composition** | -- | -- | -- |
| **CLI** | -- | -- | Yes (keygen, encrypt, sign) |

### 1.5 Java / JVM

| Capability | Bouncy Castle | JDK 24+ (JEP 527) |
|------------|:-------------:|:------------------:|
| **ML-KEM** | 512/768/1024 | X25519MLKEM768 (TLS only) |
| **ML-DSA** | 44/65/87 | -- |
| **SLH-DSA** | All param sets | -- |
| **Hybrid general-purpose** | -- | TLS hybrid only |

---

## 2. CLI Tools

Tools that provide PQ operations from the command line without requiring library integration.

| Tool | Language | ML-KEM | ML-DSA | SLH-DSA | FN-DSA | Hybrid | Use-case selection | Key format |
|------|----------|:------:|:------:|:-------:|:------:|:------:|:------------------:|------------|
| **latticearc-cli** | Rust | 512/768/1024 | 44/65/87 | 128s | 512 | PQ+Classical (default) | 22 use cases | LPK (JSON + CBOR) |
| **openssl** (3.5+) | C | 512/768/1024 | 44/65/87 | Yes | -- | TLS only | -- | PEM/DER |
| **oqs-provider + openssl** | C | 512/768/1024 | 44/65/87 | Yes | Falcon | TLS + X.509 hybrids | -- | PEM/DER |
| **age** (1.3+) | Go | 768 (hybrid with X25519) | -- | -- | -- | Yes (KEM only) | -- | age-native |
| **GnuPG** (2.5 beta) | C | Kyber (pre-standard) ^7^ | -- | -- | -- | -- | -- | OpenPGP v5 |
| **Sequoia sq** | Rust | Planned (H1 2026) | Planned (H1 2026) | -- | -- | Planned (ML-KEM+X25519, ML-DSA+Ed25519) | -- | OpenPGP |
| **quantcrypt** | Python | Yes (PQClean) | Yes (PQClean) | Yes | -- | -- | -- | Custom |
| **quantum-sign** | Rust | -- | ML-DSA-87 only | -- | -- | -- | -- | Custom |
| **crystallize** | Rust | Kyber (pre-standard) | Dilithium (pre-standard) | -- | -- | -- | -- | Custom |

^7^ GnuPG 2.5 uses Kyber (pre-ML-KEM finalization). The implementation may diverge from the final FIPS 203 spec. OpenPGP PQ draft is expected to be ratified H1 2026.

---

## 3. Managed Services (Cloud KMS)

| Service | ML-KEM | ML-DSA | SLH-DSA | Hybrid TLS | Status |
|---------|:------:|:------:|:-------:|:----------:|--------|
| **AWS KMS** | Yes (TLS endpoints) | Yes (signing) | -- | X25519MLKEM768 | GA for TLS; ML-DSA signing available |
| **Google Cloud KMS** | Preview | Preview (ML-DSA) | Preview (SLH-DSA) | X25519MLKEM768 | Preview as of late 2025 |
| **Azure Key Vault** | Preview | Preview | -- | -- | Preview as of early 2026 |

---

## 4. TLS Implementations

PQ TLS key exchange is the most mature deployment vector. This is narrow scope — hybrid
KEM for TLS 1.3 only, not general-purpose encryption or signing.

| Implementation | Hybrid KEM | Default? | Since |
|---------------|:----------:|:--------:|-------|
| **Chrome / BoringSSL** | X25519MLKEM768 | Yes | Chrome 131 (Nov 2024) |
| **Firefox / NSS** | X25519MLKEM768 | Yes | Firefox 135 (Feb 2025) |
| **Go crypto/tls** | X25519MLKEM768 | Yes | Go 1.24 (Feb 2025) |
| **OpenSSL 3.5** | X25519MLKEM768 | Yes | Apr 2025 |
| **rustls** | X25519MLKEM768 | Opt-in (`prefer-post-quantum`) | rustls 0.23.22+ |
| **wolfSSL** | ML-KEM hybrid | Yes | wolfSSL 5.7+ |
| **AWS s2n-tls** | X25519MLKEM768 | Yes | Late 2024 |

---

## 5. What's Missing Across the Ecosystem

These are gaps we observed while surveying the landscape — not criticisms. The PQ
transition is early, and every project is making pragmatic tradeoffs.

| Gap | Who it affects | Current state |
|-----|---------------|---------------|
| **No CMVP-validated PQ signature backend** | Anyone needing FIPS 140-3 for ML-DSA/SLH-DSA | aws-lc has ML-DSA in FIPS module, but the Rust API was unstable. No CMVP cert covers SLH-DSA or FN-DSA anywhere. |
| **libsodium has no PQ algorithms** | Massive cross-language user base (C, Python, JS, Go, .NET) | ML-KEM is "on the roadmap" per maintainer; blocked on standardized hybrid scheme and SHAKE/SHA-3 implementation. |
| **pyca/cryptography has no PQ yet** | Python's dominant crypto library | ML-KEM API design in progress (issue #12824). Target: H1 2026. Needs backend support from BoringSSL/aws-lc, not OpenSSL. |
| **GnuPG PQ is pre-standard** | GPG users wanting PQ encryption | GnuPG 2.5 beta uses Kyber (not final ML-KEM). OpenPGP PQ spec expected H1 2026. |
| **No general-purpose hybrid composition** | Developers who need PQ+classical encryption (not just TLS) | TLS hybrid is widespread. General-purpose hybrid encrypt/decrypt (KEM + KDF + AEAD) remains DIY in most ecosystems. age 1.3 is the notable exception for KEM. |
| **FN-DSA (FIPS 206) coverage is thin** | Users wanting compact lattice signatures | Only pqcrypto (Falcon), liboqs, and LatticeArc ship FN-DSA. The standard is still in draft. |

---

## Where LatticeArc Fits

LatticeArc is a **composition layer**, not a primitive implementation. We don't implement
ML-KEM — aws-lc-rs and the fips20x crates do. Our value is the glue that nobody else
ships as a single dependency: hybrid composition, use-case selection, compliance
guardrails, and a CLI — backed by the same library code.

### What we're ahead on

These three capabilities are not available together in any other project we surveyed:

1. **General-purpose hybrid PQ+classical composition.** Most PQ deployment today is TLS
   hybrid key exchange (X25519MLKEM768). General-purpose hybrid encrypt/decrypt — where
   the library combines ML-KEM + X25519 + HKDF + AES-GCM into a complete AEAD pipeline —
   is DIY everywhere else. age 1.3 does hybrid KEM but not the AEAD pipeline.

2. **Use-case-driven algorithm selection.** 22 workload types, two compliance modes, two
   crypto modes (Hybrid / PQ-Only). No other library or CLI in any language offers
   "I'm protecting healthcare records" → automatic algorithm, security level, and
   compliance mode selection.

3. **Library + CLI from the same trust boundary.** The CLI is a thin frontend over the
   `latticearc` crate. AAD binding, constant-time tag compare, zeroization, and use-case
   selection all carry over. openssl and oqs-provider have CLIs, but they don't offer
   use-case selection or general-purpose hybrid encrypt/decrypt.

### What we're on par with

- **ML-KEM/ML-DSA/SLH-DSA coverage** — same parameter sets as pqcrypto, liboqs, Bouncy Castle.
- **Memory safety** — zeroize + subtle is standard Rust practice. Not a differentiator.
- **FN-DSA (FIPS 206)** — thin everywhere; we, pqcrypto, and liboqs are the only options.

### Out of scope (and where to look)

These are not gaps — they're different problems with established solutions:

| Need | Where to look |
|------|---------------|
| **A TLS stack** | rustls (with `prefer-post-quantum`), OpenSSL 3.5, wolfSSL, Go crypto/tls |
| **Cross-language bindings** | liboqs (C, Python, Go, Java, Rust from one project) |
| **Embedded / `no_std`** | wolfCrypt — the clear leader for PQ on constrained devices |
| **A CMVP-certified module end-to-end** | aws-lc-rs FIPS directly — it *is* the validated module; we wrap it |
| **A single low-level primitive** | `aws-lc-rs`, `fips204`, `fips205`, or `fn-dsa` directly |

### Positioning

LatticeArc targets **application-layer PQ crypto** — signing documents, encrypting
records, protecting keys at rest. The PQ transition today is dominated by TLS hybrid
key exchange, which is a transport-layer problem with mature solutions (see table above).
Application-layer PQ encryption is a smaller market *right now*, but it's growing as
organizations move from transport protection to data-at-rest and document-level
encryption.

Our bet is that developers making that move need a higher-level tool than raw primitives,
and that "wire up ML-KEM + X25519 + HKDF + AES-GCM yourself" is an adoption barrier
that a composition layer can remove.

---

## Keeping This Document Current

This document will drift. When updating:

1. Check the "Last verified" date above — if it's > 6 months old, reverify everything.
2. For each project, check the latest release on crates.io / PyPI / GitHub releases.
3. Update footnotes when unstable APIs are stabilized or previews go GA.
4. Add new entrants (e.g., if libsodium ships ML-KEM, it changes the landscape significantly).
