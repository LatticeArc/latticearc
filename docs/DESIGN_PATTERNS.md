# LatticeArc Design Patterns — Definitive Reference

## Mission

LatticeArc aims to be the exemplary implementation of a post-quantum cryptography
library — the reference that other projects study, cite, and measure themselves against.

Not "good enough." Not "passes CI." Exemplary means:

- **Every pattern is justified from first principles** — NIST standards, IETF RFCs,
  published cryptographic research, and Rust language guarantees. Not because someone
  decided it, but because the math and the standards require it.
- **Every safety property is structural, not behavioral** — enforced by the compiler,
  the type system, or formal proofs. Not by code review discipline that erodes over time.
- **Every line of code is auditable** — a security auditor unfamiliar with the project
  can read any module and understand what it does, why it's correct, and which standard
  governs it, without reading any other file.
- **The codebase teaches** — reading LatticeArc should teach a developer how to build
  a cryptography library correctly. The patterns, the comments, the test methodology,
  the documentation style — all of it should be worth learning from.

This standard applies equally to the open-source core and every proprietary extension.
An enterprise crate with lower standards than the core weakens the entire platform.

---

## Context: What LatticeArc Is Building

LatticeArc is a three-layer post-quantum cryptography platform:

| Layer | Repository | Contents |
|-------|-----------|----------|
| **Layer 1 — Primitives** | `apache_repo` (Apache 2.0) | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, AES-GCM, ChaCha20, X25519, Ed25519, HKDF, hybrid encryption, unified API |
| **Layer 2 — Enterprise Capabilities** | `proprietary_repo` | Self-healing security ^[Implementation: K-Means anomaly detection over op telemetry; CVE-driven algorithm rotation. See `proprietary_repo/arc-enterprise-security/`.]^, zero-trust crypto ops, runtime-adaptive selection ^[Implementation: data-characteristic + hardware-capability scoring; see `proprietary_repo/arc-enterprise-perf/adaptive_selector.rs`.]^, Conditional Cryptography Engine (CCE) |
| **Layer 3 — Products** | `proprietary_repo` | Migration Accelerator, CryptoSOC, Code Signing, Governed Database, Timelock, 45+ more |

The apache core is published to crates.io as a single `latticearc` crate. The proprietary
repo depends on it via Cargo. The CCE engine extends it with 17 condition dimensions
(time, location, quorum, biometric, HSM, TEE, ZKP, etc.) that embed conditions into
key derivation so decryption keys mathematically do not exist until all conditions are met.

**Every design pattern must work for both repositories.** A pattern that only works for the
open-source core but breaks when enterprise code extends it is wrong.

---

# Standards Compliance Map

Every design pattern traces to a published standard. This section maps **all** relevant
standards — not just NIST — to our implementation, so contributors know exactly which
requirements govern their code.

## Algorithms and Their Standards

| Algorithm | NIST Standard | What It Specifies | Our Implementation |
|-----------|--------------|-------------------|-------------------|
| ML-KEM (512/768/1024) | FIPS 203 | Module-Lattice Key Encapsulation Mechanism | `primitives::kem::ml_kem` via aws-lc-rs (FIPS 140-3 Cert #4631, #4759, #4816) |
| ML-DSA (44/65/87) | FIPS 204 | Module-Lattice Digital Signature Algorithm | `primitives::sig::ml_dsa` via `fips204` crate |
| SLH-DSA | FIPS 205 | Stateless Hash-Based Digital Signature Algorithm | `primitives::sig::slh_dsa` via `fips205` crate |
| FN-DSA (512/1024) | draft FIPS 206 | FFT-over-NTRU-Lattice Digital Signature Algorithm | `primitives::sig::fndsa` via `fn-dsa` crate |
| AES-GCM (128/256) | SP 800-38D | Galois/Counter Mode for Authenticated Encryption | `primitives::aead::aes_gcm` via aws-lc-rs |
| HKDF-SHA256 | SP 800-56C Rev.2 / RFC 5869 | Key Derivation using HMAC-based Extract-and-Expand | `primitives::kdf::hkdf` via aws-lc-rs HMAC |
| HMAC-SHA256 | FIPS 198-1 / SP 800-107 | Keyed-Hash Message Authentication Code | `primitives::mac::hmac` via aws-lc-rs |
| PBKDF2 | SP 800-132 | Password-Based Key Derivation | `primitives::kdf::pbkdf2` via `pbkdf2` crate |
| SP 800-108 Counter KDF | SP 800-108 Rev.1 | KDF in Counter Mode using HMAC-PRF | `primitives::kdf::sp800_108_counter_kdf` |
| X25519 ECDH | SP 800-186 / RFC 7748 | Elliptic Curve Diffie-Hellman Key Agreement | `primitives::kem::ecdh` via aws-lc-rs |
| Ed25519 | FIPS 186-5 / RFC 8032 | Edwards-Curve Digital Signature Algorithm | `primitives::ec::ed25519` via `ed25519-dalek` |
| ChaCha20-Poly1305 | RFC 8439 | AEAD with ChaCha20 stream cipher and Poly1305 MAC | `primitives::aead::chacha20poly1305` via `chacha20poly1305` crate |

## Key Management Standards

| Standard | What It Governs | How We Comply |
|----------|----------------|---------------|
| **SP 800-57 Part 1 Rev.5** | Key lifecycle: generation, activation, rotation, destruction | Pattern 5 (Secret Type Lifecycle): `ZeroizeOnDrop` enforces §8.3 key destruction. `types::key_lifecycle::KeyStateMachine` enforces §5.3 state transitions. |
| **SP 800-57 §8.3.1** | "Keys shall be zeroized when no longer needed" | Every secret type derives `ZeroizeOnDrop` or has manual `Drop` calling `zeroize()`. Verified: 20+ secret types comply. |
| **SP 800-57 §5.6.1** | Key agreement scheme requirements | Hybrid KEM uses HKDF-SHA256 dual-PRF combiner per SP 800-56C. ML-KEM provides IND-CCA2 security per FIPS 203 §3. |

## Cryptographic Operation Standards

| Standard | What It Governs | How We Comply |
|----------|----------------|---------------|
| **SP 800-175B Rev.1 §4.1** | "Implementations shall not leak information through timing" | Pattern 5 property 3: all secret comparisons use `subtle::ConstantTimeEq` with bitwise `&` (not short-circuit `&&`). |
| **SP 800-38D §5.2.2** | "The decryption function shall return FAIL without any additional information" | Pattern 6 (Cryptographic Error Opacity): all adversary-reachable errors collapse into a single opaque returned variant. Scope: AEAD decrypt, hybrid KEM `encapsulate`+`decapsulate`, hybrid signature `verify`, encrypt-side defence-in-depth (recipient-PK / ephemeral-PK / KEM-CT length checks). Per-stage diagnostics still emit via internal `tracing::debug!` so operators can debug via correlation IDs. See `docs/DESIGN_PATTERNS.md` Pattern 6 for the canonical form. |
| **SP 800-38D §8.2** | "The nonce shall be unique for each invocation of GCM with a given key" | Pattern 3 (Nonce Encapsulation): nonces generated internally from OS CSPRNG via `generate_nonce()`. Callers cannot supply nonces in high-level APIs. |
| **SP 800-56C Rev.2 §4** | "Each application of a KDF shall use a distinct set of values" | Pattern 2 (Domain Separation Registry): every HKDF call uses a registered constant from `types::domains`. Kani proof verifies pairwise distinctness. |
| **SP 800-108 Rev.1 §4** | "The label shall be distinct for each key derivation purpose" | Same as above. Counter-mode KDF labels also centralized. |
| **SP 800-90A Rev.1** | Deterministic Random Bit Generator requirements | RNG routed through `primitives::rand` which uses OS CSPRNG. In FIPS mode, aws-lc-rs uses its FIPS-approved DRBG. Pattern 1 ensures no direct `OsRng` bypass. |
| **SP 800-131A Rev.2 §4** | Transitioning to stronger crypto: key length minimums | All symmetric operations use 256-bit keys (AES-256-GCM). ML-KEM-768 is the default (NIST Category 3 = AES-192 equivalent). |

## FIPS 140-3 Module Requirements

| FIPS 140-3 Section | Requirement | How We Comply |
|-------------------|-------------|---------------|
| **§7.4** | Approved security functions only | All crypto operations use NIST-approved algorithms (FIPS 203–205, draft 206, SP 800-38D, SP 800-56C). Non-approved algorithms (secp256k1 ZKP) are disabled under `feature = "fips"`. |
| **§7.7** | Pairwise consistency test for keypairs | `primitives::pct` module runs PCT after every keypair generation (ML-DSA, FN-DSA). |
| **§7.10.1** | Power-up self-test | `primitives::self_test` runs KAT vectors for AES-GCM on module load. |
| **§7.10.2** | Module integrity test | `primitives::self_test` computes HMAC-SHA256 over module binary, compares against expected value. |
| **§7.11** | Conditional self-tests | Conditional KAT tests run on algorithm first-use (`latticearc/tests/primitives_self_test_conditional_kats.rs`). |

## IETF RFCs

| RFC | Title | What It Governs | Our Implementation |
|-----|-------|----------------|-------------------|
| **RFC 5869** | HMAC-based Extract-and-Expand Key Derivation (HKDF) | Key derivation from non-uniform input material | `primitives::kdf::hkdf` — Extract-then-Expand with SHA-256. All hybrid shared secrets and convenience API keys derived via this path. |
| **RFC 7748** | Elliptic Curves for Security (X25519/X448) | X25519 Diffie-Hellman key agreement | `primitives::kem::ecdh::X25519KeyPair` — ephemeral ECDH with low-order point rejection per §6.1. |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (Ed25519/Ed448) | Ed25519 signing and verification | `primitives::ec::ed25519` — used in hybrid signatures (ML-DSA + Ed25519 AND-composition). |
| **RFC 8439** | ChaCha20 and Poly1305 for IETF Protocols | AEAD for software-only environments | `primitives::aead::chacha20poly1305` — fallback when AES-NI hardware is unavailable. |
| **RFC 9180** | Hybrid Public Key Encryption (HPKE) | HPKE-style key schedule for hybrid encryption | `hybrid::encrypt_hybrid::derive_encryption_key` — follows HPKE §5.1 LabeledExtract pattern with length-prefixed info+AAD binding. |
| **RFC 8949** | Concise Binary Object Representation (CBOR) | Binary key serialization | `unified_api::key_format::PortableKey::to_cbor()` — compact wire format for key exchange. |

## NSA CNSA 2.0 (Commercial National Security Algorithm Suite)

CNSA 2.0 defines the timeline for transitioning to quantum-resistant algorithms in
National Security Systems. Our defaults align with CNSA 2.0 requirements.

| CNSA 2.0 Requirement | Deadline | Our Compliance |
|---------------------|----------|----------------|
| Software/firmware signing: use CNSA 2.0 algorithms | 2025 (passed) | ML-DSA-65/87 and SLH-DSA available for code signing. `latticearc-docsign` and `latticearc-firmware` products use these by default. |
| Web browsers/servers and cloud: quantum-resistant TLS | 2025 | Out of scope — use rustls 0.23.37+ with `aws-lc-rs` for X25519MLKEM768 directly. LatticeArc does not ship a TLS stack. |
| Traditional networking: quantum-resistant VPN/IPsec | 2026 | Hybrid encryption schemes (ML-KEM + X25519 + HKDF + AES-256-GCM) ready for integration. |
| All symmetric encryption: AES-256 minimum | Immediate | `EncryptionScheme` defaults to AES-256-GCM. No AES-128 is available in the unified API. (AES-128 exists in `primitives` for legacy compatibility but is not routed by the policy engine.) |
| CNSA 2.0 approved KEM | FIPS 203 | ML-KEM-768 (Category 3) is the default. ML-KEM-1024 (Category 5) available for `SecurityLevel::Maximum`. |
| CNSA 2.0 approved signatures | FIPS 204 / FIPS 205 | ML-DSA-65 default. SLH-DSA for stateless hash-based. FN-DSA (draft FIPS 206) for compact signatures. |

## ISO/IEC Standards

| Standard | Title | Relevance | Our Compliance |
|----------|-------|-----------|----------------|
| **ISO/IEC 19790:2012** | Security requirements for cryptographic modules (basis for FIPS 140-3) | Module boundary, self-tests, key management | Same as FIPS 140-3 section above — ISO 19790 and FIPS 140-3 are harmonized. |
| **ISO/IEC 27001:2022** | Information Security Management Systems | Enterprise customers require ISO 27001 compliance for key management | `unified_api::audit` provides cryptographic audit trails. `types::key_lifecycle` enforces SP 800-57 key states. Enterprise `arc-enterprise-policy` adds RBAC and policy enforcement. |
| **ISO/IEC 18033-2** | Encryption algorithms (block ciphers, stream ciphers) | AES-256-GCM standardization | AES-256-GCM via aws-lc-rs, which is ISO 18033-2 compliant through FIPS validation. |

## OWASP Cryptographic Guidelines

| OWASP Rule | Description | Our Compliance |
|-----------|-------------|----------------|
| **Use strong algorithms** | Never use MD5, SHA-1, DES, RC4, or algorithms with known weaknesses | Denied at the supply-chain level: `deny.toml` forbids crates providing weak algorithms. All hash operations use SHA-256 minimum. |
| **Use sufficient key lengths** | AES-256 for symmetric, 256-bit minimum for asymmetric | Enforced by `EncryptionScheme` — all variants use 256-bit symmetric keys. ML-KEM-768+ for KEM. |
| **Use AEAD for encryption** | Authenticated encryption prevents ciphertext tampering | All encryption paths use AES-256-GCM or ChaCha20-Poly1305 (both AEAD). No unauthenticated encryption is available in the API. |
| **Do not roll your own crypto** | Use NIST-standardized, peer-reviewed algorithms | All algorithms are NIST FIPS/SP standardized. Backends are aws-lc-rs (FIPS validated), `fips204`, `fips205` (NIST reference implementations). |
| **Protect keys at rest** | Keys in memory must be zeroized; keys in storage must be encrypted | Pattern 5 (Secret Type Lifecycle) enforces `ZeroizeOnDrop`. `PortableKey` supports encrypted key storage. |
| **Use constant-time operations** | Prevent timing side-channels | Pattern 5 property 3: all secret comparisons use `subtle::ConstantTimeEq`. |

## Hybrid Construction Standards

| Reference | Title | How We Apply It |
|-----------|-------|----------------|
| **Bindel et al., PQCrypto 2019** | "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange" | Our hybrid KEM uses the HKDF dual-PRF combiner pattern: `HKDF(ML-KEM_ss ‖ ECDH_ss)`. Theorem 3.1 proves this is secure if either component remains pseudorandom. |
| **IETF draft-ietf-lamps-pq-composite-kem** | Composite KEM for hybrid key exchange | Our `HybridKemPublicKey` concatenates ML-KEM and X25519 public keys following the composite encoding. |
| **IETF draft-ietf-tls-hybrid-design** | Hybrid Key Exchange in TLS 1.3 | Out of scope for this crate — consumers use rustls-native `X25519MLKEM768` directly. Informs our hybrid combiner choice for data-at-rest, not TLS. |
| **NIST SP 800-227 (draft)** | Recommendations for Key Encapsulation Mechanisms | ML-KEM parameter selection follows SP 800-227 guidance for security categories 1/3/5. |

---

# Rust Secure Coding Practices

These practices leverage Rust's ownership model, type system, and compiler guarantees
to make entire classes of cryptographic bugs structurally impossible.

## Why Rust Is The Right Language for This Library

| Rust Feature | Security Benefit | How We Use It |
|-------------|-----------------|---------------|
| **Ownership & borrowing** | Memory safety without GC — no use-after-free, no double-free | Secret types move (not copy). `Zeroizing<Vec<u8>>` owns key bytes; dropping the owner zeroizes and deallocates. |
| **No implicit copies** | Secret material cannot be accidentally duplicated | Secret types do not derive `Clone`. Passing a key to a function moves it — the caller cannot use it again. |
| **`Drop` trait** | Deterministic destruction at scope exit | Every secret type implements `Drop` (via `ZeroizeOnDrop`) ensuring keys are zeroized even on panic unwind. |
| **Type system (newtypes)** | Prevents mixing different crypto values | `MlKemPublicKey`, `MlKemSecretKey`, `MlKemCiphertext` are distinct types — the compiler rejects `decrypt(public_key, public_key)`. |
| **`#[deny(unsafe_code)]`** | Memory safety is provable | The entire crate denies unsafe. All memory access is bounds-checked by the compiler. (aws-lc-rs uses unsafe internally for FFI — that's their responsibility, audited by AWS.) |
| **Sealed traits** | Prevent broken external implementations | `AeadCipher`, `EcKeyPair`, `EcSignature` use the sealed-trait pattern. External crates cannot implement them with non-constant-time or non-zeroizing logic. |
| **`#[must_use]`** | Prevent discarding security-critical values | `generate_key()`, `allow_request()`, and builder methods are `#[must_use]` — the compiler warns if the return value is dropped. |
| **`#[non_exhaustive]`** | Semver-safe enum extensibility | All 70 public enums are `#[non_exhaustive]`, allowing new algorithm variants without breaking 30+ downstream enterprise crates. |
| **Workspace lints** | Consistent enforcement across all crates | `deny(unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)` — no crate can opt out. |

## Rust-Specific Anti-Patterns We Prevent

The six anti-patterns in this section are teaching examples. The normative
rules governing every type that holds secret material live in
[`SECRET_TYPE_INVARIANTS.md`](SECRET_TYPE_INVARIANTS.md) — ten invariants
(I-1 through I-10) enforced by the compile-time barrier at
`latticearc/tests/no_partial_eq_on_secret_types.rs`, by universal adoption of
the sealed `expose_secret()` accessor, and by CI clippy/audit rules. When the
examples below and the spec disagree, the spec wins.

### Anti-Pattern 1: Derived Debug on Secrets
```rust
// WRONG — Rust's #[derive(Debug)] prints all fields including secrets
#[derive(Debug)]
struct Key { bytes: [u8; 32] }
// println!("{:?}", key) → "Key { bytes: [172, 58, 91, ...] }" — LEAKED

// RIGHT — Manual Debug redacts secret fields
impl Debug for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key").field("bytes", &"[REDACTED]").finish()
    }
}
```

### Anti-Pattern 2: Clone on Secrets
```rust
// WRONG — Clone creates an uncontrolled copy of key material
#[derive(Clone)]
struct PrivateKey { bytes: Vec<u8> }
let copy = key.clone(); // Two copies of the same key in memory

// RIGHT — No Clone. Borrow via the sealed `expose_secret()` accessor; for
// deliberate duplication, expose an explicit, grep-able method.
struct PrivateKey { bytes: Zeroizing<Vec<u8>> }
impl PrivateKey {
    pub fn expose_secret(&self) -> &[u8] { &self.bytes }   // Sealed borrow, not copy
    pub fn clone_for_transmission(&self) -> Self { /* ... */ } // Audit-able copy
}
```

The accessor is named `expose_secret()` — never `as_bytes()` or `as_slice()` — so
that every site touching secret bytes is grep-able as a distinct audit point.
Public bytes (e.g., `PublicKey`, signatures, ciphertexts) keep `as_bytes()`/
`as_slice()`; the naming distinction is structural. See
[`docs/SECRET_TYPE_INVARIANTS.md`](SECRET_TYPE_INVARIANTS.md) — the canonical,
normative spec for every type holding secret material — for the full rule set
(invariants I-1 through I-10), including why `AsRef<[u8]>`/`Deref` are also
forbidden on secret types.

### Anti-Pattern 3: Short-Circuit Comparison
```rust
// WRONG — && short-circuits: returns false on first mismatch (timing leak)
let valid = tag_length_ok && mac_matches;

// RIGHT — & evaluates both sides regardless (constant time)
let valid = tag_length_ok & mac_matches;
```

### Anti-Pattern 4: Unwrap in Crypto Code
```rust
// WRONG — unwrap crashes the process on error
let key = generate_key().unwrap();

// RIGHT — propagate errors, let the caller decide
let key = generate_key().map_err(|e| CryptoError::KeyGenFailed(e))?;
```
The workspace denies `clippy::unwrap_used` and `clippy::panic`. The only exceptions
are in `#[cfg(test)]` modules with `#[allow(clippy::unwrap_used)]` and a justification.

### Anti-Pattern 5: Public Fields on Crypto Types
```rust
// WRONG — external code can construct invalid ciphertexts
pub struct Ciphertext { pub nonce: Vec<u8>, pub data: Vec<u8> }
let fake = Ciphertext { nonce: vec![], data: vec![0xFF] }; // Invalid but compiles

// RIGHT — private fields + validated constructor + getters
pub struct Ciphertext { nonce: Vec<u8>, data: Vec<u8> }
impl Ciphertext {
    pub fn new(nonce: Vec<u8>, data: Vec<u8>) -> Result<Self, Error> {
        if nonce.len() != 12 { return Err(Error::InvalidNonce); }
        Ok(Self { nonce, data })
    }
    pub fn nonce(&self) -> &[u8] { &self.nonce }
    pub fn data(&self) -> &[u8] { &self.data }
}
```

Note: Consuming structs expose `into_parts()` for destructuring without field access
(see `PqOnlyCiphertext::into_parts()`).

### Anti-Pattern 6: Bare Vec<u8> Returns for Secrets
```rust
// WRONG — caller may forget to zeroize the returned key
pub fn export_key(&self) -> Vec<u8> { self.bytes.clone() }

// RIGHT — Zeroizing wrapper ensures cleanup on drop
pub fn export_key(&self) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(self.bytes.to_vec())
}
```

## Formal Verification Integration

Rust's type system catches many bugs at compile time, but cryptographic correctness
requires stronger guarantees. We use:

| Tool | What It Verifies | Where |
|------|-----------------|-------|
| **Kani** | Bounded model checking — proves domain constant uniqueness, state machine correctness | `types/domains.rs` Kani proofs, `types/key_lifecycle.rs` state transition proofs |
| **Proptest** | Property-based testing — statistical verification of crypto properties (roundtrip, independence, uniqueness) | `tests/tests/proptest_*.rs` — 256+ cases per property |
| **CAVP** | Known Answer Tests against NIST test vectors | `prelude/cavp_compliance.rs`, `tests/src/validation/` |
| **Clippy deny-all** | Static analysis — catches arithmetic overflow, indexing, unused code | `Cargo.toml` workspace lint config |
| **cargo audit** | Dependency vulnerability scanning | CI pipeline, pre-push hook |
| **cargo deny** | License compliance, banned crates, source restrictions | `deny.toml` — forbids `libc`, `nix`, GPL crates |

---

# Coding Style Guide

Consistent style makes code reviewable, auditable, and maintainable. These are not
preferences — they are rules enforced by CI and code review.

## Rust Edition and Toolchain

| Setting | Value | Why |
|---------|-------|-----|
| Edition | 2024 | Latest Rust edition for modern syntax and new language features |
| MSRV | 1.93 | Minimum Supported Rust Version — all CI runs against this |
| Formatter | `rustfmt` with `max_width = 100` | 100-char line width balances readability and diff size |
| Linter | `cargo clippy` with workspace-level `deny` lints | Zero warnings policy — every clippy warning is a compile error |

## Modern Rust Idioms (1.93-era best practices)

The codebase uses these idioms across crypto-relevant paths. Reviewers
should flag deviations during PR review even if the older form
compiles cleanly.

| Idiom | Stable since | Use it when | Avoid for |
|-------|--------------|-------------|-----------|
| `let-else` | 1.65 | Early-return on `Option`/`Result` you'd otherwise `match` with one bind arm | Multi-arm matches; stick with `match` for exhaustiveness |
| `if let` chains (`let X && let Y`) | 1.88 | Chained binding when both must succeed | Three+ bindings — extract a helper |
| `format!("{e}")` captured-identifier | 1.58 | Always preferred over `format!("{}", e)` | Never use the positional form |
| `std::sync::LazyLock` | 1.80 | Static lazy initialization without `lazy_static!` / `once_cell` | Per-thread lazy init (use `thread_local!`) |
| `#[expect(lint)]` | 1.81 | Lint-allow that should resolve as code evolves — compile error if lint becomes irrelevant | A genuinely permanent allow (use `#[allow]`) |
| `core::hint::black_box` | 1.66 | Constant-time microbenches that need to defeat the optimizer | Cryptographic constant-time — use `subtle` traits, not `black_box` |
| `OsStr::display()` | 1.87 | Path / OsStr display in user-facing messages | — |
| `std::mem::offset_of!` | 1.77 | Layout assertions in `static_assertions!` blocks | FFI struct layout — use `#[repr(C)]` + tests |
| `c"..."` C string literals | 1.77 | FFI bindings that need null-terminated bytes | Internal-only string handling |

**Closure of obsolete patterns:**

- ❌ `lazy_static!` macro — use `std::sync::LazyLock`
- ❌ `once_cell::sync::Lazy` — same; std now covers this
- ❌ `format!("{}", x)` for any captured identifier — use `format!("{x}")`
- ❌ `match opt { Some(x) => x, None => return ... }` — use `let-else`
- ❌ `#[allow(clippy::xxx)]` for transient noise — use `#[expect(clippy::xxx)]` so the allow is removed automatically when the underlying issue is fixed

## Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Types (structs, enums, traits) | `PascalCase` | `MlKemSecurityLevel`, `AeadCipher`, `HybridCiphertext` |
| Functions, methods | `snake_case` | `generate_keypair()`, `encrypt_hybrid()`, `derive_encryption_key()` |
| Constants | `SCREAMING_SNAKE_CASE` | `HYBRID_KEM_SS_INFO`, `NONCE_LEN`, `TAG_LEN` |
| Type parameters | Single uppercase letter or short `PascalCase` | `<T>`, `<R: RngCore>` |
| Feature flags | `kebab-case` | `fips`, `fn-dsa`, `zkp-serde` |
| Module files | `snake_case.rs` | `ml_kem.rs`, `encrypt_hybrid.rs`, `key_lifecycle.rs` |
| Test functions | `test_<what>_<condition>_<expected>` | `test_ml_kem_encrypt_empty_key_fails` |
| Influence tests | `test_<field>_influences_<operation>` | `test_security_level_influences_scheme_selection` |

## Error Handling Style

```rust
// PATTERN: thiserror for error types, Result<T, E> for all fallible functions
#[derive(Debug, Error)]
pub enum KemError {
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),
    #[error("Encapsulation failed: {0}")]
    EncapsulationError(String),
}

// PATTERN: map_err with {e} format (captured-identifier shorthand,
// stable since 1.58 — see "Modern Rust Idioms" above), never `{}`,
// never `{:?}`
let key = generate().map_err(|e| KemError::KeyGenerationError(format!("{e}")))?;

// PATTERN: context-rich errors that name the operation and the cause
// WRONG: Err("failed")
// RIGHT: Err(CoreError::EncryptionFailed(format!("AES-GCM encryption failed: {e}")))
```

> ⚠️ **`format!("{e}")` is for non-adversary-reachable errors only**
> (programmer mistakes, configuration errors, I/O setup). For any
> decrypt / decapsulate / verify / authenticate path that an attacker
> can reach, see [Pattern 6: Error Opacity on Adversary-Reachable
> Paths](#pattern-6-error-opacity-on-adversary-reachable-paths) — the
> upstream error's `Display` (let alone `Debug`) walks the source
> chain and can leak attacker-controlled JSON snippets, byte offsets,
> or variant fingerprints. Use `Display` (`%e`) over `Debug` (`?e`)
> when logging via `tracing::debug!`, and prefer a single opaque
> `VerificationFailed` / `DecryptionFailed` variant over `format!`
> with the upstream cause.

## Function Signature Style

```rust
// PATTERN: #[instrument] for tracing on crypto operations
#[instrument(level = "debug", skip(secret_key), fields(security_level = ?level))]
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, SignError> {

// PATTERN: skip secret parameters in tracing (never log key material)
// PATTERN: include metadata fields (security_level, data_len) for debugging

// PATTERN: #[must_use] on all pure functions returning values
#[must_use]
pub fn generate_nonce() -> [u8; NONCE_LEN] {

// PATTERN: Resource validation at the top of every public crypto function
pub fn encrypt(data: &[u8], key: &Key) -> Result<Vec<u8>, Error> {
    validate_encryption_size(data.len())?;  // DoS prevention
    // ... crypto operations ...
}
```

## Structural Invariants with `debug_assert!`

`debug_assert!` is used for structural invariants in constructors (e.g., `EncryptedOutput::new()`
validates PQ-only scheme has empty ECDH key). These fire in debug/test builds without runtime
cost in release.

```rust
// PATTERN: debug_assert! for structural invariants (not security checks)
pub fn new(scheme: CryptoScheme, components: HybridComponents) -> Self {
    debug_assert!(
        scheme != CryptoScheme::PqOnly || components.ecdh_ephemeral_pk.is_empty(),
        "PQ-only output must have empty ECDH component"
    );
    Self { scheme, components }
}
```

Note: `debug_assert!` is appropriate only for programmer-error invariants that are guaranteed
by construction. Security-critical checks must use `Result`-returning validation (not `assert!`).

## Import Organization

```rust
// PATTERN: Group imports in this order, separated by blank lines:

// 1. Standard library
use std::fmt;
use std::collections::BTreeMap;

// 2. External crates
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use subtle::ConstantTimeEq;

// 3. Internal crate modules
use crate::primitives::aead::AeadCipher;
use crate::types::domains;
```

## Module File Structure

Every module file follows this order:

```rust
// 1. Module-level lint attributes (OPTIONAL — workspace lints in
//    `Cargo.toml`'s `[workspace.lints.rust]` and `[workspace.lints.clippy]`
//    already enforce these workspace-wide. Per-file `#![deny(...)]`
//    is belt-and-suspenders: useful in security-sensitive modules
//    where a future contributor might accidentally relax workspace
//    lints, but redundant for most modules. Use for `unsafe_code`,
//    `missing_docs`, `clippy::unwrap_used`, `clippy::panic` at your
//    discretion; the workspace floor already catches violations.)
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

// 2. Module-level documentation (//! doc comments)
//! Module description — what this module provides and why.

// 3. Imports (grouped as above)

// 4. Constants and type aliases

// 5. Error types (#[non_exhaustive] pub enum XxxError)

// 6. Public types (structs, enums) with full /// doc comments

// 7. Implementations (impl blocks, trait impls)

// 8. Private helper functions

// 9. Tests (#[cfg(test)] mod tests { ... })
```

## The `#[allow(...)]` Convention

Every `#[allow]` override in production code must have a justification comment on the
same line or immediately above explaining why the suppression is safe:

```rust
// GOOD — justification explains why the indexing is bounded
#[allow(clippy::indexing_slicing)] // ZETAS[k] where k ∈ [0,127] for ZETAS: [i32; 128]
fn ntt(coefficients: &mut [i32; 256]) { ... }

// GOOD — justification explains the EC math exception
#[allow(clippy::arithmetic_side_effects)] // EC point addition is modular, cannot overflow
fn pedersen_commit(v: Scalar, r: Scalar) -> ProjectivePoint { ... }

// BAD — no justification
#[allow(dead_code)]
fn unused_helper() { ... }  // Why does this exist? Remove it.
```

---

# Documentation Style Guide

Clear documentation is as important as correct code. A crypto library that nobody can
understand is a crypto library nobody can audit.

## Doc Comment Format

Every public item (`pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub const`) must have
a `///` doc comment. Module-level docs use `//!`.

### Function Documentation Template

```rust
/// One-line summary in imperative mood ("Generate", "Encrypt", "Verify").
///
/// Extended description if needed — explain the algorithm, security properties,
/// or non-obvious behavior. Reference NIST standards inline:
/// "Uses AES-256-GCM (NIST SP 800-38D) for authenticated encryption."
///
/// # Arguments
///
/// * `data` - The plaintext to encrypt (arbitrary length)
/// * `key` - AES-256 key (must be exactly 32 bytes)
///
/// # Returns
///
/// A tuple of `(ciphertext, tag)` where the tag is 16 bytes.
///
/// # Errors
///
/// Returns [`AeadError::InvalidKeyLength`] if the key is not 32 bytes.
/// Returns [`AeadError::EncryptionFailed`] if the AEAD operation fails.
///
/// # Security
///
/// - Nonce is generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - Key material is zeroized on drop (SP 800-57 §8.3.1)
/// - This function is constant-time with respect to the key
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::aead::aes_gcm::AesGcm256;
/// use latticearc::primitives::aead::AeadCipher;
///
/// let key = AesGcm256::generate_key();
/// let cipher = AesGcm256::new(&*key)?;
/// // `seal` encapsulates nonce generation per Pattern 3 — prefer
/// // it over the lower-level `encrypt(&nonce, ...)` form which
/// // exists for KAT/CAVP test paths only.
/// let blob = cipher.seal(b"secret data", None)?;
/// # Ok(())
/// # }
/// ```
pub fn seal(&self, data: &[u8], aad: Option<&[u8]>) -> Result<EncryptedBlob, AeadError> {
```

### Required Doc Sections by Item Type

| Item Type | Required Sections |
|-----------|------------------|
| Public function | Summary, `# Errors`, `# Example` (or `no_run` if it requires setup) |
| Crypto function | All above + `# Security` (nonce handling, zeroization, timing) + `# Arguments` |
| Config field | One-line description + `/// Consumer: fn_name()` |
| Public struct | Summary, field descriptions, `# Security` if holds secrets, `# Example` |
| Public enum | Summary, variant descriptions |
| Public trait | Summary, `# Implementors` (or "Sealed — cannot be implemented outside this crate") |
| Error enum | Summary, variant descriptions with when-each-occurs |
| Constants | One-line description + which module/function uses it |

### The `# Security` Section

Every function that handles secret material must have a `# Security` doc section listing:

1. **What key material it handles** and how it's protected
2. **Nonce/IV generation** — internal or caller-supplied
3. **Timing properties** — constant-time or not, and with respect to which input
4. **Zeroization** — which values are zeroized and when
5. **Error information** — whether error messages are opaque (for decrypt paths)

```rust
/// # Security
///
/// - The shared secret is wrapped in `Zeroizing` and zeroized on drop
/// - Nonce is generated internally from OS CSPRNG (never caller-supplied)
/// - AES-GCM authentication tag comparison is constant-time
/// - Decrypt errors are opaque ("AEAD authentication failed") to prevent oracles
```

### Doc Comment Style Rules

| Rule | Example |
|------|---------|
| Start with imperative verb | "Generate a keypair" not "This function generates a keypair" |
| Reference standards inline | "Uses HKDF-SHA256 (SP 800-56C Rev.2)" |
| Link to related items | "See [`MlKemSecurityLevel`] for parameter sets" |
| No marketing language | "Policy-based selection" not "Intelligent selection" |
| No speculative claims | "Supports ML-KEM-768" not "Will support all future NIST algorithms" |
| Explain the WHY for non-obvious code | `// Dual-bind AAD into both HKDF info and AEAD input (prevents AAD substitution)` |
| Use `///` for items, `//` for logic | `///` = API contract, `//` = implementation notes |

### Inline Comment Conventions

```rust
// PATTERN: Explain WHY, not WHAT. The code shows what; the comment explains why.

// WRONG
// Increment counter
counter += 1;

// RIGHT
// Advance to next HKDF iteration (SP 800-108 §5.1 counter mode)
counter += 1;

// PATTERN: Security-critical comments use these prefixes:
// SECURITY: <explanation of security-critical decision>
// AUDIT-TRACKED(#NN): <known limitation, linked to an OPEN tracking issue>
// Wire <field>: <explains which config field is being consumed here>

// PATTERN: TODO/FIXME are forbidden in production (workspace denies todo!())
// Use issue tracker references instead:
// See: https://github.com/LatticeArc/latticearc/issues/123
```

### ASCII Diagrams in Module Docs

Complex modules include ASCII flow diagrams in their `//!` doc comments to show
data flow. This is critical for crypto modules where the reader must understand
the construction at a glance.

```rust
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  HYBRID KEM: Encapsulation Flow                 │
//! ├─────────────────────────────────────────────────┤
//! │  ML-KEM-768 Encaps ──► SS₁ (32 B)              │
//! │  X25519 ECDH        ──► SS₂ (32 B)              │
//! │  HKDF-SHA256(SS₁ ‖ SS₂, info=domain) ──► 64 B  │
//! └─────────────────────────────────────────────────┘
//! ```
```

Every `hybrid/` and `primitives/` module should have a flow diagram.
Every `unified_api/` module should have an API usage diagram.

---

# Section 1: Architecture Patterns

## Pattern 1: Layered Primitives Routing

### What
All cryptographic computation routes through `latticearc::primitives`. Upper layers
(`hybrid`, `unified_api`, `zkp`) import from `primitives` — never from external crates.

### Why This Is The Right Pattern
A crypto library has one job: guarantee that every operation uses correct, hardened
implementations. If encryption can happen via two paths — one through the hardened
wrapper and one directly calling `aws-lc-rs` — then zeroization, error mapping, resource
limits, instrumentation, and FIPS compliance can all be bypassed. A single routing point
makes safety properties **structural**, not behavioral.

This also enables proprietary extensibility: enterprise crates (`arc-enterprise-security`,
`arc-enterprise-cce`) call the same `primitives` API. If a FIPS backend changes (e.g.,
aws-lc-rs → BoringSSL update), only `primitives` needs updating — all 30+ enterprise
crates automatically get the fix.

### Rules

| Layer | May import `primitives/` | May import external crypto crates | May import `subtle` | May import `OsRng`/`rand` |
|-------|------|------|------|------|
| `primitives/` | Self | YES (wraps them) | YES | YES |
| `hybrid/` | YES | NO | YES (ct_eq only) | NO |
| `unified_api/` | YES | NO | YES (ct_eq only) | NO |
| `zkp/` | YES | k256 EC math only (no wrapper exists) | YES | NO |
| `types/` | NO | NO | YES | NO |
| Enterprise crates | YES (via `latticearc` dep) | NO | YES | NO |

**Documented exceptions** (each must have a code comment explaining why):
- `zkp/` uses `k256` for secp256k1 group arithmetic — no primitives wrapper for EC scalar math
- `prelude/error/` imports `aws_lc_rs::error` types for `From` impls

### How To Follow It
- New crypto operation? Add a wrapper in `primitives/`, then call it from the upper layer.
- Need randomness? Call `crate::primitives::rand::csprng::random_bytes(n)`. Never `OsRng`.
- Need AES-GCM? Call `crate::primitives::aead::aes_gcm::AesGcm256`. Never `aws_lc_rs::aead`.

---

## Pattern 2: Domain Separation Registry

### What
Every HKDF info/label string is a named constant in `types/domains.rs`. No inline
`b"..."` literals for HKDF parameters in production code. A Kani formal proof verifies
all constants are pairwise distinct.

### Why This Is The Right Pattern
NIST SP 800-108 §4 and SP 800-56C §4 require unique labels per KDF application. If two
different protocols accidentally use the same HKDF label, keys derived for one protocol
can decrypt traffic from another — a catastrophic cross-protocol attack.

Centralizing labels in one file with a formal proof makes collisions **impossible**, not just
unlikely. This is especially critical for proprietary extensibility: the CCE engine adds
17 dimension-specific key derivations. Each needs a unique label. Without a registry, a
dimension author could accidentally collide with the core hybrid encryption label.

### Rules
1. Every HKDF `info` parameter must reference a constant from `types::domains::*`
2. New HKDF use → add constant to `domains.rs` → add to Kani proof → reference by name
3. The Kani proof must cover ALL constants (currently 8, checking all 28 pairs — C(8,2))
4. ZKP Fiat-Shamir labels use a separate namespace (`arc-zkp/*`) and do not collide because they use a different hash construction (not HKDF)

---

## Pattern 3: Nonce Encapsulation

### What
High-level encrypt APIs generate nonces internally via `primitives::aead::*::generate_nonce()`.
No high-level API accepts a caller-supplied nonce.

### Why This Is The Right Pattern
NIST SP 800-38D §8.2 requires nonce uniqueness per key. A caller who supplies nonces can
(and eventually will) reuse one, which completely breaks AES-GCM confidentiality. By
generating nonces inside the encrypt function, the library enforces uniqueness by construction.

Low-level `primitives::aead` functions MAY accept nonces for KAT/CAVP testing — that's the
correct layer for it, since test code is the only legitimate reason to supply a nonce.

---

## Pattern 4: Sealed Security Traits

### What
Traits defining security-critical operations (`AeadCipher`, `EcKeyPair`, `EcSignature`)
use the Rust sealed-trait pattern to prevent external implementation.

### Why This Is The Right Pattern
If an external crate implements `AeadCipher`, it could bypass key validation, skip
zeroization, or use non-constant-time comparisons. Sealing prevents this while still
allowing the trait to be used as a bound in generic code.

### How
```rust
mod sealed { pub trait Sealed {} }
pub trait AeadCipher: sealed::Sealed { /* ... */ }
impl sealed::Sealed for AesGcm256 {}
```

---

# Section 2: Cryptographic Safety Patterns

## Pattern 5: Secret Type Lifecycle

### What
Every Rust struct holding cryptographic secret material must enforce 5 properties.

### Why This Is The Right Pattern
NIST SP 800-57 Part 1 Rev.5 §8.3 requires keys to be destroyed when no longer needed.
SP 800-175B §4.1 requires protection against timing side-channels. These are not
guidelines — they are requirements for FIPS 140-3 validation.

### The 5 Required Properties

| # | Property | Implementation | NIST Reference |
|---|----------|---------------|----------------|
| 1 | **Zeroize on drop** | `#[derive(ZeroizeOnDrop)]` or manual `impl Drop` calling `zeroize()` | SP 800-57 §8.3.1 |
| 2 | **Redacted Debug** | Manual `impl Debug` printing `[REDACTED]`. Never `#[derive(Debug)]`. | Prevents log leakage |
| 3 | **Constant-time eq** | `impl subtle::ConstantTimeEq` using `&` not `&&` | SP 800-175B §4.1 |
| 4 | **No Clone** | Do not implement `Clone`. If required (serde), add `AUDIT-TRACKED(#NN)` comment linking an open issue. | Prevents uncontrolled copies |
| 5 | **Private fields** | No `pub` on secret fields. Expose via `&[u8]` getters. Owned returns use `Zeroizing<Vec<u8>>`. | Prevents external mutation |

### The AUDIT-TRACKED Convention
When an upstream type (e.g., aws-lc-rs `DecapsulationKey`) does not support Rust-level
`Zeroize`, document the delegation **and open a GitHub tracking issue**. The marker
always references the issue number so auditors can see what's still pending:
```rust
/// # Zeroization
///
/// AUDIT-TRACKED(#48): Zeroization delegated to aws-lc-rs (BoringSSL zeros on free).
/// Rust-level ZeroizeOnDrop cannot be derived because DecapsulationKey does not
/// implement Zeroize. Re-evaluate once aws-lc-rs exposes Zeroize; see #48.
```

**Rule:** `AUDIT-TRACKED(#NN)` requires an **open** issue. If the referenced issue is
closed, the marker must either be removed (the limitation was resolved) or updated to
point at a new open issue. We deliberately do not use "AUDIT-ACCEPTED" — "accepted"
implies closure and creates a false sense of audit completeness. Tracked limitations
stay visible until genuinely resolved.

### Constant-Time Equality — The Canonical Pattern
From `slh_dsa.rs` (the reference implementation, reproduced verbatim):
```rust
impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare security level in constant time
        let level_eq = (self.security_level as u8).ct_eq(&(other.security_level as u8));
        // Compare length in constant time
        let len_eq = self.len.ct_eq(&other.len);
        // Compare bytes in constant time (only up to the actual length)
        let bytes_eq = self.bytes[..self.len].ct_eq(&other.bytes[..other.len]);
        level_eq & len_eq & bytes_eq
    }
}
```
**Three components, ALL combined with `&`** (bitwise AND, NOT `&&` short-circuit):
1. Discriminant / parameter set (`level_eq`)
2. Length prefix (`len_eq`) — for over-allocated buffers where the
   declared length is smaller than the underlying array, this prevents
   an attacker from probing past-end bytes
3. Bytes-up-to-length (`bytes_eq`) — sliced to `self.len` so an
   attacker who controls a buffer with garbage tail bytes can't pass
   `ct_eq` by matching only the active prefix

**Never** use `if level != ... { return Choice::from(0) }` before
the byte comparison — that leaks timing. **Never** use `&&`
(short-circuit) — use `&` (bitwise AND) to evaluate all branches in
constant time. **Always include the length component** if the type's
storage is over-allocated; copying this pattern without `len_eq`
re-introduces a leak the slh_dsa reference closes.

---

## Pattern 6: Error Opacity on Adversary-Reachable Paths

### What
**On any path where an adversary supplies input** (decrypt, decap, verify, deserialize
from wire, etc.):

1. **Returned error values** are opaque — identical across all failure modes (parse fail,
   MAC fail, decap fail, HKDF fail, etc.). The caller / remote client / potential
   adversary sees only a single `"decryption failed"`-style message and a single error
   variant.
2. **Internal `tracing::debug!` / `log_crypto_operation_error!` calls** preserve the
   specific reason. Operators debug via structured log output correlated by request ID.

On paths that are NOT adversary-reachable (caller-side programmer mistakes, operational
I/O errors, internal state transitions), distinguishable errors are fine and often
desirable — they help legitimate callers diagnose their own bugs.

### Why This Is The Right Pattern
- **Vaudenay 2002** demonstrated that distinguishing "MAC failed" from "padding failed"
  enables a padding oracle that recovers plaintext byte-by-byte.
- **NIST SP 800-38D §5.2.2** requires AEAD decryption to return only "FAIL" with no
  additional information.
- **HPKE RFC 9180 §5.2** — `ContextR.Open` returns a single `OpenError` for all failure
  modes (parse, decap, AEAD).
- **TLS 1.3 RFC 8446 §5.2** — all AEAD record protection failures collapse to
  `bad_record_mac`.
- **aws-lc-rs** — uses a single `Unspecified` error type across its entire surface,
  citing in its own docs: *"providing more details about a failure might provide a
  dangerous side channel"*.

### Industry reference — how everyone does the split

| Library | External return | Internal observability |
|---|---|---|
| aws-lc-rs / BoringSSL / OpenSSL | `Unspecified` / return 0 | `ERR_put_error` queue accessible via `ERR_get_error` |
| rustls | `Error::InvalidMessage` (generic) | `tracing::debug!` with full context |
| Signal / WireGuard | Failed messages silently dropped | Diagnostic counters / internal logs |

Our equivalent: opaque `CoreError::DecryptionFailed("decryption failed")` returned to
the caller; the `log_crypto_operation_error!` macro (which expands to `tracing::debug!`
at `target: "crypto::operation"`) with the specific reason written to the structured
log, indexed by correlation ID. Always go through the macro — it owns the log level,
target, and field schema centrally.

### The Canonical Pattern (Rust) — exactly one form for every adversary-reachable site

There is **one** Rust pattern for this library. Do not invent variants.

1. **Returned error**: fixed opaque string in a single error variant. Use a local
   `let opaque = || ErrorType::Variant("decryption failed".to_string());` closure when
   the same error is returned from 2+ branches in the same function. Zero captures,
   zero cost on the happy path.
2. **Internal log**: always via the `log_crypto_operation_error!` macro from
   `latticearc::unified_api::logging`. **Do not** call `tracing::debug!` /
   `tracing::error!` directly with `target: "crypto::operation"` — the macro
   already handles level, target, structured fields (`operation`, `error`,
   `phase`, `correlation_id`).
3. **Level**: the macro emits at `DEBUG` (not `error!`). Rationale: adversary-reachable
   decrypt failures are *normal* under attack. Logging them at `error!` lets an attacker
   DoS the log aggregator by flooding garbage. Operators enable
   `RUST_LOG=crypto::operation=debug` on demand and correlate by ID. Matches rustls /
   OpenSSL ERR-queue behavior.
4. **One specific reason string per branch**: name the STAGE that rejected, not the
   upstream error object. The upstream error (`aws-lc-rs::Unspecified`, etc.) goes to
   `_` because relying on upstream Display staying opaque across versions is fragile.

```rust
// ✅ Correct — exactly this shape, every site.
//
// Use `op::X` constants from `latticearc::unified_api::logging::op` for the
// operation tag (NOT a bare `&str` literal). Operators filter/correlate logs
// by this tag, so a typo silently loses that stage's observability. The const
// tag stays stable across stages within one function.
use crate::log_crypto_operation_error;
use crate::unified_api::logging::op;

let opaque = || CoreError::DecryptionFailed("decryption failed".to_string());

let ct = MlKemCiphertext::new(level, bytes).map_err(|_e| {
    log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "invalid ML-KEM ciphertext");
    opaque()
})?;
let ss = MlKem::decapsulate(&sk, &ct).map_err(|_e| {
    log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "ML-KEM decapsulation failed");
    opaque()
})?;
let pt = cipher.decrypt(&nonce, &ct, &tag, aad).map_err(|_aead_err| {
    log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "AEAD authentication failed");
    opaque()
})?;
```

**Anti-patterns — never do any of these:**

```rust
// ❌ Wrong 1: upstream error Display leaks through format!
.map_err(|e| PqOnlyError::KemError(format!("Invalid ML-KEM ciphertext: {e}")))?
//                                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ stage-specific + includes upstream e

// ❌ Wrong 2: raw tracing::debug! with the target string instead of the macro
.map_err(|_e| {
    tracing::debug!(target: "crypto::operation", "decrypt: invalid ciphertext");
    //              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ should be log_crypto_operation_error!
    opaque()
})?

// ❌ Wrong 3: tracing::error! or log_crypto_operation_error! that emits at error level
tracing::error!(target: "crypto::operation", "decrypt failed");
// Production log spam under attack probing; operators can't distinguish real incidents
// from attacker noise. Use the debug-level macro instead.

// ❌ Wrong 4: distinguishable returned strings per stage
.map_err(|_| PqOnlyError::KemError("KEM failed".to_string()))?
.map_err(|_| PqOnlyError::AeadError("AEAD failed".to_string()))?
// Attacker distinguishes stages via variant name / Display. Use a single variant
// with the same string for every adversary-reachable branch.
```

### When It Applies

**MUST be opaque (adversary-reachable):**
- AEAD decrypt / `open` — every stage from size check through tag verification
- KEM decapsulate — from ciphertext parse through shared-secret derivation
- Signature verify — from PK / signature parse through the final verify
- Deserialization of ciphertext / signature / attacker-controlled key from wire
- Any HKDF / key-derivation step in a decrypt/decap pipeline
- Any resource-limit check on adversary-supplied input sizes

**SHOULD be opaque (encrypt-side defense-in-depth):**
- AEAD encrypt / seal — even though adversary doesn't usually craft inputs, don't rely
  on that assumption. Upstream errors (e.g. aws-lc-rs `Unspecified`) are opaque today
  but future versions may not be.
- KEM encapsulate, sign — same reasoning

**MAY stay distinguishable (not adversary-reachable):**
- Wrong key length from caller (programmer mistake; legitimate user wants to know)
- Local I/O failures (audit log write, file open) — filesystem errors are not
  adversary-controlled
- Internal state transitions (session expired, challenge generation failure)
- Config validation (wrong algorithm enum value from the application, not the wire)

### How to Enforce

1. **Grep check — no upstream-error leaks in crypto paths:**
   ```sh
   rg 'format!\([^)]*\{e\}[^)]*"\|e\.to_string\(\) *\)' \
      src/primitives/{aead,kem,sig,mac,kdf} \
      src/hybrid \
      src/unified_api/convenience \
      --glob '!**/tests/**'
   ```
   Every hit must be either (a) on a non-adversary-reachable path with a comment
   documenting why, or (b) converted to the canonical pattern above.

2. **Grep check — no raw `tracing::debug!` on `crypto::operation`:**
   ```sh
   rg 'tracing::(debug|info|warn|error)!\(target: "crypto::operation"' src/
   ```
   Every hit must use `log_crypto_operation_error!` instead. If the macro does not fit,
   update the macro, not the call site.

3. **Review checklist** — when reviewing any PR that touches an error path in
   `primitives/{aead,kem,sig,mac,kdf}`, `hybrid/`, or `unified_api/convenience/`, ask:
   *"Is the caller of this error adversary-controlled? If yes, does the returned error
   distinguish stages?"*

4. **Manual Debug impl on Error enums** — never derive `Debug` on an error variant that
   wraps `String` produced from a library error, if the error is returned from an
   adversary-reachable path. Derive is fine only if the variant itself is already opaque.

5. **Tests** — regression tests that feed different failure modes and assert the
   returned error is byte-identical. Example: `test_encrypt_with_passphrase_corrupted_
   ciphertext_matches_wrong_passphrase_error` in `key_format.rs`.

---

## Pattern 7: Hybrid Combiner Safety

### What
Hybrid encryption/KEM combines PQC and classical shared secrets via HKDF-SHA256 with
domain separation and public-key binding.

### Why This Is The Right Pattern
The HKDF dual-PRF lemma (Bindel et al., PQCrypto 2019) proves that if either input to
HKDF-Extract is pseudorandom, the output is pseudorandom. This means the hybrid is
secure as long as **either** ML-KEM **or** X25519 remains unbroken — the standard
definition of hybrid security.

Public-key binding in the HKDF info parameter prevents cross-key attacks where an attacker
replays a ciphertext under a different key. The domain label prevents cross-protocol
attacks where the same shared secret is used for different purposes.

### The Pattern
```
shared_secret = HKDF-SHA256(
    IKM = ML-KEM_ss ‖ ECDH_ss,
    salt = None,
    info = domain_label ‖ len(pk_static) ‖ pk_static ‖ len(pk_ephemeral) ‖ pk_ephemeral
)
```

---

### Pattern 7b: PQ-Only Construction

PQ-only encryption follows the same ML-KEM → HKDF → AES-256-GCM pipeline as hybrid,
but omits the X25519 component. Key differences:

- **Domain separation**: Uses `PQ_ONLY_ENCRYPTION_INFO` (distinct from `HYBRID_ENCRYPTION_INFO`)
- **Key types**: `PqOnlyPublicKey` / `PqOnlySecretKey` (no classical component)
- **EncryptedOutput**: Reuses `HybridComponents` with empty `ecdh_ephemeral_pk`.
  Invariant enforced by `debug_assert!` in `EncryptedOutput::new()`.
- **Security**: Secure if ML-KEM is secure (no classical fallback)

---

# Section 3: Config Design Patterns

## Pattern 8: Consumer Documentation

### What
Every `pub` field on a config struct must have `/// Consumer: fn_name()` naming which
function reads it. Fields with no consumer use `/// Consumer: None — <reason>`.

### Why This Is The Right Pattern
Config structs are the API surface that users interact with. A field that accepts a value
but silently discards it is a broken promise. The Consumer tag creates an auditable
contract that CI can enforce with a simple grep.

For proprietary extensibility: enterprise crates add config fields (e.g., `CcePolicy`,
`HsmConfig`). Without Consumer tags, it's impossible to verify that enterprise config
fields are actually wired — especially across 30+ crates.

### Rules
1. Every `pub` field → `/// Consumer: fn_name()`
2. No consumer → `/// Consumer: None — <reason>` (must explain why the field exists)
3. No `_param` prefixed parameters in production functions — implement it or remove it
4. For every config field, a test `test_<field>_influences_<operation>` must exist
5. If you cannot write the influence test, the field is dead. Wire it or remove it.

---

## Pattern 9: Non-Exhaustive Public Enums

### What
Every `pub enum` must have `#[non_exhaustive]`.

### Why This Is The Right Pattern
Adding a variant to a public enum is a semver-breaking change in Rust. Without
`#[non_exhaustive]`, downstream crates (including all 30+ enterprise crates) must pin
exact versions or risk build breaks when the apache core adds an algorithm or security
level. With `#[non_exhaustive]`, new variants are additive and non-breaking.

---

## Pattern 10: Must-Use on Pure Functions

### What
Every public function that returns a value with no side effects must have `#[must_use]`.

### Why This Is The Right Pattern
Discarding a crypto key, boolean security gate, or builder result is always a bug. The
`#[must_use]` attribute makes the compiler catch it. Priority targets:
- `generate_key()` / `generate_nonce()` — discarding a key is a security hole
- `allow_request()` → `bool` — unchecked circuit breaker defeats the purpose
- Builder methods returning `Self` — discarding the builder drops the configuration

---

## Pattern 11: Config Struct Destructuring

### What
`From`/`Into` implementations and consumer functions must destructure config structs,
so adding a new field produces a compile error.

### Why This Is The Right Pattern
Without destructuring, adding a field to a config struct silently compiles — the new
field is just ignored. With destructuring, the compiler forces every consumer to
acknowledge every field. The `_` binding with a comment (`retry_policy: _, // Not yet
wired`) is the correct way to acknowledge a field you intentionally skip.

For example, `From<&CryptoConfig> for InternalSchemeArgs` must destructure all of
`security_level`, `performance_preference`, `crypto_mode`, etc. — not just take
`config.security_level` field-access — so that adding `compliance_mode` next year
fails to compile until every conversion site is updated.

---

## Pattern 12: Workspace Lint Enforcement

### What
The workspace `Cargo.toml` denies: `unsafe_code`, `clippy::unwrap_used`,
`clippy::expect_used`, `clippy::panic`, `dead_code`. Individual crates inherit via
`[lints] workspace = true`.

### Why This Is The Right Pattern
- `unsafe_code` — a crypto library must prove memory safety via the Rust type system
- `unwrap/expect/panic` — a crypto library must never crash; all errors must be propagated
- `dead_code` — if clippy says it's dead, it's dead. No `#[allow(dead_code)]` in production.

Any `#[allow(...)]` override must have a justification comment explaining why the
specific case is safe. Example:
```rust
#[allow(clippy::indexing_slicing)] // ZETAS[k] where k ∈ [0,127] for ZETAS: [i32; 128]
```

### Error Format Style
Production code uses `format!("{e}")` (captured-identifier shorthand,
stabilised in Rust 1.58 and the workspace baseline since the MSRV
moved to 1.93). Never `format!("{}", e)`.

### Banned Adjectives
Marketing language in doc comments is prohibited unless accompanied by
`/// Implementation: module::function()` proving the claim. Banned words:
`intelligent`, `adaptive`, `hardware-aware`, `data-aware`, `self-healing`,
`ML-based`, `AI-powered`, `real-time`, `production-ready`, `enterprise-grade`.

---

# Section 4: Test Completeness Patterns

## Pattern 13: Roundtrip Invariant
Every reversible operation needs a test: `reverse(forward(x)) == x`.
Covers: encrypt/decrypt, sign/verify, serialize/deserialize, commit/open, encaps/decaps.

## Pattern 14: Negative Path Coverage
Every public `Result`-returning function needs tests triggering each error variant.
Every public error variant must have a test that produces it.

## Pattern 15: Property-Based Testing
Crypto operations get proptest with 256+ cases covering: roundtrip, key independence,
uniqueness, non-malleability, AAD integrity.

## Pattern 16: Cross-Library Validation
When two implementations exist for the same algorithm (e.g., `fips203` vs `aws-lc-rs`
for ML-KEM), cross-library tests verify interop for all parameter sets.

## Pattern 17: Release Mode for Crypto Tests
Crypto tests run in `--release` mode. SLH-DSA is 10x slower in debug. Timing tests
require optimization to produce meaningful results. CI thresholds accommodate 3-4x
slower CI runners.

## Pattern 18: No Ignored Tests Without Justification

`#[ignore]` is never the first solution. When a test fails: ask why → fix the root
cause → only ignore if truly environment-dependent (with a comment explaining why).

### Permitted exception: perf-floor / quiescent-only tests

Tests that assert hard throughput or rate floors (e.g.
`throughput_mbps > 10.0`, `rate > 50/s`) are **expected to flake** on
debug builds and on loaded release builds — they don't measure
functional correctness, they measure that the host is fast enough for
the floor to hold. The canonical pattern in this project is:

```rust
#[test]
#[ignore = "perf-floor: throughput_mbps > 10.0; opt in via --include-ignored on a quiescent release build"]
fn test_aes_gcm_256_bulk_encryption_throughput_succeeds() { ... }
```

**Why `#[ignore]` and not `#[cfg(not(debug_assertions))]`:** the
workspace pins `[profile.release].debug-assertions = true` ("Keep for
crypto validation" — see root `Cargo.toml`). That makes the cfg
evaluate to `false` in release mode too, which would skip these tests
in CI as well. `#[ignore]` correctly skips by default and runs under
`cargo test --include-ignored`.

**The rationale string MUST name the floor.** "perf-floor" alone is
not enough; readers should be able to grep the file for the specific
threshold to understand what changed if the test starts failing under
`--include-ignored`. A prior reviewer's "passes on a clean checkout"
claim turned out to be false because the test file didn't surface
which assertions were the flaky ones — the rationale string is what
prevents that recurrence.

**Where to put the assertion instead:** if you need ongoing perf
tracking, add a Criterion benchmark in `benches/` (handles
statistical variance properly) and treat the in-tree `#[ignore]`d
test as an opt-in canary, not a regression gate.

## Pattern 19: Test File Layering Policy

The workspace has three test locations. Each has a clear purpose. Pick the
right one when adding tests; do not invent a fourth.

| Location | Purpose | Imports |
|----------|---------|---------|
| `latticearc/src/**/*.rs` inline `#[cfg(test)] mod tests` | Unit tests for a single function/struct that need access to private API. Co-located with the code under test. | `use super::*` |
| `latticearc/tests/*.rs` | Integration tests of `latticearc::primitives::*` (low-level layer). Public API only, no private items. | `use latticearc::primitives::...` |
| `tests/tests/*.rs` (workspace member `latticearc-tests`) | Integration tests of `latticearc::unified_api`, `latticearc::hybrid`, FIPS / CAVP validation, cross-module behavior. | `use latticearc::...` (top-level re-exports) |

**Rules:**

- Property tests (`proptest!`) live in `tests/tests/proptest_*.rs`,
  regardless of layer being tested. Keep the `proptest_` prefix consistent.
- KAT (Known Answer Test) vectors for FIPS algorithms live in
  `tests/tests/fips_kat_{kem,sig,aead,hash_kdf}.rs`, grouped by primitive
  family. Never split per-algorithm into separate files.
- Do not name files `*_coverage.rs`, `*_extended_tests.rs`, or
  `*_boost_tests.rs`. These naming patterns signal coverage-metric
  manipulation rather than functional grouping. If a test file gets too
  large, split by sub-domain (e.g., `fips_kat_sig.rs` →
  `fips_kat_sig_ml_dsa.rs` + `fips_kat_sig_slh_dsa.rs`), not by an
  arbitrary file count.
- Do not duplicate a test across the two integration locations. If a
  property needs both primitive-level and convenience-level coverage,
  write each test once at its appropriate layer.
- The `_tests.rs` suffix is implicit (the file is in `tests/`). Drop it
  for new files: prefer `negative_aead.rs` over `negative_tests_aead.rs`.

---

# Software Engineering Benchmarks

These are the measurable quality targets the project must achieve and maintain.
They are not aspirational — they are gates. Code that doesn't meet these benchmarks
does not ship.

## Code Quality Metrics

| Metric | Target | How Measured | Why This Target |
|--------|--------|-------------|-----------------|
| **Test coverage (line)** | ≥ 90% | `cargo llvm-cov --workspace --all-features` | NIST SP 800-53 SA-11 requires thorough developer testing. 80% is the FIPS 140-3 floor — we target 90% because crypto code has no acceptable "untested" paths. Every untested line is a potential vulnerability. |
| **Test coverage (branch)** | ≥ 80% | `cargo llvm-cov --branch` | Branch coverage catches missed error paths that line coverage misses. 80% ensures every `if`/`match` arm in crypto code is exercised. |
| **Clippy warnings** | 0 | `cargo clippy -- -D warnings` | Zero-warning policy. Every clippy diagnostic is either fixed or has a justified `#[allow]`. |
| **Format violations** | 0 | `cargo fmt --check` | Consistent formatting eliminates style arguments in review and reduces diff noise. |
| **Unsafe code** | 0 blocks | `#![deny(unsafe_code)]` on every crate | Memory safety must be provable by the compiler. All FFI is delegated to aws-lc-rs. |
| **Known vulnerabilities** | 0 | `cargo audit --deny warnings` | No shipped code may have known CVEs in its dependency tree. |
| **License violations** | 0 | `cargo deny check all` | Only MIT, Apache-2.0, BSD, ISC, CC0, MPL-2.0. No copyleft (GPL, AGPL, LGPL). |
| **Documentation coverage** | 100% of public API | `#![deny(missing_docs)]` | Every public item must have a `///` doc comment. Undocumented APIs are unusable APIs. |
| **Compile time (incremental)** | < 15s | Developer experience | If incremental builds exceed 15s, split the crate or reduce generics. |
| **Binary size (release)** | Track, don't gate | `cargo bloat` | Monitor for accidental size regressions from dependency additions. |

## Performance Benchmarks

| Operation | Target Latency | How Measured | Basis |
|-----------|---------------|-------------|-------|
| ML-KEM-768 keygen | < 1 ms | `cargo bench` (criterion) | aws-lc-rs with AES-NI on modern x86_64 |
| ML-KEM-768 encaps | < 1 ms | Same | Same |
| ML-KEM-768 decaps | < 1 ms | Same | Same |
| ML-DSA-65 sign | < 5 ms | Same | fips204 crate, release mode |
| ML-DSA-65 verify | < 3 ms | Same | Same |
| SLH-DSA-SHAKE-128s sign | < 100 ms | Same | Hash-based, inherently slower |
| SLH-DSA-SHAKE-128s verify | < 10 ms | Same | Verification is faster than signing |
| AES-256-GCM encrypt 1KB | < 0.1 ms | Same | aws-lc-rs with AES-NI |
| Hybrid encrypt (ML-KEM-768 + X25519 + AES-256-GCM) | < 3 ms | Same | End-to-end including HKDF |
| HKDF-SHA256 derive | < 0.01 ms | Same | Single expansion |

These are measured on a modern x86_64 with AES-NI. CI runners are 3-4x slower —
CI benchmarks use relaxed thresholds for regression detection, not absolute targets.

## Security Audit Benchmarks

| Metric | Target | Rationale |
|--------|--------|-----------|
| Secret types with ZeroizeOnDrop | 100% | SP 800-57 §8.3.1 — no exceptions |
| Secret types with redacted Debug | 100% | No secret material in any log output |
| Secret comparisons using ct_eq | 100% | SP 800-175B §4.1 — no timing leaks |
| Public enums with #[non_exhaustive] | 100% | Semver safety for 30+ downstream crates |
| HKDF labels in domain registry | 100% | SP 800-108 §4 — no unregistered labels |
| Kani proof covers all domain constants | 100% | Formal guarantee of label uniqueness |
| Config fields with Consumer tags | 100% | No dead config accepted by users |

---

# Test Methodology

This section defines the complete testing methodology — from unit tests through
real-world usage mirroring. Every category has a specific purpose, specific requirements,
and a specific place in the test hierarchy.

## The Test Pyramid

```text
                    ┌────────────────────���────┐
                    │   Real-World Mirrors     │  ← Few, expensive, high-fidelity
                    │   (production scenarios) │
                   ─┼─────────────────────────┼─
                  │   End-to-End Tests          │  ← Cross-module, full stack
                  │   (encrypt → store → load   │
                  │    → decrypt → verify)      │
                 ─┼────────────────────────��────┼─
                │   Integration Tests             │  ← Module boundary tests
                │   (hybrid encrypt uses          │
                │    primitives KEM + AEAD)        │
               ─┼─────────────────────────────────┼─
              │   Property-Based Tests              │  ← Statistical correctness (proptest)
              │   (∀ key, ∀ plaintext:              │
              │    decrypt(encrypt(pt)) == pt)       │
             ─┼─────────────────────────────────────┼─
            │   Negative / Error Path Tests           │  ← Every error variant triggered
            │   (wrong key → error, truncated →       │
            │    error, empty → error)                │
           ─┼─────────────────────────────────────────┼─
          │   Unit Tests                                │  ← Every function in isolation
          │   (keygen returns valid key,                │
          │    encrypt produces ciphertext)              │
         ─┼─────────────────────────────────────────────┼─
        │   Known Answer Tests (KAT / CAVP)               │  ← NIST test vectors
        │   (algorithm output matches published vector)    │
        └─────────────────────────────────────────────────┘
```

Every layer is mandatory. Skipping a layer creates a blind spot that the other
layers cannot cover.

## Level 1: Known Answer Tests (KAT / CAVP)

**Purpose:** Verify that our implementation produces the exact same output as the
NIST reference implementation for the same input. This catches algorithmic bugs
that are invisible to roundtrip tests (a broken implementation can still roundtrip
with itself).

**Requirements:**
- ML-KEM: NIST CAVP vectors for all 3 parameter sets (512, 768, 1024)
- ML-DSA: NIST CAVP vectors for all 3 parameter sets (44, 65, 87)
- SLH-DSA: NIST CAVP vectors for all supported parameter sets
- AES-GCM: NIST CAVP GCM vectors (encrypt + decrypt + AAD)
- SHA-2/SHA-3: NIST CAVP hash vectors (short, long, Monte Carlo)
- HMAC: NIST CAVP HMAC vectors
- HKDF: RFC 5869 test vectors

**Where:** `tests/src/validation/nist_kat/`, `prelude/cavp_compliance.rs`

**When to add:** Every new algorithm implementation must ship with KAT vectors
on the same PR. No algorithm merges without known-answer test coverage.

## Level 2: Unit Tests

**Purpose:** Verify each function in isolation — correct output for valid input,
correct error for invalid input, correct behavior at boundaries.

**Requirements:**
- Every `pub fn` that returns `Result` must have at least one success test and
  one failure test
- Every error variant must be triggered by at least one test
- Boundary conditions: empty input, single byte, minimum valid, maximum valid,
  one byte over maximum

**Naming:** `test_<function>_<condition>_<expected_result>`
```rust
#[test] fn test_ml_kem_keygen_768_succeeds() { ... }
#[test] fn test_ml_kem_encapsulate_empty_key_fails() { ... }
#[test] fn test_aes_gcm_encrypt_empty_plaintext_succeeds() { ... }
#[test] fn test_aes_gcm_decrypt_wrong_tag_fails() { ... }
```

**Where:** `#[cfg(test)] mod tests` inside each source file.

## Level 3: Negative / Error Path Tests

**Purpose:** Systematically verify that every invalid input produces the correct
error, and that error messages don't leak secret information.

**Requirements:**
For every crypto operation, test with:

| Invalid Input | What It Tests |
|--------------|---------------|
| Empty key | Key validation catches zero-length |
| Truncated key (key_len - 1) | Off-by-one validation |
| Oversized key (key_len + 1) | Excess data rejection |
| All-zero key | Zero-key guard (AES-GCM specifically) |
| Key from wrong algorithm | Cross-algorithm confusion |
| Corrupted ciphertext (flip one bit) | AEAD authentication catches tampering |
| Truncated ciphertext | Length validation |
| Wrong nonce | Decryption produces garbage or auth failure |
| Wrong AAD | AAD binding catches substitution |
| Cross-key decryption | Correct error, not garbage output |

**Where:** `tests/tests/negative_tests_*.rs`

**Decrypt error opacity check:** Every negative test for decryption must assert
that the error message is opaque — it must NOT contain "MAC", "padding",
"authentication", or any information distinguishing the failure mode.

## Level 4: Property-Based Tests (proptest)

**Purpose:** Statistical verification of cryptographic properties that cannot be
exhaustively tested. A roundtrip test with one input proves one case. A proptest
with 256 random inputs gives statistical confidence.

**Requirements:**
Every crypto operation must have proptest coverage for these properties:

| Property | What It Proves | Example |
|----------|---------------|---------|
| **Roundtrip** | `decrypt(encrypt(pt, k), k) == pt` for random pt and k | Correctness |
| **Key independence** | `encrypt(pt, k1) != encrypt(pt, k2)` for random k1 ≠ k2 | No key reuse |
| **Ciphertext uniqueness** | `encrypt(pt, k) != encrypt(pt, k)` (different nonces) | Nonce uniqueness |
| **Non-malleability** | Flipping any bit in ciphertext → decrypt fails | AEAD authentication |
| **AAD integrity** | Changing AAD → decrypt fails | AAD binding |
| **Key-ciphertext binding** | Decrypting with wrong key → error (not garbage) | Key isolation |

**Configuration:**
```rust
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..65536)) {
        // ...
    }
}
```

Minimum 256 cases per property. Crypto-critical properties (roundtrip, non-malleability)
should use 1000 cases for higher confidence.

**Where:** `tests/tests/proptest_*.rs`

## Level 5: Integration Tests

**Purpose:** Verify that modules work together correctly across the layer
boundaries. A unit test proves `AesGcm256::encrypt` works. An integration test
proves `hybrid::encrypt → primitives::kem + primitives::aead → decrypt` works
end-to-end through the actual module boundaries.

**Requirements:**
- Every layer boundary must have at least one integration test
- Hybrid encryption: test the full `ML-KEM encaps → HKDF → AES-GCM encrypt` chain
- Hybrid signatures: test the full `ML-DSA sign + Ed25519 sign → verify both` chain
- Unified API: test `encrypt(data, config) → decrypt(ct, key)` via the public API
- Zero-trust: test `establish_session → authenticate → encrypt with session → verify`

**Where:** `tests/tests/*_integration.rs`, `tests/tests/*_roundtrip*.rs`

## Level 6: End-to-End Tests

**Purpose:** Verify complete workflows that cross multiple subsystems, including
serialization, storage, and retrieval.

**Requirements:**
Test these complete workflows:

| Workflow | What It Covers |
|---------|----------------|
| **Key lifecycle** | Generate → serialize (PortableKey JSON/CBOR) → store to disk → load → deserialize → use for encrypt/sign → rotate → destroy |
| **Encrypt-store-retrieve-decrypt** | Encrypt data → serialize `EncryptedOutput` → store → load → deserialize → decrypt → verify plaintext match |
| **Sign-verify-serialize** | Sign message → serialize signature → transmit (simulate) → deserialize → verify with public key |
| **Hybrid key exchange** | Generate hybrid keypair → encapsulate → transmit ciphertext → decapsulate �� derive same shared secret |
| **Config-driven encryption** | Use `CryptoConfig` with different `SecurityLevel` values → verify scheme selection → encrypt/decrypt roundtrip |
| **Cross-level compatibility** | Encrypt with ML-KEM-768 keypair → attempt decrypt with ML-KEM-512 keypair → verify correct error (not garbage) |

**Where:** `tests/tests/practical_*.rs`, `tests/tests/*_e2e_*.rs`

## Level 7: Real-World Usage Mirroring

**Purpose:** Simulate actual deployment scenarios that exercise the library the
way customers will use it. These tests catch integration bugs that only appear
under realistic conditions.

**Requirements:**

### Scenario 1: File Encryption Service
```
User uploads file → server encrypts with hybrid scheme →
stores EncryptedOutput + PortableKey to database →
different server instance loads both → decrypts → returns file →
verify byte-for-byte match with original
```
Tests: serialization round-trip, key portability, cross-instance decryption.

### Scenario 2: Document Signing Workflow
```
Author signs document with ML-DSA-65 →
signature + public key serialized to JSON →
transmitted to verifier (different process) →
verifier deserializes and verifies →
repeat with SLH-DSA for long-term archival signature
```
Tests: cross-algorithm verification, signature format portability.

### Scenario 3: Key Rotation Under Load
```
Generate keypair v1 → encrypt 100 messages →
generate keypair v2 (rotation) →
encrypt 100 more messages with v2 →
decrypt all 200 messages (100 with v1, 100 with v2) →
destroy v1 → verify v1 decryption now fails
```
Tests: key lifecycle, rotation correctness, destruction verification.

### Scenario 4: Multi-Algorithm Compatibility
```
Encrypt same plaintext with every EncryptionScheme variant →
serialize each EncryptedOutput →
decrypt each → verify all match original →
verify each uses different ciphertext size (scheme distinction)
```
Tests: algorithm selection, scheme completeness, no cross-scheme confusion.

### Scenario 5: Compliance Audit Trail
```
Establish zero-trust session → perform 10 crypto operations →
query audit log → verify all 10 operations logged →
verify timestamps are monotonic →
verify no secret material appears in audit records
```
Tests: audit completeness, secret exclusion from logs.

### Scenario 6: Error Recovery
```
Encrypt with valid key → corrupt ciphertext →
attempt decrypt → verify clean error (no panic, no garbage) →
attempt decrypt with wrong key → verify clean error →
encrypt again with same key → verify still works (no state corruption)
```
Tests: error isolation, no state leakage between operations.

**Where:** `tests/tests/real_world_*.rs`, `tests/tests/scenario_*.rs`

## Level 8: Fuzz Testing

**Purpose:** Find crashes, panics, and undefined behavior by feeding random
(and semi-structured) inputs to every entry point.

**Requirements:**
- Every public function that accepts `&[u8]` input must have a fuzz target
- Fuzz targets must run for at least 300 seconds per target in CI
- Any crash found by fuzzing is a P0 bug — fix before next release

**Where:** `fuzz/fuzz_targets/`

**Priority targets:**
1. Decrypt functions (attacker-controlled ciphertext)
2. Key deserialization (attacker-controlled key bytes)
3. Signature verification (attacker-controlled signature)
4. CBOR/JSON deserialization (attacker-controlled wire format)

## Level 9: Side-Channel Tests

**Purpose:** Verify that timing of crypto operations does not depend on secret
values. These are statistical tests that measure execution time variance.

**Requirements:**
- Constant-time comparison: verify `ct_eq(a, b)` takes same time regardless
  of where `a` and `b` differ
- Key-dependent timing: verify `encrypt(pt, k1)` and `encrypt(pt, k2)` have
  statistically similar timing distributions
- Use coefficient of variation (CV) as the metric. CV < 5% is constant-time.
  CI uses relaxed threshold (CV < 2000%) because virtualized runners add jitter.

**Where:** `tests/tests/*_timing*.rs`, `latticearc/examples/crypto_timing.rs`

## Test Execution Order in CI

```text
1. cargo fmt --check          (instant — formatting)
2. cargo clippy -D warnings   (30s — static analysis)
3. cargo test --release        (40s — all unit + integration tests)
4. cargo test --doc            (10s — doc examples compile and run)
5. cargo audit / cargo deny   (5s — vulnerability + license scan)
6. cargo llvm-cov             (60s — coverage report, gate at 90%)
7. fuzz (scheduled, not PR)   (300s/target — nightly fuzzing)
8. benchmarks (scheduled)      (120s — performance regression detection)
```

Steps 1-6 run on every PR. Steps 7-8 run on schedule (nightly/weekly).

## Adding Tests for New Code — The Checklist

When adding any new crypto operation, ALL of these must ship in the same PR:

- [ ] KAT vectors (if NIST vectors exist for the algorithm)
- [ ] Unit tests: at least 1 success + 1 failure per public function
- [ ] Negative tests: empty/truncated/corrupted/cross-key inputs
- [ ] Proptest: roundtrip + key independence + uniqueness (256+ cases)
- [ ] Integration test: verify it works through the layer boundary
- [ ] E2E test: serialize → store → load → deserialize → use
- [ ] Fuzz target: for any function accepting `&[u8]`
- [ ] Coverage check: `cargo llvm-cov` must stay ≥ 90%

When adding a new config field:

- [ ] `test_<field>_influences_<operation>` influence test
- [ ] Negative test: invalid value produces correct error

When fixing a bug:

- [ ] Regression test that would have caught the bug
- [ ] The test must fail without the fix and pass with it

---

# Quick Reference Card

### Adding a new crypto operation:
1. Implement in `primitives/` wrapping the external crate
2. Add zeroization, error mapping, resource limits, instrumentation
3. Call from upper layer via `crate::primitives::*`
4. Never import the external crate in the upper layer

### Adding a new secret type:
1. `#[derive(Zeroize, ZeroizeOnDrop)]` (or `AUDIT-TRACKED(#NN)` with open issue for upstream types)
2. Manual `impl Debug` with `[REDACTED]`
3. `impl ConstantTimeEq` using `&` combinators
4. No `Clone` (or `AUDIT-TRACKED(#NN)` with open issue)
5. Private fields + `&[u8]` getters + `Zeroizing<Vec<u8>>` owned returns

### Adding a new config field:
1. `/// Consumer: fn_name()` doc tag
2. `test_<field>_influences_<operation>` test
3. Update consumer's destructuring pattern
4. Update any `From`/`Into` bridges
5. If you can't write the influence test, the field is dead

### Adding a new HKDF use:
1. Add constant to `types/domains.rs`
2. Add to Kani pairwise-distinct proof
3. Reference by `crate::types::domains::CONSTANT_NAME` — never inline literals

### Adding a new public enum:
1. `#[non_exhaustive]` on the enum
2. `#[must_use]` on all methods
3. Ensure downstream `match` arms use `_ =>` for extensibility

---

# Zero-Shortcut Policy

This section exists because shortcuts compound. A skipped test today becomes a
production incident tomorrow. A "temporary" `#[allow]` becomes permanent tech debt
that no one removes. A `todo!()` placeholder ships to crates.io and panics in a
customer's production system.

## The Rule

**Every implementation must be correct and complete before it merges. No exceptions.**

This means:

### No Stub Implementations
```rust
// FORBIDDEN — ships to crates.io, panics in production
pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
    todo!("implement later")
}

// FORBIDDEN — silently returns success without doing anything
pub fn validate(&self) -> Result<()> {
    Ok(()) // "will add real validation later"
}

// REQUIRED — if you can't implement it now, don't add it to the public API
// Wait until the implementation is ready. An absent function is better than
// a broken one.
```

### No Skipped Tests to Save Time
```rust
// FORBIDDEN — test exists but is disabled
#[test]
#[ignore] // "too slow, will fix later"
fn test_slh_dsa_roundtrip() { ... }

// REQUIRED — if the test is slow, fix the root cause
// SLH-DSA slow in debug? → run in release mode (--release flag)
// Test flaky on CI? → fix the flakiness, don't ignore
// Test needs setup? → add the setup, don't skip
```

### No Placeholder Error Handling
```rust
// FORBIDDEN — swallows the error, caller doesn't know something failed
fn process(&self, data: &[u8]) -> Result<Vec<u8>> {
    match self.encrypt(data) {
        Ok(ct) => Ok(ct),
        Err(_) => Ok(vec![]), // "return empty on error for now"
    }
}

// FORBIDDEN — logs the error but continues as if nothing happened
fn process(&self, data: &[u8]) -> Vec<u8> {
    self.encrypt(data).unwrap_or_else(|e| {
        eprintln!("encryption failed: {e}"); // silently degraded
        vec![]
    })
}

// REQUIRED — propagate the error. Let the caller decide.
fn process(&self, data: &[u8]) -> Result<Vec<u8>, ProcessError> {
    self.encrypt(data).map_err(|e| ProcessError::EncryptionFailed(e))
}
```

### No Dead Config Fields
```rust
// FORBIDDEN — accepts input the user thinks matters, but ignores it
pub fn recommend_scheme(use_case: &UseCase, _config: &CoreConfig) -> String {
    // _config is never read. User sets security_level = Maximum,
    // gets the same scheme as Standard. Broken promise.
    match use_case { ... }
}

// REQUIRED — either use the parameter or remove it from the signature
pub fn recommend_scheme(use_case: &UseCase) -> String { ... }
// OR
pub fn recommend_scheme(use_case: &UseCase, config: &CoreConfig) -> String {
    let base = match use_case { ... };
    adjust_for_security_level(base, &config.security_level) // actually uses config
}
```

### No Unfinished Refactors
```rust
// FORBIDDEN — old code and new code coexist, neither is complete
pub fn encrypt_v1(&self, data: &[u8]) -> Vec<u8> { ... } // "deprecated but still used"
pub fn encrypt_v2(&self, data: &[u8]) -> Result<Vec<u8>> { ... } // "new, but not all callers migrated"

// REQUIRED — complete the migration in the same PR
// Remove v1, update all callers to v2, verify all tests pass
```

### No Coverage Shortcuts
```rust
// FORBIDDEN — marking code as unreachable to inflate coverage
fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>> {
    // ...
    #[cfg(not(tarpaulin_include))] // hides this branch from coverage
    if unlikely_condition {
        return Err(Error::EdgeCase);
    }
}

// REQUIRED — write a test that exercises the edge case
#[test]
fn test_decrypt_edge_case() {
    let result = cipher.decrypt(&crafted_input);
    assert!(matches!(result, Err(Error::EdgeCase)));
}
```

### No Deferred Documentation
```rust
// FORBIDDEN — public API without documentation
pub fn derive_hybrid_secret(ss1: &[u8], ss2: &[u8]) -> Vec<u8> {
    // No doc comment. What does this do? What are the security properties?
    // What standard does it follow? What errors can it return?
}

// REQUIRED — documentation ships with the code, not "later"
/// Derive a hybrid shared secret from ML-KEM and ECDH components.
///
/// Uses HKDF-SHA256 (SP 800-56C Rev.2) as a dual-PRF combiner.
/// Security: if either `ss1` or `ss2` is pseudorandom, the output
/// is pseudorandom (Bindel et al., PQCrypto 2019, Theorem 3.1).
///
/// # Arguments
/// * `ss1` - ML-KEM shared secret (32 bytes)
/// * `ss2` - ECDH shared secret (32 bytes)
///
/// # Errors
/// Returns `KdfError` if HKDF expansion fails.
///
/// # Security
/// - Both inputs are zeroized after derivation
/// - Output is wrapped in `Zeroizing` for automatic cleanup
pub fn derive_hybrid_secret(ss1: &[u8], ss2: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
```

## Why This Policy Exists

This is a cryptography library. Our code protects other people's secrets — medical
records, financial transactions, national security communications. A shortcut in
this codebase is not "tech debt" — it is a vulnerability.

Every `todo!()` is a panic waiting to happen in someone's production system.
Every `#[ignore]`'d test is a bug that could have been caught.
Every dead config field is a user who thinks they configured security but didn't.
Every missing doc comment is an integrator who misuses the API.

The standard is: **correct and complete, or it doesn't merge.**

---

# The Exemplary Implementation Standard

This section defines what it means for LatticeArc to be the reference implementation
that the industry learns from. These are not features — they are qualities of the
codebase itself.

## What Sets an Exemplary Crypto Library Apart

Most crypto libraries get the algorithms right. The difference between a good library
and an exemplary one is everything surrounding the algorithms:

| Dimension | Typical Library | Exemplary Library (Our Standard) |
|-----------|----------------|----------------------------------|
| **Key destruction** | `Drop` frees memory (OS may reuse without zeroing) | `ZeroizeOnDrop` overwrites key bytes with zeros before deallocation, verified for every secret type |
| **Debug output** | `#[derive(Debug)]` prints key bytes into logs | Manual `Debug` prints `[REDACTED]`, verified for every secret type |
| **Timing safety** | "We use constant-time where we remember to" | `ConstantTimeEq` on every secret comparison, verified by audit, with the canonical pattern documented |
| **Error messages** | Different messages for MAC failure vs padding failure (oracle) | Single opaque error for all post-crypto failures, pre-crypto validation may be distinct (documented why) |
| **Nonce handling** | Caller supplies nonce (and eventually reuses one) | Library generates nonce internally, caller cannot supply one in high-level API |
| **Domain separation** | Inline string literals scattered across files | Centralized registry with formal proof of pairwise uniqueness |
| **RNG routing** | `OsRng` imported wherever needed | Single `primitives::rand` module, upper layers cannot import `OsRng` |
| **Config fields** | "Set this to configure X" (but X is never read) | Every field names its consumer function, with an influence test proving it works |
| **Enum extensibility** | Adding a variant breaks all downstream crates | `#[non_exhaustive]` on every public enum |
| **Test coverage** | "We have tests" | 9-level test pyramid from KAT vectors to real-world scenario mirrors, ≥90% line coverage |
| **Documentation** | "See the code" | Every public item documented with `# Security` section, NIST standard references, and code examples |
| **Dependency safety** | "We run `cargo audit` sometimes" | Zero CVEs enforced in CI, banned crate list, license allowlist, source restrictions |

## The Audit Question

The ultimate test of an exemplary implementation: **can a security auditor unfamiliar
with the project verify any claim in under 5 minutes?**

- "All secret types are zeroized on drop" → auditor greps for secret types, checks
  each for `ZeroizeOnDrop` or `AUDIT-TRACKED(#NN)` pointing at an open issue. Any
  marker referencing a closed issue is a lint failure.
- "HKDF labels are unique" → auditor reads `types/domains.rs`, sees all constants,
  reads the Kani proof. Formally verified, one file.
- "No OsRng bypass in upper layers" → auditor greps for `OsRng` outside `primitives/`,
  finds zero production hits. Provable in one command.
- "Decrypt errors don't leak information" → auditor reads the two AEAD decrypt
  functions, sees identical error messages with a comment explaining why.

If the auditor has to read 50 files, trace 10 call chains, and "trust that the team
follows the convention" — it's not exemplary. It's hoping.

## What We Measure Against

These are the open-source crypto libraries we benchmark our engineering quality
against (not algorithms — engineering practices):

| Library | Language | What They Excel At | What We Do Better |
|---------|----------|-------------------|-------------------|
| **ring** (briansmith) | Rust | Minimal API surface, aggressive unsafe minimization | We have zero `unsafe` (they have ~50 blocks for performance). We have formal proofs (Kani). |
| **rustls** | Rust | Excellent API design, strong type safety | We add PQC algorithms, hybrid combiners, and domain separation that rustls doesn't need (it delegates crypto to ring/aws-lc-rs). |
| **libsodium** | C | Misuse-resistant API, excellent documentation | We match their misuse resistance (nonce encapsulation, sealed traits) with Rust's additional compile-time guarantees (ownership, lifetimes, no use-after-free). |
| **aws-lc-rs** | Rust/C | FIPS 140-3 validated, production-hardened | We build on their validated crypto and add: hybrid PQC, domain separation, zero-trust session management, and the unified API layer they don't provide. |
| **BoringSSL** | C | Battle-tested in Chrome/Android, excellent constant-time discipline | We match their constant-time discipline with Rust's memory safety. They have 20 years of CVE history we avoid by construction. |

We do not claim to be better than these libraries at their core mission. We claim to
be the exemplary implementation of a **post-quantum hybrid cryptography library with
enterprise extensibility** — a category none of them occupy.

## The 10-Point Quality Scorecard

Every release must score 10/10. Any score below 10 blocks the release.

| # | Criterion | How Verified |
|---|-----------|-------------|
| 1 | **Zero clippy warnings** | `cargo clippy -D warnings` in CI |
| 2 | **Zero known CVEs** | `cargo audit --deny warnings` in CI |
| 3 | **≥90% line coverage** | `cargo llvm-cov` in CI |
| 4 | **All public items documented** | `#![deny(missing_docs)]` in every crate |
| 5 | **All secret types audited** | Checklist: ZeroizeOnDrop ✓, Debug redacted ✓, ct_eq ✓, no Clone ✓ |
| 6 | **All domain labels in registry** | Kani proof covers all constants |
| 7 | **All public enums non_exhaustive** | Grep count matches |
| 8 | **All tests pass in release mode** | `cargo test --release` in CI |
| 9 | **No `todo!`, `unimplemented!`, `#[ignore]`** | Workspace lint + grep in CI |
| 10 | **CHANGELOG updated** | Pre-push hook checks |

## How This Document Evolves

This document is not frozen. As the project grows, new patterns will emerge. The
process for adding a pattern:

1. **Identify the bug class** — what went wrong, or what could go wrong?
2. **Research the standard** — what does NIST/IETF/academic literature say is correct?
3. **Define the pattern** — what, why, how, with wrong/right code examples
4. **Define the measurement** — how do we verify compliance? (must be mechanical, not judgment-based)
5. **Measure the codebase** — N/M compliant today
6. **Fix all non-compliant code** — patterns are not aspirational
7. **Add to this document** — with the same structure as existing patterns
8. **Add CI enforcement** — grep, lint, or test that catches future violations

A pattern without mechanical enforcement is a suggestion. We don't do suggestions.
