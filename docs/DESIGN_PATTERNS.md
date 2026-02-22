# Correct-By-Construction Design Patterns

Design patterns that make bugs **structurally impossible** at creation time. Two sections:

1. **Config Correctness Patterns (#1-10)** — prevent dead/unwired configuration fields. Born from a "Promise Audit" that found 19 issues despite 95% coverage, 7,786 tests, and Kani proofs.
2. **Cryptographic Safety Patterns (#11-18)** — prevent crypto-specific bugs: timing leaks, secret exposure, type confusion, nonce reuse, downgrade attacks. These codify patterns the codebase already implements but were never formalized as enforceable rules.

These patterns are mandatory for all PRs. See also: [CONTRIBUTING.md](../CONTRIBUTING.md) for the Config Field Checklist.

---

# Section 1: Config Correctness Patterns

## Audit Finding Mapping

Every pattern maps to a class of bug found in the Promise Audit:

| # | Pattern | Bug Class | Findings Prevented |
|---|---------|-----------|-------------------|
| 1 | Consumer Tag | Dead fields | 6 |
| 2 | No Underscore Params | Silently ignored params | 2 |
| 3 | Config Lives With Consumer | Orphan configs | 2 |
| 4 | Parameter Influence Test | All categories | 19 (universal) |
| 5 | Implementation Reference | Doc drift | 5 |
| 6 | Capability Must Exist | Impossible features | 1 |
| 7 | Destructure at Consumer | New fields silently ignored | 2 |
| 8 | Exhaustive Config Bridges | Unwired TLS fields | 3 |
| 9 | Banned Adjectives | Marketing in docs | 5 |
| 10 | Wire Comment | Bidirectional traceability | 6 |

---

## Pattern 1: Consumer Tag

**Rule:** Every config field's doc comment names its consumer with `/// Consumer: fn_name()`.

**Prevents:** Dead fields — config fields that exist but no code reads them (6 findings).

### WRONG

```rust
// latticearc/src/types/config.rs — CoreConfig
pub struct CoreConfig {
    /// Whether hardware acceleration is enabled.
    pub hardware_acceleration: bool,
    // ^ No consumer named. Who reads this? Is it wired?
}
```

### RIGHT

```rust
pub struct CoreConfig {
    /// Whether hardware acceleration is enabled.
    ///
    /// Consumer: CryptoPolicyEngine::recommend_scheme() via CryptoContext
    pub hardware_acceleration: bool,
}
```

### Enforcement

CI script greps all `pub` fields in config structs for `Consumer:` tag:

```bash
# Fail if any pub field in a config struct lacks a Consumer tag
grep -n 'pub [a-z_]*:' src/**/config*.rs | grep -v 'Consumer:'
```

---

## Pattern 2: No Underscore Params

**Rule:** Never use `_param` to silence unused warnings on non-test functions. Implement the parameter or remove it.

**Prevents:** Silently ignored parameters — a function accepts config but discards it (2 findings).

### WRONG

```rust
// latticearc/src/types/selector.rs:67-75 — CryptoPolicyEngine::recommend_scheme()
pub fn recommend_scheme(use_case: &UseCase, config: &CoreConfig) -> Result<String> {
    let _ctx = CryptoContext {
        security_level: config.security_level.clone(),
        performance_preference: config.performance_preference.clone(),
        // ...
    };
    // _ctx is never read — config fields are accepted but ignored
    match *use_case {
        UseCase::SecureMessaging => Ok("hybrid-ml-kem-768-aes-256-gcm".to_string()),
        // ... hardcoded strings, config has zero influence
    }
}
```

### RIGHT

```rust
pub fn recommend_scheme(use_case: &UseCase, config: &CoreConfig) -> Result<String> {
    let base_scheme = match *use_case {
        UseCase::SecureMessaging => "hybrid-ml-kem-768-aes-256-gcm",
        // ...
    };
    // Wire config.security_level: upgrade scheme if security level demands it
    let scheme = adjust_for_security_level(base_scheme, &config.security_level);
    Ok(scheme.to_string())
}
```

### Enforcement

CI script greps for underscore-prefixed parameters in non-test function signatures:

```bash
# Flag _param patterns in function signatures (exclude test modules)
grep -n 'fn [a-z_]*(' src/**/*.rs | grep -v '#\[cfg(test)\]' | grep '_[a-z].*:'
```

---

## Pattern 3: Config Lives With Consumer

**Rule:** A config struct must be defined in the same module as the function(s) that consume it. If it crosses module boundaries, there must be a documented bridge (Pattern 8).

**Prevents:** Orphan configs — config types defined far from their consumers, making it invisible when fields go unwired (2 findings).

### WRONG

```rust
// Config defined in types/config.rs
pub struct CoreConfig {
    pub security_level: SecurityLevel,
    pub performance_preference: PerformancePreference,
    pub hardware_acceleration: bool,
}

// Consumer in types/selector.rs — different module, no bridge documentation
// Fields silently ignored because consumer doesn't know about new fields
```

### RIGHT

```rust
// Option A: Config in same module as consumer
// types/selector.rs
pub struct SchemeSelectionConfig { /* ... */ }
impl CryptoPolicyEngine {
    pub fn recommend_scheme(config: &SchemeSelectionConfig) -> Result<String> { /* ... */ }
}

// Option B: Config crosses modules but has documented bridge
// types/config.rs
/// Bridge: Consumed by CryptoPolicyEngine (types/selector.rs) via recommend_scheme()
pub struct CoreConfig { /* ... */ }
```

### Enforcement

PR review: reviewer checks that config structs and their consumers are co-located or explicitly bridged.

---

## Pattern 4: Parameter Influence Test

**Rule:** For every config field, a test proves that changing ONLY that field changes the output of its consumer.

**Prevents:** All categories of dead config — if you can't write this test, the field is dead (universal, covers all 19 findings).

### Test Template

```rust
#[test]
fn test_security_level_influences_scheme_selection() {
    let config_a = CoreConfig::default()
        .with_security_level(SecurityLevel::Standard);
    let result_a = CryptoPolicyEngine::select_encryption_scheme(
        b"test", &config_a, None,
    ).unwrap();

    let config_b = CoreConfig::default()
        .with_security_level(SecurityLevel::Maximum);
    let result_b = CryptoPolicyEngine::select_encryption_scheme(
        b"test", &config_b, None,
    ).unwrap();

    assert_ne!(result_a, result_b,
        "security_level must influence scheme selection");
}
```

### The Rule

**If you cannot write this test, the field is dead. Wire it or remove it.**

### Naming Convention

```
test_<field>_influences_<operation>
```

Examples:
- `test_security_level_influences_scheme_selection`
- `test_enable_early_data_influences_tls_config`
- `test_compliance_mode_influences_algorithm_choice`
- `test_session_lifetime_influences_ticket_config`

### Enforcement

Naming convention enables CI grep:

```bash
# For each config field, verify a matching influence test exists
grep -r 'test_.*_influences_' tests/ src/
```

---

## Pattern 5: Implementation Reference

**Rule:** Doc comments that make capability claims must reference specific code paths with `/// Implementation: module::function()`.

**Prevents:** Doc drift — documentation claims features that don't exist or work differently than described (5 findings).

### WRONG

```rust
// latticearc/src/types/mod.rs:38
/// Cryptographic policy engine for intelligent scheme selection
pub use selector::CryptoPolicyEngine;
// ^ "intelligent" — what intelligence? Where is the implementation?
```

### RIGHT

```rust
/// Cryptographic policy engine for use-case-based scheme selection.
///
/// Implementation: types::selector::CryptoPolicyEngine::recommend_scheme()
/// maps UseCase variants to hybrid scheme strings. Security level adjusts
/// KEM parameter size (512/768/1024).
pub use selector::CryptoPolicyEngine;
```

### Enforcement

CI script flags banned adjectives without an `Implementation:` tag:

```bash
# Find banned adjectives in doc comments without Implementation reference
grep -n '///' src/**/*.rs | grep -iE 'intelligent|adaptive|hardware-aware' | grep -v 'Implementation:'
```

---

## Pattern 6: Capability Must Exist

**Rule:** Don't add config fields for features the underlying library can't do. Verify the downstream API exists before adding the knob.

**Prevents:** Impossible features — config accepts values that can never take effect (1 finding).

### WRONG

```rust
// latticearc/src/tls/mod.rs:256-261 — TlsConfig
/// Session ticket lifetime in seconds.
///
/// **Note:** Not yet wired to rustls. Requires a custom `TimeBase` ticketer
/// implementation. Currently stored for configuration purposes only; the actual
/// session ticket lifetime is controlled by rustls defaults.
pub session_lifetime: u32,
// ^ Field exists, user sets it, but rustls has no API to honor it
```

### RIGHT

```rust
// Don't add the field until rustls supports it.
// If you must add it for forward-compatibility, mark it clearly:

/// Session ticket lifetime in seconds.
///
/// **Status: NOT YET WIRED.** Requires rustls custom TimeBase ticketer.
/// Tracked in: <issue URL>
///
/// Consumer: None (placeholder for future rustls API)
#[deprecated(note = "Not yet wired to rustls. Setting this has no effect.")]
pub session_lifetime: u32,
```

### Enforcement

PR review: for every new config field, reviewer asks "does the downstream library have an API for this?" Verify by reading downstream docs, not by assuming.

---

## Pattern 7: Destructure at Consumer

**Rule:** Functions consuming a config struct must destructure it, so adding a new field produces a compile error at the consumer.

**Prevents:** New fields silently ignored — a new field is added to a config struct but no consumer is updated to handle it (2 findings).

### WRONG

```rust
fn apply_config(config: &TlsConfig) -> Result<()> {
    // Cherry-pick fields — if a new field is added, this function silently ignores it
    if config.enable_early_data {
        // ...
    }
    if let Some(size) = config.max_fragment_size {
        // ...
    }
    Ok(())
}
```

### RIGHT

```rust
fn apply_config(config: &TlsConfig) -> Result<()> {
    // Destructure — compiler forces handling of every field
    let TlsConfig {
        mode,
        enable_tracing,
        retry_policy,
        enable_fallback,
        alpn_protocols,
        max_fragment_size,
        enable_early_data,
        max_early_data_size,
        enable_resumption,
        session_lifetime,   // Wire session_lifetime: see Pattern 6
        enable_key_logging,
        cipher_suites,
        min_protocol_version,
        max_protocol_version,
        client_auth,
        client_verification,
        client_ca_certs,
        session_persistence,
    } = config;

    // Now every field is in scope — compiler enforces exhaustiveness
    // If someone adds `new_field` to TlsConfig, this destructure fails to compile
    Ok(())
}
```

### Enforcement

Code convention enforced during PR review. Consider a clippy lint or custom lint for config consumer functions.

---

## Pattern 8: Exhaustive Config Bridges

**Rule:** `From`/`Into` implementations between config types must destructure the source type, ensuring every source field is explicitly mapped or acknowledged.

**Prevents:** Unwired TLS fields — config conversion silently drops fields that the source has but the target doesn't map (3 findings).

### WRONG

```rust
// latticearc/src/tls/mod.rs:635-680 — From<&TlsConfig> for Tls13Config
impl From<&TlsConfig> for Tls13Config {
    fn from(config: &TlsConfig) -> Self {
        let mut tls13_config = match config.mode { /* ... */ };

        // Cherry-picks: alpn, fragment_size, early_data, protocol_version
        // Silently drops: enable_tracing, retry_policy, enable_fallback,
        //   enable_resumption, session_lifetime, enable_key_logging,
        //   cipher_suites, client_auth, client_verification, client_ca_certs,
        //   session_persistence
        tls13_config
    }
}
```

### RIGHT

```rust
impl From<&TlsConfig> for Tls13Config {
    fn from(config: &TlsConfig) -> Self {
        let TlsConfig {
            mode,
            enable_tracing: _,        // Not applicable to Tls13Config
            retry_policy: _,           // Handled by connection layer, not config
            enable_fallback: _,        // Handled by connection layer, not config
            alpn_protocols,
            max_fragment_size,
            enable_early_data,
            max_early_data_size,
            enable_resumption: _,      // NOT WIRED: awaiting Tls13Config support
            session_lifetime: _,       // NOT WIRED: see Pattern 6
            enable_key_logging: _,     // Handled by connection builder
            cipher_suites: _,          // NOT WIRED: cipher suites set by mode selection
            min_protocol_version,
            max_protocol_version,
            client_auth: _,            // Handled by server/client config builders
            client_verification: _,    // Handled by server config builder
            client_ca_certs: _,        // Handled by server config builder
            session_persistence: _,    // Handled by connection layer
        } = config;

        // Now every field is accounted for — adding a new field forces a decision
        let mut tls13_config = match mode { /* ... */ };
        // ... apply mapped fields ...
        tls13_config
    }
}
```

### Enforcement

Code convention enforced during PR review. All `From`/`Into` impls involving config types must destructure.

---

## Pattern 9: Banned Adjectives

**Rule:** Marketing adjectives are banned in doc comments unless accompanied by an `/// Implementation: module::function()` tag proving the claim.

**Prevents:** Marketing in docs — documentation makes claims that code doesn't back up (5 findings).

### Banned Words

| Word | Why Banned |
|------|-----------|
| `hardware-aware` | Implies runtime hardware detection; aws-lc-rs handles this internally |
| `data-aware` | Implies data analysis influencing selection; verify implementation exists |
| `adaptive` | Implies runtime adaptation; verify feedback loop exists |
| `intelligent` | Implies ML/heuristics; verify algorithm exists beyond `match` |
| `self-healing` | Implies automatic recovery; verify detection + response loop |
| `mandatory` | Implies enforcement; verify enforcement code exists |
| `automatic` | Acceptable for Rust's `Drop`/`Zeroize`; requires `Implementation:` for anything else |
| `real-time` | Implies latency guarantees; verify with benchmarks |
| `ML-based` | Implies machine learning model; verify model exists |
| `AI-powered` | Implies AI system; verify AI component exists |

### WRONG

```rust
// latticearc/src/types/traits.rs:379
/// Trait for hardware-aware operations
pub trait HardwareAware { /* ... */ }
// ^ "hardware-aware" — but no runtime hardware detection in apache_repo
```

### RIGHT

```rust
/// Trait for operations that can use hardware acceleration.
///
/// Implementation: Hardware detection is handled by aws-lc-rs at the C level.
/// This trait defines the interface contract; see `aws-lc-rs` docs for
/// actual AES-NI/AVX2 acceleration behavior.
pub trait HardwareAware { /* ... */ }
```

### Enforcement

CI script:

```bash
# Find banned adjectives in doc comments without Implementation tag
BANNED='intelligent|adaptive|hardware-aware|data-aware|self-healing|mandatory|real-time|ML-based|AI-powered'
grep -rn '///' src/ | grep -iE "$BANNED" | grep -v 'Implementation:' | grep -v '#\[cfg(test)\]'
```

Note: `automatic` is allowed when describing Rust's built-in mechanisms (`Drop`, `Zeroize`, `ZeroizeOnDrop`) since those are language/derive features, not marketing claims.

---

## Pattern 10: Wire Comment

**Rule:** At the point where a config field is consumed, the consumer marks it with `// Wire <field>:` comment. This creates bidirectional traceability with the `Consumer:` tag on the field definition.

**Prevents:** Traceability gaps — you can't tell from reading the consumer which config fields it handles (6 findings, same as Pattern 1 from the other direction).

### WRONG

```rust
fn select_encryption_scheme(data: &[u8], config: &CoreConfig, use_case: Option<&UseCase>) -> Result<String> {
    // Uses config.security_level somewhere in here... but where?
    // Reader has to trace through the entire function to find out
    match config.security_level {
        SecurityLevel::Maximum => { /* ... */ }
        // ...
    }
}
```

### RIGHT

```rust
fn select_encryption_scheme(data: &[u8], config: &CoreConfig, use_case: Option<&UseCase>) -> Result<String> {
    // Wire security_level: select KEM parameter size based on security level
    let kem_size = match config.security_level {
        SecurityLevel::Maximum => 1024,
        SecurityLevel::High => 768,
        SecurityLevel::Standard => 512,
    };

    // Wire performance_preference: choose AEAD cipher based on preference
    let aead = match config.performance_preference {
        PerformancePreference::Speed => "chacha20-poly1305",
        _ => "aes-256-gcm",
    };

    // Wire hardware_acceleration: flag for hw-optimized code paths
    if config.hardware_acceleration {
        // Use hardware-accelerated path
    }

    Ok(format!("hybrid-ml-kem-{kem_size}-{aead}"))
}
```

### Enforcement

CI grep matching `Wire` comments against `Consumer:` tags:

```bash
# Extract Consumer tags and Wire comments, verify they match
grep -rn 'Consumer:' src/ > /tmp/consumers.txt
grep -rn '// Wire ' src/ > /tmp/wires.txt
# Manual or scripted diff to find unmatched pairs
```

---

## Quick Reference Card

For every new config field, verify:

1. `/// Consumer: fn_name()` doc tag on the field
2. No `_` prefix to silence unused warnings
3. Config struct co-located with consumer (or bridged)
4. `test_<field>_influences_<operation>` test exists
5. No banned adjectives without `/// Implementation:` tag
6. Downstream library actually supports this feature
7. Consumer function destructures the config struct
8. Any `From`/`Into` bridge destructures the source
9. Doc comments are factual, not aspirational
10. `// Wire <field>:` comment at the consumption point

**If you cannot satisfy rule 4, the field is dead. Wire it or remove it.**

---

# Section 2: Cryptographic Safety Patterns

These patterns prevent crypto-specific bugs that testing alone cannot catch. Unlike config patterns (which are about coverage), these are about **cryptographic correctness** — the kind of bugs that pass every test but break in production under adversarial conditions.

---

## Pattern 11: Secret Debug Redaction

**Rule:** Every type holding secret material must implement `Debug` manually with redacted output. Never derive `Debug` on secret types.

**Prevents:** Accidental logging of key material via `println!("{:?}", key)`, log frameworks, or error messages that include debug output.

### WRONG

```rust
#[derive(Debug, Clone)]  // Debug will print raw key bytes!
pub struct SecretKey {
    key_bytes: Vec<u8>,
}
// log::debug!("Processing with key: {:?}", secret_key);
// => "SecretKey { key_bytes: [172, 58, 91, ...] }"  LEAKED
```

### RIGHT

```rust
// latticearc/src/primitives/keys/mod.rs:203-215 — SecretKey
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) ml_sk: Zeroizing<Vec<u8>>,
    pub(crate) ecc_sk: Zeroizing<EccSecretKey>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
        // => "SecretKey { .. }"  — no key material exposed
    }
}

// latticearc/src/primitives/security.rs:119-122 — SecureBytes
impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {} bytes])", self.len())
        // => "SecureBytes([REDACTED; 32 bytes])"  — length only
    }
}
```

### Enforcement

PR review: any new struct containing `Vec<u8>`, `[u8; N]`, `Zeroizing<>`, or named `*Key`, `*Secret`, `*Credential` must have a manual `Debug` impl. `#[derive(Debug)]` on such types is a blocking review comment.

---

## Pattern 12: Constant-Time Comparison for Secrets

**Rule:** All comparisons involving secret data must use `subtle::ConstantTimeEq`. Plain `==` is forbidden on any type that could hold secrets.

**Prevents:** Timing side-channel attacks — an attacker measures response time to learn how many bytes of a MAC/key/token match, enabling byte-by-byte brute force.

### WRONG

```rust
fn verify_mac(computed: &[u8], received: &[u8]) -> bool {
    computed == received  // Short-circuits on first mismatch — timing leak!
}
```

### RIGHT

```rust
// latticearc/src/primitives/security.rs:125-136 — SecureBytes::eq
impl PartialEq for SecureBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        // Both length and content compared in constant time
        let len_equal = self.inner.len().ct_eq(&other.inner.len());
        let content_equal = self.inner.ct_eq(&other.inner);
        (len_equal & content_equal).into()
    }
}
```

### When `==` is OK

Plain `==` is allowed on:
- Public keys (not secret)
- Error variants and enum discriminants
- Lengths and sizes used for validation (e.g., `key.len() != 32`)
- Strings (algorithm names, scheme identifiers)

### Enforcement

CI grep for `==` on known secret types:

```bash
# Flag direct equality on secret types (SecureBytes, SecretKey, SharedSecret, etc.)
# These should use ct_eq instead
grep -rn '\.eq(' src/ | grep -v 'ct_eq' | grep -v '#\[cfg(test)\]'
```

PR review: any comparison involving `&[u8]` that represents secret data (MACs, keys, tokens, shared secrets) must use `subtle::ConstantTimeEq`.

---

## Pattern 13: Zeroize on All Paths

**Rule:** Every type holding secret material must derive `ZeroizeOnDrop` or wrap contents in `Zeroizing<>`. Manual `zeroize()` calls are insufficient because error paths may skip them.

**Prevents:** Secret persistence in memory — after a key is "done", its bytes remain in memory and can be recovered via cold boot attacks, core dumps, or swap files.

### WRONG

```rust
fn use_key(key_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut working_key = key_bytes.to_vec();
    let result = do_crypto(&working_key)?;  // Error skips zeroize!
    working_key.zeroize();
    Ok(result)
}
```

### RIGHT

```rust
// latticearc/src/primitives/keys/mod.rs:203-209 — SecretKey
#[derive(Zeroize, ZeroizeOnDrop)]  // Automatic zeroize on drop — works on ALL paths
pub struct SecretKey {
    pub(crate) ml_sk: Zeroizing<Vec<u8>>,    // Double protection: field + struct
    pub(crate) ecc_sk: Zeroizing<EccSecretKey>,
}

fn use_key(key: &SecretKey) -> Result<Vec<u8>> {
    let result = do_crypto(key.ml_kem())?;  // If error, key still zeroized on drop
    Ok(result)
}
```

### Key Rules

1. **Prefer `#[derive(ZeroizeOnDrop)]`** over manual `zeroize()` calls
2. **Wrap inner fields in `Zeroizing<>`** for defense-in-depth
3. **Never return raw `Vec<u8>` for secrets** — return `Zeroizing<Vec<u8>>` or `SecureBytes`
4. **Error returns before secret creation are fine** — if no secret exists yet, nothing to zeroize

### Enforcement

PR review: any new type holding `Vec<u8>` or `[u8; N]` that represents secret material must derive `Zeroize` + `ZeroizeOnDrop` or wrap in `Zeroizing<>`.

---

## Pattern 14: Error Information Hiding

**Rule:** Crypto error types must not distinguish between failure modes that could enable oracle attacks. Decryption failure, MAC failure, and padding failure must all return the same error variant.

**Prevents:** Padding oracle attacks (Bleichenbacher, Vaudenay) — an attacker uses different error messages for "bad padding" vs "bad MAC" to decrypt ciphertexts without the key.

### WRONG

```rust
enum DecryptError {
    InvalidPadding,           // Attacker: "padding was checked first — I can exploit this"
    MacVerificationFailed,    // Attacker: "padding was OK, MAC was wrong"
    InvalidCiphertext,        // Attacker: "neither padding nor MAC — format issue"
}
```

### RIGHT

```rust
// latticearc/src/primitives/aead/mod.rs:113-135 — AeadError
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),  // Single generic variant — no tag/padding/MAC distinction
    // ...
}

// latticearc/src/unified_api/error.rs:42-47 — CoreError
#[error("Decryption failed: {0}")]
DecryptionFailed(String),      // Same generic message regardless of cause
#[error("Signature verification failed")]
VerificationFailed,            // No details — just "failed"
```

### Rules

1. **One error for decryption failure** — never separate padding from MAC from ciphertext format
2. **No details in verification errors** — `VerificationFailed` not `VerificationFailed { reason }`
3. **Key length errors are OK** — `InvalidKeyLength { expected, actual }` reveals no secrets
4. **Test for it** — verify that different bad inputs produce identical error variants

### Enforcement

PR review: any new error variant in crypto modules must be checked for oracle potential. Test that corrupted-ciphertext and corrupted-MAC produce the same error type.

---

## Pattern 15: Newtype Distinction for Crypto Primitives

**Rule:** Different cryptographic values (nonces, tags, keys, shared secrets) must be distinct types, not type aliases or raw `[u8; N]`. The type system should prevent passing a nonce where a tag is expected.

**Prevents:** Type confusion — passing a nonce in a tag parameter, using a signing key for encryption, or mixing up shared secrets with symmetric keys. These bugs compile and may even pass tests with contrived inputs, but break security guarantees.

### WRONG (current state)

```rust
// latticearc/src/primitives/aead/mod.rs:44-47
pub type Nonce = [u8; NONCE_LEN];  // = [u8; 12]
pub type Tag = [u8; TAG_LEN];      // = [u8; 16]
// These are just aliases — the compiler cannot distinguish them from raw arrays.
// This compiles: let tag: Tag = [0u8; 16]; let nonce: Nonce = [0u8; 12];
// This also compiles: fn bad(n: &Nonce) {} bad(&some_random_12_bytes);
```

### RIGHT

```rust
/// AEAD nonce (12 bytes). Cannot be confused with Tag or key material.
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// AEAD authentication tag (16 bytes). Distinct from Nonce and keys.
pub struct Tag([u8; TAG_LEN]);
// Now the compiler prevents: fn encrypt(nonce: &Nonce, ...) called with a Tag
```

### Current Gaps

| Type | Current | Should Be |
|------|---------|-----------|
| `Nonce` | `type Nonce = [u8; 12]` (alias) | `struct Nonce([u8; 12])` (newtype) |
| `Tag` | `type Tag = [u8; 16]` (alias) | `struct Tag([u8; 16])` (newtype) |
| `PublicKey` | `struct PublicKey { ... }` (newtype) | Already correct |
| `SecretKey` | `struct SecretKey { ... }` (newtype) | Already correct |
| `SecureBytes` | `struct SecureBytes { ... }` (newtype) | Already correct |

### Enforcement

PR review: new crypto value types must be `struct` newtypes, not `type` aliases. Type aliases for `[u8; N]` or `Vec<u8>` in crypto modules are a blocking review comment.

---

## Pattern 16: Sealed Security Traits

**Rule:** Security-critical traits (`AeadCipher`, `KEM`, `Signature`) should be sealed to prevent external implementations that may not uphold security invariants.

**Prevents:** Weakened custom implementations — a user implements `AeadCipher` with non-constant-time tag comparison or `Signature` with `==` instead of `ct_eq`, silently breaking security for all code that uses the trait generically.

### WRONG (current state)

```rust
// latticearc/src/primitives/aead/mod.rs:50 — fully public trait
pub trait AeadCipher {
    const KEY_LEN: usize;
    fn new(key: &[u8]) -> Result<Self, AeadError> where Self: Sized;
    fn generate_nonce() -> Nonce;
    fn encrypt(&self, nonce: &Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), AeadError>;
    fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8], tag: &Tag, aad: Option<&[u8]>) -> Result<Vec<u8>, AeadError>;
}
// A user can impl AeadCipher for MyBrokenCipher { ... } with no safety checks
```

### RIGHT

```rust
mod sealed {
    pub trait Sealed {}
}

/// AEAD cipher trait. Sealed — only library-provided implementations are allowed.
///
/// This prevents external implementations that might not uphold
/// constant-time guarantees or proper nonce handling.
pub trait AeadCipher: sealed::Sealed {
    const KEY_LEN: usize;
    fn new(key: &[u8]) -> Result<Self, AeadError> where Self: Sized;
    fn generate_nonce() -> Nonce;
    fn encrypt(&self, nonce: &Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), AeadError>;
    fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8], tag: &Tag, aad: Option<&[u8]>) -> Result<Vec<u8>, AeadError>;
}

impl sealed::Sealed for AesGcm128 {}
impl sealed::Sealed for AesGcm256 {}
impl sealed::Sealed for ChaCha20Poly1305Cipher {}
// External crates cannot impl Sealed, so they cannot impl AeadCipher
```

### Which Traits to Seal

| Trait | Seal? | Reason |
|-------|-------|--------|
| `AeadCipher` | Yes | Constant-time tag verification, nonce generation |
| `KEM` (if trait exists) | Yes | Shared secret handling, zeroization |
| `Signature` (if trait exists) | Yes | Constant-time verification |
| `HardwareAware` | No | Interface-only, no security invariants |
| `Encryptable`/`Decryptable` | No | User data types, not crypto internals |

### Enforcement

PR review: any new trait in `primitives/` that defines cryptographic operations should be sealed unless there's a documented reason for extensibility.

---

## Pattern 17: Nonce Management

**Rule:** Nonce generation must be encapsulated in the cipher API, not exposed as a caller responsibility. The API should make nonce reuse impossible by default.

**Prevents:** Nonce reuse — the catastrophic failure mode for AES-GCM and ChaCha20-Poly1305. Reusing a nonce with the same key reveals the XOR of two plaintexts and enables forgery.

### WRONG

```rust
// Caller generates and manages nonces — easy to accidentally reuse
let nonce = [0u8; 12]; // static nonce — catastrophic!
let (ct1, tag1) = cipher.encrypt(&nonce, plaintext1, None)?;
let (ct2, tag2) = cipher.encrypt(&nonce, plaintext2, None)?; // SAME NONCE — security broken
```

### RIGHT (current approach)

```rust
// latticearc/src/primitives/aead/aes_gcm.rs:71-74 — AesGcm128::generate_nonce
fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);  // Cryptographic random — 2^96 space
    nonce
}

// Convenience API encapsulates nonce entirely:
// latticearc/src/unified_api/convenience/api.rs — encrypt()
// Generates fresh nonce internally, prepends to ciphertext
// Caller never sees or manages nonces
```

### BETTER (aspirational: nonce-misuse resistance)

```rust
/// Encrypt with automatic nonce. Returns nonce || ciphertext || tag.
/// Caller cannot provide a nonce — eliminating reuse by construction.
pub fn encrypt_auto_nonce(
    &self,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, AeadError> {
    let nonce = Self::generate_nonce();
    let (ciphertext, tag) = self.encrypt(&nonce, plaintext, aad)?;
    let mut output = Vec::with_capacity(12 + ciphertext.len() + 16);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
    Ok(output)
}
```

### Current State

The convenience API (`encrypt()` / `decrypt()`) already encapsulates nonce management correctly. The low-level `AeadCipher` trait exposes `generate_nonce()` + `encrypt(nonce, ...)` separately, which is necessary for protocols that manage nonces externally (TLS, streaming) but requires caller discipline.

### Rules

1. **High-level APIs must encapsulate nonces** — caller never provides one
2. **Low-level APIs may expose nonces** but must document the birthday bound: rotate key after 2^32 encryptions for random nonces with AES-GCM
3. **Never accept `&[u8]` as nonce from user input** — always generate internally

### Enforcement

PR review: new encryption APIs must either encapsulate nonce generation or document why the caller needs control. Any function accepting a nonce parameter from outside the crypto module requires justification.

---

## Pattern 18: Hybrid Composition Safety

**Rule:** Hybrid constructions (PQ + classical) must use a KDF-based combiner with domain separation. Never XOR shared secrets directly. The combined secret must be at least as strong as the stronger component.

**Prevents:** Weak hybrid composition — if shared secrets are combined incorrectly, compromising one component can compromise the whole system, defeating the purpose of hybrid crypto.

### WRONG

```rust
fn combine_secrets(pq_secret: &[u8], classical_secret: &[u8]) -> Vec<u8> {
    // Direct XOR — if either secret has low entropy, result has low entropy
    pq_secret.iter().zip(classical_secret).map(|(a, b)| a ^ b).collect()
}

fn combine_secrets_concat(pq_secret: &[u8], classical_secret: &[u8]) -> Vec<u8> {
    // Simple concatenation — no domain separation, no binding to participants
    let mut combined = pq_secret.to_vec();
    combined.extend_from_slice(classical_secret);
    combined
}
```

### RIGHT

```rust
// latticearc/src/hybrid/kem_hybrid.rs:451-487 — derive_hybrid_shared_secret
pub fn derive_hybrid_shared_secret(
    ml_kem_ss: &[u8],   // ML-KEM shared secret (32 bytes)
    ecdh_ss: &[u8],      // X25519 shared secret (32 bytes)
    static_pk: &[u8],    // Recipient's static public key
    ephemeral_pk: &[u8], // Ephemeral public key from encapsulation
) -> Result<Vec<u8>, HybridKemError> {
    // Validate input lengths
    if ml_kem_ss.len() != 32 { return Err(/* ... */); }
    if ecdh_ss.len() != 32 { return Err(/* ... */); }

    // Concatenate for KDF input (HKDF extracts entropy from both)
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ml_kem_ss);
    ikm.extend_from_slice(ecdh_ss);

    // Domain separation — binds to this library and these specific keys
    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS");
    info.extend_from_slice(b"||");
    info.extend_from_slice(static_pk);
    info.extend_from_slice(b"||");
    info.extend_from_slice(ephemeral_pk);

    // HKDF-SHA256 produces 64-byte combined secret
    let result = hkdf(&ikm, None, Some(&info), 64)?;
    Ok(result.key().to_vec())
}
```

### Key Properties

1. **HKDF extraction** — handles arbitrary-entropy inputs safely (vs raw XOR)
2. **Domain separation** — `"LatticeArc-Hybrid-KEM-SS"` prevents cross-protocol attacks
3. **Key binding** — public keys in the info string bind the secret to this specific exchange
4. **Input validation** — rejects wrong-length secrets before combining

### Enforcement

PR review: any new hybrid construction must use HKDF (or approved KDF) with domain separation and key binding. Direct XOR or concatenation of shared secrets is a blocking review comment.

---

# Quick Reference Cards

## Config Correctness (Patterns 1-10)

For every new config field, verify:

1. `/// Consumer: fn_name()` doc tag on the field
2. No `_` prefix to silence unused warnings
3. Config struct co-located with consumer (or bridged)
4. `test_<field>_influences_<operation>` test exists
5. No banned adjectives without `/// Implementation:` tag
6. Downstream library actually supports this feature
7. Consumer function destructures the config struct
8. Any `From`/`Into` bridge destructures the source
9. Doc comments are factual, not aspirational
10. `// Wire <field>:` comment at the consumption point

## Cryptographic Safety (Patterns 11-18)

For every new type or function handling crypto material:

11. Secret types have manual `Debug` with redacted output
12. Secret comparisons use `subtle::ConstantTimeEq`, not `==`
13. Secret types derive `ZeroizeOnDrop` or wrap in `Zeroizing<>`
14. Error types don't distinguish padding vs MAC failures
15. Crypto values are newtypes, not type aliases for `[u8; N]`
16. Security-critical traits are sealed against external impl
17. Nonce generation is encapsulated; callers don't provide nonces at high-level APIs
18. Hybrid combiners use KDF with domain separation and key binding

---

# Section 3: Test Patterns

These patterns define **what kinds of tests are required**, not just "did you write tests?" A codebase can have 95% coverage and 7,786 tests while missing entire categories of bugs because coverage measures lines executed, not properties verified.

Each pattern specifies: what to test, what it catches, a naming convention, and when it's required.

---

## Pattern 19: Roundtrip Invariant

**Rule:** Every reversible operation (encrypt/decrypt, sign/verify, serialize/deserialize, encode/decode) must have a test proving `reverse(forward(x)) == x` for representative inputs including edge cases.

**Catches:** Asymmetric bugs — encryption works but decryption is broken for specific inputs, or serialization loses data that deserialization expects.

### Template

```rust
#[test]
fn test_aes_gcm_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"test data for roundtrip";
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();

    let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).unwrap();
    let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice(),
        "decrypt(encrypt(x)) must equal x");
}
```

### Required For

| Operation | Roundtrip Test Needed |
|-----------|----------------------|
| `encrypt` / `decrypt` | Yes — every AEAD cipher, every security level |
| `sign` / `verify` | Yes — every signature scheme |
| `encapsulate` / `decapsulate` | Yes — every KEM at every parameter size |
| `PublicKey::to_bytes` / `from_bytes` | Yes — key serialization |
| `SecretKey::to_bytes` / `from_bytes` | Yes — key serialization |
| Hybrid operations | Yes — full hybrid chain end-to-end |

### Naming Convention

```
test_<operation>_roundtrip
test_<algorithm>_<operation>_roundtrip
```

### Current Status

Strong: 572 roundtrip mentions across 20+ files. All major operations covered.

---

## Pattern 20: Negative Path Coverage

**Rule:** Every public function that returns `Result` must have at least one test triggering each distinct error condition. If an error variant has no test, it's either dead code or an untested failure mode.

**Catches:** Dead error variants (error types defined but never produced), silent error swallowing (function catches and re-wraps errors losing information), and untested failure modes that may behave unexpectedly in production.

### Template

```rust
// latticearc/tests/primitives_negative_tests_aead.rs — real example pattern
#[test]
fn test_aes_gcm_rejects_empty_key() {
    let result = AesGcm256::new(&[]);
    assert!(result.is_err(), "Should fail with empty key");
}

#[test]
fn test_aes_gcm_rejects_corrupted_tag() {
    let key = [0x42u8; 32];
    let cipher = AesGcm256::new(&key).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let (ciphertext, mut tag) = cipher.encrypt(&nonce, b"data", None).unwrap();
    tag[0] ^= 0xFF; // corrupt one byte
    let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
    assert!(result.is_err(), "Should fail with corrupted tag");
}
```

### Required Inputs

Every public crypto function must be tested with:

| Input | What It Tests |
|-------|--------------|
| Empty input (`b""`, `&[]`) | Zero-length handling |
| Wrong-length key | Key validation |
| Corrupted ciphertext | Tamper detection |
| Corrupted tag/signature | Authentication verification |
| Wrong key (valid length, wrong value) | Key isolation |
| Truncated input | Boundary parsing |

### The Rule

**Every error variant in a public error enum must have at least one test that triggers it.** If you can't trigger a variant, it may be dead code — investigate.

### Current Gaps

9 variants across `LatticeArcError` and `CoreError` lack direct trigger tests. All are non-critical path (DevTool, Wasm, Profiling, Migration). FIPS critical codes (0x0001-0x0005: `SelfTestFailed`, `IntegrityCheckFailed`, `ConditionalTestFailed`, `ContinuousRngTestFailed`) need trigger tests even if they require mocking.

### Naming Convention

```
test_<function>_rejects_<invalid_condition>
test_<function>_fails_on_<bad_input>
```

---

## Pattern 21: Cross-Validation

**Rule:** When two implementations exist for the same algorithm (e.g., `fips203` crate vs `aws-lc-rs` for ML-KEM), a test must prove they produce identical outputs for the same inputs.

**Catches:** Implementation drift — two libraries implement the same NIST standard but produce different outputs due to different parameter encoding, endianness, or version. Code works with each library independently but interop breaks.

### Template

```rust
#[test]
fn test_ml_kem_768_cross_library_encapsulation() {
    // Generate keypair with library A
    let (pk_a, sk_a) = lib_a::ml_kem_768_keygen();

    // Encapsulate with library B using library A's public key
    let (ciphertext_b, shared_secret_b) = lib_b::ml_kem_768_encaps(&pk_a);

    // Decapsulate with library A
    let shared_secret_a = lib_a::ml_kem_768_decaps(&sk_a, &ciphertext_b);

    assert_eq!(shared_secret_a, shared_secret_b,
        "Cross-library ML-KEM-768 must produce identical shared secrets");
}
```

### Required When

- Two crates implement the same NIST FIPS standard
- A migration from one backend to another (e.g., `fips204` → `aws-lc-rs` ML-DSA)
- A pure-Rust implementation exists alongside a C-backed one
- CAVP/KAT vectors validate individual libraries, but interop between them is not guaranteed

### Current Gaps

No systematic cross-validation between `fips203` and `aws-lc-rs` ML-KEM, or between `fips204` and future `aws-lc-rs` ML-DSA. CAVP tests validate each library against NIST vectors independently, but don't prove the two libraries agree with each other.

### Naming Convention

```
test_<algorithm>_cross_library_<operation>
test_<algorithm>_interop_<lib_a>_<lib_b>
```

---

## Pattern 22: Property-Based Testing

**Rule:** Every cryptographic operation must have property tests (proptest) that verify invariants hold across randomized inputs, not just hand-picked test vectors.

**Catches:** Edge-case bugs that hand-written tests miss — specific plaintext lengths that trigger buffer handling errors, key values near algebraic boundaries, or inputs that expose off-by-one errors in length calculations.

### Required Properties

| Property | What It Verifies |
|----------|-----------------|
| **Roundtrip recovery** | `decrypt(encrypt(random_plaintext)) == random_plaintext` for all lengths 0..65536 |
| **Key independence** | `decrypt(encrypt(data, key_a), key_b)` fails for random `key_a != key_b` |
| **Non-malleability** | Flipping any bit in ciphertext causes decryption failure |
| **Signature unforgeability** | `verify(random_message, sign(different_message))` fails |
| **Deterministic output length** | Output size depends only on input size, not input content |
| **AAD integrity** | Changing AAD after encryption causes decryption failure |

### Template

```rust
// tests/tests/proptest_hybrid_encrypt.rs — real pattern
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn hybrid_encrypt_decrypt_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..65536)
    ) {
        let (pk, sk) = generate_keypair().unwrap();
        let ciphertext = hybrid_encrypt(&plaintext, &pk).unwrap();
        let decrypted = hybrid_decrypt(&ciphertext, &sk).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }
}
```

### Case Counts

| Test Type | Minimum Cases |
|-----------|--------------|
| Roundtrip properties | 256 |
| Failure properties (key independence, malleability) | 256 |
| Algebraic properties (NTT, polynomial) | 1000 |

### Current Status

Strong: 7-8 proptest files, 256-1000 cases each, covering roundtrip, key independence, non-malleability, AAD integrity, and variable plaintext sizes.

---

## Pattern 23: Error Variant Exhaustion

**Rule:** Every variant in a public error enum must have a test that constructs or triggers it. Untested variants are either dead code or untested failure modes — both are bugs.

**Catches:** Dead error variants (defined in enum but never returned by any code path), error variants that can only be triggered by internal inconsistencies (indicating defensive programming that should be documented), and error conversion chains where the original error is lost.

### Template

```rust
#[test]
fn test_all_core_error_variants_constructible() {
    // Verify each variant can be constructed and displays correctly
    let errors: Vec<CoreError> = vec![
        CoreError::InvalidInput("test".into()),
        CoreError::InvalidKeyLength { expected: 32, actual: 16 },
        CoreError::EncryptionFailed("test".into()),
        CoreError::DecryptionFailed("test".into()),
        CoreError::VerificationFailed,
        CoreError::SessionExpired,
        // ... every variant
    ];

    for error in &errors {
        // Verify Display impl doesn't panic and produces non-empty output
        let msg = format!("{}", error);
        assert!(!msg.is_empty(), "Error display must not be empty: {:?}", error);
    }
}

#[test]
fn test_core_error_from_aead_error() {
    // Verify error conversion doesn't lose information
    let aead_err = AeadError::DecryptionFailed("tag mismatch".into());
    let core_err: CoreError = aead_err.into();
    let msg = format!("{}", core_err);
    assert!(msg.contains("Decryption"),
        "Converted error must preserve failure context");
}
```

### The Audit Rule

For each error enum, maintain a coverage table:

```
ErrorEnum: 22 variants
Tested: 18 (82%)
Untested: EntropyDepleted, SelfTestFailed, KeyGenerationFailed, HardwareError
Status: EntropyDepleted — requires mocking OsRng, tracked in #123
         SelfTestFailed — FIPS module init only, integration test planned
         KeyGenerationFailed — unreachable with current RNG, mark as defensive
         HardwareError — no hardware in CI, mock test planned
```

### Current Status

174 total error variants, ~165 tested (95%). Gaps are in non-critical paths (DevTool, Wasm, Profiling) and FIPS module init errors that require mocking.

---

## Pattern 24: Boundary and Degenerate Input

**Rule:** Every public function must be tested with degenerate inputs: empty, minimum, maximum, and off-by-one values. These tests must be explicit, not hidden inside property tests.

**Catches:** Buffer handling bugs at exact boundaries — off-by-one in length checks, empty-input panics in slice operations, integer overflow in size calculations, and allocation failures on maximum-size inputs.

### Required Boundary Inputs

| Input | Values to Test |
|-------|---------------|
| Plaintext length | `0`, `1`, `15` (AES block - 1), `16` (AES block), `17` (block + 1), `65535`, `65536` |
| Key length | `0`, `KEY_LEN - 1`, `KEY_LEN`, `KEY_LEN + 1` |
| Nonce length | `0`, `NONCE_LEN - 1`, `NONCE_LEN`, `NONCE_LEN + 1` |
| AAD | `None`, `Some(b"")`, `Some(&[0u8; 65536])` |
| Security level | Every enum variant (not just the default) |

### Template

```rust
#[test]
fn test_aes_gcm_empty_plaintext() {
    let cipher = AesGcm256::new(&[0x42; 32]).unwrap();
    let nonce = AesGcm256::generate_nonce();
    let (ct, tag) = cipher.encrypt(&nonce, b"", None).unwrap();
    let pt = cipher.decrypt(&nonce, &ct, &tag, None).unwrap();
    assert!(pt.is_empty(), "Empty plaintext roundtrip must produce empty output");
}

#[test]
fn test_aes_gcm_key_off_by_one() {
    assert!(AesGcm256::new(&[0u8; 31]).is_err(), "31-byte key must fail");
    assert!(AesGcm256::new(&[0u8; 32]).is_ok(),  "32-byte key must succeed");
    assert!(AesGcm256::new(&[0u8; 33]).is_err(), "33-byte key must fail");
}
```

### Naming Convention

```
test_<function>_empty_<input>
test_<function>_<input>_off_by_one
test_<function>_maximum_<input>
```

### Current Status

Strong: 463+ empty/boundary instances, all KEM parameter sizes tested at exact NIST boundaries. Well-covered.

---

# Quick Reference Cards

## Config Correctness (Patterns 1-10)

For every new config field, verify:

1. `/// Consumer: fn_name()` doc tag on the field
2. No `_` prefix to silence unused warnings
3. Config struct co-located with consumer (or bridged)
4. `test_<field>_influences_<operation>` test exists
5. No banned adjectives without `/// Implementation:` tag
6. Downstream library actually supports this feature
7. Consumer function destructures the config struct
8. Any `From`/`Into` bridge destructures the source
9. Doc comments are factual, not aspirational
10. `// Wire <field>:` comment at the consumption point

## Cryptographic Safety (Patterns 11-18)

For every new type or function handling crypto material:

11. Secret types have manual `Debug` with redacted output
12. Secret comparisons use `subtle::ConstantTimeEq`, not `==`
13. Secret types derive `ZeroizeOnDrop` or wrap in `Zeroizing<>`
14. Error types don't distinguish padding vs MAC failures
15. Crypto values are newtypes, not type aliases for `[u8; N]`
16. Security-critical traits are sealed against external impl
17. Nonce generation is encapsulated; callers don't provide nonces at high-level APIs
18. Hybrid combiners use KDF with domain separation and key binding

## Test Completeness (Patterns 19-24)

For every new crypto operation or public API:

19. Roundtrip test: `reverse(forward(x)) == x`
20. Negative tests for every distinct error condition
21. Cross-validation when two implementations of the same algorithm exist
22. Property tests with 256+ randomized inputs
23. Every error variant has a test that triggers it
24. Boundary tests: empty, min, max, off-by-one for all inputs
