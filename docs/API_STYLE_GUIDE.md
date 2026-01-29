# LatticeArc API Style Guide

This document defines the conventions and patterns used across the LatticeArc API to ensure consistency, discoverability, and ease of use.

## Parameter Ordering Conventions

### 1. RNG Parameter (when required)

When a function requires randomness (e.g., key generation, encapsulation), the RNG parameter should come **first**:

```rust
// Correct
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(PublicKey, SecretKey)>

// Correct
pub fn encapsulate<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey) -> Result<EncapsulatedKey>
```

**Note:** Deterministic operations (like ML-DSA signing, Ed25519 signing) do NOT require an RNG parameter.

### 2. Data Parameter

The primary data being operated on (message, plaintext, ciphertext) comes **after** the RNG (if present) but **before** keys:

```rust
pub fn encrypt(data: &[u8], public_key: &[u8]) -> Result<Vec<u8>>
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>
```

### 3. Key Parameters

Keys follow the data parameter. For operations involving both public and private keys, the "acting" key comes first:

```rust
// Signing uses secret key
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>

// Verification uses public key
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>
```

### 4. Algorithm Configuration Parameters

Security levels, parameter sets, and other algorithm-specific parameters come **after** keys:

```rust
pub fn encrypt_pq_ml_kem(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,  // Algorithm config last
) -> Result<Vec<u8>>
```

### 5. Config Parameter (for `_with_config` variants)

The `CoreConfig` parameter is always the **last** parameter:

```rust
pub fn encrypt_pq_ml_kem_with_config(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,  // Config always last
) -> Result<Vec<u8>>
```

## Key Parameter Naming Conventions

### Algorithm-Prefixed Names for Raw Byte Slices

When a function accepts raw key bytes (`&[u8]`), use algorithm-prefixed parameter names to prevent confusion:

| Algorithm | Secret Key | Public Key |
|-----------|------------|------------|
| ML-KEM | `ml_kem_sk` | `ml_kem_pk` |
| ML-DSA | `ml_dsa_sk` | `ml_dsa_pk` |
| SLH-DSA | `slh_dsa_sk` | `slh_dsa_pk` |
| FN-DSA | `fn_dsa_sk` | `fn_dsa_pk` |
| Ed25519 | `ed25519_sk` | `ed25519_pk` |

```rust
// Correct
pub fn sign_pq_ml_dsa(message: &[u8], ml_dsa_sk: &[u8], parameter_set: MlDsaParameterSet)

// Avoid
pub fn sign_pq_ml_dsa(message: &[u8], private_key: &[u8], parameter_set: MlDsaParameterSet)
```

### Generic Names for Typed Keys

When using strongly-typed key structs, shorter generic names are acceptable since the type provides context:

```rust
pub fn sign(sk: &HybridSecretKey, message: &[u8]) -> Result<HybridSignature>
```

## Error Type Derivation Requirements

All public error types must derive the following traits for maximum usability:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MyError {
    // ...
}
```

### Required Derives

| Trait | Reason |
|-------|--------|
| `Debug` | Debugging and logging |
| `Clone` | Error propagation patterns |
| `PartialEq` | Testing assertions |
| `Eq` | Hash map keys, pattern matching |
| `Error` (thiserror) | Standard error trait implementation |

## `_with_config` Variant Pattern

Every public cryptographic function should have a `_with_config` variant that accepts a `CoreConfig` parameter.

### Naming Convention

```rust
// Base function
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>>

// Config variant
pub fn encrypt_with_config(data: &[u8], key: &[u8], config: &CoreConfig) -> Result<Vec<u8>>
```

### Implementation Pattern

The `_with_config` variant should:
1. Validate the configuration first
2. Delegate to the base function

```rust
pub fn encrypt_with_config(data: &[u8], key: &[u8], config: &CoreConfig) -> Result<Vec<u8>> {
    config.validate()?;
    encrypt(data, key)
}
```

### When to Use Config

- **Base function**: For simple use cases with sensible defaults
- **Config variant**: When callers need to:
  - Specify security levels
  - Enable/disable hardware acceleration
  - Configure performance vs. security tradeoffs
  - Apply enterprise policy constraints

## Function Documentation Requirements

### Required Sections

Every public function must document:

1. **Brief description** (first line)
2. **# Errors** section listing all error conditions

```rust
/// Sign a message using ML-DSA
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified parameter set
/// - The ML-DSA signing operation fails
pub fn sign_pq_ml_dsa(...) -> Result<Vec<u8>>
```

### Optional Sections

- **# Examples** - For complex or non-obvious usage
- **# Panics** - If the function can panic (should be avoided)
- **# Safety** - For unsafe functions (should be avoided)

## Module Organization

### Convenience Module Pattern

```
src/convenience/
    mod.rs          # Re-exports all public items
    keygen.rs       # Key generation functions
    pq_kem.rs       # Post-quantum KEM operations
    pq_sig.rs       # Post-quantum signature operations
    ed25519.rs      # Classical signature operations
    aes_gcm.rs      # Symmetric encryption
    hybrid.rs       # Hybrid encryption
    hashing.rs      # Hashing and HMAC
```

### Export Guidelines

- Re-export all public items in `mod.rs`
- Group related items together
- Alphabetize within groups

```rust
pub use keygen::{
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config,
    generate_keypair, generate_keypair_with_config,
    generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config,
    // ...
};
```

## Versioning and Breaking Changes

### Breaking Change Categories

1. **Parameter changes** - Adding, removing, or reordering parameters
2. **Type changes** - Changing return types or error types
3. **Behavioral changes** - Changing the semantics of a function

### Minimizing Breaking Changes

- Use `_with_config` variants for new functionality
- Deprecate before removing
- Document breaking changes in CHANGELOG.md
