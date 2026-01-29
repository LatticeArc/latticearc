# Memory Safety Guarantees

This document describes LatticeArc's memory safety guarantees and practices.

## Safe Rust Only

LatticeArc is written entirely in safe Rust:

```toml
# Workspace-level lint in Cargo.toml
[lints.rust]
unsafe_code = "forbid"
```

This means:
- No raw pointer dereferences
- No manual memory management
- No unchecked type casts
- No inline assembly

## Memory Safety Properties

### Guaranteed by Rust's Type System

| Property | Guarantee |
|----------|-----------|
| No null pointers | Option<T> instead of nullable |
| No dangling pointers | Ownership and borrowing |
| No buffer overflows | Bounds checking on slices |
| No use-after-free | Ownership prevents this |
| No double-free | Single ownership |
| No data races | Send + Sync traits |

### Guaranteed by LatticeArc's Design

| Property | Mechanism |
|----------|-----------|
| Secret zeroization | `zeroize` crate |
| No secret copies | Move semantics, no Clone on secrets |
| Constant-time operations | `subtle` crate |
| Input validation | All public APIs validate |

## Zeroization

Sensitive data is automatically cleared from memory when no longer needed.

### Implementation

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key with automatic zeroization
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    data: [u8; 32],
}

// Automatically zeroed when dropped
```

### Coverage

| Type | Zeroized |
|------|----------|
| Private keys | Yes |
| Shared secrets | Yes |
| Intermediate values | Yes |
| Public keys | No (not secret) |
| Ciphertexts | No (not secret) |

### Limitations

Zeroization cannot protect against:
- Swapped memory (use encrypted swap)
- Core dumps (disable in production)
- Compiler optimizations eliminating zeroization (mitigated by volatile writes)
- Memory copied by the OS (e.g., fork)

## Secret Handling

### Type Design

Secret types are designed to prevent accidental exposure:

```rust
pub struct SecretKey {
    data: [u8; 32],
}

impl SecretKey {
    // No Debug impl - prevents accidental logging
    // No Clone impl - prevents accidental copying
    // No PartialEq impl - prevents timing leaks

    /// Access the raw bytes (use carefully)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

// Explicit zeroization on drop
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
```

### Safe Patterns

```rust
// GOOD: Secret used and dropped
fn sign(message: &[u8], key: &SecretKey) -> Result<Signature> {
    // Key is borrowed, not moved
    // Original owner still responsible for cleanup
}

// GOOD: Secret wrapped in Zeroizing
use zeroize::Zeroizing;
let secret: Zeroizing<Vec<u8>> = Zeroizing::new(derive_key()?);
// Automatically zeroed when dropped
```

### Unsafe Patterns (Prevented)

```rust
// PREVENTED: No Clone on secrets
let key_copy = secret_key.clone(); // Compile error

// PREVENTED: No Debug on secrets
println!("{:?}", secret_key); // Compile error

// PREVENTED: No direct comparison
if secret_a == secret_b { } // Compile error (use ct_eq)
```

## Input Validation

All public APIs validate inputs before processing:

```rust
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        });
    }

    // Validate ciphertext length
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(Error::InvalidCiphertext("too short"));
    }

    // Proceed with decryption
    // ...
}
```

### Validation Coverage

| Input Type | Validated |
|------------|-----------|
| Key lengths | Yes |
| Ciphertext lengths | Yes |
| Signature lengths | Yes |
| Nonce lengths | Yes |
| Message contents | When applicable |

## Constant-Time Operations

Secret-dependent operations use constant-time primitives:

```rust
use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

// Constant-time comparison
fn verify_mac(computed: &[u8], received: &[u8]) -> bool {
    computed.ct_eq(received).into()
}

// Constant-time selection
fn select_key(choice: Choice, a: &Key, b: &Key) -> Key {
    Key::conditional_select(a, b, choice)
}
```

### Constant-Time Coverage

| Operation | Constant-Time |
|-----------|---------------|
| MAC verification | Yes |
| Signature verification | Yes |
| Key comparison | Yes |
| Decapsulation | Implementation-dependent |

## Panic Freedom

Library code never panics on valid inputs:

```toml
# Workspace-level lints
[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

### Panic Sources (Prevented)

| Source | Prevention |
|--------|------------|
| unwrap() | Denied by lint |
| expect() | Denied by lint |
| panic!() | Denied by lint |
| Index out of bounds | Use .get() with Result |
| Integer overflow | Checked arithmetic |

### Testing

Panic freedom is verified by:
1. Fuzz testing with arbitrary inputs
2. Property-based testing
3. Explicit edge case tests

## Safe Array Access

Direct array indexing is avoided in favor of bounds-checked access:

```rust
// AVOIDED: Direct indexing (can panic)
// let byte = data[index];

// PREFERRED: Bounds-checked access
let byte = data.get(index).ok_or(Error::IndexOutOfBounds)?;

// PREFERRED: Slice with bounds check
let slice = data.get(start..end).ok_or(Error::InvalidRange)?;
```

## Thread Safety

All types implement `Send + Sync` where safe:

| Type | Send | Sync | Notes |
|------|------|------|-------|
| PublicKey | Yes | Yes | Immutable |
| SecretKey | Yes | No | Not Sync to prevent sharing |
| Config | Yes | Yes | Immutable after build |

## Error Handling

Errors never expose secret data:

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    // Does NOT include the actual key material
    #[error("decryption failed")]
    DecryptionFailed,
}
```

## Memory Layout

Secret types use predictable memory layout:

```rust
#[repr(C)]  // Predictable layout for zeroization
pub struct SecretKey {
    data: [u8; 32],
}
```

## Verification

Memory safety is verified through:

1. **Rust compiler**: Borrow checker, type system
2. **Clippy**: Static analysis with security lints
3. **Fuzzing**: Memory safety under arbitrary input
4. **Code review**: Manual verification of patterns

## Limitations

### What We Cannot Guarantee

| Issue | Reason |
|-------|--------|
| Compiler bugs | Outside our control |
| Hardware bugs | Outside our control |
| Swap exposure | OS responsibility |
| Core dump exposure | Configuration issue |
| Spectre/Meltdown | CPU microarchitecture |
| Physical attacks | Out of scope |

### Recommendations

1. **Disable swap** or use encrypted swap
2. **Disable core dumps** in production
3. **Use hardware memory encryption** where available
4. **Limit secret lifetimes** in application code

## Further Reading

- [Rust Book: Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [Zeroize crate documentation](https://docs.rs/zeroize)
- [Subtle crate documentation](https://docs.rs/subtle)
- [Secure Coding Guidelines for Rust](https://anssi-fr.github.io/rust-guide/)
