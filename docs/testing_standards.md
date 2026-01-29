# Testing Standards

This document defines the testing requirements and standards for LatticeArc.

## Overview

LatticeArc maintains rigorous testing standards appropriate for a cryptographic library:

| Metric | Target | Current |
|--------|--------|---------|
| Line coverage | 90%+ | Tracked in CI |
| Branch coverage | 80%+ | Tracked in CI |
| Public API coverage | 100% | Required |
| Doc test coverage | 100% | Required |

## Test Categories

### 1. Unit Tests

Located inline in source files under `#[cfg(test)]` modules.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"test data";

        let encrypted = encrypt(plaintext, &key).expect("encryption failed");
        let decrypted = decrypt(&encrypted, &key).expect("decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
```

**Requirements:**
- Test happy path for all public functions
- Test error conditions and edge cases
- Use descriptive test names explaining what is tested

### 2. Integration Tests

Located in `tests/` directories within each crate.

```rust
// tests/hybrid_encryption.rs
use latticearc::prelude::*;

#[test]
fn end_to_end_hybrid_encryption() {
    // Generate keys
    let (pk, sk) = HybridKem::generate_keypair().unwrap();

    // Encrypt
    let plaintext = b"secret message";
    let ciphertext = hybrid_encrypt(plaintext, &pk).unwrap();

    // Decrypt
    let recovered = hybrid_decrypt(&ciphertext, &sk).unwrap();

    assert_eq!(plaintext.as_slice(), recovered.as_slice());
}
```

**Requirements:**
- Test cross-crate functionality
- Test realistic usage scenarios
- Test interoperability between components

### 3. Property-Based Tests

Using `proptest` for invariant testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_any_message(plaintext in any::<Vec<u8>>()) {
        let key = generate_key().unwrap();
        let ciphertext = encrypt(&plaintext, &key).unwrap();
        let recovered = decrypt(&ciphertext, &key).unwrap();

        prop_assert_eq!(plaintext, recovered);
    }

    #[test]
    fn signature_verifies_for_any_message(message in any::<Vec<u8>>()) {
        let (vk, sk) = generate_keypair().unwrap();
        let signature = sign(&message, &sk).unwrap();

        prop_assert!(verify(&message, &signature, &vk).unwrap());
    }
}
```

**Requirements:**
- Test cryptographic invariants
- Minimum 256 test cases per property
- Regression testing for found failures

### 4. CAVP/KAT Tests

Known Answer Tests using NIST test vectors in `arc-validation`:

```rust
#[test]
fn ml_kem_768_kat() {
    let vectors = load_kat_vectors("ML-KEM-768.json");

    for vector in vectors {
        let (pk, sk) = MlKem::from_seed(&vector.seed);

        assert_eq!(pk.to_bytes(), vector.expected_pk);
        assert_eq!(sk.to_bytes(), vector.expected_sk);

        let (ss, ct) = MlKem::encapsulate_deterministic(&pk, &vector.enc_seed);
        assert_eq!(ss.as_ref(), vector.expected_ss);
        assert_eq!(ct.to_bytes(), vector.expected_ct);
    }
}
```

**Requirements:**
- All FIPS 203-206 algorithms must pass CAVP vectors
- Vectors must be from official NIST sources
- Test both positive and negative cases

### 5. Fuzz Tests

Located in `arc-fuzz/` using `cargo-fuzz`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use latticearc::prelude::*;

fuzz_target!(|data: &[u8]| {
    // Should not panic on any input
    let _ = MlKemPublicKey::from_bytes(data);
});
```

**Requirements:**
- All public APIs accepting byte slices must be fuzzed
- Minimum 1 hour fuzzing per target before release
- Corpus maintained in repository

### 6. Documentation Tests

Every public API must have working examples:

```rust
/// Encrypts data using AES-256-GCM.
///
/// # Examples
///
/// ```
/// use latticearc::prelude::*;
///
/// let key = [0u8; 32];
/// let nonce = [0u8; 12];
/// let plaintext = b"secret";
///
/// let ciphertext = aes_gcm_encrypt(plaintext, &key, &nonce, &[])?;
/// let recovered = aes_gcm_decrypt(&ciphertext, &key, &nonce, &[])?;
///
/// assert_eq!(plaintext.as_slice(), recovered.as_slice());
/// # Ok::<(), latticearc::Error>(())
/// ```
pub fn aes_gcm_encrypt(/* ... */) -> Result<Vec<u8>> {
    // ...
}
```

**Requirements:**
- All public items must have `# Examples` section
- Examples must compile and pass
- Examples must demonstrate common usage

## Security-Specific Tests

### Zeroization Tests

Verify sensitive data is cleared from memory:

```rust
#[test]
fn secret_key_zeroized_on_drop() {
    let (_, sk) = generate_keypair().unwrap();
    let sk_ptr = sk.as_ptr();
    let sk_len = sk.len();

    drop(sk);

    // Memory should be zeroed (best effort verification)
    // Note: Optimizer may interfere; use black_box in real tests
    unsafe {
        let slice = std::slice::from_raw_parts(sk_ptr, sk_len);
        assert!(slice.iter().all(|&b| b == 0));
    }
}
```

### Constant-Time Tests

Verify timing-sensitive operations don't leak information:

```rust
#[test]
fn signature_verification_constant_time() {
    let (vk, sk) = generate_keypair().unwrap();
    let message = b"test";
    let valid_sig = sign(message, &sk).unwrap();
    let invalid_sig = vec![0u8; valid_sig.len()];

    // Measure verification time
    let valid_time = measure(|| verify(message, &valid_sig, &vk));
    let invalid_time = measure(|| verify(message, &invalid_sig, &vk));

    // Times should be similar (within statistical noise)
    let ratio = valid_time.max(invalid_time) / valid_time.min(invalid_time);
    assert!(ratio < 1.1, "Timing difference too large: {ratio}");
}
```

### Panic-Freedom Tests

Ensure no panics in library code:

```rust
#[test]
fn no_panic_on_invalid_input() {
    // These should all return errors, not panic
    assert!(MlKemPublicKey::from_bytes(&[]).is_err());
    assert!(MlKemPublicKey::from_bytes(&[0; 1]).is_err());
    assert!(decrypt(&[], &[0; 32]).is_err());
}
```

## Running Tests

### Full Test Suite

```bash
# All tests with all features
cargo test --workspace --all-features

# With output
cargo test --workspace --all-features -- --nocapture
```

### Specific Test Categories

```bash
# Unit tests only
cargo test --workspace --lib

# Integration tests only
cargo test --workspace --test '*'

# Doc tests only
cargo test --workspace --doc

# Property tests
cargo test --workspace --all-features proptest

# CAVP/KAT tests
cargo test --package arc-validation --all-features
```

### Fuzzing

```bash
# Install cargo-fuzz (requires nightly)
cargo +nightly install cargo-fuzz

# Run specific fuzz target
cd arc-fuzz
cargo +nightly fuzz run fuzz_ml_kem_decapsulate

# Run for specific duration
cargo +nightly fuzz run fuzz_ml_kem_decapsulate -- -max_total_time=3600
```

### Coverage

```bash
# Install llvm-cov
cargo install cargo-llvm-cov

# Generate coverage report
cargo llvm-cov --workspace --all-features --html

# Open report
open target/llvm-cov/html/index.html
```

## CI Requirements

All PRs must pass:

1. **Build**: `cargo build --workspace --all-features`
2. **Tests**: `cargo test --workspace --all-features`
3. **Lints**: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. **Format**: `cargo fmt --all -- --check`
5. **Audit**: `cargo audit`
6. **Deny**: `cargo deny check all`

## Test Organization

```
latticearc/
├── arc-core/
│   ├── src/
│   │   └── lib.rs        # Unit tests inline
│   └── tests/
│       └── integration.rs
├── arc-primitives/
│   ├── src/
│   │   ├── kem/
│   │   │   └── ml_kem.rs # Unit tests inline
│   │   └── sig/
│   │       └── ml_dsa.rs # Unit tests inline
│   └── tests/
│       ├── kem_tests.rs
│       └── sig_tests.rs
├── arc-validation/
│   └── src/
│       └── cavp/         # NIST test vectors
└── arc-fuzz/
    └── fuzz_targets/     # Fuzz test targets
```

## Adding New Tests

### For New Features

1. Add unit tests in the implementation file
2. Add integration tests if cross-crate
3. Add property tests for invariants
4. Add fuzz target if accepting untrusted input
5. Add doc tests to public APIs

### For Bug Fixes

1. Add regression test reproducing the bug
2. Verify the fix
3. Add edge case tests to prevent similar bugs

## Test Naming Conventions

```rust
// Format: <what>_<condition>_<expected_result>
#[test]
fn encrypt_with_valid_key_succeeds() { }

#[test]
fn encrypt_with_invalid_key_returns_error() { }

#[test]
fn decrypt_with_wrong_key_fails() { }

#[test]
fn signature_on_modified_message_fails_verification() { }
```

## Mocking and Test Utilities

Test utilities in `#[cfg(test)]` modules:

```rust
#[cfg(test)]
pub(crate) mod test_utils {
    pub fn fixed_key() -> [u8; 32] {
        [0x42; 32]
    }

    pub fn random_bytes(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut bytes = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}
```

## Performance Regression Tests

Located in `arc-perf/`:

```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn ml_kem_benchmark(c: &mut Criterion) {
    c.bench_function("ml_kem_768_keygen", |b| {
        b.iter(|| MlKem::generate_keypair(MlKemVariant::MlKem768))
    });
}

criterion_group!(benches, ml_kem_benchmark);
criterion_main!(benches);
```

Run with:
```bash
cargo bench --workspace --all-features
```
