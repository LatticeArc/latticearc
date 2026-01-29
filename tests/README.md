# Test Organization

This document describes how tests are organized in LatticeArc.

## Overview

LatticeArc uses multiple testing strategies to ensure correctness and security:

| Test Type | Location | Purpose |
|-----------|----------|---------|
| Unit tests | `src/**/*.rs` | Test individual functions |
| Integration tests | `*/tests/*.rs` | Test component interactions |
| Property tests | `*/tests/*.rs` | Test invariants with random inputs |
| CAVP tests | `arc-validation/` | NIST test vector validation |
| Fuzz tests | `arc-fuzz/` | Find crashes with arbitrary input |
| Doc tests | `src/**/*.rs` | Verify documentation examples |
| Benchmarks | `*/benches/*.rs` | Performance measurement |

## Directory Structure

```
latticearc/
├── arc-core/
│   ├── src/
│   │   └── lib.rs          # Unit tests inline
│   └── tests/
│       └── integration.rs  # Integration tests
├── arc-primitives/
│   ├── src/
│   │   ├── kem/
│   │   │   └── ml_kem.rs   # Unit tests inline
│   │   └── sig/
│   │       └── ml_dsa.rs   # Unit tests inline
│   └── tests/
│       ├── kem_tests.rs
│       └── sig_tests.rs
├── arc-validation/
│   └── src/
│       └── cavp/           # NIST test vectors
│           ├── ml_kem.rs
│           ├── ml_dsa.rs
│           └── ...
├── arc-fuzz/
│   └── fuzz_targets/       # Fuzzing targets
│       ├── fuzz_ml_kem.rs
│       └── ...
└── tests/                  # Workspace-level tests
    └── README.md           # This file
```

## Running Tests

### All Tests

```bash
# Run all tests
cargo test --workspace --all-features

# With output
cargo test --workspace --all-features -- --nocapture

# Parallel execution
cargo test --workspace --all-features -- --test-threads=4
```

### Specific Crate

```bash
# Test specific crate
cargo test -p arc-core --all-features

# Test specific module
cargo test -p arc-primitives kem:: --all-features
```

### Specific Test

```bash
# Run test by name
cargo test test_encrypt_decrypt --all-features

# Run tests matching pattern
cargo test ml_kem --all-features
```

### Test Categories

```bash
# Unit tests only
cargo test --workspace --lib

# Integration tests only
cargo test --workspace --test '*'

# Doc tests only
cargo test --workspace --doc

# Ignored tests (long-running)
cargo test --workspace -- --ignored
```

## Unit Tests

Unit tests are inline in source files:

```rust
// src/kem/ml_kem.rs

pub fn encapsulate(pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)> {
    // implementation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_produces_valid_ciphertext() {
        let (pk, sk) = generate_keypair().unwrap();
        let (ss, ct) = encapsulate(&pk).unwrap();

        // Verify ciphertext length
        assert_eq!(ct.len(), CIPHERTEXT_SIZE);

        // Verify decapsulation works
        let ss2 = decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss, ss2);
    }

    #[test]
    fn encapsulate_with_invalid_key_fails() {
        let invalid_pk = PublicKey::from_bytes(&[0u8; 10]);
        assert!(invalid_pk.is_err());
    }
}
```

## Integration Tests

Integration tests are in `tests/` directories:

```rust
// tests/hybrid_encryption.rs

use latticearc::prelude::*;

#[test]
fn hybrid_kem_full_flow() {
    // Key generation
    let (pk, sk) = HybridKem::generate_keypair().unwrap();

    // Encapsulation
    let (ss1, ct) = HybridKem::encapsulate(&pk).unwrap();

    // Decapsulation
    let ss2 = HybridKem::decapsulate(&ct, &sk).unwrap();

    assert_eq!(ss1, ss2);
}
```

## Property-Based Tests

Using `proptest` for invariant testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
        key in prop::collection::vec(any::<u8>(), 32..33),
    ) {
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = [0u8; 12];

        let ciphertext = encrypt(&plaintext, &key, &nonce).unwrap();
        let recovered = decrypt(&ciphertext, &key, &nonce).unwrap();

        prop_assert_eq!(plaintext, recovered);
    }
}
```

## CAVP/KAT Tests

NIST test vector validation in `arc-validation`:

```rust
// arc-validation/src/cavp/ml_kem.rs

#[test]
fn ml_kem_768_encapsulation_kat() {
    let vectors = load_kat_vectors("ML-KEM-768-encap.json");

    for v in vectors {
        let pk = MlKemPublicKey::from_bytes(&v.pk).unwrap();
        let (ss, ct) = MlKem::encapsulate_deterministic(&pk, &v.seed).unwrap();

        assert_eq!(ss.as_ref(), &v.expected_ss);
        assert_eq!(ct.to_bytes(), v.expected_ct);
    }
}
```

## Fuzz Tests

Fuzz targets in `arc-fuzz/`:

```rust
// arc-fuzz/fuzz_targets/fuzz_ml_kem.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Should not panic on any input
    let _ = MlKemPublicKey::from_bytes(data);

    // If we can parse, try to use it
    if let Ok(pk) = MlKemPublicKey::from_bytes(data) {
        let _ = MlKem::encapsulate(&pk);
    }
});
```

Running fuzz tests:

```bash
cd arc-fuzz
cargo +nightly fuzz run fuzz_ml_kem -- -max_total_time=3600
```

## Security Tests

### Zeroization Tests

```rust
#[test]
fn secret_key_zeroized_on_drop() {
    let sk = generate_secret_key().unwrap();
    let ptr = sk.as_ptr();
    let len = sk.len();

    // Capture bytes before drop
    let bytes_before: Vec<u8> = unsafe {
        std::slice::from_raw_parts(ptr, len).to_vec()
    };
    assert!(bytes_before.iter().any(|&b| b != 0));

    drop(sk);

    // Check memory is zeroed after drop
    // Note: May be unreliable due to optimizer
}
```

### Constant-Time Tests

```rust
#[test]
fn mac_verification_constant_time() {
    let key = generate_key().unwrap();
    let message = b"test message";

    let valid_mac = compute_mac(message, &key).unwrap();
    let invalid_mac = vec![0u8; valid_mac.len()];

    // Measure timing
    let valid_time = time_operation(|| verify_mac(message, &valid_mac, &key));
    let invalid_time = time_operation(|| verify_mac(message, &invalid_mac, &key));

    // Should be approximately equal
    let ratio = valid_time.max(invalid_time) as f64 / valid_time.min(invalid_time) as f64;
    assert!(ratio < 1.1, "Timing difference: {ratio}");
}
```

## Test Utilities

Common test helpers in `#[cfg(test)]` modules:

```rust
#[cfg(test)]
pub(crate) mod test_utils {
    pub fn random_bytes(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut bytes = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    pub fn fixed_key() -> [u8; 32] {
        [0x42; 32]
    }
}
```

## Test Naming Convention

```rust
// Pattern: <function>_<scenario>_<expected_result>

#[test]
fn encrypt_with_valid_key_succeeds() { }

#[test]
fn encrypt_with_short_key_returns_error() { }

#[test]
fn decrypt_with_corrupted_ciphertext_fails() { }

#[test]
fn signature_on_modified_message_fails_verification() { }
```

## Coverage

Generate coverage reports:

```bash
# Install llvm-cov
cargo install cargo-llvm-cov

# Generate HTML report
cargo llvm-cov --workspace --all-features --html

# View report
open target/llvm-cov/html/index.html

# Coverage summary
cargo llvm-cov --workspace --all-features --summary-only
```

### Coverage Targets

| Metric | Target |
|--------|--------|
| Line coverage | 90%+ |
| Branch coverage | 80%+ |
| Function coverage | 95%+ |

## CI Integration

Tests run automatically on:
- Every push
- Every pull request
- Nightly (extended tests)

See `.github/workflows/` for CI configuration.

## Adding New Tests

### For New Features

1. Add unit tests in the implementation file
2. Add integration test if cross-crate functionality
3. Add property test for invariants
4. Add fuzz target if accepting untrusted input
5. Add doc tests with examples

### For Bug Fixes

1. Add regression test reproducing the bug
2. Verify fix with the test
3. Consider adding edge case tests

## Debugging Tests

```bash
# Run with debug output
RUST_LOG=debug cargo test test_name -- --nocapture

# Run single-threaded for easier debugging
cargo test test_name -- --test-threads=1

# Run with backtrace
RUST_BACKTRACE=1 cargo test test_name
```
