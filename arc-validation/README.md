# arc-validation

NIST CAVP validation and testing utilities for LatticeArc.

## Overview

`arc-validation` provides:

- **CAVP test vectors** - NIST Cryptographic Algorithm Validation Program tests
- **KAT validation** - Known Answer Test verification
- **Self-test infrastructure** - FIPS 140-3 style self-tests
- **Timing analysis** - Constant-time verification utilities

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-validation = "0.1"
```

### CAVP Validation

```rust
use arc_validation::cavp::*;

// Run ML-KEM CAVP tests
run_ml_kem_cavp_tests()?;

// Run ML-DSA CAVP tests
run_ml_dsa_cavp_tests()?;

// Run all CAVP tests
run_all_cavp_tests()?;
```

### Known Answer Tests

```rust
use arc_validation::kat::*;

// Load and run KAT vectors
let vectors = load_kat_vectors("ML-KEM-768")?;
for v in vectors {
    let result = ml_kem_encapsulate_deterministic(&v.pk, &v.seed)?;
    assert_eq!(result.shared_secret, v.expected_ss);
    assert_eq!(result.ciphertext, v.expected_ct);
}
```

### Self-Tests

```rust
use arc_validation::self_test::*;

// Run FIPS 140-3 style power-up self-tests
let results = run_self_tests()?;

assert!(results.ml_kem_passed);
assert!(results.ml_dsa_passed);
assert!(results.aes_gcm_passed);
assert!(results.rng_passed);
```

### Timing Analysis

```rust
use arc_validation::timing::*;

// Measure operation timing variance
let analysis = analyze_timing(|| {
    verify_signature(&message, &signature, &key)
}, 1000)?;

// Check for timing leaks
assert!(analysis.variance_ratio < 1.1, "Timing variance too high");
```

## Test Vector Sources

| Algorithm | Source |
|-----------|--------|
| ML-KEM | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| ML-DSA | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| SLH-DSA | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| AES-GCM | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |

## Running Tests

```bash
# Run all CAVP validation tests
cargo test -p arc-validation --all-features

# Run specific algorithm tests
cargo test -p arc-validation ml_kem

# Run timing analysis (slow)
cargo test -p arc-validation timing -- --ignored
```

## Modules

| Module | Description |
|--------|-------------|
| `cavp` | CAVP test vector validation |
| `kat` | Known Answer Test utilities |
| `self_test` | Self-test infrastructure |
| `timing` | Timing analysis tools |
| `fips_validation` | FIPS compliance testing |

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library | Yes |
| `timing-tests` | Enable timing analysis | No |

## License

Apache-2.0
