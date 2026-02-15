# arc-validation

NIST CAVP validation and testing utilities for LatticeArc.

## Overview

`arc-validation` provides:

- **CAVP test vectors** - NIST Cryptographic Algorithm Validation Program tests
- **KAT validation** - Known Answer Tests for ML-KEM, ML-DSA, AES-GCM, HMAC, HKDF, ChaCha20-Poly1305
- **Timing analysis** - Constant-time verification utilities
- **FIPS validation** - FIPS 140-3 compliance testing infrastructure
- **Wycheproof** - Google Wycheproof test vectors
- **Resource limits** - Bounds checking and input validation tests

## Modules

| Module | Description |
|--------|-------------|
| `cavp` | CAVP framework: vector storage, pipeline, compliance, enhanced framework |
| `nist_kat` | Known Answer Tests: ML-KEM, ML-DSA, AES-GCM, HMAC, HKDF, SHA-2, ChaCha20-Poly1305 |
| `kat_tests` | KAT test runners, loaders, reporters, EC vectors |
| `timing` | Timing analysis for constant-time verification |
| `constant_time` | Constant-time operation validators |
| `fips_validation` | FIPS 140-3 validator, algorithm tests, interface tests, policy tests |
| `wycheproof` | Google Wycheproof test vector integration |
| `rfc_vectors` | RFC-sourced test vectors |
| `nist_functions` | NIST statistical functions |
| `nist_sp800_22` | SP 800-22 randomness tests |
| `resource_limits` | Resource limit and bounds checking |
| `validation_summary` | Test result summary reporting |

## Running Tests

```bash
# Run all validation tests
cargo test -p arc-validation --all-features

# Run specific algorithm KATs
cargo test -p arc-validation ml_kem
cargo test -p arc-validation aes_gcm

# Run timing analysis (release mode required for accurate results)
cargo test -p arc-validation timing --all-features --release
```

## Test Vector Sources

| Algorithm | Source |
|-----------|--------|
| ML-KEM | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| ML-DSA | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| AES-GCM | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |
| HMAC | [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) |

## License

Apache-2.0
