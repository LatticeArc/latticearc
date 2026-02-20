# Contributing to LatticeArc

Thank you for your interest in contributing to LatticeArc! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing Requirements](#testing-requirements)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Security](#security)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

**Required for all builds:**
- Rust 1.93+ (2024 edition)
- C/C++ compiler (clang or gcc) — aws-lc-rs compiles AWS-LC from C source
- Git
- cargo-deny (`cargo install cargo-deny`)
- cargo-audit (`cargo install cargo-audit`)

**Additional requirements for FIPS builds (`--features fips`):**
- CMake 3.x
- Go 1.18+

> **Why CMake and Go for FIPS?** The `fips` feature enables aws-lc-rs's FIPS 140-3 validated module, which requires CMake for its build system and Go for the `delocate` tool. Default builds (without `--features fips`) do not need CMake or Go. See [aws-lc-rs build requirements](https://aws.github.io/aws-lc-rs/) for details.

### Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/latticearc.git
cd latticearc
```

## Development Setup

### Build

```bash
# Build all crates
cargo build --workspace --all-features

# Build specific crate
cargo build -p latticearc --all-features
```

### Verify Setup

```bash
# Run all checks (must pass before submitting PR)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check all
```

## Making Changes

### Branch Strategy

- `main` - stable, release-ready code
- Feature branches: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat` - new feature
- `fix` - bug fix
- `docs` - documentation only
- `test` - adding/updating tests
- `refactor` - code change that neither fixes a bug nor adds a feature
- `perf` - performance improvement
- `chore` - maintenance tasks
- `security` - security-related changes

**Examples:**
```
feat(primitives): add ML-KEM-1024 support
fix(primitives): correct HKDF output length validation
docs: update API documentation for encrypt function
security(hybrid): fix timing vulnerability in signature verification
```

### What to Include

Each PR should:
- Address a single concern
- Include tests for new functionality
- Update documentation as needed
- Update CHANGELOG.md
- Pass all CI checks

## Testing Requirements

### Coverage Thresholds

- Unit tests: 90%+ line coverage
- Overall: 80%+ coverage
- All public APIs must have tests

### Running Tests

```bash
# All tests
cargo test --workspace --all-features

# Specific crate
cargo test -p latticearc --all-features

# With output
cargo test --workspace --all-features -- --nocapture

# Doc tests only
cargo test --workspace --doc
```

### Test Categories

1. **Unit Tests** - inline in source files (`#[cfg(test)]` modules)
2. **Integration Tests** - consolidated in `tests/tests/` (latticearc-tests crate)
3. **Property Tests** - using proptest for invariants
4. **Doc Tests** - examples in documentation
5. **CAVP Vectors** - NIST test vectors in latticearc-tests

### Adding Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use latticearc::CryptoConfig;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let data = b"test data";

        let encrypted = encrypt(data, &key, CryptoConfig::new()).expect("encryption failed");
        let decrypted = decrypt(&encrypted, &key, CryptoConfig::new()).expect("decryption failed");

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
```

### Benchmarks

```bash
# Run benchmarks
cargo bench --workspace --all-features

# Specific benchmark
cargo bench -p latticearc
```

## Submitting Changes

### Pull Request Process

1. **Create PR** against `main` branch
2. **Fill out PR template** completely
3. **Ensure CI passes** - all checks must be green
4. **Request review** from maintainers
5. **Address feedback** promptly
6. **Squash commits** if requested

### PR Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No security vulnerabilities introduced
- [ ] Commit messages follow convention

### Review Process

- PRs require 2 approvals from maintainers
- Security-sensitive changes require security team review
- Performance-critical changes require benchmark comparison

## Code Style

### Formatting

- Use `rustfmt` with project config (rustfmt.toml)
- Max line width: 100 characters
- Run before committing: `cargo fmt --all`

### Linting

All code must pass strict clippy checks:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Documentation

- All public items must be documented
- Use `///` for item documentation
- Include `# Examples` section for complex APIs
- Include `# Errors` section for fallible functions
- Include `# Panics` section if function can panic (should be rare)

**Example:**
```rust
/// Encrypts data with automatic algorithm selection.
///
/// # Arguments
///
/// * `data` - The plaintext to encrypt
/// * `key` - 32-byte encryption key
/// * `config` - Crypto configuration for algorithm selection
///
/// # Returns
///
/// Encrypted data with metadata for decryption.
///
/// # Errors
///
/// Returns `CoreError::InvalidKeyLength` if key is not 32 bytes.
/// Returns `CoreError::EncryptionFailed` if encryption fails.
///
/// # Examples
///
/// ```
/// use latticearc::{encrypt, CryptoConfig};
///
/// let key = [0u8; 32];
/// let encrypted = encrypt(b"secret", &key, CryptoConfig::new())?;
/// # Ok::<(), latticearc::CoreError>(())
/// ```
pub fn encrypt(data: &[u8], key: &[u8], config: CryptoConfig) -> Result<EncryptedData> {
    // ...
}
```

### Error Handling

- Never use `unwrap()` or `expect()` in library code
- Use `?` operator for error propagation
- Return descriptive error types
- Test error paths

### Cryptographic Code

- No unsafe code in cryptographic paths
- Use constant-time operations for secret data
- Zeroize sensitive data on drop
- Validate all inputs

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for reporting instructions.

### Security Requirements

All contributions must:
- Not introduce timing vulnerabilities
- Properly zeroize sensitive data
- Validate all inputs
- Use approved cryptographic primitives
- Pass security review for crypto changes

### Prohibited Patterns

```rust
// FORBIDDEN - panics on failure
let key = generate_key().unwrap();

// FORBIDDEN - timing leak
if secret_a == secret_b { ... }

// FORBIDDEN - sensitive data not zeroized
let key: [u8; 32] = generate_key();
// key goes out of scope without zeroization

// FORBIDDEN - unsafe code
unsafe { ... }
```

### Required Patterns

```rust
// CORRECT - proper error handling
let key = generate_key()?;

// CORRECT - constant-time comparison
use subtle::ConstantTimeEq;
if secret_a.ct_eq(&secret_b).into() { ... }

// CORRECT - automatic zeroization
use zeroize::Zeroize;
let mut key = generate_key()?;
// ... use key ...
key.zeroize(); // or use ZeroizeOnDrop derive
```

## Questions?

- Open a [Discussion](https://github.com/latticearc/latticearc/discussions) for questions
- Check existing issues before opening new ones
- Join our community channels (if available)

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
