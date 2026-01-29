# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in LatticeArc, please report it privately:

### Email

Send details to: **Security@LatticeArc.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Any suggested fixes (optional)

### GitHub Security Advisory

You can also report via [GitHub Security Advisory](https://github.com/latticearc/latticearc/security/advisories/new).

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgment | 24 hours |
| Severity assessment | 48 hours |
| Fix development | 7-30 days (severity dependent) |
| Coordinated disclosure | 90 days max |

## Supported Versions

| Version | Status | Security Updates Until |
|---------|--------|------------------------|
| 0.1.x | Supported | Current |

We recommend always using the latest version.

## Security Guarantees

### What We Guarantee

- **No unsafe code** in cryptographic code paths
- **Constant-time operations** for all secret-dependent computations
- **Zeroization** of sensitive data when no longer needed
- **FIPS 203-206 compliance** for post-quantum algorithms
- **Input validation** on all public APIs

### What We Do Not Guarantee

- Protection against physical attacks (power analysis, EM emanations)
- Protection against compromised operating systems
- Protection against compromised hardware
- Memory clearing after process termination (OS responsibility)
- Side-channel resistance in Rust compiler-generated code

## Security Design

### Cryptographic Primitives

| Primitive | Standard | Implementation |
|-----------|----------|----------------|
| ML-KEM | FIPS 203 | aws-lc-rs |
| ML-DSA | FIPS 204 | fips204 crate |
| SLH-DSA | FIPS 205 | fips205 crate |
| FN-DSA | FIPS 206 | fn-dsa crate |
| AES-GCM | FIPS 197, SP 800-38D | aes-gcm crate |
| SHA-3 | FIPS 202 | sha3 crate |
| HKDF | RFC 5869 | hkdf crate |

### Defense in Depth

1. **Hybrid cryptography** - PQC + classical for defense against future threats
2. **Strict linting** - `forbid(unsafe_code)`, `deny(unwrap_used)`
3. **Memory safety** - Rust's ownership model + explicit zeroization
4. **Input validation** - All public APIs validate inputs
5. **Constant-time** - Using `subtle` crate for timing-safe operations

## Security Testing

### Continuous Security Measures

- **Fuzzing** - Daily fuzzing with cargo-fuzz
- **Static analysis** - Clippy with security lints
- **Dependency audit** - cargo-audit in CI
- **License compliance** - cargo-deny checks
- **CAVP validation** - NIST test vectors

### Formal Verification

- Kani model checking for critical functions
- Property-based testing with proptest

## Security Audits

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| Q1 2026 | Internal | Full codebase | Complete |

Audit reports will be published in the `docs/audits/` directory when available.

## Known Limitations

### Timing Side Channels

While we use constant-time primitives, we cannot guarantee:
- Rust compiler optimizations don't introduce timing variance
- CPU microarchitectural timing (cache, branch prediction)
- OS scheduling effects on timing

### Memory

- Stack memory may not be cleared if thread panics
- Swap may contain sensitive data (use encrypted swap)
- Core dumps may contain sensitive data (disable in production)

## Vulnerability Disclosure Policy

We follow coordinated disclosure:

1. Reporter contacts us privately
2. We acknowledge within 24 hours
3. We assess severity and develop fix
4. We coordinate disclosure timeline with reporter
5. We release fix and publish advisory
6. Maximum 90 days to public disclosure

### Recognition

We maintain a security acknowledgments page for researchers who report valid vulnerabilities (with permission).

## Security Advisories

Published advisories are available at:
- [GitHub Security Advisories](https://github.com/latticearc/latticearc/security/advisories)
- [RustSec Advisory Database](https://rustsec.org/) (when applicable)

## Contact

- **Security reports**: Security@LatticeArc.com
- **General questions**: Use GitHub Discussions
- **Non-security bugs**: Use GitHub Issues
