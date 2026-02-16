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
| AES-GCM | FIPS 197, SP 800-38D | aws-lc-rs |
| SHA-3 | FIPS 202 | sha3 crate |
| HKDF | RFC 5869 | aws-lc-rs (HMAC-based) |

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

#### Our Code (Kani Model Checker)

| Component | Proofs | Properties Verified | Run Frequency |
|-----------|--------|---------------------|---------------|
| arc-hybrid | 7 | Correctness, Memory Safety, Security | Nightly + Weekly |
| arc-types | 12 | State Machine, Trust Ordering, Policy Completeness, Defaults | Nightly + Weekly + On Push |

**Kani proofs verify:**
- Encrypt→Decrypt roundtrip returns original plaintext
- KEM encapsulate→decapsulate produces consistent shared secrets
- Key derivation is deterministic (same inputs → same keys)
- Valid signatures verify correctly
- Invalid key lengths are rejected (no crashes)
- Operations are panic-free with valid inputs
- Secrets are zeroized correctly (no memory leaks)
- Key lifecycle state machine enforces valid transitions (5 proofs)
- Trust level ordering is total and consistent (3 proofs)
- Policy engine covers all security levels and scheme categories (3 proofs)
- Default security level is NIST Level 3 (1 proof)

**Verification approach:**
- Proofs available in source code (`arc-hybrid/src/formal_verification.rs`, `arc-types/src/key_lifecycle.rs`, `arc-types/src/zero_trust.rs`, `arc-types/src/types.rs`, `arc-types/src/selector.rs`)
- Run on nightly schedule (not every commit) following AWS-LC model
- Full suite runs weekly for comprehensive verification
- Manual runs via GitHub Actions workflow_dispatch

#### Underlying Primitives (AWS-LC SAW Verification)

We inherit formal verification for cryptographic primitives from aws-lc-rs:
- AES-GCM, ML-KEM, SHA-2, HMAC, AES-KWP
- Verified using SAW (Software Analysis Workbench) with Cryptol specifications
- Proofs maintained in [aws-lc-verification](https://github.com/awslabs/aws-lc-verification)

#### Property-Based Testing

- Property-based testing with proptest for additional randomized validation

## Security Audits

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| Q1 2026 | Internal | Full codebase | Complete |

Audit reports will be published in the `docs/audits/` directory when available.

## Known Limitations

### Constant-Time Guarantees

**Primitives (AES-GCM, ML-KEM, etc.):**
- We rely on [aws-lc-rs](https://github.com/aws/aws-lc-rs) cryptographic primitives
- These are [formally verified](https://github.com/awslabs/aws-lc-verification) for constant-time execution
- Verification uses SAW (Software Analysis Workbench) with Cryptol specifications
- **Mathematically proven**, not just tested

**Our API Layer:**
- Uses the [`subtle`](https://docs.rs/subtle) crate for constant-time comparisons
- `subtle` is maintained by [dalek-cryptography](https://github.com/dalek-cryptography/subtle)
- **Not formally verified** - uses pure Rust bitwise operations to prevent timing leaks
- Battle-tested: 22.7M downloads/month, used by rustls, RustCrypto, curve25519-dalek
- Zero known timing vulnerabilities (no RustSec advisories)
- Maintainers emphasize this is a "best-effort attempt" dependent on compiler behavior

**Why we use `subtle`:**
- Industry standard in Rust cryptography ecosystem
- No formally verified alternative exists for Rust custom types (enums, structs)
- aws-lc-rs provides `verify_slices_are_equal` only for `&[u8]` (not custom types)
- Pragmatic trade-off: battle-tested (proven) vs formally verified (doesn't exist for our use case)

**What We Cannot Guarantee:**
- CPU microarchitectural side-channels (cache timing, speculative execution)
- Compiler optimizations that break constant-time properties (mitigated via `subtle`)
- OS scheduling effects on timing measurements

**Verification Approach:**
- ✅ Formal verification (SAW) for primitives via aws-lc-rs
- ✅ Battle-tested libraries (`subtle`) for API layer comparisons
- ✅ Code review for constant-time patterns (no secret-dependent branches)

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
