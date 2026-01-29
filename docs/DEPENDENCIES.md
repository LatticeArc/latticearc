# Dependencies

This document describes LatticeArc's dependencies and supply chain security practices.

## Supply Chain Security

### Dependency Policy

1. **Minimal dependencies**: Use only what is necessary
2. **Trusted sources**: Only crates.io and audited git repos
3. **License compliance**: MIT, Apache-2.0, BSD, ISC, CC0-1.0 only
4. **Audited crates**: Prefer crates audited by RustSec
5. **Pinned versions**: Lock files committed to repository

### Automated Checks

| Check | Tool | Frequency |
|-------|------|-----------|
| Vulnerability scan | cargo-audit | Every CI run |
| License compliance | cargo-deny | Every CI run |
| Dependency review | GitHub Dependabot | Continuous |
| SBOM generation | Planned | Releases |

## Cryptographic Dependencies

These dependencies implement cryptographic primitives:

| Crate | Version | Purpose | FIPS Validated |
|-------|---------|---------|----------------|
| `aws-lc-rs` | 1.15+ | ML-KEM (FIPS 203), AES-GCM | Yes (Cert #4631, #4759, #4816) |
| `fips204` | Latest | ML-DSA (FIPS 204) | No (pure Rust, awaiting aws-lc-rs) |
| `fips205` | Latest | SLH-DSA (FIPS 205) | Audited |
| `fn-dsa` | Latest | FN-DSA (FIPS 206) | Partial |
| `chacha20poly1305` | Latest | ChaCha20-Poly1305 | RustCrypto audited |
| `sha2` | Latest | SHA-256, SHA-384, SHA-512 | RustCrypto audited |
| `sha3` | Latest | SHA-3, SHAKE | RustCrypto audited |
| `hmac` | Latest | HMAC, HKDF | RustCrypto audited |
| `pbkdf2` | Latest | PBKDF2 key derivation | RustCrypto audited |
| `ed25519-dalek` | Latest | Ed25519 signatures | Dalek audited |
| `k256` | Latest | secp256k1 signatures | RustCrypto audited |

### aws-lc-rs

LatticeArc uses `aws-lc-rs` for FIPS 140-3 validated cryptography:
- ML-KEM (FIPS 203) key encapsulation
- AES-GCM authenticated encryption
- ECDH key exchange (X25519)

aws-lc-rs is backed by AWS-LC, which holds FIPS 140-3 certificates.

### RustCrypto

LatticeArc uses multiple crates from the [RustCrypto](https://github.com/RustCrypto) organization, which:
- Has a strong security track record
- Undergoes regular security audits
- Maintains formal verification efforts
- Has responsive vulnerability handling

### Dalek Cryptography

For classical elliptic curve operations, LatticeArc uses Dalek crates:
- `ed25519-dalek`: Ed25519 signatures
- `x25519-dalek`: X25519 Diffie-Hellman

These crates are widely used and audited.

## Security-Critical Dependencies

| Crate | Purpose | Why Trusted |
|-------|---------|-------------|
| `zeroize` | Memory clearing | RustCrypto, audited |
| `subtle` | Constant-time operations | Dalek, audited |
| `rand` | Random number generation | Rust team maintained |
| `rand_core` | RNG traits | Rust team maintained |
| `getrandom` | OS entropy | Rust team maintained |

## TLS Dependencies

For TLS functionality (`arc-tls`):

| Crate | Purpose | Trust Level |
|-------|---------|-------------|
| `rustls` | TLS implementation | High (ISRG, audited) |
| `webpki` | Certificate validation | High (part of rustls) |
| `rustls-pki-types` | PKI type definitions | High (part of rustls) |

Rustls is:
- Memory-safe TLS implementation
- Audited by multiple parties
- Used in production by major services

## Utility Dependencies

Non-cryptographic utilities:

| Crate | Purpose | Trust Level |
|-------|---------|-------------|
| `thiserror` | Error derive macros | High (widely used) |
| `tracing` | Logging/instrumentation | High (Tokio project) |
| `serde` | Serialization | High (widely used) |
| `criterion` | Benchmarking | Dev only |
| `proptest` | Property testing | Dev only |

## Forbidden Dependencies

The following are explicitly forbidden via `deny.toml`:

| Crate | Reason |
|-------|--------|
| `libc` | Direct C bindings increase attack surface |
| `nix` | Direct syscall bindings |
| `ring` | Includes C code; prefer pure Rust |
| `openssl` | C library with security history |

### License Restrictions

Forbidden licenses (copyleft):
- GPL
- AGPL
- LGPL
- CDDL

These would create licensing complications for users.

## Dependency Graph

```
latticearc
├── arc-core
│   ├── arc-primitives
│   │   ├── aws-lc-rs (ML-KEM, AES-GCM, X25519) [FIPS validated]
│   │   ├── fips204 (ML-DSA)
│   │   ├── fips205 (SLH-DSA)
│   │   ├── fn-dsa (FN-DSA)
│   │   ├── chacha20poly1305
│   │   ├── sha2, sha3
│   │   ├── hmac, pbkdf2
│   │   ├── ed25519-dalek
│   │   ├── k256 (secp256k1)
│   │   ├── zeroize
│   │   └── subtle
│   └── arc-prelude
│       ├── thiserror
│       └── zeroize
├── arc-hybrid
│   ├── arc-primitives
│   └── arc-prelude
└── arc-tls
    ├── rustls
    ├── arc-primitives
    └── arc-prelude
```

## Updating Dependencies

### Regular Updates

1. Run `cargo update` to get latest compatible versions
2. Run `cargo audit` to check for vulnerabilities
3. Run full test suite
4. Review changelog for breaking changes

### Security Updates

When a vulnerability is disclosed:

1. Check if LatticeArc is affected
2. Update immediately if affected
3. Release patch version
4. Notify users via security advisory

## Dependency Configuration

### `deny.toml`

```toml
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0"]
deny = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"]

[bans]
multiple-versions = "warn"
deny = [
    { name = "libc" },
    { name = "openssl" },
    { name = "openssl-sys" },
]

[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[sources]
allow-git = []
```

### Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      rust-dependencies:
        patterns:
          - "*"
```

## Verifying Dependencies

### Audit

```bash
# Check for known vulnerabilities
cargo audit

# Check licenses and bans
cargo deny check all
```

### Inspect

```bash
# View dependency tree
cargo tree

# View dependency for specific crate
cargo tree -p aes-gcm

# Find why a crate is included
cargo tree --invert some-crate
```

## Reporting Dependency Issues

If you discover a security issue in a dependency:

1. Report to the dependency maintainers first
2. If it affects LatticeArc, report to us at security@latticearc.com
3. We will coordinate disclosure and updates

## SBOM (Software Bill of Materials)

For releases, we generate SBOM in SPDX format:

```bash
# Generate SBOM
cargo sbom > sbom.spdx.json
```

This allows users to:
- Verify all dependencies
- Check against vulnerability databases
- Meet compliance requirements
