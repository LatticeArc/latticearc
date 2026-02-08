# Frequently Asked Questions

## General

### What is LatticeArc?

LatticeArc is a post-quantum cryptography library for Rust implementing NIST FIPS 203-206 standards. It provides key encapsulation, digital signatures, and hybrid encryption resistant to both classical and quantum computer attacks.

### Why should I use post-quantum cryptography?

Quantum computers pose a threat to classical cryptographic algorithms:
- RSA, DSA, DH, ECDH, ECDSA will be broken by Shor's algorithm
- AES security is reduced by Grover's algorithm (halved key strength)

Post-quantum algorithms are designed to resist quantum attacks while remaining secure against classical attacks.

### When will quantum computers break current cryptography?

Expert estimates vary widely (2030-2050+). However, "harvest now, decrypt later" attacks mean adversaries can store encrypted data today and decrypt it when quantum computers become available. Sensitive long-term data should use PQC now.

### Is LatticeArc production-ready?

LatticeArc implements NIST-standardized algorithms (FIPS 203-206) and follows security best practices. However:
- It has not yet undergone third-party security audit
- It is not FIPS 140-3 validated
- Use hybrid mode for defense-in-depth

## Algorithms

### Which algorithm should I use?

| Use Case | Recommended |
|----------|-------------|
| Key exchange | ML-KEM-768 |
| Digital signatures | ML-DSA-65 |
| Hash-based signatures | SLH-DSA-SHAKE-128f |
| Maximum security | ML-KEM-1024 + ML-DSA-87 |
| Constrained devices | ML-KEM-512 |

### What's the difference between ML-KEM variants?

| Variant | Security Level | Performance | Use When |
|---------|---------------|-------------|----------|
| ML-KEM-512 | Level 1 | Fastest | Low-security or constrained environments |
| ML-KEM-768 | Level 3 | Balanced | General purpose (recommended) |
| ML-KEM-1024 | Level 5 | Slowest | Maximum security requirements |

### Should I use hybrid mode?

**Yes**, during the transition period (now through ~2035). Hybrid mode combines:
- Post-quantum algorithm (protects against quantum attacks)
- Classical algorithm (fallback if PQC has unknown weaknesses)

This provides defense-in-depth until PQC algorithms are battle-tested.

### What's the difference between SLH-DSA-*f and SLH-DSA-*s?

- **-f (fast)**: Faster signing, larger signatures
- **-s (small)**: Smaller signatures, slower signing

Choose based on your constraints:
- Bandwidth-limited: Use -s variants
- Performance-critical: Use -f variants

## Usage

### How do I encrypt data?

```rust
use latticearc::prelude::*;

// Generate keys
let (pk, sk) = MlKem::generate_keypair(MlKemVariant::MlKem768)?;

// Encrypt
let (shared_secret, ciphertext) = MlKem::encapsulate(&pk)?;

// Use shared_secret with AES-GCM for symmetric encryption
let encrypted = aes_gcm_encrypt(&data, &shared_secret, &nonce, &[])?;
```

### How do I sign data?

```rust
use latticearc::prelude::*;

// Generate keys
let (vk, sk) = MlDsa::generate_keypair(MlDsaVariant::MlDsa65)?;

// Sign
let signature = MlDsa::sign(&message, &sk)?;

// Verify
let is_valid = MlDsa::verify(&message, &signature, &vk)?;
```

### How do I serialize keys?

```rust
use latticearc::prelude::*;

// To bytes
let pk_bytes = public_key.to_bytes();

// From bytes
let public_key = MlKemPublicKey::from_bytes(&pk_bytes)?;
```

### How do I use hybrid encryption?

```rust
use latticearc::hybrid::*;

let (pk, sk) = HybridKem::generate_keypair()?;
let (shared_secret, ciphertext) = HybridKem::encapsulate(&pk)?;
let shared_secret = HybridKem::decapsulate(&ciphertext, &sk)?;
```

## Security

### Is LatticeArc constant-time?

LatticeArc uses constant-time primitives via the `subtle` crate for all secret-dependent operations. However, we cannot guarantee:
- Rust compiler optimizations don't introduce timing variance
- CPU microarchitectural effects (cache timing, speculative execution)

### How are secrets protected in memory?

1. **Zeroization**: Secrets are zeroed when dropped using the `zeroize` crate
2. **No copying**: APIs are designed to minimize secret copies
3. **Type safety**: Secret types don't implement `Clone` or `Debug`

### Does LatticeArc use unsafe code?

No. `unsafe_code = "forbid"` is set at the workspace level. All code is safe Rust.

### Can I use LatticeArc for FIPS 140-3 compliance?

LatticeArc implements FIPS-compliant algorithms but is not itself validated. For FIPS 140-3:
1. Use LatticeArc's algorithms as building blocks
2. Implement required self-tests (arc-validation provides infrastructure)
3. Consider validated hardware modules for the certification boundary

## Performance

### How fast is ML-KEM?

Approximate performance on modern x86_64:

| Operation | ML-KEM-768 |
|-----------|------------|
| Key generation | ~50 μs |
| Encapsulation | ~70 μs |
| Decapsulation | ~80 μs |

### How fast is ML-DSA?

Approximate performance on modern x86_64:

| Operation | ML-DSA-65 |
|-----------|-----------|
| Key generation | ~150 μs |
| Signing | ~300 μs |
| Verification | ~150 μs |

### How can I improve performance?

1. Enable hardware acceleration (AVX2/NEON) via `--target-cpu=native`
2. Use release builds with LTO
3. Batch operations when possible
4. Choose appropriate algorithm variants (smaller = faster)

## Compatibility

### What Rust version is required?

Rust 1.93+ (2024 edition). See `rust-version` in Cargo.toml.

### What platforms are supported?

| Platform | Status |
|----------|--------|
| Linux x86_64 | Fully supported |
| Linux aarch64 | Fully supported |
| macOS x86_64 | Fully supported |
| macOS aarch64 | Fully supported |
| Windows x86_64 | Fully supported |
| WebAssembly | Experimental |

### Can I use LatticeArc with async?

LatticeArc operations are synchronous. For async contexts:

```rust
let result = tokio::task::spawn_blocking(move || {
    encrypt(&data, &key)
}).await?;
```

### Is there a C API?

Not currently. C FFI bindings are planned for a future release.

## Troubleshooting

### I get "invalid key" errors

Check that:
1. Key bytes are the correct length for the algorithm
2. Keys haven't been corrupted during serialization
3. You're using matching public/private keys

### Decryption fails but encryption worked

Common causes:
1. Different keys used for encryption and decryption
2. Ciphertext modified in transit (use authenticated encryption)
3. Nonce reuse with AES-GCM

### Performance is slower than expected

1. Are you building in release mode? (`cargo build --release`)
2. Build with `--target-cpu=native` to enable AES-NI, AVX2, and other CPU features
3. Check if you're accidentally cloning large data structures

### Memory usage is high

1. Large PQC keys consume more memory than classical
2. Ensure secrets are dropped promptly (limit lifetimes)
3. Avoid unnecessary key caching

## Contributing

### How do I report a bug?

Open a GitHub issue using the bug report template.

### How do I report a security vulnerability?

**Do NOT open a public issue.** Email Security@LatticeArc.com. See [SECURITY.md](SECURITY.md).

### How do I contribute code?

1. Fork the repository
2. Create a feature branch
3. Make changes following [CONTRIBUTING.md](CONTRIBUTING.md)
4. Submit a pull request

## More Questions?

- Open a [GitHub Discussion](https://github.com/latticearc/latticearc/discussions)
- Check the [API Documentation](https://docs.rs/latticearc)
- Read the [Security Guide](docs/SECURITY_GUIDE.md)
