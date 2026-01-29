# Examples

This directory provides an index of examples across the LatticeArc workspace.

## Running Examples

Examples are located in individual crate directories. Run them using:

```bash
# Run a specific example
cargo run -p <crate-name> --example <example-name> --all-features

# Example:
cargo run -p arc-primitives --example test_ml_kem --all-features
cargo run -p arc-tls --example tls13_hybrid_client --all-features
```

## Example Index

### arc-primitives

| Example | Description |
|---------|-------------|
| `test_ml_kem` | ML-KEM key encapsulation demonstration |

```bash
cargo run -p arc-primitives --example test_ml_kem --all-features
```

### arc-tls

| Example | Description |
|---------|-------------|
| `tls13_hybrid_client` | TLS 1.3 client with hybrid PQ key exchange |
| `tls13_custom_hybrid` | Custom hybrid TLS configuration |
| `test_rustls_compat` | Rustls compatibility testing |

```bash
cargo run -p arc-tls --example tls13_hybrid_client --all-features
cargo run -p arc-tls --example tls13_custom_hybrid --all-features
```

## Quick Start Examples

### Key Encapsulation (ML-KEM)

```rust
use latticearc::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let (pk, sk) = MlKem::generate_keypair(MlKemVariant::MlKem768)?;

    // Encapsulate (sender side)
    let (shared_secret, ciphertext) = MlKem::encapsulate(&pk)?;

    // Decapsulate (receiver side)
    let recovered_secret = MlKem::decapsulate(&ciphertext, &sk)?;

    assert_eq!(shared_secret.as_ref(), recovered_secret.as_ref());
    println!("Key encapsulation successful!");
    Ok(())
}
```

### Digital Signatures (ML-DSA)

```rust
use latticearc::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate signing key pair
    let (vk, sk) = MlDsa::generate_keypair(MlDsaVariant::MlDsa65)?;

    // Sign a message
    let message = b"Hello, post-quantum world!";
    let signature = MlDsa::sign(message, &sk)?;

    // Verify the signature
    let is_valid = MlDsa::verify(message, &signature, &vk)?;

    assert!(is_valid);
    println!("Signature verification successful!");
    Ok(())
}
```

### Hybrid Encryption

```rust
use latticearc::hybrid::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate hybrid key pair (ML-KEM + X25519)
    let (pk, sk) = HybridKem::generate_keypair()?;

    // Encapsulate with both algorithms
    let (shared_secret, ciphertext) = HybridKem::encapsulate(&pk)?;

    // Decapsulate
    let recovered = HybridKem::decapsulate(&ciphertext, &sk)?;

    assert_eq!(shared_secret.as_ref(), recovered.as_ref());
    println!("Hybrid key exchange successful!");
    Ok(())
}
```

### Symmetric Encryption (AES-GCM)

```rust
use latticearc::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a key (in practice, derive from KEM shared secret)
    let key = [0u8; 32];  // Use proper key generation
    let nonce = [0u8; 12]; // Use unique nonce per message

    // Encrypt
    let plaintext = b"Secret message";
    let ciphertext = aes_gcm_encrypt(plaintext, &key, &nonce, &[])?;

    // Decrypt
    let recovered = aes_gcm_decrypt(&ciphertext, &key, &nonce, &[])?;

    assert_eq!(plaintext.as_slice(), recovered.as_slice());
    println!("AES-GCM encryption successful!");
    Ok(())
}
```

### Key Derivation (HKDF)

```rust
use latticearc::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Input keying material (e.g., from KEM shared secret)
    let ikm = b"shared secret from key exchange";
    let salt = b"optional salt";
    let info = b"application context";

    // Derive a 32-byte key
    let derived_key = hkdf_sha256(ikm, salt, info, 32)?;

    println!("Derived key: {} bytes", derived_key.len());
    Ok(())
}
```

## Creating New Examples

When adding new examples:

1. Place in the appropriate crate's `examples/` directory
2. Add entry to the crate's `Cargo.toml`:
   ```toml
   [[example]]
   name = "my_example"
   path = "examples/my_example.rs"
   ```
3. Update this README with the new example
4. Ensure the example compiles: `cargo build --example my_example`
5. Test the example works: `cargo run --example my_example`

## Documentation

- [API Documentation](https://docs.rs/latticearc)
- [Security Guide](../docs/SECURITY_GUIDE.md)
- [NIST Compliance](../docs/NIST_COMPLIANCE.md)
