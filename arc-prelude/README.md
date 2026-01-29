# arc-prelude

Common types, traits, and error handling for LatticeArc.

## Overview

`arc-prelude` provides foundational types used across all LatticeArc crates:

- **Error types** - Unified error handling
- **Common traits** - Shared trait definitions
- **Utility types** - Commonly used type aliases
- **Memory safety** - Zeroization utilities

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-prelude = "0.1"
```

### Error Handling

```rust
use arc_prelude::*;

fn crypto_operation() -> Result<Vec<u8>, CryptoError> {
    // Operations return CryptoError variants
    let key = parse_key(input)?;
    Ok(encrypt(data, &key)?)
}

// Match on specific errors
match result {
    Err(CryptoError::InvalidKey { reason }) => {
        eprintln!("Key error: {}", reason);
    }
    Err(CryptoError::DecryptionFailed) => {
        eprintln!("Decryption failed - wrong key?");
    }
    Ok(data) => { /* use data */ }
    Err(e) => return Err(e),
}
```

### Common Traits

```rust
use arc_prelude::traits::*;

// Implement for custom types
impl Zeroizable for MySecret {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}
```

## Error Types

| Error | Description |
|-------|-------------|
| `InvalidKey` | Key format or length invalid |
| `InvalidInput` | Input validation failed |
| `InvalidCiphertext` | Ciphertext format invalid |
| `InvalidSignature` | Signature verification failed |
| `EncryptionFailed` | Encryption operation failed |
| `DecryptionFailed` | Decryption operation failed |
| `KeyGenerationFailed` | Key generation failed |
| `InternalError` | Unexpected internal error |

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library | Yes |
| `alloc` | Heap allocation | Yes |

## Re-exports

Common dependencies re-exported for convenience:

```rust
use arc_prelude::prelude::*;

// Includes:
// - zeroize::{Zeroize, ZeroizeOnDrop}
// - subtle::{ConstantTimeEq, Choice}
// - Error types
// - Common traits
```

## Security

- No unsafe code
- Zeroization utilities for secret data
- Constant-time comparison helpers

## License

Apache-2.0
