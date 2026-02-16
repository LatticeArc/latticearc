# arc-prelude

Common types, traits, and error handling for LatticeArc.

## Overview

`arc-prelude` provides foundational types used across LatticeArc crates:

- **Error types** - `LatticeArcError` enum with recovery mechanisms
- **Error recovery** - Circuit breaker, graceful degradation, enhanced error handler
- **Testing infrastructure** - CAVP compliance, property-based testing, side-channel analysis
- **Re-exports** - Common dependencies (zeroize, subtle, serde, rand, etc.)
- **Domains** - HKDF domain separation constants (re-exported from `arc-types`)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-prelude = "0.1"
```

### Error Handling

```rust,ignore
use arc_prelude::prelude::{LatticeArcError, Result};

fn crypto_operation() -> Result<()> {
    // Operations return LatticeArcError variants
    Ok(())
}
```

### Error Types

The main error type is `LatticeArcError` defined in `prelude::error::types`:

```rust,ignore
pub enum LatticeArcError {
    // Cryptographic operation errors
    // Key validation errors
    // Configuration errors
    // etc.
}
```

### Re-exports

Common dependencies re-exported for convenience:

```rust,ignore
use arc_prelude::prelude::*;

// Includes access to:
// - LatticeArcError, Result
// - Error recovery (CircuitBreaker, EnhancedErrorHandler)
// - CAVP compliance testing (UtilityCavpTester, CryptoCavpTester)
// - Property-based testing utilities
// - Side-channel analysis tools
```

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library support | Yes |
| `std-backtrace` | Backtrace support in error types | No |
| `async` | Async runtime (tokio) support | No |
| `database` | Database error conversions | No |

## Security

- No unsafe code (`#![deny(unsafe_code)]`)
- Zeroization via `zeroize` crate (re-exported)
- Constant-time comparison via `subtle` crate (re-exported)

## License

Apache-2.0
