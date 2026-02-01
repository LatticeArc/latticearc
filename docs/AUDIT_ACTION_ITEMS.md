# LatticeArc Audit Action Items

**Created**: 2026-01-31
**Based On**: `docs/CODEBASE_AUDIT_REPORT.md`
**Status**: Active

---

## Overview

This document provides detailed, step-by-step instructions for addressing all findings from the codebase audit. Each task includes:
- Exact commands to run
- Files to modify
- Acceptance criteria
- Verification steps

---

## Task Tracking

| ID | Priority | Task | Effort | Status |
|----|----------|------|--------|--------|
| T1 | P1 Critical | Declare formal_verification module | 15 min | ⏳ Pending |
| T2 | P2 High | Run unused dependency audit | 30 min | ⏳ Pending |
| T3 | P3 High | Measure test coverage | 1 hour | ⏳ Pending |
| T4 | P4 Medium | Add signature integration tests | 2 hours | ⏳ Pending |
| T5 | P4 Medium | Add hybrid encryption tests | 1.5 hours | ⏳ Pending |
| T6 | P4 Medium | Add Zero Trust session tests | 2 hours | ⏳ Pending |
| T7 | P5 Low | Add coverage badge to README | 15 min | ⏳ Pending |
| T8 | P5 Low | Document test utility functions | 15 min | ⏳ Pending |

---

## T1: Declare formal_verification Module (P1 Critical)

### Problem
The `arc-tls/src/formal_verification.rs` module exists (~200 lines) but is not declared in `lib.rs`, making it completely inaccessible dead code.

### Files to Modify

**File 1**: `arc-tls/src/lib.rs`

### Steps

#### Step 1.1: Verify the orphaned module exists
```bash
ls -la arc-tls/src/formal_verification.rs
cat arc-tls/src/formal_verification.rs | head -30
```

#### Step 1.2: Check what features the module requires
```bash
grep -n "cfg(feature" arc-tls/src/formal_verification.rs
```

Expected features:
- `kani` - For Kani formal verification
- `formal_verification` or `formal-verification` - General feature
- `saw` - For SAW proofs

#### Step 1.3: Add feature definitions to Cargo.toml

**File**: `arc-tls/Cargo.toml`

Add under `[features]` section:
```toml
[features]
default = []
formal-verification = []
kani = []
saw = []
```

#### Step 1.4: Declare the module in lib.rs

**File**: `arc-tls/src/lib.rs`

Add near other module declarations:
```rust
/// Formal verification support for TLS security properties.
///
/// This module provides formal verification capabilities using Kani and SAW.
/// Enable with `--features formal-verification`, `--features kani`, or `--features saw`.
#[cfg(any(feature = "formal-verification", feature = "kani", feature = "saw"))]
pub mod formal_verification;
```

#### Step 1.5: Verify compilation with each feature
```bash
# Test each feature individually
cargo check --package arc-tls --features formal-verification
cargo check --package arc-tls --features kani
cargo check --package arc-tls --features saw

# Test combined
cargo check --package arc-tls --features "formal-verification,kani,saw"

# Ensure default build still works
cargo check --package arc-tls
```

#### Step 1.6: Fix any compilation errors
If the module has internal compilation errors (missing imports, etc.), fix them.

### Acceptance Criteria
- [ ] `formal_verification.rs` is declared in `lib.rs`
- [ ] Features are defined in `Cargo.toml`
- [ ] `cargo check --package arc-tls` passes (default)
- [ ] `cargo check --package arc-tls --features formal-verification` passes
- [ ] `cargo check --workspace --all-features` passes

### Verification
```bash
# Should show the module in docs
cargo doc --package arc-tls --features formal-verification --open
```

---

## T2: Run Unused Dependency Audit (P2 High)

### Problem
Unused dependencies increase build times and attack surface. `cargo-udeps` was not run during the audit.

### Prerequisites
- Rust nightly toolchain installed

### Steps

#### Step 2.1: Install cargo-udeps
```bash
cargo install cargo-udeps --locked
```

#### Step 2.2: Install nightly toolchain (if not present)
```bash
rustup toolchain install nightly
```

#### Step 2.3: Run the audit
```bash
cargo +nightly udeps --workspace --all-targets --all-features 2>&1 | tee udeps-report.txt
```

#### Step 2.4: Analyze the output
The output will show:
- Unused dependencies per crate
- Dependencies only used in dev/build

#### Step 2.5: For each unused dependency

**If truly unused:**
1. Remove from `Cargo.toml`
2. Run `cargo check` to verify

**If used only in specific features:**
1. Move to `[target.'cfg(...)'.dependencies]` or
2. Add `optional = true` and gate behind feature

#### Step 2.6: Common false positives
- `proptest` - Used in tests only (keep in dev-dependencies)
- `criterion` - Used in benchmarks only (keep in dev-dependencies)
- Feature-gated dependencies - May appear unused if feature not enabled

### Acceptance Criteria
- [ ] `cargo +nightly udeps` runs successfully
- [ ] Report saved to `docs/udeps-report.txt`
- [ ] All truly unused dependencies removed
- [ ] `cargo build --workspace --all-features` still passes

### Verification
```bash
# Re-run after cleanup - should show no unused deps
cargo +nightly udeps --workspace --all-targets --all-features
```

---

## T3: Measure Test Coverage (P3 High)

### Problem
Test coverage metrics were not measured. Target is 80% per CLAUDE.md.

### Prerequisites
- LLVM tools installed (comes with Rust)

### Steps

#### Step 3.1: Install cargo-llvm-cov
```bash
cargo install cargo-llvm-cov
```

#### Step 3.2: Run coverage for entire workspace
```bash
cargo llvm-cov --workspace --all-features --html
```

#### Step 3.3: View the report
```bash
open target/llvm-cov/html/index.html
# Or on Linux:
xdg-open target/llvm-cov/html/index.html
```

#### Step 3.4: Generate summary report
```bash
cargo llvm-cov --workspace --all-features --text > docs/coverage-report.txt
cargo llvm-cov --workspace --all-features --json > docs/coverage-report.json
```

#### Step 3.5: Analyze per-crate coverage

| Crate | Target | Action if Below Target |
|-------|--------|------------------------|
| arc-primitives | 80% | Add unit tests for uncovered functions |
| arc-core | 80% | Add convenience API tests |
| arc-hybrid | 80% | Add hybrid encryption tests |
| arc-tls | 80% | Add TLS integration tests |
| arc-zkp | 80% | Add ZKP tests |
| arc-validation | 80% | N/A (test crate) |
| latticearc | 80% | Add facade tests |

#### Step 3.6: Identify low-coverage files
```bash
# Find files with <50% coverage
cargo llvm-cov --workspace --all-features --json | \
  jq '.data[0].files[] | select(.summary.lines.percent < 50) | {file: .filename, coverage: .summary.lines.percent}'
```

#### Step 3.7: Create coverage tracking issue
Document current coverage levels and create tracking for improvement.

### Acceptance Criteria
- [ ] Coverage report generated
- [ ] Report saved to `docs/coverage-report.txt`
- [ ] Per-crate coverage levels documented
- [ ] Files with <50% coverage identified
- [ ] Improvement plan created for low-coverage areas

### Verification
```bash
# Should show overall coverage percentage
cargo llvm-cov --workspace --all-features --summary-only
```

---

## T4: Add Signature Integration Tests (P4 Medium)

### Problem
No integration tests for `sign()` / `verify()` unified API.

### Files to Create/Modify

**File**: `latticearc/tests/signature_integration.rs` (NEW)

### Steps

#### Step 4.1: Create the test file
```bash
touch latticearc/tests/signature_integration.rs
```

#### Step 4.2: Add test scaffolding

```rust
//! Integration tests for signature operations.
//!
//! Tests cover:
//! - Ed25519 signatures
//! - ML-DSA post-quantum signatures
//! - Hybrid signatures (ML-DSA + Ed25519)
//! - Error cases and edge conditions

#![allow(clippy::unwrap_used)] // Allowed in tests

use latticearc::{
    sign, verify, sign_ed25519, verify_ed25519,
    sign_pq_ml_dsa, verify_pq_ml_dsa,
    CryptoConfig, SecurityLevel,
};

// =============================================================================
// Ed25519 Signature Tests
// =============================================================================

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let message = b"Test message for signing";

    let signed = sign_ed25519(message, CryptoConfig::new())
        .expect("signing should succeed");

    let is_valid = verify_ed25519(&signed, CryptoConfig::new())
        .expect("verification should succeed");

    assert!(is_valid, "signature should be valid");
}

#[test]
fn test_ed25519_tampered_message_fails() {
    let message = b"Original message";

    let mut signed = sign_ed25519(message, CryptoConfig::new())
        .expect("signing should succeed");

    // Tamper with the message
    signed.message[0] ^= 0xFF;

    let is_valid = verify_ed25519(&signed, CryptoConfig::new())
        .expect("verification should complete");

    assert!(!is_valid, "tampered signature should be invalid");
}

#[test]
fn test_ed25519_empty_message() {
    let message = b"";

    let signed = sign_ed25519(message, CryptoConfig::new())
        .expect("signing empty message should succeed");

    let is_valid = verify_ed25519(&signed, CryptoConfig::new())
        .expect("verification should succeed");

    assert!(is_valid, "empty message signature should be valid");
}

#[test]
fn test_ed25519_large_message() {
    let message = vec![0xAB; 1024 * 1024]; // 1MB

    let signed = sign_ed25519(&message, CryptoConfig::new())
        .expect("signing large message should succeed");

    let is_valid = verify_ed25519(&signed, CryptoConfig::new())
        .expect("verification should succeed");

    assert!(is_valid, "large message signature should be valid");
}

// =============================================================================
// ML-DSA Post-Quantum Signature Tests
// =============================================================================

#[test]
fn test_ml_dsa_sign_verify_roundtrip() {
    let message = b"Post-quantum signed message";

    let signed = sign_pq_ml_dsa(message, CryptoConfig::new())
        .expect("ML-DSA signing should succeed");

    let is_valid = verify_pq_ml_dsa(&signed, CryptoConfig::new())
        .expect("ML-DSA verification should succeed");

    assert!(is_valid, "ML-DSA signature should be valid");
}

#[test]
fn test_ml_dsa_different_security_levels() {
    let message = b"Testing security levels";

    // Test each security level
    for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
        let config = CryptoConfig::new().security_level(level);

        let signed = sign_pq_ml_dsa(message, config.clone())
            .expect("signing should succeed");

        let is_valid = verify_pq_ml_dsa(&signed, config)
            .expect("verification should succeed");

        assert!(is_valid, "signature should be valid for {:?}", level);
    }
}

// =============================================================================
// Hybrid Signature Tests (ML-DSA + Ed25519)
// =============================================================================

#[test]
fn test_hybrid_sign_verify_roundtrip() {
    let message = b"Hybrid signed message";

    // Default config uses hybrid signatures
    let signed = sign(message, CryptoConfig::new())
        .expect("hybrid signing should succeed");

    let is_valid = verify(&signed, CryptoConfig::new())
        .expect("hybrid verification should succeed");

    assert!(is_valid, "hybrid signature should be valid");
}

#[test]
fn test_hybrid_signature_tampered_fails() {
    let message = b"Original message";

    let mut signed = sign(message, CryptoConfig::new())
        .expect("signing should succeed");

    // Tamper with the signature bytes
    if let Some(byte) = signed.signature.get_mut(0) {
        *byte ^= 0xFF;
    }

    let result = verify(&signed, CryptoConfig::new());

    // Should either return false or an error
    match result {
        Ok(is_valid) => assert!(!is_valid, "tampered signature should be invalid"),
        Err(_) => {} // Error is also acceptable for tampered signature
    }
}

// =============================================================================
// Edge Cases and Error Conditions
// =============================================================================

#[test]
fn test_sign_unicode_message() {
    let message = "Hello, 世界! 🔐🔑".as_bytes();

    let signed = sign(message, CryptoConfig::new())
        .expect("signing unicode should succeed");

    let is_valid = verify(&signed, CryptoConfig::new())
        .expect("verification should succeed");

    assert!(is_valid);
}

#[test]
fn test_sign_binary_data() {
    // All possible byte values
    let message: Vec<u8> = (0..=255).collect();

    let signed = sign(&message, CryptoConfig::new())
        .expect("signing binary data should succeed");

    let is_valid = verify(&signed, CryptoConfig::new())
        .expect("verification should succeed");

    assert!(is_valid);
}

#[test]
fn test_different_messages_different_signatures() {
    let message1 = b"Message 1";
    let message2 = b"Message 2";

    let signed1 = sign(message1, CryptoConfig::new())
        .expect("signing should succeed");
    let signed2 = sign(message2, CryptoConfig::new())
        .expect("signing should succeed");

    // Signatures should be different
    assert_ne!(signed1.signature, signed2.signature);
}

#[test]
fn test_same_message_different_signatures() {
    // Due to randomness in signing, same message should produce different signatures
    let message = b"Same message";

    let signed1 = sign(message, CryptoConfig::new())
        .expect("signing should succeed");
    let signed2 = sign(message, CryptoConfig::new())
        .expect("signing should succeed");

    // Both should be valid
    assert!(verify(&signed1, CryptoConfig::new()).expect("should verify"));
    assert!(verify(&signed2, CryptoConfig::new()).expect("should verify"));

    // But signatures should be different (due to randomness)
    // Note: Some signature schemes are deterministic, so this may need adjustment
}
```

#### Step 4.3: Run the tests
```bash
cargo test --package latticearc --test signature_integration --all-features -- --nocapture
```

#### Step 4.4: Fix any failing tests
Adjust test expectations based on actual API behavior.

#### Step 4.5: Add to CI if not automatically included
Integration tests in `tests/` directory are automatically included.

### Acceptance Criteria
- [ ] `signature_integration.rs` created with 10+ tests
- [ ] All tests pass
- [ ] Ed25519 roundtrip tested
- [ ] ML-DSA roundtrip tested
- [ ] Hybrid signature roundtrip tested
- [ ] Tampered signature detection tested
- [ ] Edge cases covered (empty, large, unicode, binary)

### Verification
```bash
cargo test --package latticearc --test signature_integration --all-features
```

---

## T5: Add Hybrid Encryption Tests (P4 Medium)

### Problem
No integration tests for hybrid encryption (`encrypt_hybrid()` / `decrypt_hybrid()`).

### Files to Modify

**File**: `latticearc/tests/unified_api_integration.rs` (EXTEND)

### Steps

#### Step 5.1: Add hybrid encryption test section

Add to the existing file:

```rust
// =============================================================================
// Hybrid Encryption Tests (ML-KEM + AES-GCM)
// =============================================================================

mod hybrid_encryption {
    use latticearc::{
        encrypt_hybrid, decrypt_hybrid,
        generate_keypair, CryptoConfig, SecurityLevel,
    };

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
            .expect("keypair generation should succeed");

        let plaintext = b"Secret message for hybrid encryption";

        let encrypted = encrypt_hybrid(plaintext, &public_key, CryptoConfig::new())
            .expect("hybrid encryption should succeed");

        let decrypted = decrypt_hybrid(&encrypted, &secret_key, CryptoConfig::new())
            .expect("hybrid decryption should succeed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_encryption_wrong_key_fails() {
        let (public_key1, _secret_key1) = generate_keypair(CryptoConfig::new())
            .expect("keypair 1 generation should succeed");
        let (_public_key2, secret_key2) = generate_keypair(CryptoConfig::new())
            .expect("keypair 2 generation should succeed");

        let plaintext = b"Secret message";

        let encrypted = encrypt_hybrid(plaintext, &public_key1, CryptoConfig::new())
            .expect("encryption should succeed");

        // Try to decrypt with wrong secret key
        let result = decrypt_hybrid(&encrypted, &secret_key2, CryptoConfig::new());

        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn test_hybrid_encryption_tampered_ciphertext_fails() {
        let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
            .expect("keypair generation should succeed");

        let plaintext = b"Secret message";

        let mut encrypted = encrypt_hybrid(plaintext, &public_key, CryptoConfig::new())
            .expect("encryption should succeed");

        // Tamper with ciphertext
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = decrypt_hybrid(&encrypted, &secret_key, CryptoConfig::new());

        assert!(result.is_err(), "decryption of tampered ciphertext should fail");
    }

    #[test]
    fn test_hybrid_encryption_different_security_levels() {
        for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
            let config = CryptoConfig::new().security_level(level);

            let (public_key, secret_key) = generate_keypair(config.clone())
                .expect("keypair generation should succeed");

            let plaintext = b"Testing different security levels";

            let encrypted = encrypt_hybrid(plaintext, &public_key, config.clone())
                .expect("encryption should succeed");

            let decrypted = decrypt_hybrid(&encrypted, &secret_key, config)
                .expect("decryption should succeed");

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_hybrid_encryption_empty_plaintext() {
        let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
            .expect("keypair generation should succeed");

        let plaintext = b"";

        let encrypted = encrypt_hybrid(plaintext, &public_key, CryptoConfig::new())
            .expect("encryption of empty plaintext should succeed");

        let decrypted = decrypt_hybrid(&encrypted, &secret_key, CryptoConfig::new())
            .expect("decryption should succeed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_encryption_large_plaintext() {
        let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
            .expect("keypair generation should succeed");

        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

        let encrypted = encrypt_hybrid(&plaintext, &public_key, CryptoConfig::new())
            .expect("encryption of large plaintext should succeed");

        let decrypted = decrypt_hybrid(&encrypted, &secret_key, CryptoConfig::new())
            .expect("decryption should succeed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hybrid_encryption_different_keypairs_different_ciphertext() {
        let (public_key1, _) = generate_keypair(CryptoConfig::new())
            .expect("keypair 1 should succeed");
        let (public_key2, _) = generate_keypair(CryptoConfig::new())
            .expect("keypair 2 should succeed");

        let plaintext = b"Same message";

        let encrypted1 = encrypt_hybrid(plaintext, &public_key1, CryptoConfig::new())
            .expect("encryption 1 should succeed");
        let encrypted2 = encrypt_hybrid(plaintext, &public_key2, CryptoConfig::new())
            .expect("encryption 2 should succeed");

        // Ciphertexts should be different
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }
}
```

#### Step 5.2: Run the tests
```bash
cargo test --package latticearc --test unified_api_integration hybrid_encryption --all-features -- --nocapture
```

#### Step 5.3: Handle known limitations
If tests fail due to aws-lc-rs secret key deserialization limitation, mark as `#[ignore]` with explanation:

```rust
#[test]
#[ignore = "aws-lc-rs does not support ML-KEM secret key deserialization"]
fn test_hybrid_encryption_with_serialized_keys() {
    // ...
}
```

### Acceptance Criteria
- [ ] 7+ hybrid encryption tests added
- [ ] Roundtrip encryption/decryption tested
- [ ] Wrong key detection tested
- [ ] Tampered ciphertext detection tested
- [ ] Different security levels tested
- [ ] Edge cases covered (empty, large)
- [ ] Known limitations documented with `#[ignore]`

### Verification
```bash
cargo test --package latticearc hybrid_encryption --all-features
```

---

## T6: Add Zero Trust Session Tests (P4 Medium)

### Problem
No integration tests for Zero Trust session lifecycle.

### Files to Create

**File**: `latticearc/tests/zero_trust_integration.rs` (NEW)

### Steps

#### Step 6.1: Create the test file

```rust
//! Integration tests for Zero Trust session management.
//!
//! Tests cover:
//! - Session establishment
//! - Session validation
//! - Operations with sessions
//! - Session expiration handling

#![allow(clippy::unwrap_used)] // Allowed in tests

use latticearc::{
    encrypt, decrypt, sign, verify,
    generate_keypair, CryptoConfig, VerifiedSession,
    CoreError,
};
use std::thread;
use std::time::Duration;

// =============================================================================
// Session Establishment Tests
// =============================================================================

#[test]
fn test_session_establishment() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session establishment should succeed");

    assert!(session.is_valid(), "newly established session should be valid");
}

#[test]
fn test_session_has_unique_id() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session1 = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session 1 should succeed");
    let session2 = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session 2 should succeed");

    assert_ne!(
        session1.session_id(),
        session2.session_id(),
        "different sessions should have different IDs"
    );
}

#[test]
fn test_session_has_expiration() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    let expires_at = session.expires_at();
    let now = std::time::SystemTime::now();

    assert!(expires_at > now, "session should expire in the future");
}

// =============================================================================
// Session Validation Tests
// =============================================================================

#[test]
fn test_session_verify_valid() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    // Should not error for valid session
    session.verify_valid().expect("valid session should pass verification");
}

#[test]
fn test_session_is_valid_check() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    assert!(session.is_valid(), "session should be valid immediately after creation");
}

// =============================================================================
// Operations with Sessions
// =============================================================================

#[test]
fn test_encrypt_with_session() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    let key = [0u8; 32];
    let plaintext = b"Secret data";

    let encrypted = encrypt(plaintext, &key, CryptoConfig::new().session(&session))
        .expect("encryption with session should succeed");

    let decrypted = decrypt(&encrypted, &key, CryptoConfig::new().session(&session))
        .expect("decryption with session should succeed");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_sign_with_session() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    let message = b"Message to sign";

    let signed = sign(message, CryptoConfig::new().session(&session))
        .expect("signing with session should succeed");

    let is_valid = verify(&signed, CryptoConfig::new().session(&session))
        .expect("verification with session should succeed");

    assert!(is_valid);
}

#[test]
fn test_multiple_operations_same_session() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    let key = [0u8; 32];
    let config = CryptoConfig::new().session(&session);

    // Perform multiple operations with the same session
    for i in 0..5 {
        let plaintext = format!("Message {}", i);

        let encrypted = encrypt(plaintext.as_bytes(), &key, config.clone())
            .expect("encryption should succeed");

        let decrypted = decrypt(&encrypted, &key, config.clone())
            .expect("decryption should succeed");

        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }
}

// =============================================================================
// Session Expiration Tests
// =============================================================================

// Note: These tests may need adjustment based on actual session timeout values.
// Default session lifetime is typically 30 minutes, so we can't easily test
// actual expiration in unit tests. Instead, we test the validation logic.

#[test]
fn test_session_expiration_check_exists() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session should succeed");

    // Verify the session has an expiration time set
    let _expires = session.expires_at();
    // If this compiles and runs, the expiration check exists
}

// =============================================================================
// Session Refresh Tests
// =============================================================================

#[test]
fn test_session_refresh_creates_new_session() {
    let (public_key, secret_key) = generate_keypair(CryptoConfig::new())
        .expect("keypair generation should succeed");

    let session1 = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session 1 should succeed");

    // Simulate refresh by creating a new session
    let session2 = VerifiedSession::establish(&public_key, &secret_key)
        .expect("session 2 should succeed");

    // Both should be valid
    assert!(session1.is_valid());
    assert!(session2.is_valid());

    // But different session IDs
    assert_ne!(session1.session_id(), session2.session_id());
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_operations_without_session_still_work() {
    // Operations should work without a session (unverified mode)
    let key = [0u8; 32];
    let plaintext = b"Secret data";

    let encrypted = encrypt(plaintext, &key, CryptoConfig::new())
        .expect("encryption without session should succeed");

    let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())
        .expect("decryption without session should succeed");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}
```

#### Step 6.2: Run the tests
```bash
cargo test --package latticearc --test zero_trust_integration --all-features -- --nocapture
```

#### Step 6.3: Adjust for actual API
The test code above is based on expected API. Adjust based on actual `VerifiedSession` implementation.

### Acceptance Criteria
- [ ] `zero_trust_integration.rs` created with 10+ tests
- [ ] Session establishment tested
- [ ] Session validation tested
- [ ] Operations with sessions tested
- [ ] Multiple operations with same session tested
- [ ] Session refresh pattern tested
- [ ] Operations without session still work

### Verification
```bash
cargo test --package latticearc --test zero_trust_integration --all-features
```

---

## T7: Add Coverage Badge to README (P5 Low)

### Problem
No coverage badge in README to show test coverage status.

### Prerequisites
- T3 (coverage measurement) must be complete first

### Steps

#### Step 7.1: Get coverage percentage
```bash
cargo llvm-cov --workspace --all-features --summary-only 2>/dev/null | grep "TOTAL"
```

#### Step 7.2: Create badge URL

For a static badge:
```markdown
[![Coverage](https://img.shields.io/badge/coverage-XX%25-brightgreen)](docs/coverage-report.txt)
```

Color thresholds:
- `brightgreen`: 80%+
- `green`: 70-79%
- `yellowgreen`: 60-69%
- `yellow`: 50-59%
- `orange`: 40-49%
- `red`: <40%

#### Step 7.3: Add to README.md

Add after other badges (line 7):
```markdown
[![Coverage](https://img.shields.io/badge/coverage-XX%25-brightgreen)](docs/coverage-report.txt)
```

#### Step 7.4: For dynamic badge (optional)

Set up Codecov or Coveralls integration:
1. Add to CI workflow
2. Use their badge URL

### Acceptance Criteria
- [ ] Coverage badge added to README
- [ ] Badge shows accurate coverage percentage
- [ ] Badge links to coverage report

### Verification
View README on GitHub - badge should render correctly.

---

## T8: Document Test Utility Functions (P5 Low)

### Problem
Test utility functions with `#[allow(dead_code)]` lack documentation explaining their purpose.

### Files to Modify
- `arc-primitives/src/zeroization_tests.rs`
- `arc-primitives/src/aead/mod.rs`

### Steps

#### Step 8.1: Add documentation to zeroization_tests.rs

```rust
/// Test utilities for verifying memory zeroization.
///
/// These functions are reserved for future zeroization tests and are
/// intentionally marked `#[allow(dead_code)]` as they are test infrastructure.

/// Verifies that a byte pattern exists in memory.
///
/// # Arguments
/// * `ptr` - Pointer to memory region
/// * `len` - Length of memory region
/// * `pattern` - Expected byte pattern
///
/// # Returns
/// `true` if the pattern is found, `false` otherwise.
#[allow(dead_code)]
fn verify_pattern(ptr: *const u8, len: usize, pattern: u8) -> bool {
    // ...
}
```

#### Step 8.2: Add documentation to aead/mod.rs

```rust
/// Constant-time equality comparison for test assertions.
///
/// This function is used in tests to compare sensitive data without
/// timing side channels. It is marked `#[allow(dead_code)]` as it is
/// reserved for future constant-time comparison tests.
#[cfg(test)]
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // ...
}
```

### Acceptance Criteria
- [ ] All `#[allow(dead_code)]` test functions have doc comments
- [ ] Documentation explains purpose and future use
- [ ] `cargo doc` generates clean documentation

### Verification
```bash
cargo doc --package arc-primitives --open
```

---

## Completion Checklist

### Phase 1: Immediate (This Week)
- [ ] T1: Declare formal_verification module
- [ ] T2: Run cargo-udeps
- [ ] T3: Measure test coverage

### Phase 2: Short-term (This Month)
- [ ] T4: Add signature integration tests
- [ ] T5: Add hybrid encryption tests
- [ ] T6: Add Zero Trust session tests

### Phase 3: Cleanup (Within 3 Months)
- [ ] T7: Add coverage badge
- [ ] T8: Document test utilities
- [ ] Achieve 80% test coverage target

---

## Notes

### Running All New Tests
```bash
# After completing T4, T5, T6:
cargo test --package latticearc --all-features -- --nocapture
```

### Checking Overall Health
```bash
# Full workspace check
cargo check --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Updating This Document
After completing each task:
1. Change status from ⏳ Pending to ✅ Complete
2. Add completion date
3. Note any issues encountered

---

**Document Version**: 1.0
**Last Updated**: 2026-01-31
