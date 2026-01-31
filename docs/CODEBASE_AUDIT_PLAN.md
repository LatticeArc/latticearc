# LatticeArc Codebase Audit Plan

**Created**: 2026-01-30
**Purpose**: Comprehensive audit to ensure all cryptographic functions work as expected, documentation matches implementation, and tests provide adequate coverage.

**Lesson Learned**: The `unified_api/` directory (~11,500 lines) was dead code shadowed by an inline module. This audit aims to prevent similar issues.

---

## Audit Categories

1. **Dead Code Audit** - Find unreachable/unused code
2. **Cryptographic Function Audit** - Verify all crypto operations work correctly
3. **Documentation Audit** - Ensure docs/comments match implementation
4. **Test Coverage Audit** - Identify gaps in test coverage

---

## Phase 1: Dead Code Audit

### 1.1 Module Shadowing Check
- [ ] Verify no directory modules are shadowed by inline module definitions
- [ ] Check all `mod.rs` files actually export their submodules
- [ ] Verify all `pub use` re-exports point to real implementations

### 1.2 Unused Code Detection
- [ ] Run `cargo +nightly udeps` to find unused dependencies
- [ ] Check for `#[allow(dead_code)]` outside of test modules
- [ ] Verify all public functions are either used internally or documented as API

### 1.3 Duplicate Implementation Check
- [ ] Search for duplicate function names across crates
- [ ] Verify facade crate (latticearc) only re-exports, no duplicate implementations
- [ ] Check for copy-pasted code that diverged

---

## Phase 2: Cryptographic Function Audit

### 2.1 arc-primitives - Core Cryptographic Primitives

#### AEAD (Authenticated Encryption)
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `encrypt_aes_gcm` | `aead/aes_gcm.rs` | [ ] | |
| `decrypt_aes_gcm` | `aead/aes_gcm.rs` | [ ] | |
| `encrypt_chacha20_poly1305` | `aead/chacha20poly1305.rs` | [ ] | |
| `decrypt_chacha20_poly1305` | `aead/chacha20poly1305.rs` | [ ] | |

#### KEM (Key Encapsulation)
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `MlKem::generate_keypair` | `kem/ml_kem.rs` | [ ] | |
| `MlKem::encapsulate` | `kem/ml_kem.rs` | [ ] | |
| `MlKem::decapsulate` | `kem/ml_kem.rs` | [ ] | aws-lc-rs limitation for SK deserialization |
| `Ecdh::generate_keypair` | `kem/ecdh.rs` | [ ] | |
| `Ecdh::key_exchange` | `kem/ecdh.rs` | [ ] | |

#### Digital Signatures
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `MlDsa::sign` | `sig/ml_dsa.rs` | [ ] | ML-DSA-44, 65, 87 |
| `MlDsa::verify` | `sig/ml_dsa.rs` | [ ] | |
| `SlhDsa::sign` | `sig/slh_dsa.rs` | [ ] | SLH-DSA variants |
| `SlhDsa::verify` | `sig/slh_dsa.rs` | [ ] | |
| `FnDsa::sign` | `sig/fndsa.rs` | [ ] | FN-DSA-512, 1024 |
| `FnDsa::verify` | `sig/fndsa.rs` | [ ] | |
| `Ed25519::sign` | `ec/ed25519.rs` | [ ] | |
| `Ed25519::verify` | `ec/ed25519.rs` | [ ] | |

#### Hash Functions
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `Sha256::hash` | `hash/sha2.rs` | [ ] | |
| `Sha512::hash` | `hash/sha2.rs` | [ ] | |
| `Sha3_256::hash` | `hash/sha3.rs` | [ ] | |
| `Sha3_512::hash` | `hash/sha3.rs` | [ ] | |
| `Shake128::hash` | `hash/sha3.rs` | [ ] | |
| `Shake256::hash` | `hash/sha3.rs` | [ ] | |

#### Key Derivation
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `hkdf_extract` | `kdf/hkdf.rs` | [ ] | RFC 5869 |
| `hkdf_expand` | `kdf/hkdf.rs` | [ ] | RFC 5869 |
| `hkdf` | `kdf/hkdf.rs` | [ ] | Combined extract+expand |
| `pbkdf2` | `kdf/pbkdf2.rs` | [ ] | |
| `sp800_108_counter_kdf` | `kdf/sp800_108_counter_kdf.rs` | [ ] | |

#### MAC (Message Authentication)
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `Hmac::compute` | `mac/hmac.rs` | [ ] | |
| `Hmac::verify` | `mac/hmac.rs` | [ ] | |
| `Cmac::compute` | `mac/cmac.rs` | [ ] | |
| `Cmac::verify` | `mac/cmac.rs` | [ ] | |

#### RNG (Random Number Generation)
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `Csprng::fill_bytes` | `rand/csprng.rs` | [ ] | |
| `Csprng::generate_key` | `rand/csprng.rs` | [ ] | |
| Entropy tests | `rand/entropy_tests.rs` | [ ] | |

### 2.2 arc-core - Unified API Layer

#### Convenience API
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `encrypt` | `convenience/api.rs` | [ ] | Unified entry point |
| `decrypt` | `convenience/api.rs` | [ ] | Must honor scheme from EncryptedData |
| `sign` | `convenience/api.rs` | [ ] | |
| `verify` | `convenience/api.rs` | [ ] | |
| `encrypt_aes_gcm` | `convenience/aes_gcm.rs` | [ ] | |
| `decrypt_aes_gcm` | `convenience/aes_gcm.rs` | [ ] | |
| `encrypt_hybrid` | `convenience/hybrid.rs` | [ ] | |
| `decrypt_hybrid` | `convenience/hybrid.rs` | [ ] | |
| `sign_ed25519` | `convenience/ed25519.rs` | [ ] | |
| `verify_ed25519` | `convenience/ed25519.rs` | [ ] | |
| `encrypt_pq_ml_kem` | `convenience/pq_kem.rs` | [ ] | |
| `decrypt_pq_ml_kem` | `convenience/pq_kem.rs` | [ ] | |
| `sign_pq_ml_dsa` | `convenience/pq_sig.rs` | [ ] | |
| `verify_pq_ml_dsa` | `convenience/pq_sig.rs` | [ ] | |
| `sign_pq_slh_dsa` | `convenience/pq_sig.rs` | [ ] | |
| `verify_pq_slh_dsa` | `convenience/pq_sig.rs` | [ ] | |
| `sign_pq_fn_dsa` | `convenience/pq_sig.rs` | [ ] | |
| `verify_pq_fn_dsa` | `convenience/pq_sig.rs` | [ ] | |

#### Scheme Selection
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `CryptoPolicyEngine::select_encryption_scheme` | `selector.rs` | [ ] | |
| `CryptoPolicyEngine::select_signature_scheme` | `selector.rs` | [ ] | |
| `CryptoPolicyEngine::recommend_scheme` | `selector.rs` | [ ] | |

#### Zero Trust
| Function | File | Status | Notes |
|----------|------|--------|-------|
| `VerifiedSession::establish` | `zero_trust.rs` | [ ] | |
| `VerifiedSession::verify_valid` | `zero_trust.rs` | [ ] | |
| `ZeroTrustAuth::generate_challenge` | `zero_trust.rs` | [ ] | |
| `ZeroTrustAuth::generate_proof` | `zero_trust.rs` | [ ] | |
| `ZeroTrustAuth::verify_proof` | `zero_trust.rs` | [ ] | |

### 2.3 arc-hybrid - Hybrid Encryption

| Function | File | Status | Notes |
|----------|------|--------|-------|
| `kem_hybrid::generate_keypair` | `kem_hybrid.rs` | [ ] | ML-KEM + ECDH |
| `kem_hybrid::encapsulate` | `kem_hybrid.rs` | [ ] | |
| `kem_hybrid::decapsulate` | `kem_hybrid.rs` | [ ] | |
| `sig_hybrid::generate_keypair` | `sig_hybrid.rs` | [ ] | ML-DSA + Ed25519 |
| `sig_hybrid::sign` | `sig_hybrid.rs` | [ ] | |
| `sig_hybrid::verify` | `sig_hybrid.rs` | [ ] | |

### 2.4 arc-tls - Post-Quantum TLS

| Function | File | Status | Notes |
|----------|------|--------|-------|
| `tls_connect` | `lib.rs` | [ ] | Client connection |
| `tls_accept` | `lib.rs` | [ ] | Server accept |
| `TlsPolicyEngine::select_cipher_suite` | `policy.rs` | [ ] | |
| `PqKeyExchange::generate_keypair` | `pq_key_exchange.rs` | [ ] | |
| `PqKeyExchange::encapsulate` | `pq_key_exchange.rs` | [ ] | |
| `PqKeyExchange::decapsulate` | `pq_key_exchange.rs` | [ ] | |

### 2.5 arc-zkp - Zero Knowledge Proofs

| Function | File | Status | Notes |
|----------|------|--------|-------|
| `SchnorrProof::prove` | `schnorr.rs` | [ ] | |
| `SchnorrProof::verify` | `schnorr.rs` | [ ] | |
| Sigma protocols | `sigma.rs` | [ ] | |

---

## Phase 3: Documentation Audit

### 3.1 README Files
| File | Status | Check |
|------|--------|-------|
| `/README.md` | [ ] | API examples match implementation |
| `/docs/UNIFIED_API_GUIDE.md` | [ ] | SecurityLevel descriptions accurate |
| `/docs/SECURITY_GUIDE.md` | [ ] | Security claims verified |
| `/docs/NIST_COMPLIANCE.md` | [ ] | Algorithm compliance claims accurate |
| `/docs/DESIGN.md` | [ ] | Architecture matches implementation |

### 3.2 Code Comments Audit
For each crate, verify:
- [ ] Function doc comments match actual behavior
- [ ] `# Examples` in doc comments compile and work
- [ ] `# Errors` sections list all possible error conditions
- [ ] `# Panics` sections are accurate (should be none in production code)
- [ ] `# Safety` sections for any unsafe code (should be none)

### 3.3 Specific Documentation Checks
- [ ] `SecurityLevel` enum - verify each level uses claimed algorithms
- [ ] `UseCase` enum - verify each use case selects claimed algorithms
- [ ] Scheme strings in docs match actual scheme strings in code
- [ ] Key sizes documented match actual key sizes
- [ ] NIST FIPS references are accurate

---

## Phase 4: Test Coverage Audit

### 4.1 Unit Test Coverage
| Crate | Current | Target | Status |
|-------|---------|--------|--------|
| `arc-primitives` | ? | 80% | [ ] |
| `arc-core` | ? | 80% | [ ] |
| `arc-hybrid` | ? | 80% | [ ] |
| `arc-tls` | ? | 80% | [ ] |
| `arc-zkp` | ? | 80% | [ ] |
| `arc-validation` | ? | 80% | [ ] |
| `latticearc` | ? | 80% | [ ] |

### 4.2 Integration Test Audit
| Test File | Status | Covers |
|-----------|--------|--------|
| `latticearc/tests/unified_api_integration.rs` | [ ] | Unified API roundtrips |
| `latticearc/tests/nist_kat_tests.rs` | [ ] | NIST Known Answer Tests |
| `arc-hybrid/tests/zeroization_tests.rs` | [ ] | Memory zeroization |
| `arc-tls/tests/selector_tests.rs` | [ ] | TLS cipher selection |
| `arc-validation/src/cavp/tests.rs` | [ ] | CAVP validation |

### 4.3 Missing Test Identification
- [ ] Identify functions without unit tests
- [ ] Identify error paths without test coverage
- [ ] Identify edge cases not tested (empty input, max size, etc.)

### 4.4 Test Quality Audit
- [ ] Tests actually assert correct behavior (not just "doesn't panic")
- [ ] Negative tests exist (wrong key, tampered data, etc.)
- [ ] Roundtrip tests for all encrypt/decrypt pairs
- [ ] Roundtrip tests for all sign/verify pairs

---

## Phase 5: Known Issues Tracking

### 5.1 Known Limitations
| Issue | Location | Status | Notes |
|-------|----------|--------|-------|
| ML-KEM SK deserialization | `arc-primitives/kem/ml_kem.rs` | Documented | aws-lc-rs limitation |
| Hybrid decrypt with serialized keys | `arc-core/convenience/hybrid.rs` | Documented | Same root cause |

### 5.2 Deprecation Audit
- [ ] All `#[deprecated]` functions have migration path documented
- [ ] Deprecated functions still work correctly
- [ ] Timeline for removal documented

---

## Execution Order

### Priority 1 (Critical - Security)
1. [ ] Phase 2.1 - Cryptographic primitives audit
2. [ ] Phase 2.2 - Unified API audit (especially encrypt/decrypt dispatch)
3. [ ] Phase 4.4 - Test quality audit

### Priority 2 (High - Correctness)
4. [ ] Phase 1 - Dead code audit
5. [ ] Phase 2.3-2.5 - Hybrid, TLS, ZKP audit
6. [ ] Phase 3.2 - Code comments audit

### Priority 3 (Medium - Documentation)
7. [ ] Phase 3.1 - README audit
8. [ ] Phase 3.3 - Specific documentation checks
9. [ ] Phase 4.1-4.3 - Test coverage audit

---

## Audit Checklist Template

For each function audited:
```
Function: <name>
File: <path>
Status: [ ] Not Started / [~] In Progress / [x] Complete

Checks:
- [ ] Implementation matches documented behavior
- [ ] Error handling is complete
- [ ] No panics in normal operation
- [ ] Unit tests exist
- [ ] Unit tests cover error cases
- [ ] Doc comments accurate
- [ ] Examples in docs work

Issues Found:
-

Recommendations:
-
```

---

## Completion Criteria

The audit is complete when:
1. All checkboxes in Phases 1-4 are marked complete
2. All issues found are either fixed or documented in Phase 5
3. Test coverage meets 80% target for all crates
4. No dead code remains
5. All documentation matches implementation
