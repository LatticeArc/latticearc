# Verification Strategy

LatticeArc verifies correctness at three layers, each with the right tool for the job.

## Three-Layer Approach

| Layer | Tool | Scope | What it proves |
|-------|------|-------|----------------|
| **Primitives** | [SAW](https://github.com/awslabs/aws-lc-verification) (via aws-lc-rs) | AES-GCM, ML-KEM, X25519, SHA-2 | Mathematical correctness of C implementations |
| **API crypto** | [Proptest](https://proptest-rs.github.io/proptest/) (40+ tests) | Hybrid KEM/encrypt/sign, unified API, ML-KEM | Roundtrip, non-malleability, key independence, wrong-key rejection |
| **Type invariants** | [Kani](https://github.com/model-checking/kani) (29 proofs) | `latticearc::types` (pure Rust) | State machine rules, config validation, domain separation, enum exhaustiveness, ordering, defaults |

### Why three layers?

Kani uses bounded model checking to prove properties hold for **all possible inputs**, not just test cases. But Kani cannot verify code that calls FFI (like aws-lc-rs). Our crypto operations all go through FFI, so Kani can only verify the pure-Rust policy and type layer.

For crypto correctness, we use two complementary approaches:
- **SAW** (inherited from aws-lc-rs) proves the primitives are correct at the C level
- **Proptest** proves our Rust wrappers correctly compose those primitives (256 random cases per property, release mode)

This means: no single tool covers everything, but together they form a complete chain from C primitives through Rust wrappers to type-level invariants.

## Layer 1: SAW — Primitive Correctness (inherited)

We don't run SAW ourselves. aws-lc-rs provides [mathematically verified implementations](https://github.com/awslabs/aws-lc-verification) of AES-GCM, ML-KEM, X25519, and SHA-2. These are the building blocks our library composes.

## Layer 2: Proptest — API Crypto Correctness

40+ property-based tests in `tests/tests/proptest_*.rs`, each running 256 random cases:

| File | Tests | What it covers |
|------|-------|----------------|
| `proptest_hybrid_kem.rs` | 5 | ML-KEM-768 + X25519: roundtrip, key independence, wrong-key rejection |
| `proptest_hybrid_encrypt.rs` | 6 | Hybrid encryption: roundtrip, non-malleability, AAD integrity, key independence |
| `proptest_hybrid_sig.rs` | 7 | ML-DSA-65 + Ed25519: roundtrip, wrong-message/key, Ed25519 determinism, sizes |
| `proptest_unified_api.rs` | 8 | Unified API: AEAD + signing across all security levels and use cases |
| `proptest_pq_kem.rs` | 8 | ML-KEM-512/768/1024: roundtrip, FIPS 203 key/ciphertext sizes |
| `proptest_selector.rs` | 6 | CryptoPolicyEngine: determinism, monotonicity, exhaustiveness |

These are the tests that verify **actual cryptographic correctness** — encrypt/decrypt roundtrip, KEM consistency, signature verification, and FIPS spec compliance.

## Layer 3: Kani — Type Invariants

29 bounded model checking proofs across 7 files in `latticearc::types` (pure Rust, zero FFI). These verify the policy and state management layer, **not** cryptographic operations.

### What Kani verifies

#### Key Lifecycle State Machine — `types/key_lifecycle.rs` (5 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `key_state_machine_transitions_match_spec` | `is_valid_transition` matches an independent SP 800-57 encoding |
| `key_state_machine_destroyed_cannot_transition` | Destroyed keys are immutable (no resurrection) |
| `key_state_machine_no_backward_to_generation` | Key lifecycle is unidirectional (no rollback) |
| `key_state_machine_only_generation_from_none` | Keys must begin in Generation state |
| `key_state_machine_retired_only_to_destroyed` | Retired keys can only be destroyed (no reactivation) |

#### Configuration Validation — `types/config.rs` (6 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `core_config_default_validates` | `CoreConfig::default()` always passes validation |
| `core_config_for_production_validates` | `CoreConfig::for_production()` always passes validation |
| `core_config_for_development_validates` | `CoreConfig::for_development()` always passes validation |
| `core_config_validation_biconditional` | `validate()` passes IFF both safety invariants hold (exhaustive over all 96 CoreConfig combinations) |
| `encryption_compression_requires_integrity` | Compression without integrity check fails validation (prevents oracle attacks) |
| `signature_chain_requires_timestamp` | Certificate chain without timestamp fails validation (revocation checking) |

The bi-conditional proof (`core_config_validation_biconditional`) is the strongest — it proves validation has no false positives AND no false negatives across all 96 possible CoreConfig combinations (4 security levels × 3 performance preferences × 2³ booleans).

#### Policy Engine — `types/selector.rs` (5 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `force_scheme_covers_all_variants` | Every `CryptoScheme` maps to a non-empty algorithm string |
| `select_pq_encryption_covers_all_levels` | Every `SecurityLevel` has a PQ encryption algorithm |
| `select_pq_signature_covers_all_levels` | Every `SecurityLevel` has a PQ signature algorithm |
| `select_encryption_covers_all_levels` | Hybrid/general encryption selection succeeds for all SecurityLevels |
| `select_signature_covers_all_levels` | Signature scheme selection succeeds for all SecurityLevels |

These catch bugs when someone adds a new enum variant but forgets to handle it — Kani exhaustively checks all variants, including hybrid and general scheme selection paths.

#### Compliance Mode — `types/types.rs` (3 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `compliance_mode_requires_fips_exhaustive` | `requires_fips()` is true IFF mode is Fips140_3 or Cnsa2_0 |
| `compliance_mode_allows_hybrid_exhaustive` | `allows_hybrid()` is true IFF mode is NOT Cnsa2_0 (CNSA 2.0 mandates PQ-only) |
| `performance_preference_default_is_balanced` | Default PerformancePreference is Balanced, not Speed (prevents accidental classical-only fallback) |

#### Trust Levels — `types/zero_trust.rs` (4 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `trust_level_ordering_total` | Trust hierarchy has no ambiguous comparisons |
| `trust_level_is_trusted_iff_at_least_partial` | Untrusted entities are never considered trusted |
| `trust_level_untrusted_is_minimum` | Trust floor is well-defined (Untrusted is lowest) |
| `trust_level_is_fully_trusted_iff_fully_trusted` | `is_fully_trusted()` returns true IFF level is FullyTrusted |

#### Domain Separation — `types/domains.rs` (1 proof)

| Proof | What It Guarantees |
|-------|-------------------|
| `domain_constants_pairwise_distinct` | All 4 HKDF domain constants (HYBRID_KEM, CASCADE_OUTER, CASCADE_INNER, SIGNATURE_BIND) are pairwise distinct |

This is a critical security property — if any two domain constants collide, different protocol layers derive the same keys, destroying cryptographic isolation (NIST SP 800-108).

#### Verification Status — `types/traits.rs` (1 proof)

| Proof | What It Guarantees |
|-------|-------------------|
| `verification_status_is_verified_iff_verified` | `is_verified()` returns true IFF status is Verified (expired/failed/pending sessions are never "verified") |

#### Security Defaults — `types/types.rs` (4 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `security_level_default_is_high` | Default security is NIST Level 3, not a weaker option |
| `compliance_mode_default_is_unrestricted` | Default compliance is Unrestricted (not FIPS-restricted) |
| `cnsa_requires_fips` | CNSA 2.0 mode requires FIPS validation |
| `cnsa_disallows_hybrid` | CNSA 2.0 mode disallows hybrid (PQ-only mandated) |

### Proof summary by file

| File | Proofs | Key Property |
|------|--------|-------------|
| `types/key_lifecycle.rs` | 5 | SP 800-57 state machine correctness |
| `types/config.rs` | 6 | CoreConfig bi-conditional validation (96 combos) |
| `types/selector.rs` | 5 | Encryption + signature selection completeness |
| `types/types.rs` | 7 | ComplianceMode, SecurityLevel defaults and exhaustive checks |
| `types/zero_trust.rs` | 4 | Trust level ordering + `is_fully_trusted()` |
| `types/domains.rs` | 1 | Domain separation pairwise distinctness |
| `types/traits.rs` | 1 | VerificationStatus correctness |
| **Total** | **29** | |

### What Kani does NOT verify

- Encryption/decryption correctness (requires FFI → use proptest)
- KEM encapsulate/decapsulate consistency (requires FFI → use proptest)
- Signature sign/verify correctness (requires FFI → use proptest)
- Constant-time execution (CPU microarchitecture → use aws-lc-rs SAW + `subtle` crate)
- Side channels, speculative execution, hardware attacks

## Running Proofs

### Kani (automated)

- Runs on every push to `main` (when `latticearc/src/types/` changes)
- Nightly at 3 AM UTC, weekly Sunday at 5 AM UTC

### Kani (local)

```bash
cargo install --locked kani-verifier
cargo kani setup

# Run all 29 proofs
cargo kani -p latticearc

# Run a specific proof
cargo kani --harness core_config_validation_biconditional -p latticearc
cargo kani --harness domain_constants_pairwise_distinct -p latticearc
```

### Proptest (local)

```bash
# Run all property-based tests (release mode required for crypto perf)
cargo test --package latticearc-tests --release -- proptest
```

## Comparison

| Tool | What It Verifies | Coverage | Cost |
|------|------------------|----------|------|
| **SAW** | Primitive correctness (via aws-lc-rs) | AES-GCM, ML-KEM, SHA-2 | Inherited |
| **Proptest** | API crypto correctness (256 random cases/property) | 40+ properties, 6 files | ~60s (release) |
| **Kani** | Type invariants (all possible inputs) | 29 proofs across 7 files in latticearc::types | ~15 min |
| **Unit tests** | Specific test cases | 8,500+ tests | ~120s (release) |
| **Fuzzing** | Edge cases via randomness | 28 fuzz targets | 5 min/day |

## Additional Resources

- [Kani User Guide](https://model-checking.github.io/kani/)
- [AWS-LC Verification](https://github.com/awslabs/aws-lc-verification) — SAW proofs for primitives
- [Proptest Book](https://proptest-rs.github.io/proptest/)
- [SECURITY.md](../SECURITY.md) — Security policy and guarantees
- [Code Audit Methodology](../../CODE_AUDIT_METHODOLOGY.md) — Complete testing and audit approach
