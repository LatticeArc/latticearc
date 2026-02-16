# Verification Strategy

LatticeArc verifies correctness at three layers, each with the right tool for the job.

## Three-Layer Approach

| Layer | Tool | Scope | What it proves |
|-------|------|-------|----------------|
| **Primitives** | [SAW](https://github.com/awslabs/aws-lc-verification) (via aws-lc-rs) | AES-GCM, ML-KEM, X25519, SHA-2 | Mathematical correctness of C implementations |
| **API crypto** | [Proptest](https://proptest-rs.github.io/proptest/) (40+ tests) | Hybrid KEM/encrypt/sign, unified API, ML-KEM | Roundtrip, non-malleability, key independence, wrong-key rejection |
| **Type invariants** | [Kani](https://github.com/model-checking/kani) (12 proofs) | `arc-types` (pure Rust) | State machine rules, enum exhaustiveness, ordering, defaults |

### Why three layers?

Kani uses bounded model checking to prove properties hold for **all possible inputs**, not just test cases. But Kani cannot verify code that calls FFI (like aws-lc-rs). Our crypto operations all go through FFI, so Kani can only verify the pure-Rust policy and type layer.

For crypto correctness, we use two complementary approaches:
- **SAW** (inherited from aws-lc-rs) proves the primitives are correct at the C level
- **Proptest** proves our Rust wrappers correctly compose those primitives (256 random cases per property, release mode)

This means: no single tool covers everything, but together they form a complete chain from C primitives through Rust wrappers to type-level invariants.

## Layer 1: SAW — Primitive Correctness (inherited)

We don't run SAW ourselves. aws-lc-rs provides [mathematically verified implementations](https://github.com/awslabs/aws-lc-verification) of AES-GCM, ML-KEM, X25519, and SHA-2. These are the building blocks our library composes.

## Layer 2: Proptest — API Crypto Correctness

40+ property-based tests in `arc-tests/tests/proptest_*.rs`, each running 256 random cases:

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

12 bounded model checking proofs in `arc-types` (pure Rust, zero FFI). These verify the policy and state management layer, **not** cryptographic operations.

### What Kani verifies

#### Key Lifecycle State Machine — `src/key_lifecycle.rs` (5 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `key_state_machine_transitions_match_spec` | `is_valid_transition` matches an independent SP 800-57 encoding |
| `key_state_machine_destroyed_cannot_transition` | Destroyed keys are immutable (no resurrection) |
| `key_state_machine_no_backward_to_generation` | Key lifecycle is unidirectional (no rollback) |
| `key_state_machine_only_generation_from_none` | Keys must begin in Generation state |
| `key_state_machine_retired_only_to_destroyed` | Retired keys can only be destroyed (no reactivation) |

#### Policy Engine — `src/selector.rs` (3 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `force_scheme_covers_all_variants` | Every `CryptoScheme` maps to a non-empty algorithm string |
| `select_pq_encryption_covers_all_levels` | Every `SecurityLevel` has a PQ encryption algorithm |
| `select_pq_signature_covers_all_levels` | Every `SecurityLevel` has a PQ signature algorithm |

These catch bugs when someone adds a new enum variant but forgets to handle it — Kani exhaustively checks all variants.

#### Trust Levels — `src/zero_trust.rs` (3 proofs)

| Proof | What It Guarantees |
|-------|-------------------|
| `trust_level_ordering_total` | Trust hierarchy has no ambiguous comparisons |
| `trust_level_is_trusted_iff_at_least_partial` | Untrusted entities are never considered trusted |
| `trust_level_untrusted_is_minimum` | Trust floor is well-defined (Untrusted is lowest) |

#### Security Defaults — `src/types.rs` (1 proof)

| Proof | What It Guarantees |
|-------|-------------------|
| `security_level_default_is_high` | Default security is NIST Level 3, not a weaker option |

### What Kani does NOT verify

- Encryption/decryption correctness (requires FFI → use proptest)
- KEM encapsulate/decapsulate consistency (requires FFI → use proptest)
- Signature sign/verify correctness (requires FFI → use proptest)
- Constant-time execution (CPU microarchitecture → use aws-lc-rs SAW + `subtle` crate)
- Side channels, speculative execution, hardware attacks

## Running Proofs

### Kani (automated)

- Runs on every push to `main` (when `arc-types/src/` changes)
- Nightly at 3 AM UTC, weekly Sunday at 5 AM UTC

### Kani (local)

```bash
cargo install --locked kani-verifier
cargo kani setup

# Run all 12 proofs
cargo kani -p arc-types

# Run a specific proof
cargo kani --harness key_state_machine_transitions_match_spec -p arc-types
```

### Proptest (local)

```bash
# Run all property-based tests (release mode required for crypto perf)
cargo test --package arc-tests --release -- proptest
```

## Comparison

| Tool | What It Verifies | Coverage | Cost |
|------|------------------|----------|------|
| **SAW** | Primitive correctness (via aws-lc-rs) | AES-GCM, ML-KEM, SHA-2 | Inherited |
| **Proptest** | API crypto correctness (256 random cases/property) | 40+ properties, 6 files | ~60s (release) |
| **Kani** | Type invariants (all possible inputs) | 12 proofs in arc-types | ~10 min |
| **Unit tests** | Specific test cases | 977+ tests | ~120s (release) |
| **Fuzzing** | Edge cases via randomness | 9 fuzz targets | 5 min/day |

## Additional Resources

- [Kani User Guide](https://model-checking.github.io/kani/)
- [AWS-LC Verification](https://github.com/awslabs/aws-lc-verification) — SAW proofs for primitives
- [Proptest Book](https://proptest-rs.github.io/proptest/)
- [SECURITY.md](../SECURITY.md) — Security policy and guarantees
- [TESTING_STRATEGY.md](TESTING_STRATEGY.md) — Complete testing approach
