# Formal Verification with Kani

LatticeArc uses the [Kani model checker](https://github.com/model-checking/kani) to formally verify critical properties of our cryptographic implementations.

## What is Formal Verification?

Formal verification uses mathematical proofs to guarantee properties hold for *all possible inputs*, not just test cases. Kani symbolically executes Rust code to prove:
- **Correctness**: Operations produce expected results
- **Memory Safety**: No panics, buffer overflows, or undefined behavior
- **Security**: Invalid inputs are rejected, secrets are cleared

## Verification Approach

Following the [AWS-LC model](https://github.com/awslabs/aws-lc-verification), our proofs:
- ✅ Are written in source code alongside implementations
- ✅ Run on scheduled basis (nightly/weekly), not every commit
- ✅ Cover critical cryptographic operations
- ✅ Use symbolic execution (all possible inputs)
- ❌ Are NOT run on every commit (too expensive, 30+ min)

**Why not run on every commit?**
- Full Kani verification takes 30+ minutes for 9 proofs
- GitHub Actions free tier has limited compute minutes
- Even AWS-LC (with Amazon's resources) doesn't run SAW proofs on every commit
- Code changes rarely break mathematical properties that proofs verify

## Verified Components

### arc-hybrid (7 proofs in `src/formal_verification.rs`)

| Proof | Property | What It Guarantees |
|-------|----------|-------------------|
| `encrypt_decrypt_roundtrip` | Correctness | Encrypt→Decrypt returns original plaintext |
| `kem_encapsulate_decapsulate_consistency` | Correctness | KEM shared secrets match on both sides |
| `key_derivation_deterministic` | Correctness | KDF produces same key from same inputs |
| `signature_verify_correctness` | Correctness | Valid signatures verify successfully |
| `reject_invalid_key_lengths` | Security | Invalid keys are rejected (no crashes) |
| `memory_safety_no_panics` | Memory Safety | Operations never panic with valid inputs |
| `zeroization_testing` | Memory Safety | Secrets are completely zeroized |

### arc-core (2 proofs in `src/key_lifecycle.rs`)

| Proof | Property | What It Guarantees |
|-------|----------|-------------------|
| `key_state_machine_destroyed_cannot_transition` | Security | Destroyed keys are immutable (no resurrection) |
| `key_state_machine_no_backward_to_generation` | Security | Key lifecycle is unidirectional (no rollback) |

## Running Proofs

### Automated (GitHub Actions)

- **Nightly**: Runs at 3 AM UTC daily (per-crate jobs, ~10 min)
- **Weekly**: Runs at 5 AM UTC Sunday (extended crypto proofs, 180 min)
- **On main merge**: Validates releases before publishing

### Manual (Local)

```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs (30+ min)
cargo kani --workspace --all-features

# Run specific crate
cargo kani -p arc-hybrid --all-features

# Run specific proof
cargo kani --harness encrypt_decrypt_roundtrip -p arc-hybrid
```

### Manual (GitHub Actions)

1. Go to [Kani workflow](https://github.com/latticearc/latticearc/actions/workflows/kani.yml)
2. Click "Run workflow"
3. Select branch and click "Run workflow" button

## Adding New Proofs

1. Create `#[kani::proof]` function in crate's `src/formal_verification.rs`
2. Use `kani::any()` for symbolic inputs (all possible values)
3. Use `kani::assume()` to constrain inputs to valid ranges
4. Use `assert!()` to state property that must always hold
5. Run locally to validate proof works
6. Proofs will run automatically on next schedule

Example:
```rust
#[kani::proof]
fn new_property() {
    let input: u32 = kani::any();
    kani::assume(input < 1000);  // Constrain to valid range

    let result = my_function(input);

    assert!(result.is_ok(), "Function should never fail with valid input");
}
```

## Cost Analysis

**GitHub Actions free tier: 2000 minutes/month**

| Schedule | Frequency | Duration | Monthly Cost |
|----------|-----------|----------|--------------|
| Nightly | Daily | 10 min | 300 min/month |
| Weekly | Sunday | 180 min | 720 min/month |
| On merge | ~4/month | 10 min | 40 min/month |
| **Total** | | | **1060 min/month (53%)** |

Leaves 47% of free tier for other CI jobs (tests, security, fuzzing).

## Limitations

### What Kani CAN verify

- ✅ Control flow correctness (no secret-dependent branches)
- ✅ Memory safety (no panics, buffer overflows, use-after-free)
- ✅ Arithmetic correctness (no overflows, correct results)
- ✅ State machine validity (only valid transitions)

### What Kani CANNOT verify

- ❌ Cache-timing side channels (CPU microarchitecture)
- ❌ Speculative execution vulnerabilities (Spectre/Meltdown)
- ❌ Hardware-level attacks (power analysis, EM emanation)
- ❌ Constant-time execution (use ctgrind for this)

For constant-time verification, see `arc-primitives/tests/constant_time.rs` (ctgrind-based).

## Comparison with Other Approaches

| Tool | What It Verifies | Cost | Coverage |
|------|------------------|------|----------|
| **Kani** | Properties for all possible inputs | High (30 min) | 9 critical proofs |
| **Tests** | Properties for specific test cases | Low (2 min) | 977 tests |
| **Fuzzing** | Find edge cases via randomness | Medium (5 min/day) | 9 fuzz targets |
| **ctgrind** | Constant-time execution | Low (30 sec) | 4 API layer proofs |
| **SAW** | Primitives (via aws-lc-rs) | Inherited | AES-GCM, ML-KEM, SHA-2 |

Each approach complements the others. We use all five.

## Additional Resources

- [Kani User Guide](https://model-checking.github.io/kani/)
- [AWS-LC Verification](https://github.com/awslabs/aws-lc-verification) — SAW proofs for primitives
- [FIPS 203-206 Standards](https://csrc.nist.gov/) — NIST post-quantum cryptography standards
- [Property-Based Testing with Proptest](https://proptest-rs.github.io/proptest/)

## Related Documentation

- [SECURITY.md](../SECURITY.md) — Security policy and guarantees
- [NIST_COMPLIANCE.md](NIST_COMPLIANCE.md) — FIPS conformance details
- [TESTING_STRATEGY.md](TESTING_STRATEGY.md) — Complete testing approach
