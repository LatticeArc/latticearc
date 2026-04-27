# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in LatticeArc, please report it privately:

### Email

Send details to: **Security@LatticeArc.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Any suggested fixes (optional)

### GitHub Security Advisory

You can also report via [GitHub Security Advisory](https://github.com/latticearc/latticearc/security/advisories/new).

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Initial acknowledgment | 24 hours |
| Severity assessment | 48 hours |
| Fix development | 7-30 days (severity dependent) |
| Coordinated disclosure | 90 days max |

## Supported Versions

| Version | Status | Security Updates Until |
|---------|--------|------------------------|
| 0.8.x | Supported | Current |
| 0.7.x | Supported | Security fixes only |
| 0.6.x | End of life | Superseded by 0.7.0 |
| 0.5.x | End of life | Superseded by 0.6.0 |
| 0.4.x | End of life | Superseded by 0.5.0 |
| 0.3.x | End of life | Superseded by 0.4.0 |
| 0.2.x | End of life | Superseded by 0.3.0 |
| 0.1.x | End of life | Superseded by 0.2.0 |

We recommend always using the latest version.

## Security Guarantees

### What We Guarantee

- **No unsafe code** in cryptographic code paths
- **Constant-time operations** for all secret-dependent computations
- **Zeroization** of sensitive data when no longer needed
- **FIPS 203-206 compliance** for post-quantum algorithms
- **Input validation** on all public APIs

### What We Do Not Guarantee

- Protection against physical attacks (power analysis, EM emanations)
- Protection against compromised operating systems
- Protection against compromised hardware
- Memory clearing after process termination (OS responsibility)
- Side-channel resistance in Rust compiler-generated code

## Security Design

### Cryptographic Primitives

| Primitive | Standard | Implementation |
|-----------|----------|----------------|
| ML-KEM | FIPS 203 | aws-lc-rs |
| ML-DSA | FIPS 204 | fips204 crate |
| SLH-DSA | FIPS 205 | fips205 crate |
| FN-DSA | FIPS 206 | fn-dsa crate |
| AES-GCM | FIPS 197, SP 800-38D | aws-lc-rs |
| SHA-3 | FIPS 202 | sha3 crate |
| HKDF | RFC 5869 | aws-lc-rs (HMAC-based) |

### FIPS Feature Flag and Compliance Modes

LatticeArc supports compile-time and runtime compliance controls:

**Compile-time:** The `fips` feature flag (`--features fips`) enables the FIPS 140-3 validated backend via aws-lc-rs. Without this flag, aws-lc-rs uses its default (non-FIPS) backend.

**Runtime:** The `ComplianceMode` enum controls algorithm constraints:

| Mode | FIPS Required | Hybrid Allowed | Description |
|------|---------------|----------------|-------------|
| `Default` | No | Yes | No restrictions — all algorithms available |
| `Fips140_3` | Yes | Yes | Only FIPS-validated backends |
| `Cnsa2_0` | Yes | No | PQ-only algorithms (NSA CNSA 2.0) |

Kani formally verifies that `requires_fips()` and `allows_hybrid()` return correct values for every `ComplianceMode` variant (exhaustive proofs).

### Defense in Depth

1. **Hybrid cryptography** - PQC + classical for defense against future threats
2. **Strict linting** - `forbid(unsafe_code)`, `deny(unwrap_used)`
3. **Memory safety** - Rust's ownership model + explicit zeroization
4. **Input validation** - All public APIs validate inputs
5. **Constant-time** - Using `subtle` crate for timing-safe operations
6. **Compliance enforcement** - `ComplianceMode` with formal verification
7. **Weak-key rejection** - `AeadCipher::new` rejects the all-zero key
   pattern (`AeadError::WeakKey`) via constant-time fold-no-early-exit.
   An all-zero AEAD key is overwhelmingly the signature of uninitialised
   memory or an unset configuration field; failing closed at the
   constructor prevents that state from ever reaching encryption. The
   `kat-test-vectors` Cargo feature exposes
   `AeadCipher::new_allow_weak_key` for NIST AES-GCM Test Cases 1 and 2
   reproduction; off by default so production builds cannot accidentally
   construct a weak-key cipher.
8. **FIPS DRBG fallback prevention** - Earlier `RngHandle` could fall
   back to a `ChaCha20Rng`-seeded path on mutex poison, silently
   downgrading from the FIPS-approved DRBG. This was a real FIPS
   140-3 module-policy violation (mod-policy §7.4: "approved security
   functions only"). Fixed in 0.8.0: `RngHandle::ThreadLocal` is now
   `cfg`-gated `not(fips)` so it cannot be constructed in a FIPS build,
   and the mutex-poison path returns an explicit error instead of
   silently downgrading.

## Yank / republish runbook

The first 24 hours after a release are the highest-risk window for a
crypto crate — a regression discovered in that window is the worst time
to be improvising. This runbook is the mechanical procedure for the
maintainer on call.

### When to yank

Yank without ceremony if a published version has any of:

- **Functional crypto regression.** Encryption, decryption, signing, or
  verification produces output incompatible with prior releases or with
  the underlying NIST KAT vectors. (Roundtrip-fails-on-self counts.)
- **FIPS 140-3 compliance regression** under `--features fips`. E.g.,
  RNG falls back to a non-approved DRBG, self-tests skipped, weak-key
  check bypassed.
- **Memory-safety regression.** Use-after-free / double-free / OOB read
  in any path. (`forbid(unsafe_code)` should make these compile-time
  failures, but a `cargo audit` advisory on a dep counts.)
- **Secret-material disclosure.** Any path that lets a `Secret*` type
  leak into a log line, panic message, `Debug` output, or error
  variant.
- **Confused-deputy or downgrade vulnerability** in the unified API
  (e.g., wrong scheme dispatched, hybrid silently downgraded to
  classical-only).

Open a placeholder GHSA before yanking so the disclosure timeline
starts cleanly; details land later.

### Procedure

1. **Yank from crates.io.** From the maintainer machine:
   ```bash
   cargo yank --version <X.Y.Z> latticearc
   ```
   Yank does NOT delete the crate, so existing `Cargo.lock` files keep
   working; new fresh resolves stop selecting the bad version. Do this
   FIRST, before any other step, so the blast radius stops growing
   while you're investigating.

2. **Pin the upstream advisory.** Open or update `RUSTSEC-YYYY-NNNN`
   via the `rustsec/advisory-db` PR template. Reference the yanked
   version range; cite the GHSA opened in step 0 for cross-platform
   coordination.

3. **Patch on a fix branch.** Branch from the LAST KNOWN GOOD tag (not
   from main, which may already have unrelated changes). Apply the
   minimal targeted fix; resist the urge to bundle other improvements.

4. **Re-run the full release validation matrix locally.** Same gates
   the release.yml pipeline runs:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo clippy --workspace --all-targets --features fips -- -D warnings
   cargo test --workspace --all-features --release --no-fail-fast
   cargo audit --deny warnings
   cargo deny check all
   ./scripts/verify-kat-checksums.sh
   ```
   All must be green before the republish.

5. **Bump the patch version and republish.** PATCH-only bumps for
   yanked-version replacements (`X.Y.(Z+1)`) — never reuse the yanked
   number, never minor-bump unless the fix unavoidably changes a
   public signature. Tag the fix commit; let `release.yml` publish.

6. **Communicate.** Within 24 h of the original yank, post:
   - GHSA published with details, affected versions, fix version,
     remediation steps.
   - CHANGELOG entry calling out the yank + fix.
   - `README.md` security banner pointing at the GHSA.
   - Post to the disclosure list (security@latticearc, plus the OSS
     mailing lists where the vulnerability is in scope: oss-security if
     it's a primitive bug, fips-validation@nist if it's a module-policy
     violation).

### When NOT to yank

Yanking has a real downstream cost — it doesn't delete the crate, but
it does break tooling that locks to "latest stable" without an explicit
`Cargo.lock`. Don't yank for:

- Documentation-only mistakes (publish a patch instead)
- Performance regressions that don't affect correctness
- Unsoundness in code paths that aren't reachable from the published
  API surface
- Policy violations that are warnings, not blocking errors
  (e.g., `cargo audit` warning on a dep that's been advised but not
  yanked upstream)

For these, ship a patch release with a `CHANGELOG.md` callout. The
yank tool is a circuit breaker; pulling it for non-circuit-breaker
events erodes the signal.

### Audit log

Every yank is logged at `docs/audit/YANKS.md` (gitignored, internal)
with:
- Yanked version
- Discovery date / time
- Fix version
- GHSA / RUSTSEC IDs
- Postmortem link

The public-facing record is the GHSA + the CHANGELOG entry; the
internal log captures the additional context (who reported, who
patched, what almost-shipped instead).

## Security Testing

### Continuous Security Measures

- **Fuzzing** - Daily fuzzing with cargo-fuzz
- **Static analysis** - Clippy with security lints
- **Dependency audit** - cargo-audit in CI
- **License compliance** - cargo-deny checks
- **CAVP validation** - NIST test vectors

### Verification (Three Layers)

Correctness is verified at three layers. See [docs/FORMAL_VERIFICATION.md](docs/FORMAL_VERIFICATION.md) for full details.

#### Layer 1: SAW — Primitive Correctness (inherited)

We inherit formal verification for cryptographic primitives from aws-lc-rs:
- AES-GCM, ML-KEM, SHA-2, HMAC, AES-KWP
- Verified using SAW (Software Analysis Workbench) with Cryptol specifications
- Proofs maintained in [aws-lc-verification](https://github.com/awslabs/aws-lc-verification)

#### Layer 2: Proptest — API Crypto Correctness (40+ tests)

Property-based tests verify our Rust wrappers correctly compose the verified primitives:
- Encrypt/decrypt roundtrip, KEM encapsulate/decapsulate consistency
- Signature sign/verify, wrong-key/wrong-message rejection
- Non-malleability (bit-flip in ciphertext → decryption fails)
- FIPS 203 key/ciphertext size compliance across all ML-KEM parameter sets
- 256 random cases per property, release mode

#### Layer 3: Kani — Type Invariants (29 proofs)

Kani model checking verifies the pure-Rust policy and state management layer in `latticearc::types`. These proofs do **not** cover cryptographic operations (which require FFI). They verify:
- Key lifecycle state machine enforces SP 800-57 transitions (5 proofs)
- Configuration validation bi-conditional over all 96 CoreConfig combinations (6 proofs)
- Policy engine maps every enum variant to a valid algorithm, including hybrid schemes (5 proofs)
- Compliance mode `requires_fips()` and `allows_hybrid()` exhaustive (3 proofs)
- Trust level ordering is total and consistent, `is_fully_trusted()` correctness (4 proofs)
- Domain separation constants are pairwise distinct (1 proof)
- Verification status `is_verified()` iff Verified variant (1 proof)
- Default security level is NIST Level 3, CNSA 2.0 compliance constraints (4 proofs)

Proofs in source code: `latticearc/src/types/{key_lifecycle,zero_trust,types,selector,config,domains,traits}.rs`

## Security Audits

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| Q1 2026 | Internal | Full codebase | Complete |

Audit reports will be published in the `docs/audits/` directory when available.

## Known Limitations

### Constant-Time Guarantees

**Primitives (AES-GCM, ML-KEM, etc.):**
- We rely on [aws-lc-rs](https://github.com/aws/aws-lc-rs) cryptographic primitives
- These are [formally verified](https://github.com/awslabs/aws-lc-verification) for constant-time execution
- Verification uses SAW (Software Analysis Workbench) with Cryptol specifications
- **Mathematically proven**, not just tested

**Our API Layer:**
- Uses the [`subtle`](https://docs.rs/subtle) crate for constant-time comparisons
- `subtle` is maintained by [dalek-cryptography](https://github.com/dalek-cryptography/subtle)
- **Not formally verified** - uses pure Rust bitwise operations to prevent timing leaks
- Battle-tested: 22.7M downloads/month, used by rustls, RustCrypto, curve25519-dalek
- Zero known timing vulnerabilities (no RustSec advisories)
- Maintainers emphasize this is a "best-effort attempt" dependent on compiler behavior

**Why we use `subtle`:**
- Industry standard in Rust cryptography ecosystem
- No formally verified alternative exists for Rust custom types (enums, structs)
- aws-lc-rs provides `verify_slices_are_equal` only for `&[u8]` (not custom types)
- Pragmatic trade-off: battle-tested (proven) vs formally verified (doesn't exist for our use case)

**What We Cannot Guarantee:**
- CPU microarchitectural side-channels (cache timing, speculative execution)
- Compiler optimizations that break constant-time properties (mitigated via `subtle`)
- OS scheduling effects on timing measurements

**Verification Approach:**
- ✅ Formal verification (SAW) for primitives via aws-lc-rs
- ✅ Battle-tested libraries (`subtle`) for API layer comparisons
- ✅ Code review for constant-time patterns (no secret-dependent branches)
- ⚠️ **Statistical timing tests** (`tests/primitives_side_channel.rs`)
  measure wall-clock variance across failure paths and assert it stays
  within a permissive `0.02x..50x` window. This catches order-of-
  magnitude regressions but is NOT a substitute for instruction-level
  constant-time verification.

**Hardware-instruction-level verification (gap, planned for 1.0):**

The instruction-level constant-time tools that the Rust crypto ecosystem
uses (`dudect`, `ctgrind`, `valgrind --tool=massif`) are referenced in
this codebase but are **not currently part of the PR-blocking CI matrix**.
A `valgrind` job exists in the workflows but runs only on the nightly
schedule. Before tagging 1.0 we plan to:

- Promote the `valgrind --tool=massif` constant-time check from nightly
  to PR-blocking on `unified_api/convenience/api.rs` and the `subtle`
  call sites in `primitives/aead/`.
- Add a `dudect`-style statistical test harness that computes Welch's
  t-statistic on per-operation cycle counts and fails the build at
  |t| > 4.5 (the standard publish threshold).
- Wire `cargo +nightly miri` runs against the secret-comparison code
  paths to flag UB-class compiler optimizations that could break
  constant-time properties under newer rustc versions.

Until that lands, callers in adversary-reachable contexts (TLS
handshake, untrusted-network protocols, multi-tenant key vaults) should
treat constant-time guarantees on this crate's API layer as
"best-effort within the limits of the `subtle` crate's compiler-
fence behavior" rather than mathematically proven.

### Memory

- Stack memory may not be cleared if thread panics
- Swap may contain sensitive data (use encrypted swap)
- Core dumps may contain sensitive data (disable in production)

### Hybrid Mode — Composition Security Claims

LatticeArc's hybrid schemes combine a post-quantum algorithm with a classical
algorithm so the composition is secure as long as *either* component remains
secure. This section documents the formal security claims for each hybrid
construction. The implementation lives in `crate::hybrid`; the analytical
details and the runtime "proof" helpers are in
[`latticearc::hybrid::compose`](./latticearc/src/hybrid/compose.rs).

#### Hybrid KEM

- **Construction**: ML-KEM (FIPS 203) + X25519 ECDH, combined via a
  HKDF-SHA256 dual-PRF combiner (concatenate both shared secrets as IKM →
  `HKDF-Extract` with a per-session salt → domain-separated `HKDF-Expand`).
  Implementation: `crate::hybrid::kem_hybrid::derive_hybrid_shared_secret`.
- **Claim**: **IND-CCA2** under the *or* of the two component assumptions —
  Module-LWE (ML-KEM) and Computational Diffie-Hellman on Curve25519
  (X25519), combined through the HKDF/HMAC PRF assumption.
- **Reduction reference**: Bindel et al., *Hybrid Key Encapsulation
  Mechanisms and Authenticated Key Exchange* (PQCrypto 2019), analysing
  the dual-PRF combiner.
- **What this guarantees**: if an attacker breaks ML-KEM, X25519 still
  protects the session; conversely if Shor-style attacks break X25519, ML-KEM
  still protects the session. An attacker must break *both* to compromise
  the derived shared secret.
- **Out of scope**: attacks on the underlying HKDF/HMAC PRF (treated as a
  standard model assumption), classical attacks on SHA-256, and
  side-channel attacks on the constant-time implementations (mitigated
  separately — see "Constant-Time Guarantees" below).

#### Hybrid Signatures

- **Construction**: ML-DSA-65 (FIPS 204) + Ed25519 (RFC 8032) in
  **AND-composition** — both signatures over the same message must verify
  for the hybrid signature to be accepted.
- **Claim**: **EUF-CMA** (Existential Unforgeability under Chosen Message
  Attacks) under the *stronger* of the two component assumptions — breaking
  the hybrid requires forging *both* component signatures.
- **What this guarantees**: if ML-DSA is ever broken, Ed25519 still provides
  unforgeability; conversely if Ed25519 is broken post-quantum, ML-DSA
  still provides unforgeability. An attacker cannot forge a hybrid
  signature unless they can forge *both* component signatures on the same
  message.
- **Signature size trade-off**: hybrid signatures carry both component
  signatures (~3.3 KB ML-DSA-65 + 64 bytes Ed25519), larger than either
  alone. Out-of-scope for security; consumers choose hybrid when the
  defence-in-depth matters more than bandwidth.

#### What "security claim" means in this document

These are **documented analytical claims**, not runtime proofs. The library
does not execute cryptographic reductions at runtime. The `compose` module's
`verify_hybrid_kem_security` / `verify_hybrid_signature_security` functions
return a structured `CompositionProof` object that enumerates the claim text
— they are a machine-readable record of the claims, useful for compliance
artefacts and audit trails, not a dynamic verification.

For runtime behaviour that *is* verified, see "Verification (Three Layers)"
above (SAW for primitives, proptest for API, Kani for type invariants).

### aws-lc-rs-Wrapped Secret Types

The ECDH key types (`X25519KeyPair`, `X25519StaticKeyPair`, `EcdhP256KeyPair`,
`EcdhP384KeyPair`, `EcdhP521KeyPair`) and `MlKemDecapsulationKeyPair` wrap
private-key types from [aws-lc-rs](https://github.com/aws/aws-lc-rs) whose
upstream Rust bindings do not expose raw key bytes. This affects two
Rust-level guarantees:

1. **Zeroization.** The upstream types do not implement `zeroize::Zeroize`,
   so our wrappers cannot `#[derive(ZeroizeOnDrop)]`. At runtime,
   zeroization is performed by aws-lc-rs's `Drop` impl, which invokes
   BoringSSL's memory management — BoringSSL zeroes private-key memory
   before freeing it. The delegation is load-bearing, stable, and
   documented upstream.
2. **Constant-time equality.** Because raw key bytes are not accessible,
   our wrappers cannot implement `subtle::ConstantTimeEq`. They also do
   not implement `PartialEq`/`Eq`; a compile-time barrier
   (`latticearc/tests/no_partial_eq_on_secret_types.rs`) rejects any
   future `#[derive(PartialEq)]` on these types. Secret comparisons must
   go through `ct_eq` on concrete byte-level key types, not these
   wrappers.

These properties are not tracked as open issues because there is no
actionable downstream fix: runtime behavior is already correct via
aws-lc-rs/BoringSSL, and the API shape prevents misuse.

### ZKP Proof Duplication

The ZKP proof types `SchnorrProof`, `SigmaProof`, and `DlogEqualityProof`
**do not implement `Clone`.** Every duplication of proof material must go
through an explicit `clone_for_transmission()` method on each proof type.

**Rationale**

- Proofs contain prover-derived material. A derived `Clone` is implicit —
  any code path that clones a proof silently extends the material's
  in-memory lifetime past the author's intent.
- `clone_for_transmission()` makes every copy a deliberate, grep-able audit
  checkpoint. Reviewers can grep for `clone_for_transmission` to see every
  point where a proof is duplicated.
- Fiat-Shamir binding prevents replay of a transmitted proof outside its
  intended transcript, but does not excuse memory-hygiene for the prover's
  in-memory copy.

**Tested invariants** (`latticearc/src/zkp/{schnorr,sigma}.rs`):

1. `Zeroize::zeroize()` wipes every field of the proof type.
2. `clone_for_transmission()` produces an independently-stored copy —
   zeroizing the clone must not touch the original.

Combined with the `zeroize::ZeroizeOnDrop` derive macro's contract (which
generates a `Drop` impl that calls `zeroize()`), these imply both the
original and each `clone_for_transmission()` result have their memory wiped
at end-of-scope.

**Out of scope**

- Post-drop memory observation is not tested directly. That would require
  `unsafe` raw-pointer reads of `MaybeUninit<T>`, which our
  `#![deny(unsafe_code)]` policy forbids. We rely instead on the `zeroize`
  crate's `ZeroizeOnDrop` derive — the de-facto standard in Rust
  cryptography (rustls, RustCrypto, aws-lc-rs, dalek-cryptography).
- User-provided `Rc<SchnorrProof>`-style wrappers. If downstream code wraps
  a proof in a reference-counted container and leaks the last strong
  reference, the proof's `Drop` never runs. That is a downstream
  responsibility.

### CLI passphrase via `LATTICEARC_PASSPHRASE` environment variable

The `latticearc` CLI accepts the encrypted-keyfile passphrase via the
`LATTICEARC_PASSPHRASE` environment variable as a fallback when no TTY is
available (CI, batch scripts, daemons). This is a deliberate convenience for
non-interactive automation; it is **not** intended for interactive use.

**The trade-off**: an environment variable is visible to other processes
running as the same user via `/proc/<pid>/environ` on Linux, can be read by
`root` on any platform, is inherited across `fork()` / `exec()`, and may be
captured in core dumps. Anyone who can read the process environment can read
the passphrase.

**Recommended deployment patterns**:

1. **Interactive sessions** — never set `LATTICEARC_PASSPHRASE`. Let the
   CLI prompt you on the TTY. The CLI will emit a `stderr` warning if it
   detects the variable is set on an interactive session, because the
   combination usually means an exported variable has been inherited from a
   prior shell session and the user is on a less-secure path than intended.
2. **CI / automation** — restrict the variable's scope to the single command
   that needs it, prefer ephemeral secret-injection mechanisms (GitHub
   Actions secrets, Vault, AWS Secrets Manager) over persistent env files,
   and unset the variable as soon as the operation completes.
3. **Containerised deployments** — pass the secret via a tmpfs-mounted file
   that the operator reads into the variable for the single CLI invocation,
   rather than via `--env` (which persists in container metadata).

The hard constraint that does not change: passphrases are never accepted as
command-line arguments — those are visible in `ps`, shell history, audit
logs, and crash dumps regardless of platform.

## Vulnerability Disclosure Policy

We follow coordinated disclosure:

1. Reporter contacts us privately
2. We acknowledge within 24 hours
3. We assess severity and develop fix
4. We coordinate disclosure timeline with reporter
5. We release fix and publish advisory
6. Maximum 90 days to public disclosure

### Recognition

We maintain a security acknowledgments page for researchers who report valid vulnerabilities (with permission).

## Security Advisories

Published advisories are available at:
- [GitHub Security Advisories](https://github.com/latticearc/latticearc/security/advisories)
- [RustSec Advisory Database](https://rustsec.org/) (when applicable)

## Contact

- **Security reports**: Security@LatticeArc.com
- **General questions**: Use GitHub Discussions
- **Non-security bugs**: Use GitHub Issues
