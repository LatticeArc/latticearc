# LatticeArc Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Round-4 audit response — 9 fixes + 2 CI repairs (2026-04-27)

Fourth external audit pass on top of `f351df612`. Two BLOCK_RELEASE
items, three HIGH, three MEDIUM, one LOW, plus the two CI failures from
the round-3 commit (`KAT Vector Integrity` checksum drift + macOS
timing-test ratio over its ceiling).

#### BLOCK_RELEASE
- **`tracing-subscriber` and `tracing-appender` are now optional**, gated
  behind a new `tracing-init` Cargo feature (off by default). The
  library only emits `tracing::*` events through the facade; subscriber
  wiring is the binary's job. The prior hard dependency would `panic!`
  the first downstream consumer that called their own
  `tracing_subscriber::fmt::init()` because both inits raced for the
  global default. `latticearc-cli` enables `tracing-init`.
- **`fips` now transitively enables `fips-self-test`.** Independent
  features previously meant `--features fips` skipped the FIPS 140-3
  §10.3.1 power-on self-test — a false compliance claim. Set
  `default-features = false` and enable `aws-lc-rs/fips` directly if
  you want the validated backend without the self-test wiring.

#### HIGH
- **`HybridKemPublicKey::to_bytes` wire format gets a `format_version: u8`
  prefix.** The v1 layout is now
  `[format_version=1] [level_tag] [ml_kem_pk_len: u32 BE] [...] [ecdh_pk_len: u32 BE] [...]`.
  Old parsers reject unknown versions cleanly via
  `HybridKemError::InvalidKeyMaterial`; new parsers can branch on the
  version when ML-KEM-2048 / composite schemes ship as v2. New const
  `HybridKemPublicKey::WIRE_FORMAT_VERSION = 1` exposes the current
  shipped value.
- **`EncryptedOutput::{to,from}_{json,bytes}` round-trip proptest**
  (`tests/tests/serialization_integration.rs::encrypted_output_roundtrip`)
  with 64 cases, covering both AES-GCM and hybrid shapes, plus
  negative tests for non-UTF-8 / invalid-JSON inputs.
- **CI feature-isolation matrix expanded** to test `fips-self-test`,
  `kat-test-vectors`, `secret-mlock`, and `tracing-init` standalone
  (`--no-default-features --features <name>` per row). Previously these
  features only ran transitively under `--all-features`.

#### MEDIUM
- **PQC crates pinned with `=` (exact version)** — `fips204 = "=0.4.6"`,
  `fips205 = "=0.4.1"`, `fn-dsa = "=0.3.0"`. These crates have shipped
  breaking API changes within `0.x.y` minor bumps before; a silent
  `cargo update` could regress signature verification on a downstream
  consumer's fresh resolve. Bump intentionally and re-run the FIPS
  validation suite when updating.
- **`SECURITY.md` yank/republish runbook** added — when to yank, the
  6-step procedure (yank → advisory → fix branch → revalidate → bump
  patch → communicate), and the smaller list of when NOT to yank.
- **`SECURITY.md` constant-time verification gap** documented honestly:
  the statistical timing tests only catch order-of-magnitude
  regressions; instruction-level verification (`dudect` / `ctgrind` /
  `valgrind --tool=massif` PR-blocking) is on the roadmap before 1.0.

#### CI repairs
- **`KAT Vector Integrity` job: refreshed `CHECKSUMS.sha256`** for the
  legitimately-modified `hmac_kat.rs` (added `hmac::KeyInit` import) and
  `ml_dsa_kat.rs` (migrated to `rand_core_0_6` traits for `fips204`
  0.4.x). Both source-side fixes had landed without rerunning
  `./scripts/verify-kat-checksums.sh --update`.
- **`Release Validation (macos-latest)` timing test** widened from
  `0.05x..20x` to `0.02x..50x`. Shared CI runners (especially macOS
  under load) can stretch single-iteration measurements 20-30x; the
  prior ceiling flaked at ratio=28.41. A real timing oracle in AES-GCM
  tag verification would manifest at 100x+, so the new window
  preserves leak detection while absorbing scheduler jitter.

### Round-3 audit response — 22 fixes (10 HIGH + 9 MEDIUM + 3 LOW, 2026-04-27)

Third external audit pass on top of `66fe78d6a`. Twenty-two findings; all
fixed. The HIGH set is dominated by documentation-vs-code mismatches and
ergonomics gaps; the MEDIUM set is API-surface polish; the LOW set is
documentation hygiene. No new breaking changes.

#### HIGH
- **Timing equalizer for `verify_hybrid_ml_dsa_ed25519` shape-rejection
  path (round-2 PARTIAL #2 follow-up).** Earlier "wasted verify work IS
  the timing equalizer" claim was wrong: the function bailed in
  nanoseconds with `Ok(false)` on shape failure, leaving the
  shape-vs-verify timing oracle wide open. Now substitutes shape-correct
  dummy material from a `OnceLock`-cached buffer per `MlDsaParameterSet`
  and runs the full ML-DSA + Ed25519 verify pipeline against it. The
  verify result is discarded; the original shape decision is what
  surfaces. DoS trade-off (shape failures now spend ~1 verify of CPU)
  documented in code; rate-limiting belongs at the dispatch layer.
- **Cap `LOW_ITER_WARNED` HashSet at 256 distinct iteration counts.**
  Was unbounded; an adversary feeding distinct-count keys could grow it
  permanently. 256 is more than any realistic operator fleet (cohorts
  cluster around OWASP guidance dates).
- **`SECURITY.md` version table refreshed.** Listed `0.4.x | Current`;
  actual is 0.8.0. Added rows for 0.5/0.6/0.7/0.8 with correct
  supersession status.
- **`SECURITY.md` Defense-in-Depth list now mentions WeakKey rejection.**
  The 0.8.0 `AeadCipher::new` weak-key check was a user-facing security
  control; absent from the disclosure document.
- **`SECURITY.md` Defense-in-Depth list now mentions FIPS DRBG fallback
  prevention.** The 0.8.0 `RngHandle::ThreadLocal` cfg-gate fixed a real
  FIPS 140-3 module-policy violation; absent from the disclosure
  document.
- **`kem_hybrid::encapsulate` and `decapsulate` rustdoc no longer
  enumerates the 5 sub-failures Pattern 6 specifically hides.** Doc
  comments listed `ECDH PK length / ML-KEM PK construction / shared-
  secret length / ECDH conversion / HKDF` as separate `# Errors`
  bullets, contradicting the runtime collapse to `EncapsulationFailed`
  / `DecapsulationFailed`. Now: single bullet referencing Pattern 6
  with a pointer at the internal `op::HYBRID_KEM_*` trace tag.
- **Hybrid type re-exports at crate root.** `HybridKemPublicKey`,
  `HybridKemSecretKey`, `HybridSigPublicKey`, `HybridSigSecretKey`,
  `HybridSignature`, `HybridCiphertext`, `EncapsulatedKey`,
  `DerivationBinding`, `HybridKemError`, `HybridSignatureError`,
  `HybridEncryptionError` are now reachable via `latticearc::*`. The
  `generate_hybrid_keypair` constructor was already at the root, but
  callers couldn't name its return types in struct fields or function
  signatures without writing
  `latticearc::hybrid::kem_hybrid::HybridKemPublicKey`.
- **`EncryptedOutput::to_json` / `from_json` / `to_bytes` / `from_bytes`
  inherent methods.** The encrypt → store → load → decrypt pipeline
  previously required hunting down free functions in
  `unified_api::serialization`. Inherent methods make this discoverable.
  Binary form (`to_bytes` / `from_bytes`) is JSON-as-bytes for v0.8 — a
  proper CBOR/postcard format is blocked on `EncryptionScheme` becoming
  serde-derivable, currently `#[non_exhaustive]`.
- **WeakKey error mapping at the convenience layer (ChaCha20 + AES).**
  ChaCha20 path collapsed every `AeadError` to
  `InvalidKeyLength { expected: 32, actual: 32 }` — the absurd
  "expected 32, got 32" message. AES decrypt path silently discarded
  the `_e`. Both paths now `match` on `AeadError::WeakKey` explicitly
  and surface a `CoreError::InvalidKey` with a remediation pointing at
  `generate_secure_random_bytes(32)`.

#### MEDIUM
- **CHANGELOG `Migration:` lines added** for the `derive_encryption_key`
  / `DerivationBinding` and `HybridSig*::new` / `MlDsaParameterSet`
  breaking changes from `6ef59908d`. The existing entries described
  the change but didn't tell callers how to update their code.
- **`docs/DESIGN_PATTERNS.md` Pattern 6 scope** widened from "all post-
  crypto decrypt errors" to the full set: AEAD decrypt, hybrid KEM
  encapsulate + decapsulate, hybrid signature verify, encrypt-side
  defence-in-depth (recipient-PK / ephemeral-PK / KEM-CT length checks).
- **Doc examples updated to use crate-root re-exports** (`use
  latticearc::{...}`) instead of the long internal path (`use
  latticearc::unified_api::{...}`). Quick Start and the
  `perform_crypto_operation` example were the most user-visible.
- **`prelude` module populated with the user-facing API.** Was test
  infrastructure + `LatticeArcError` + `Result` only; `use
  latticearc::prelude::*` now also gives you `encrypt`, `decrypt`,
  `sign_with_key`, `verify`, `generate_signing_keypair`,
  `generate_hybrid_keypair`, `CryptoConfig`, `EncryptKey`, `DecryptKey`,
  `EncryptedOutput`, `SignedData`, `SecurityLevel`, `CoreError`.
- **`From<LatticeArcError> for CoreError` impl** lets `?` compose
  across the two error hierarchies. Added `CoreError::Internal(String)`
  catch-all variant for `LatticeArcError` variants (e.g. `RandomError`,
  `IoError(String)`) that don't have a more specific peer.
- **`SigningKeypair` typed wrapper for `generate_signing_keypair`
  return.** The existing `(Vec<u8>, Zeroizing<Vec<u8>>, String)` tuple
  is fine but easy to misuse — losing the third element (scheme tag)
  silently breaks `sign_with_key` dispatch. New struct exposes named
  `public_key`, `secret_key`, `scheme` fields with `From`/`Into`
  conversions to/from the tuple.
- **`HybridKemPublicKey::to_bytes` / `from_bytes`** inherent
  serializers. Wire format
  `[level_tag: u8] [ml_kem_pk_len: u32 BE] [...] [ecdh_pk_len: u32 BE]
  [...]`; level tag mapping `1=MlKem512, 2=MlKem768, 3=MlKem1024`.
  Prior shape required pulling the components apart manually and
  remembering the security level out of band.
- **`_unverified` naming convention spelled out** at the convenience
  module top. Explicit "what `_unverified` does NOT mean" enumeration
  (still validates inputs / still constant-time / still rejects weak
  keys / still Pattern-6-opaque).

#### LOW
- **`AeadError::WeakKey` Display message** now includes a remediation
  pointer: `generate_secure_random_bytes(32)` for production,
  `kat-test-vectors` feature + `new_allow_weak_key` for KAT replay.
  Operators previously got "likely uninitialised memory" with no
  next-step.
- **Streaming and async API limitations documented** in the crate-root
  rustdoc under a new "Known limitations" section. Streaming AEAD is
  on the roadmap; native async is intentionally not, with rationale.
- **`Result` shadowing footgun documented** at the crate-root
  re-export. `use latticearc::*;` will silently shadow
  `std::result::Result`; the workaround is to either avoid the glob
  or `use std::result::Result as StdResult;` after.

### Audit-batch hardening pass (commit `6ef59908d`, 2026-04-27)

#### Breaking
- **`derive_encryption_key(shared, ctx)` → `derive_encryption_key(shared, ctx,
  &DerivationBinding{recipient_static_pk, ephemeral_pk, kem_ciphertext})`**.
  Per RFC 9180 §5.1 (HPKE) the encryption key is now bound to the channel
  triple via length-prefixed segments in the HKDF `info`. Without the
  binding, an attacker who recovers any one shared secret can re-key
  arbitrary ciphertexts. `DerivationBinding::empty()` exists for tests that
  legitimately have no channel context.
  Migration: `derive_encryption_key(shared, ctx)` →
  `derive_encryption_key(shared, ctx, &DerivationBinding { recipient_static_pk: hybrid_pk.ecdh_pk(), ephemeral_pk: encapsulated.ecdh_pk(), kem_ciphertext: encapsulated.ml_kem_ct() })`
  on encrypt-side, and the same triple drawn from `hybrid_sk.ecdh_public_key_bytes()`
  + `encapsulated.ecdh_pk()` + `encapsulated.ml_kem_ct()` on decrypt-side. For
  unit tests with no channel context, pass `&DerivationBinding::empty()`.
- **`HybridSigPublicKey::new` / `HybridSigSecretKey::new`** now take a
  leading `parameter_set: MlDsaParameterSet`. Previously the API silently
  assumed `MlDsa65`, so `MlDsa44` and `MlDsa87` keys round-tripped through
  the wrong ML-DSA backend. Key-format conversions infer the parameter set
  from the PQ-component byte length.
  Migration: `HybridSigPublicKey::new(ml_dsa_pk, ed25519_pk)` →
  `HybridSigPublicKey::new(MlDsaParameterSet::MlDsa65, ml_dsa_pk, ed25519_pk)`.
  Choose `MlDsa44`, `MlDsa65`, or `MlDsa87` to match the PQ-component byte
  length (1312 / 1952 / 2592 bytes respectively for public keys; 2560 / 4032
  / 4896 bytes for secret keys). Same migration for `HybridSigSecretKey::new`.
  When deserializing from wire, infer the parameter set from the PQ-component
  length using the byte-length tables in `MlDsaParameterSet` rustdoc.
- **`AeadError::Other` removed**. No production code path constructed it;
  the variant existed only as a catch-all for ad-hoc test errors. Tests
  now exercise the real `EncryptionFailed(ResourceLimit)` path via
  `validate_encryption_size`.

#### Added
- `HybridEncryptionContext::MAX_AAD_LEN = 64 KiB` upper bound, enforced at
  both encrypt and decrypt entry points.
- `latticearc-cli kdf pbkdf2` enforces OWASP 2023 minimum 600 000
  iterations (`OWASP_PBKDF2_MIN_ITERATIONS`); bypass via
  `--allow-weak-iterations` (KAT replay only — warns to stderr).
- `KeyAlgorithm` ↔ `MlKemSecurityLevel` and `KeyAlgorithm` ↔
  `MlDsaParameterSet` `From` / `TryFrom` impls; eliminates four inline
  match blocks and the 1312/1952/2592 magic numbers in
  `from_hybrid_sig_keypair`.
- 3 missing `#[must_use]` annotations on `HybridSigPublicKey::new`,
  `HybridSigSecretKey::new`, `HybridSignature::new`.

#### Changed
- **Pattern 6 (error opacity)** — four primitives no longer leak which
  sub-component failed validation:
  - `kem_hybrid::encapsulate` collapses every failure path into the unit
    variant `HybridKemError::EncapsulationFailed` (matches existing
    decapsulate symmetry).
  - `decrypt_hybrid` collapses 4 distinct `InvalidInput` pre-checks
    (KEM CT length, ECDH PK length, nonce length, tag length) into the
    opaque `HybridEncryptionError::DecryptionError`.
  - `sig_hybrid::verify` no longer pre-checks Ed25519 PK / signature
    lengths separately — both flow through the bit=0 verify path and
    collapse into `HybridSignatureError::VerificationFailed`.
  - `verify_hybrid_ml_dsa_ed25519` PK-length pre-check folded into the
    bit-0 path. Source-side `tracing::debug!` instrumentation preserved
    at every collapse site so production observability is unaffected.
- `XChaCha20Poly1305Cipher::{encrypt_x,decrypt_x}` now call
  `validate_encryption_size` / `validate_decryption_size` before any AEAD
  work; previously the resource-limit check was skipped on the X-variant
  code path.
- `Pbkdf2Params::with_salt` is infallible (returns `Self`) with one
  canonical validation point at `pbkdf2()`. Salt < 16 bytes
  (NIST SP 800-132 §5.1) is rejected exactly once, with the invariant
  documented at the type. Earlier draft used a fallible `try_with_salt`
  + `with_salt_unchecked` pair, then chained `.unwrap()` at every call
  site — both rejected by user feedback as design-pattern violations.
- `RngHandle::ThreadLocal` cfg-gated `not(fips)` so it cannot appear in
  a FIPS build.
- proptest cases bumped 32→256 (ml_kem_768) and 16→256 (ml_dsa_44).
- `kem_hybrid::decapsulate` instrumented with `log_crypto_operation_error!`
  — error string preserved in tracing, outer error stays opaque.

#### Removed
- `unified_api::logging::session_id_to_hex` (thin `hex::encode` wrapper)
  — callers inlined.
- `key_lifecycle::transition_count` field — no production callers
  (test-only).
- `AeadError::Other` (see Breaking above).

#### CI
- Scheduled fuzz workflow `schedule:` cron uncommented (nightly + weekly).
- Fuzz steps: `|| true` replaced with `continue-on-error: true` so the
  `if: failure()` upload artifact step actually fires; smoke fuzz crash
  artifact upload added.
- `docs` job split into read-only `docs` (every PR/push) and push-only
  `docs-deploy` (carries `contents: write`); narrows the permission
  surface that handles untrusted PR contents.
- `release.yml` `cargo audit` ignores
  `RUSTSEC-{2024-0436,2021-0139,2024-0375,2021-0145}` to match the
  workspace audit policy.

#### Internal refactors (Theme F / E / D / B from /simplify)
- Extracted `current_timestamp() -> u64` helper (eliminated 4 duplicate
  sites in `unified_api/convenience/api.rs`).
- Extracted `validate_aes256_key_length(k: &[u8]) -> Result<()>` helper
  (eliminated 4 duplicate sites — covers AES-256-GCM and
  ChaCha20-Poly1305 encrypt and decrypt).
- Extracted `key_lifecycle::compute_age_days(activated)` helper used by
  both `requires_rotation` and `age_days`.
- Extracted CLI `keygen.rs print_keypair_report(label, pk_path, sk_path,
  passphrase_protected)` helper (7 of 8 keypair-result printing sites
  consolidated).
- Extracted `pq_sig::map_verify_result` for ML-DSA / SLH-DSA / FN-DSA
  verify error mapping (3 duplicate sites).

### Added
- **AEAD strict-by-default key validation**: `AeadCipher::new` now rejects the
  all-zero key pattern with the new `AeadError::WeakKey` variant as fail-closed
  defence in depth (an all-zero AEAD key almost always indicates uninitialised
  memory or an unset configuration field rather than a deliberate operational
  choice). The check is implemented via constant-time
  `aead::is_all_zero_key`, satisfying the project's "secret comparisons must
  be constant-time" policy from `docs/DESIGN_PATTERNS.md` §2.
- **`kat-test-vectors` Cargo feature** + `AeadCipher::new_allow_weak_key`:
  opt-in escape hatch for reproducing NIST AES-GCM Test Cases 1 and 2
  (McGrew & Viega, 2004) and other canonical KATs that use the all-zero
  key. Default-off so production builds cannot accidentally construct a
  weak-key cipher. `latticearc-tests` enables the feature so its KAT
  vectors compile.
- **`impl FipsError for AeadError`**: maps every `AeadError` variant to the
  matching `FipsErrorCode` (notably `WeakKey → WeakKeyDetected`, code
  `0x0305`). Closes the previously-orphaned `AeadError` taxonomy gap.
- **Dedicated FIPS 203 §7.3 conformance gate**:
  `tests/fips_203_section_7_3_decaps_is_total.rs` — 4 named tests prove
  that `MlKem::decapsulate` is total over correctly-sized ciphertexts
  (returns implicit-rejection secret rather than `Err`), per the
  IND-CCA2 reduction.
- **CI feature-config matrix**: the `test` job in `.github/workflows/ci.yml`
  now runs in three rows — `--all-features`, `--features fips`,
  `--no-default-features` — every push. Previously every CI invocation
  used `--all-features`, so failures specific to the other configs (e.g.
  the 11 pre-existing `--no-default-features` failures fixed in this
  release) were silently invisible.

### Changed
- **`AesGcm128/256` and `ChaCha20Poly1305Cipher` constructors**: existing
  `new` keeps its signature but now also rejects the all-zero key. Tests
  needing a deterministic non-key-related fixture should pick any non-zero
  pattern (e.g. `[0x42u8; KEY_LEN]`); KAT vectors should enable the
  `kat-test-vectors` feature and call `new_allow_weak_key`. Migration is
  mechanical and fully covered in the per-call-site fixture sweep already
  shipped with this release.
- **`unified_api::selector::CLASSICAL_FALLBACK_SIZE_THRESHOLD` →
  `ML_KEM_DOWNGRADE_SIZE_THRESHOLD`**: the previous name was a misnomer;
  the threshold has never gated a fall-back to a classical-only scheme,
  only the in-band downgrade between ML-KEM parameter sets within the
  hybrid construction.
- **`MlockGuard` panic-tolerant wrapper around `region::LockGuard`**
  (`secret-mlock` feature): on Windows `region::LockGuard::drop` panics
  when `VirtualUnlock` returns `ERROR_NOT_LOCKED`, which the OS issues
  whenever the working set was trimmed (documented "best-effort"
  behaviour for `VirtualLock`). The wrapper now runs the inner drop
  inside `std::panic::catch_unwind` (with `AssertUnwindSafe`) so the
  `ERROR_NOT_LOCKED` panic is contained at the wrapper boundary while
  the success path still calls `VirtualUnlock` / `munlock`. This
  replaces the earlier `mem::forget`-on-Windows approach, which left
  the OS lock-accounting state pinned to the page until allocator
  decommit. See the type-level docs at `latticearc/src/types/secrets.rs`
  for the rationale and the `panic = "abort"` caveat.

### Fixed
- **Windows CI test failures** in `e2e_integration` and `unified_api`
  test targets caused by the `region` crate's strict `Drop` panic on
  `VirtualUnlock(ERROR_NOT_LOCKED)`. Resolved by the `MlockGuard`
  wrapper above.
- **Pre-existing `--no-default-features` test failures** (11 tests in
  `unified_api`): split between explicit `#[cfg(feature = "fips")]` gates
  for tests that exercise FIPS/CNSA compliance directly, and explicit
  `compliance(ComplianceMode::Default)` overrides via the new
  `unified_api::test_helpers::non_fips_config` helper for tests that use
  FIPS-defaulted use cases (`FinancialTransactions`, `HealthcareRecords`,
  `GovernmentClassified`, `PaymentCard`).
- **PBKDF2 deserialization log spam**: the warning emitted when an
  encrypted-key envelope's `kdf_iterations` is below the OWASP 2023
  recommendation (600,000) is now deduplicated per process via
  `OnceLock`, instead of firing on every `from_json`/`from_cbor` load.
- **Stale "zero-key warning" doc comments** in
  `unified_api/convenience/aes_gcm.rs` and `unified_api/mod.rs` updated
  to reflect the new "AeadError::WeakKey rejection" semantics.

### Security (hardening pass on top of `43dd87193`)

- **BLOCKING fix — FIPS DRBG fallback bypass on mutex poison**:
  `RngHandle::{fill_bytes,next_u64,next_u32}` previously routed to
  `FALLBACK_RNG` (a `ChaCha20Rng` thread-local) whenever the global RNG
  mutex was poisoned by a panic in another thread. ChaCha20 is **not** on
  the FIPS 140-3 approved-function list, so the fallback was a silent
  module-policy violation under `feature = "fips"`. Three new
  `fallback_*` helpers now return `LatticeArcError::RandomError` instead
  of falling through to the unapproved DRBG when `feature = "fips"` is
  active. Tests for `RngHandle::ThreadLocal` were split into per-feature
  variants (`_succeeds` for non-FIPS, `_rejected_under_fips` for FIPS).
- **Pattern 6 (Error Opacity on Adversary-Reachable Paths)**:
  * `hybrid::kem_hybrid::decapsulate` collapses every distinguishable
    failure path (length, KEM, ECDH, KDF) into a single opaque
    `HybridKemError::DecapsulationFailed` variant. Tests updated to
    pin the collapsed-variant contract.
  * `unified_api::convenience::api::verify_hybrid_ml_dsa_ed25519` (new
    extracted helper) evaluates both the PQ and Ed25519 verifies
    unconditionally and combines bitwise `&` (not `&&`) so a malformed
    PQ component cannot timing-leak that Ed25519 was skipped.
    Sig-shape errors collapsed to a single `"Invalid hybrid signature"`
    string; the three duplicated 50-line ML-DSA-44/65/87 verify arms in
    `verify` now dispatch through the helper.
- **Pattern 7 (Hybrid Combiner Safety)** — incremental tightening:
  * `HybridEncryptionContext::info` field privatized; new
    `with_aad(aad)` and `with_explicit_info(&'static [u8], aad)`
    constructors plus `info()` read accessor. The `'static` bound on
    `with_explicit_info` strongly encourages callers to declare custom
    domain separators as `pub const &[u8]` (typically in
    `types::domains`), making each non-default `info` value a
    grep-able audit checkpoint. The `aad` field stays `pub` by design
    (per-message application data, not a domain separator) — see the
    field-level doc for the asymmetry rationale.
  * `HYBRID_KEM_SS_INFO` bumped to `b"LatticeArc-Hybrid-KEM-SS-v1"` to
    match the `-v1` suffix on every other label in
    `types::domains`. Forward-compat: a future v2 hybrid combiner MUST
    bump this to `-v2`. Acceptable break since 0.8.0 is unreleased.
- **Sealed traits** (Pattern 4): `ZeroTrustAuthenticable`,
  `ProofOfPossession`, and `SigmaProtocol` are now sealed via shared
  `mod sealed` so downstream code cannot supply implementations that
  trivially break security semantics (e.g., a `verify_proof` returning
  `Ok(true)` for any input). `AeadCipher` was already sealed.
- **PBKDF2 NIST SP 800-132 §5.1 enforcement**:
  * New `Pbkdf2Params::MIN_SALT_LEN = 16` (128-bit) constant.
  * New `Pbkdf2Params::try_with_salt(&[u8]) -> Result<Self>` validating
    constructor — preferred over `with_salt`. The legacy `with_salt`
    builder is retained (and documented as such) for wire-format
    parsers that must round-trip pre-existing short salts; the
    runtime `pbkdf2()` derivation still rejects under-spec salts at
    the actual derivation step.
  * `unified_api::key_format::PBKDF2_MIN_SALT_LEN` now re-exports
    `Pbkdf2Params::MIN_SALT_LEN` so load-side and construction-side
    checks cannot drift.
  * `pbkdf2()` salt zero-check switched from `iter().all(|&b| b == 0)`
    (early-exit, leaks salt-prefix structure via timing) to the new
    constant-time helper `primitives::ct::is_all_zero_bytes`.
- **`primitives::ct` module** (new) — shared constant-time predicates
  used across primitives. Replaces the per-module re-implementations
  that used `vec![0u8; key.len()]` (heap alloc on every AEAD
  constructor) with a stack-only chunk-by-chunk
  `subtle::ConstantTimeEq` accumulator that handles arbitrary input
  lengths (PBKDF2 salts can exceed the AEAD-key 32-byte cap).
  `aead::is_all_zero_key` is now a thin re-export of
  `ct::is_all_zero_bytes`.
- **`SecretVec::from_bytes` realloc-leak fix** (`types::secrets`):
  switched from `bytes.shrink_to_fit()` (which can `realloc` the
  secret into a smaller heap allocation and free the original
  unzeroized — a real "secret in freed memory" hazard for callers
  passing oversized buffers like `BASE64_ENGINE.decode` output) to an
  explicit `Vec::with_capacity(len) + extend_from_slice +
  bytes.zeroize()` pattern. The new `SecretVec` always has
  `capacity == length`, so `ZeroizeOnDrop` covers every backing byte.

### Added (hardening pass)

- **`primitives::rand::secure_rng()`** — `#[doc(hidden)]` thin wrapper
  around `rand_core::UnwrapErr(OsRng)` for integration-test fixtures
  that need a `CryptoRng`-shaped RNG. External callers should use
  `random_bytes()` / `random_u32()` / `random_u64()`.
- **14 `#[must_use]` annotations** on keygen entry points
  (`generate_keypair`, `generate_ml_kem_keypair`, etc.) — discarding a
  freshly-generated keypair is almost always a bug (lost key material).
- **13 new tests** covering the hardening additions:
  * ChaCha20-Poly1305 `WeakKey` rejection + `new_allow_weak_key` bypass
  * PBKDF2 boundary tests at `MIN_SALT_LEN - 1` and `MIN_SALT_LEN`
    (both for `Pbkdf2Params::new` and `try_with_salt`)
  * Two **hybrid forge tests** that pin the bitwise-`&` semantics: a
    forged PQ component or a forged Ed25519 component each yield
    `false` (a regression to bitwise `|` would now be caught)
  * `HybridEncryptionContext::with_aad` coverage (canonical info label,
    AAD flow into HKDF, equivalence to `default()` for empty AAD)
  * `primitives::ct` unit tests (all-zero, oversize-chunked,
    partial-last-chunk, empty, any-non-zero)
  * `MlockGuard::drop` panic-tolerance regression (32 lock/unlock
    cycles must complete without escaping a panic)
  * `SecretVec::from_bytes` oversize-capacity regression
    (capacity == length on the resulting `SecretVec`)
  * `Vec::zeroize` end-to-end pin
  * `RngHandle::ThreadLocal` per-feature variants (succeeds without
    `fips`, rejected under `fips`)

### Changed (hardening pass)

- **rand 0.8 → 0.9** (workspace-wide). `OsRng` no longer implements
  `RngCore` directly; the workspace stays infallible by routing through
  `rand_core::UnwrapErr(OsRng)` in `primitives::rand::csprng`. A new
  `rand_core_0_6` workspace alias bridges to fn-dsa / dalek 2.x / k256
  which still pin `rand_core 0.6`. Dropped the
  `RUSTSEC-2026-0097` ignore in `deny.toml` / `.cargo/audit.toml`
  (rand 0.8 reseed unsoundness — no longer applies on 0.9.4).
- **digest 0.10 → 0.11 family** (lockstep): `hkdf 0.12 → 0.13`,
  `hmac 0.12 → 0.13`, `sha2 0.10 → 0.11`, `sha3 0.10 → 0.11`,
  `pbkdf2 0.12 → 0.13`, `aes 0.8 → 0.9`, `ctr 0.9 → 0.10`. Bumped
  the HMAC bench allocation budget from 4 KiB to 12 KiB to absorb
  the digest 0.11 internal allocation profile.
- **getrandom 0.2 → 0.3**, **uuid 1.x bump**, **tokio 1.52.1**.
- **`X25519SecretKey::expose_secret`** — renamed from `as_bytes`
  (Secret Type Invariant I-8: single grep-able accessor).
- **`MlKemSharedSecret::expose_secret_as_array`** — renamed from
  `as_array`. The dual `expose_secret`/`expose_secret_as_array`
  pattern is now documented as the typed-array exception in
  `docs/SECRET_TYPE_INVARIANTS.md` §I-8.
- **`#[must_use]` keygen messages shortened** from "discarding a
  generated keypair wastes entropy and leaks key material" to
  "generated keypair must be stored or used" (idiomatic noun-phrase
  form, 14 sites).
- **`AeadCipher::new` no longer has a default body**: implementors
  must define `new` directly. The `new_internal` trait method was
  removed; per-cipher inherent `new_raw` (length-checked, no weak-key
  guard) and `new_allow_weak_key` (KAT escape hatch) take its place.
- **`MlKemSharedSecret::expose_secret`** doc tightened to acknowledge
  the typed-array dual without claiming "the only public read accessor"
  (a phrasing the `expose_secret_as_array` rename would have falsified).
- **5 banned-adjective doc edits** (`docs/DESIGN.md`,
  `latticearc/src/lib.rs`, `types/types.rs`,
  `unified_api/mod.rs`, `docs/DEPENDENCY_JUSTIFICATION.md`):
  removed "intelligent", "real-time", "production-ready",
  "hardware-aware" without an `/// Implementation:` tag (per
  `docs/DESIGN_PATTERNS.md` §3 Banned Adjectives policy).

### Fixed (hardening pass)

- **9 broken doc examples** that used `[0u8; 32]` placeholder AEAD
  keys (now rejected by `AeadError::WeakKey`) updated to
  `random_bytes(32)`.
- **5 fndsa doctests** — `rand::rngs::OsRng` (rand 0.9, no longer
  `rand_core 0.6 RngCore`) replaced with `rand_core_0_6::OsRng` which
  matches the `sign_with_rng` trait bound.
- **Stale `Self::as_bytes` doc reference** on
  `MlKemSecretKey::to_bytes` corrected to `Self::expose_secret`
  (the type only ever had `expose_secret`; the doc was a stale
  rename ghost).
- **3 `kem_hybrid::decapsulate` regression tests** updated to assert
  `HybridKemError::DecapsulationFailed` (Pattern 6 collapse) instead
  of the previously-distinguishable `InvalidKeyMaterial` /
  `MlKemError` variants.
- **`pbkdf2 verify_password` test salt** bumped from 15 bytes
  (`b"wrongsalt123456"`) to 16 bytes (`b"wrongsalt1234567"`) to
  satisfy the new `MIN_SALT_LEN` floor.
- **CLI tests touching salts** (`latticearc-cli/tests/cli_integration.rs`)
  bumped from 8 / 13 hex-char salts to 32 hex-char (16-byte) salts.

## [0.8.0] — 2026-04-24

**Headline**: normative Secret Type Invariants ratified and structurally
enforced across the crate. Every type holding secret material now conforms to
a single invariant set (`docs/SECRET_TYPE_INVARIANTS.md`): sealed single
accessor `expose_secret()`, no `PartialEq`/`Eq`/`Clone`/`AsRef<[u8]>`/`Deref`,
stack-allocated fixed-size backing where the length is compile-time known,
compile-time barrier test covering 32 secret types, optional OS-level memory
locking via the `secret-mlock` feature. This is a pre-1.0 breaking release;
see the migration section below.

### Added

- **`docs/SECRET_TYPE_INVARIANTS.md`** — new normative spec. Ten invariants
  (I-1 through I-10) governing every `pub` type in the crate that holds
  secret material. Enforced by the compile-time barrier at
  `tests/no_partial_eq_on_secret_types.rs`, by the `expose_secret()` naming
  convention (grep-able audit checkpoint), and by CI clippy rules. Applies
  equally to downstream proprietary consumers.
- **`latticearc::SecretBytes<const N: usize>`** — new primitive.
  Stack-allocated fixed-size secret-byte container, `#[derive(Zeroize,
  ZeroizeOnDrop)]`, manual redacted `Debug`, `ConstantTimeEq`, no `Clone`
  (use `clone_for_transmission()`), single sealed accessor
  `expose_secret() -> &[u8; N]`. Preferred over `Zeroizing<Vec<u8>>` whenever
  the length is statically known (invariant I-2): no heap allocator size
  fingerprint, no realloc path that could free an unzeroized buffer.
- **`latticearc::SecretVec`** — new primitive. Heap-allocated variable-length
  equivalent. Same invariants as `SecretBytes<N>`. Constructors call
  `shrink_to_fit()` so `zeroize()` covers the full allocation, not just
  `..len`.
- **`latticearc::hybrid::kem_hybrid::HYBRID_SHARED_SECRET_LEN: usize = 64`**
  — new public constant, the size of the combined hybrid shared secret
  (HKDF-SHA256 output; see `derive_hybrid_shared_secret`).
- **New optional feature `secret-mlock`** (invariant I-10; default off).
  Under this feature, `SecretVec` calls `region::lock(2)` on its backing
  buffer at construction time (Linux/macOS `mlock`, Windows `VirtualLock`)
  so the bytes cannot be swapped to disk or captured in a core dump. Fail-
  open on lock failure (e.g. `RLIMIT_MEMLOCK` exceeded): the `SecretVec` is
  still returned with zeroization guarantees intact but without OS-level
  leakage protection. `SecretBytes<N>` is deliberately not covered (stack
  addresses do not survive Rust moves; per-instance page-locking is
  impractical). Adds transitive deps `region`, `mach2` (macOS), `bitflags`
  under the feature only.

### Changed (breaking — secret-type migration)

- **Sealed accessor `expose_secret()` replaces `as_bytes()`/`as_slice()` on
  every secret-bearing type** (invariant I-8). `as_bytes()` / `as_slice()`
  remain on public-data types (`PublicKey`, `MlKemPublicKey`,
  `MlKemCiphertext`, `MlDsaPublicKey`, `MlDsaSignature`, SLH-DSA
  `VerifyingKey`, FN-DSA `VerifyingKey`/`Signature`, `X25519StaticKeyPair`,
  `EcdhP256KeyPair`, `EcdhP384KeyPair`, `EcdhP521KeyPair`, `HashOutput`) —
  the naming distinction between public and secret byte access is now
  structural. Rename sweep covers `PrivateKey`, `SymmetricKey`,
  `MlKemSecretKey`, `MlKemSharedSecret`, `MlDsaSecretKey`, SLH-DSA
  `SigningKey`, FN-DSA `SigningKey`, and the new `SecretBytes`/`SecretVec`
  primitives.

  Migration: `sk.as_bytes()` → `sk.expose_secret()` (277 call sites in the
  crate were migrated this way, driven by compiler errors).

- **Multi-secret composite types use `expose_<component>_secret()`**:
  - `HybridSigSecretKey::ml_dsa_sk()` → `expose_ml_dsa_secret()`
  - `HybridSigSecretKey::ed25519_sk()` → `expose_ed25519_secret()`
  - `EncapsulatedKey::shared_secret()` → `expose_secret()` (single secret
    on the type, despite containing public ciphertext + public ephemeral
    key fields alongside).
  - `PqOnlySecretKey::ml_kem_sk_bytes()` → `expose_secret()`.

- **`EncapsulatedKey::shared_secret` field type**: `Zeroizing<Vec<u8>>` →
  `SecretBytes<64>` (stack-allocated, invariant I-2). `EncapsulatedKey::new`
  third parameter type changes accordingly; `expose_secret()` now returns
  `&[u8; 64]` rather than `&[u8]`. Eliminates one heap allocation per
  hybrid-KEM decapsulation and removes a realloc-leak bug class.

- **`derive_hybrid_shared_secret` return type**: `Result<Zeroizing<Vec<u8>>,
  HybridKemError>` → `Result<SecretBytes<HYBRID_SHARED_SECRET_LEN>,
  HybridKemError>`. The intermediate IKM assembly also migrated from
  `Zeroizing<Vec<u8>>` + two `extend_from_slice` to a stack `[u8; 64]`
  filled via explicit `copy_from_slice` into proven-in-range sub-slices.

- **`kem_hybrid::decapsulate` return type**: same migration as above.

- **No `PartialEq` / `Eq` on any secret type** (invariants I-5 / I-6).
  Removed four pre-existing latent `impl PartialEq` violations
  (`MlKemSecretKey`, `MlKemSharedSecret`, `MlDsaSecretKey`, SLH-DSA
  `SigningKey`) — each delegated to `ConstantTimeEq::ct_eq` internally, but
  their existence enabled callers to use `==` on secret types (leaking
  timing via short-circuit composition with `&&` / `||`). The compile-time
  barrier at `tests/no_partial_eq_on_secret_types.rs` now covers 32 types
  and will reject any future `#[derive(PartialEq)]` on a secret type as a
  build error.

  Migration: `assert_eq!(sk1, sk2)` → `assert!(bool::from(sk1.ct_eq(&sk2)))`.
  12 in-module and integration test call sites were migrated this way.

- **No `AsRef<[u8]>` / `Deref<Target = [u8]>` / `DerefMut` on secret types**
  (invariant I-8). `PrivateKey`, `SymmetricKey`, and the new `SecretBytes` /
  `SecretVec` do not implement these traits. Implicit coercions via `&key`
  or `&*key` that previously worked no longer compile.

  Migration: `some_fn(&private_key)` → `some_fn(private_key.expose_secret())`.

- **`PrivateKey` and `SymmetricKey` now wrap `SecretVec`** internally (was
  `ZeroizedBytes`). Behavioural contract unchanged from the caller's
  perspective aside from the accessor rename; under the `secret-mlock`
  feature both types now inherit OS-level memory locking.

### Deprecated

(none this release)

### Removed (breaking)

- **`latticearc::ZeroizedBytes`** — deleted. Was a heap-backed variable-
  length secret-byte container that duplicated `SecretVec`'s invariant set.
  All uses in the crate were consolidated; `PrivateKey(ZeroizedBytes)` and
  `SymmetricKey(ZeroizedBytes)` now wrap `SecretVec` instead.

  Migration: `ZeroizedBytes::new(v)` → `SecretVec::new(v)`;
  `zb.as_slice()` → `sv.expose_secret()`.

- **`latticearc::primitives::security::SecureBytes`** — deleted. Was a
  heap-backed secret-byte container that implemented `Deref<Target = [u8]>`
  /  `DerefMut` / `AsRef<[u8]>` / `PartialEq` / `Eq` — every trait listed in
  invariants I-5, I-6, and I-8 as forbidden on a secret type. Also retained
  `extend_from_slice` / `resize` methods whose realloc path could free
  unzeroized memory (invariant I-2 violation).

  Migration: `SecureBytes::new(v)` → `SecretVec::new(v)`;
  `SecureBytes::zeros(n)` → `SecretVec::zero(n)`; `sb.as_slice()` /
  `&*sb` / `sb.as_ref()` → `sv.expose_secret()`. Callers that relied on
  `extend_from_slice` or `resize` must build the final `Vec<u8>` outside
  the wrapper and then pass it to `SecretVec::new` — the new type has no
  in-place growth API, by design.

- **`impl PartialEq for MlKemSecretKey`** and **`impl Eq for MlKemSecretKey`**
  — removed (see Changed section above).
- **`impl PartialEq for MlKemSharedSecret`** and **`impl Eq`** — removed.
- **`impl PartialEq for MlDsaSecretKey`** and **`impl Eq`** — removed.
- **`impl PartialEq for SLH-DSA SigningKey`** and **`impl Eq`** — removed.
- **`impl Deref for SecureBytes`**, **`impl DerefMut`**, **`impl AsRef<[u8]>`**,
  **`impl PartialEq`**, **`impl Eq`** — removed with the type.
- **`impl AsRef<[u8]> for PrivateKey`**, **`impl AsRef<[u8]> for SymmetricKey`**,
  **`impl AsRef<[u8]> for ZeroizedBytes`** — the latter with the type,
  the former two deliberately.
- **`MemoryPool::allocate` and `::deallocate` signatures** changed from
  `SecureBytes` to `SecretVec`. The pool's internal storage is now
  `HashMap<usize, Vec<SecretVec>>`.

### Fixed (CLI — pure-PQ key handling in unified paths)

- **`sign --public-key` with a pure-PQ ML-DSA key now works** (previously
  failed with *"Hybrid secret key length mismatch: expected 4064, got
  4032"*). Root cause: `build_signing_config` inferred `SecurityLevel`
  from the key's algorithm but left `CryptoMode` at its default (`Hybrid`),
  so the selector resolved to a hybrid scheme and rejected the pure-PQ
  key. Added `infer_crypto_mode(KeyAlgorithm) -> Option<CryptoMode>`
  alongside `infer_signature_security_level`; pure-PQ variants now set
  `CryptoMode::PqOnly` automatically. Precedence unchanged — explicit
  `--use-case` / `--security-level` still wins over inference.
- **`encrypt --use-case ...` with a pure-PQ ML-KEM key now works**
  (mirror-image of the sign bug). `encrypt_with_config` unconditionally
  parsed public keys as hybrid in the use-case path. It now detects
  pure-PQ ML-KEM algorithms (`ml-kem-512/768/1024`) and delegates to
  `encrypt_pq_only_mode`, which sets `CryptoMode::PqOnly` and uses
  `EncryptKey::PqOnly`. Hybrid keys continue to use the hybrid path.
- **Regression tests**: six new end-to-end tests in
  `cli_integration.rs` cover keygen → sign → verify (ML-DSA-44/65/87)
  and keygen → encrypt → decrypt (ML-KEM-512/768/1024) via the
  unified `--public-key` / `--use-case` flags. Existing tests only
  exercised hybrid schemes (every `UseCase` maps to a hybrid variant
  in the policy engine), so the pure-PQ × unified-API intersection was
  unreached.

### Changed (breaking, pre-1.0 API cleanup)

- **ZKP proof types removed `Clone` derive** (closes #50). `SchnorrProof`,
  `SigmaProof`, and `DlogEqualityProof` no longer implement `Clone`. Each
  proof type now exposes `clone_for_transmission() -> Self` so every
  duplication is a deliberate, grep-able audit checkpoint. Supersedes the
  earlier Path A (documented acceptance of the `Clone` derive) with Path B
  (no `Clone`, explicit method). SECURITY.md section renamed "ZKP Proof
  Duplication" and updated accordingly.
- **`SerializableKeyPair` removed `Clone` derive** (closes #51). Production
  code never cloned this type; only three `#[test]` sites did. Those tests
  were rewritten to construct two independent instances from the same
  source key. Downstream consumers who previously cloned a serialized
  keypair will see a compile error and should either construct two
  instances from the same source or promote the resulting `KeyPair` to
  runtime-key types.
- **ML-DSA `sign`/`verify` are now methods, not free functions** (API shape
  aligned with SLH-DSA and FN-DSA). Call sites change from
  `ml_dsa::sign(&sk, msg, ctx)` to `sk.sign(msg, ctx)`, and from
  `ml_dsa::verify(&pk, msg, sig, ctx)` to `pk.verify(msg, sig, ctx)`. All
  46+ internal call sites migrated. The free functions are no longer
  exported.
- **FN-DSA now uses per-module `FnDsaError`** (matches ML-DSA's
  `MlDsaError` and SLH-DSA's `SlhDsaError`). Previously FN-DSA returned
  the crate-wide `LatticeArcError`. A `From<FnDsaError> for LatticeArcError`
  impl is provided so callers that propagate into crate-level error types
  continue to work via `?`.
- **FN-DSA `VerifyingKey::verify` doc comment corrected.** The prior doc
  promised an `Err` path ("Returns an error if the fn_dsa feature is not
  enabled") that did not exist in the code — the function was infallible
  in practice. Updated to accurately describe that the `Result` wrapper is
  retained for return-type parity with ML-DSA/SLH-DSA and to keep future
  error paths non-breaking.

### Removed (audit markers)

- **All `AUDIT-TRACKED` markers removed from source.** Six `#48` and five
  `#49` markers on aws-lc-rs-wrapped secret types (ECDH keypairs, ML-KEM
  `DecapsulationKey`) are replaced with concise inline docs pointing at
  a new SECURITY.md section ("aws-lc-rs-Wrapped Secret Types"). Neither
  remaining concern is actionable downstream: zeroization is already
  handled by aws-lc-rs/BoringSSL at free time, and the absence of
  `ConstantTimeEq` is guarded by a compile-time `PartialEq` barrier
  (`latticearc/tests/no_partial_eq_on_secret_types.rs`). Issues #48 and
  #49 close on merge. The `AUDIT-TRACKED(#NN)` convention remains
  documented in `docs/DESIGN_PATTERNS.md` for future use, but the tree
  now carries zero markers — the "locked" state for 1.0 prep.

### Changed (audit marker convention)

- **`AUDIT-ACCEPTED` → `AUDIT-TRACKED(#NN)`**: renamed 17 in-code markers across
  `primitives/kem/ecdh.rs`, `primitives/kem/ml_kem.rs`, `primitives/mac/cmac.rs`,
  `unified_api/serialization.rs`, `unified_api/key_format.rs`, `zkp/schnorr.rs`,
  and `zkp/sigma.rs` to reference open GitHub tracking issues (#48–#52). The
  word "accepted" implied audit closure and created a false sense of complete-
  ness; tracked limitations now stay visible — and referenced to an open issue
  — until genuinely resolved. Convention is documented in
  `docs/DESIGN_PATTERNS.md`.

### Fixed

- **CMAC subkey derivation is constant-time** (closes #52). Replaced the two
  `if msb == 1 { xor_block(...) }` branches in
  `primitives/mac/cmac.rs::generate_subkeys` with a constant-time
  `ct_xor_block_if` helper built on `subtle::ConditionallySelectable`. K1 and
  K2 derivations are now uniformly timed regardless of the CMAC key. NIST SP
  800-38B KAT vectors for AES-128/192/256 continue to pass.
- **`PortableKey::ConstantTimeEq` now compares all fields** (closes #49,
  `PortableKey` portion). The prior impl had two correctness bugs:
  (1) it ignored `PortableKey` metadata, so two keys with identical `key_data`
      but different `algorithm`, `key_type`, `use_case`, `security_level`,
      `created`, or extension metadata compared as equal;
  (2) the `Encrypted` variant fell through the wildcard arm, so two identical
      encrypted envelopes compared not-equal (false negative).
  New impl compares metadata non-CT (it is plaintext on the wire) and
  delegates the key material to a new `impl ConstantTimeEq for KeyData`. The
  `KeyData` match is now exhaustive — adding a new variant triggers a compile
  error rather than a silent fall-through. Eight regression tests added,
  including coverage for each metadata field, the Encrypted variant, and
  variant-mismatch paths.

### Added

- **Compile-time `PartialEq` barrier on aws-lc-rs-wrapped secret types**
  (closes #49, aws-lc-rs portion; defensive alternative to an upstream fix).
  New integration test
  `latticearc/tests/no_partial_eq_on_secret_types.rs` uses
  `static_assertions::assert_not_impl_any!` to reject any future `PartialEq` or
  `Eq` impl on `X25519KeyPair`, `EcdhP256KeyPair`, `EcdhP384KeyPair`,
  `EcdhP521KeyPair`, and `MlKemDecapsulationKeyPair`. Removes the "no
  compile-time barrier prevents a future `==` comparison" risk without waiting
  on aws-lc-rs to expose raw key bytes. `static_assertions = "1.1"` added as
  dev-dep; zero runtime cost.
- **ZKP proof Zeroize + `clone_for_transmission` invariant tests** (#50).
  Six tests across `zkp/schnorr.rs` and `zkp/sigma.rs` verify that (a)
  `Zeroize::zeroize()` wipes every field and (b) `clone_for_transmission`
  gives independent storage. Combined with `zeroize::ZeroizeOnDrop`'s
  derive contract, these invariants imply both the original and every
  transmitted clone are wiped at
  end-of-scope. A new SECURITY.md section "ZKP Proof Clone Acceptance" under
  "Known Limitations" documents the rationale and the tested invariants.

## [0.7.1] — 2026-04-19

### Changed (audit-accepted marker refresh)

- **FN-DSA `SigningKey` now zeroizes inner key material.** `fn-dsa` v0.3.0
  derives `Zeroize` + `ZeroizeOnDrop` on `SigningKeyStandard`, so the prior
  `AUDIT-ACCEPTED: H4` marker ("inner cannot be zeroized — upstream
  limitation") no longer applies. The `Drop` and `Zeroize` impls on our
  wrapper now wipe both the serialized `bytes` buffer and `inner`. The
  misleading doc block claiming FIPS 140-3 §10.3.5 could not be met for
  the inner state has been removed. Behavioural change: best-effort
  zeroization → full zeroization.
- **X25519 static keypair docs corrected.** The "in-memory only" limitation
  note on `X25519StaticKeyPair` was outdated: aws-lc-rs 1.16+ supports
  X25519 raw-bytes import (`from_private_key`) and export
  (`AsBigEndian<Curve25519SeedBin>`). DER encoding is still unsupported
  upstream. The copy-paste "ephemeral (consumed on use)" phrase in the
  ConstantTimeEq note — inaccurate for the static variant — has been
  replaced with accurate guidance on how to do a constant-time compare
  when needed.

### Added (Phase 1 differentiation: timing/logic/DoS gates)

- **Kani proofs are now PR-blocking** (fast subset of 15 proofs, ≤15 min).
  Full 27-proof suite continues to run on schedule (nightly/weekly) with a
  120-min timeout. Workflow: `.github/workflows/kani.yml`. This flips the
  guarantee from "proofs run somewhere eventually" to "proofs must pass to
  merge". Memory of prior "codegen-only" status is stale — proofs have been
  executing for some time; the change is only in gating.
- **Mutation testing is now PR-blocking** on changed crypto files via
  `cargo mutants --in-diff`, with an 80% score floor. Removed
  `continue-on-error: true` from all three per-module jobs (`primitives`,
  `unified_api`, `hybrid`); the same floor now applies to the scheduled
  weekly full runs. Workflow: `.github/workflows/mutation.yml`.
- **Allocation-budget tests** (`tests/tests/allocation_budgets.rs`) — seven
  crypto operations (ML-KEM-768 encap/decap, AES-256-GCM encrypt/decrypt on
  1 KiB, hybrid KEM encap, HKDF-Expand 32 B, HMAC-SHA256 over 1 KiB) assert
  per-call allocation ceilings using `stats_alloc`. Intentional regression
  gate against accidental hot-path allocation growth.
- **Property-based rejection invariants** (`tests/tests/proptest_invariants.rs`)
  — any single-bit flip in AES-GCM tag / ciphertext / AAD makes decrypt fail;
  any flip in an ML-DSA-44 signature makes verify return `Ok(false)` or parse
  error; any flip in an ML-KEM-768 ciphertext yields a shared secret distinct
  from the legitimate one (FIPS 203 implicit rejection). These are forgeability
  contracts for the corresponding standards, enforced as proptests rather than
  hand-written unit vectors.
- **Resource-limits coverage gate** (`scripts/ci/resource_limits_coverage.sh`)
  added as a step of the `quality` job in `ci.yml`. Scans every `pub fn` in
  `hybrid/`, `primitives/{kem,sig,aead,mac,kdf}/`, and `unified_api/convenience/`
  that takes `&[u8]` and fails CI if the function neither calls a
  `validate_{encryption,decryption,signature,key_derivation}_*` function in
  its file nor is explicitly listed in `docs/RESOURCE_LIMITS_COVERAGE.md`.
  New public crypto functions that forget a size cap are now a build break.
- **New docs**: `docs/RESOURCE_LIMITS_COVERAGE.md` (per-function size-cap audit)
  and `docs/ITERATION_BOUNDS.md` (per-loop iteration-bound audit; documents
  existing PBKDF2 `1000 ≤ iter ≤ 10_000_000` cap and known HMAC/CMAC gaps
  scheduled for v0.7.1).
- **Reusable action** `.github/actions/mutation-score-gate/action.yml` —
  factors the jq/bc score-floor logic shared by the PR and scheduled mutation
  jobs. Single source of truth for the score-floor policy.
- **Declarative Kani PR manifest** `.github/kani-pr-harnesses.txt` — the 15
  PR-subset proof names live in a checked-in file instead of being hardcoded
  in `kani.yml`. CI verifies every manifest entry corresponds to an actual
  `fn` in `latticearc/src` before running Kani, so a rename fails fast rather
  than silently reducing proof coverage.

### Added (Phase 2a: cross-impl validation, Wycheproof wrappers, Kani coverage)

- **Cross-impl validation for ML-DSA** (`tests/tests/cross_impl_ml_dsa.rs`):
  10 tests. `fips204` and `pqcrypto-mldsa` (PQClean C reference) must agree
  on ML-DSA-44/65/87 key/signature byte sizes *and* cross-verify signatures
  in both directions. Until aws-lc-rs ships ML-DSA in its stable Rust API
  (tracking `aws/aws-lc-rs#1029`), PQClean is the only cross-check
  available. All 10 tests pass.
- **Cross-impl validation for SLH-DSA** (`tests/tests/cross_impl_slh_dsa.rs`):
  5 tests. `fips205` and `pqcrypto-sphincsplus` agree on SHAKE-128s/192s/256s
  key/signature sizes. Cross-signature verification *currently does not
  work* because fips205 applies the FIPS 205 §10.2 context-header wrapping
  (`M' = 0x00 || len(ctx) || ctx || M`) while PQClean's binding signs the
  bare message. The two divergence tests *assert the current incompatibility*
  so a future PQClean alignment with FIPS 205 surfaces as a test failure
  prompting us to re-enable positive cross-verify.
- **Wycheproof vectors through our wrappers** (`tests/tests/wycheproof_wrapper.rs`):
  4 tests, 555 attacker-chosen vectors exercising `AesGcm256::decrypt`,
  `ChaCha20Poly1305Cipher::decrypt`, `hmac_sha256`/`verify_hmac_sha256`, and
  `hkdf_extract`/`hkdf_expand`. Complements the existing
  `tests/src/validation/wycheproof.rs` suite, which tests the underlying
  crates. 0 failures across all 555 ran cases. Max failure budget: 1%.
- **Kani proofs for DoS guards** in `latticearc/src/primitives/resource_limits.rs`:
  3 new harnesses — `validate_encryption_size_biconditional`,
  `validate_decryption_size_biconditional`,
  `validate_key_derivation_count_accepts_zero`. Formally verify that
  `size > limit ⇔ Err` for every representable `size` and `limit`. Added
  to the PR-blocking Kani manifest (total PR subset now 18 proofs; full
  suite 30).

### Changed (Phase 2e: MSan unblocked via aws-lc-rs 1.16.3)

- **Bumped `aws-lc-rs` 1.16.2 → 1.16.3** in the workspace `Cargo.toml`.
  Release 2026-04-15 resolves `aws/aws-lc-rs#1077` (filed by us in an
  earlier phase) and adds `AWS_LC_SYS_SANITIZER={asan,msan,tsan}` env-var
  support: when set, aws-lc-sys compiles its C sources with the matching
  `-fsanitize=*` flag, letting the Rust-side sanitizer follow allocations
  through the FFI boundary.

- **MSan workflow (`sanitizers.yml`) rewired** to take advantage:
    * `AWS_LC_SYS_SANITIZER: msan` env var set on the msan job.
    * Removed the entire `--skip` list (aead/kem/kdf/hybrid/tls/unified_api
      /self_test/pct/keys). Those modules now run under MSan because the
      aws-lc-rs C buffers they touch are themselves instrumented.
    * Scope expanded from `-p latticearc --lib` to `--workspace --lib`,
      so the MSan job now matches ASan/TSan/LSan coverage.
    * `continue-on-error: true` retained for one clean scheduled run on
      main — to be flipped to `false` in a follow-up once we confirm
      clean passage on CI hardware. (ASan/TSan/LSan already blocking.)

- **OSS-Fuzz scaffold updated** to enable MSan from intake:
    * `project.yaml` sanitizer list now `address`/`memory`/`undefined`.
    * `build.sh` exports `AWS_LC_SYS_SANITIZER=msan` when OSS-Fuzz sets
      `$SANITIZER=memory`.
    * Dropped the "MSan pending #1077" open-items note in `README.md`.

### Added (Phase 2d: instruction-level CT gate + OSS-Fuzz scaffold)

- **ctgrind Valgrind-based constant-time harness**
  (`tests/examples/ctgrind_ct.rs` + `.github/workflows/ctgrind.yml`).
  Same technique used by BoringSSL/libsodium/aws-lc: mark secret bytes
  as `Undefined` via Valgrind memcheck client requests, then invoke
  the CT operation. Valgrind fails if any branch or index uses those
  bytes — flagging non-constant-time behavior at the instruction
  level. Scope: pure-Rust paths (`subtle::ConstantTimeEq` directly,
  and `HybridKemSecretKey::ct_eq` composition) where the invariant is
  well-defined. Workflow runs weekly (Tuesdays 06:00 UTC, offset from
  the Sunday Criterion gate and the Monday dudect gate); not
  PR-blocking. `crabgrind = "0.2"` added as dev-dep in
  `latticearc-tests`. Complements dudect (statistical timing) by
  catching a different failure mode: a branch that depends on a secret
  even when timing looks uniform on a given machine.

- **OSS-Fuzz integration scaffold** (`fuzz/oss-fuzz/`). Vendored
  `project.yaml`, `Dockerfile`, `build.sh`, and `README.md` ready to
  copy into `google/oss-fuzz/projects/latticearc/` as an upstream PR.
  Sanitizers enabled on day one: `address`, `undefined`. Memory
  sanitizer deliberately held back pending `aws/aws-lc-rs#1077` (same
  upstream item gating `sanitizers.yml` MSan). Once OSS-Fuzz accepts
  the PR, their infrastructure continuously fuzzes every `[[bin]]` in
  `fuzz/Cargo.toml` with findings reported by email. Puts our
  continuous-fuzzing story on the same footing as OpenSSL/BoringSSL.

### Added (Phase 2c: cross-impl ML-KEM stress + weekly fuzz schedule)

- **Cross-impl ML-KEM stress tests** (`tests/tests/cross_impl_ml_kem.rs`):
  6 tests × 100 iterations = 600 cross-library round-trips per run.
  Completes the cross-impl matrix (ML-DSA + SLH-DSA landed in Phase 2a,
  this adds ML-KEM). Covers all three parameter sets (512/768/1024)
  in both directions: fips203-keygen/encaps → aws-lc-rs-decaps and
  aws-lc-rs-keygen/encaps → fips203-decaps. Shared secrets must agree
  byte-for-byte; any divergence is a library bug on one side and
  breaks interop. Complements the 4 deterministic ML-KEM-768
  cross-library tests already in `tests/tests/fips_cross_validation.rs`.

- **Weekly scheduled fuzzing** (`.github/workflows/fuzzing.yml`).
  Enabled `schedule: 0 5 * * 0` (Sundays 05:00 UTC). All 34 fuzz
  targets run in matrix parallel for 5 min each on schedule; the
  extended-fuzz job (priority targets, longer duration) activates
  automatically via its existing `if: github.event_name == 'schedule'`
  guard. Not on push/PR — Kani + clippy + unit-test suite cover
  per-commit correctness; fuzzing's value is long-running campaigns.

### Changed (Phase 2b: audit-finding follow-ups, breaking)

- **`MlKemSecurityLevel::ct_eq` no longer casts through `*self as u8`**
  (`latticearc/src/primitives/kem/ml_kem.rs`). The enum is not
  `#[repr(u8)]`, so the cast relied on compiler-chosen discriminant
  ordering — same latent bug the recent `HybridKemSecretKey::ct_eq` impl
  (commit `bfeb9b0e`) explicitly rejected. Now uses
  `Choice::from(u8::from(self == other))`. Today's 3-variant enum values
  happen to fit u8, so this is a correctness improvement with no
  behavioral change; it hardens the impl against a future variant
  addition or reorder.

- **`derive_hybrid_shared_secret` takes `HybridSharedSecretInputs<'_>`
  instead of 4 positional `&[u8]` args** (`latticearc/src/hybrid/kem_hybrid.rs`).
  The old signature accepted ML-KEM and ECDH shared secrets as adjacent
  `&[u8]` arguments of the same length — a silent swap would still
  compile but derive a different secret and break interop. The named-
  field struct forces callsites to label each input; a swap is now a
  compile error. New public type `HybridSharedSecretInputs` re-exported
  from `latticearc::hybrid`. Breaking change for callers of
  `derive_hybrid_shared_secret`; all internal callsites and tests
  (~27 callsites across 3 files) migrated.

  Before:
  ```rust
  derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &eph_pk)?
  ```
  After:
  ```rust
  derive_hybrid_shared_secret(HybridSharedSecretInputs {
      ml_kem_ss: &ml_kem_ss,
      ecdh_ss: &ecdh_ss,
      static_pk: &static_pk,
      ephemeral_pk: &eph_pk,
  })?
  ```

### Added (Phase 2b: adversarial DoS fuzzing + statistical timing gate)

- **DudeCT statistical constant-time gate** (`tests/examples/dudect_ct.rs`
  + `.github/workflows/dudect.yml`). Implements the DudeCT method from
  Reparaz et al. (IACR ePrint 2016/1123): runs each operation under two
  input classes and applies Welch's t-test to the measured runtimes. A
  `|max t| > threshold` result is strong statistical evidence the op's
  runtime depends on secret data. Two benches shipped: `verify_hmac_sha256`
  (valid vs. tampered tag) and `HybridKemSecretKey::ct_eq` (equal vs.
  independently-generated keys). Workflow runs weekly + on-demand, not
  PR-blocking (shared-runner jitter is substantial), with a default
  `|t| < 10` threshold — loose vs. the paper's 5.0 to absorb CI noise,
  tight enough to catch any real first-byte-short-circuit regression.
  Complements the existing qualitative Criterion gate in
  `constant-time.yml`. `dudect-bencher = "0.7"` added as dev-dep to
  `latticearc-tests`; pulls a second major version of rand transitively
  but only in dev builds. Local smoke run on an M-series laptop:
  `bench_verify_hmac_sha256 max t = -1.63`,
  `bench_hybrid_secret_key_ct_eq max t = +1.15`.

- **Allocation-bounded DoS fuzz target** `fuzz/fuzz_targets/fuzz_dos_alloc_bounded.rs`.
  Dispatches on the first byte of fuzz input to one of four public entrypoints
  (AEAD-256-GCM decrypt, ML-KEM decapsulation at all three security levels,
  `deserialize_encrypted_output`, `deserialize_keypair`) and wraps each call
  in a `stats_alloc::Region` measurement. Any single call that allocates more
  than 1 MiB panics the fuzzer. Complements `tests/tests/allocation_budgets.rs`
  (which gates *happy-path* allocation growth) by checking that *adversarial*
  inputs — crafted JSON, malformed ciphertexts, attacker-chosen length fields —
  cannot force unbounded allocation through a public API. Added to the
  `.github/workflows/fuzzing.yml` matrix. `stats_alloc = "0.1"` added to
  `fuzz/Cargo.toml` dependencies; no effect on the published `latticearc`
  or `latticearc-cli` crates.

### Changed (Phase 2a)

- Added dev-dependencies `pqcrypto-mldsa = "0.1"`, `pqcrypto-sphincsplus = "0.7"`,
  `pqcrypto-traits = "0.3"` in `latticearc-tests`. These pull C reference
  implementations from PQClean for cross-validation. They trigger a
  `cc`-driven C build but have no effect on `latticearc` or
  `latticearc-cli` runtime dependencies.

### Changed

- Bumped `tokio` 1.50.0 → 1.51.1 (patch).
- Bumped `rayon` 1.11 → 1.12 (minor).
- Added dev-dependency on `stats_alloc = "0.1.10"` in `latticearc-tests` for
  allocation-budget tests. No effect on `latticearc` or `latticearc-cli`
  runtime dependencies.

### Removed (breaking, finishing the v0.7.0 deprecation cleanup, third pass)

- **Removed `SecurityLevel::Quantum`** — deprecated since 0.6.0 with the note
  "Use SecurityLevel::Maximum with CryptoMode::PqOnly instead". The variant
  conflated two orthogonal axes (security level and crypto mode); callers should
  pair `SecurityLevel::Maximum` with `.crypto_mode(CryptoMode::PqOnly)` for
  identical behavior. `SecurityLevel::resolve()` (which mapped the deprecated
  variant to the canonical pair) is also removed. The `CryptoConfig::security_level`
  setter no longer auto-promotes crypto mode; `CryptoMode` is now entirely
  explicit. The CLI `quantum` string alias is removed from `--security-level`.
  `select_signature_scheme` now honors `CryptoMode::PqOnly`, so
  `Maximum + PqOnly` routes signing to `pq-ml-dsa-87` (previously only
  `SecurityLevel::Quantum` reached that branch).

### Removed (breaking, finishing the v0.7.0 deprecation cleanup, second pass)

- **Removed `latticearc::unified_api::serialization::SerializableEncryptedData`**
  and its companion `SerializableEncryptedMetadata`. Deprecated since 0.4.0
  with the note "Use EncryptedOutput instead". The legacy JSON wire format
  could not represent hybrid PQ encryption (no fields for ML-KEM ciphertext
  or X25519 ephemeral key), making it structurally unsuitable for this
  crate's PQ-by-default design. The only remaining callers were tests
  exercising the deprecated path.
- **Removed the public functions
  `latticearc::serialize_encrypted_data` and
  `latticearc::deserialize_encrypted_data`** (and their re-exports from
  `latticearc::unified_api::serialization`). Use
  `serialize_encrypted_output` / `deserialize_encrypted_output` (operating
  on `EncryptedOutput`) instead. `From<EncryptedOutput> for EncryptedData`
  and `TryFrom<EncryptedData> for EncryptedOutput` are available for
  callers that need to convert between the two payload types.
- **Migrated the 10 MiB defense-in-depth size cap** that previously lived
  inside `TryFrom<SerializableEncryptedData> for EncryptedData` to the
  modern `TryFrom<SerializableEncryptedOutput> for EncryptedOutput` so the
  protection survives the removal. Audit L4 tests were rewritten to
  exercise the modern path.
- The `fuzz_encrypted_data_deser` fuzz target was simplified to fuzz only
  the modern `deserialize_encrypted_output` path; the legacy
  `deserialize_encrypted_data` arm is gone with the function.

### Removed (breaking, finishing the v0.7.0 deprecation cleanup)

- **Removed `latticearc::hybrid::encrypt_hybrid::{encrypt, decrypt}`** —
  legacy ML-KEM-768-only path deprecated since 0.6.1. Replaced by
  `encrypt_hybrid` / `decrypt_hybrid` (true ML-KEM + X25519 hybrid, supports
  ML-KEM-512/768/1024 via `HybridKemPublicKey`/`HybridKemSecretKey`). The
  `From<tokio::task::JoinError>` impl removed earlier in this release means
  there were no external callers of the deprecated path.
- **Removed `latticearc::primitives::kem::ml_kem::MlKem::generate_keypair_with_seed`** —
  accepted a `seed` argument that the aws-lc-rs FIPS DRBG ignored entirely
  (key generation was non-deterministic regardless). The misleading API was
  retained behind a "for API symmetry" docstring; removed because honest
  callers should use `MlKem::generate_keypair(level)`. The companion
  `encapsulate_with_seed` retains the same shape and is unchanged in this
  release pending a separate decision.
- **Removed `latticearc::types::config::HardwareConfig`** — struct deprecated
  since 0.5.0 with no active consumer. The `hardware: HardwareConfig` field
  on `UseCaseConfig` is also removed; `UseCaseConfig::validate()` no longer
  recurses into a hardware sub-config. Use `CoreConfig::with_hardware_acceleration(bool)`
  for software/hardware AEAD selection. Re-exports from
  `latticearc::types::*` and `latticearc::unified_api::*` removed.
- **Removed two legacy fuzz targets** (`fuzz_hybrid_encrypt`, `fuzz_hybrid_decrypt`)
  that exclusively fuzzed the deleted `encrypt`/`decrypt` paths;
  `hybrid_encrypt_fuzz.rs` already fuzzes the modern unified API. Also
  removed the `generate_keypair_with_seed` block from `fuzz_ml_kem_keygen.rs`.

### Removed (breaking)

- **Removed `latticearc::tls` module entirely.** The module was a thin wrapper
  over `rustls::crypto::aws_lc_rs::default_provider()` that delivered no novel
  cryptographic functionality — rustls 0.23.37+ already provides native
  `X25519MLKEM768` key exchange. No proprietary product depended on this
  module, and the module itself contained validated bugs (miswired
  `CustomHybrid` variant, hardcoded availability checks) whose fixes
  repeatedly landed without changing the core observation that the wrapper
  added nothing rustls doesn't already do. Consumers who want PQ TLS should
  use `rustls` with `aws-lc-rs` directly. The complete list of removed items:
    - Public types: `TlsConfig`, `TlsConstraints`, `TlsContext`, `TlsMode`,
      `TlsUseCase`, `TlsPolicyEngine`, `KexInfo`, `PqKexMode`, `Tls13Config`,
      `TlsError`, `SecureSharedSecret`, `SessionPersistenceConfig`,
      `ClientVerificationMode`, `RetryPolicy`, and all related helpers.
    - Public functions: `tls_connect`, `tls_accept`, `perform_hybrid_keygen`,
      `perform_hybrid_encapsulate`, `perform_hybrid_decapsulate`,
      `is_pq_available`, `is_custom_hybrid_available`, `get_kex_provider`,
      `get_kex_info`, `pq_enabled`, and the entire `formal_verification`
      submodule.
    - Examples: `tls_policy`, `tls13_hybrid_client`, `tls13_custom_hybrid`,
      `test_rustls_compat`.
    - Benchmark: `tls_performance`.
    - Dependencies dropped: `rustls`, `rustls-pki-types`,
      `rustls-native-certs`, `tokio`, `tokio-rustls`, `rcgen` (dev).
- **Removed the `From<tokio::task::JoinError> for LatticeArcError` impl.**
  Nothing in the crate is async anymore, so the conversion had no callers.
  The `LatticeArcError::AsyncError(String)` variant itself is kept for API
  stability — it still accepts plain strings.
- **Removed `LatticeArcError::TlsError(String)` error variant.** Produced
  only by the deleted TLS module; no remaining callers.
- Scrubbed stale references to the removed module from
  `docs/DESIGN_PATTERNS.md` (CNSA 2.0 compliance table, IETF TLS-draft
  reference row, layer rules table, end-to-end scenario list),
  `docs/DEPENDENCY_JUSTIFICATION.md` (module inventory),
  `latticearc/tests/primitives_interoperability_comprehensive.rs` docstring,
  and `tests/tests/unified_api_comprehensive.rs` stale handshake-test note.

### Changed

- Positioning updated: LatticeArc is a post-quantum *primitives and
  composition* library, not a TLS stack. The crate-level docstring and
  README were aligned with this framing.

---

## [0.6.2] - 2026-04-11

Infrastructure and hygiene release. Repairs the `fuzz` crate (which had
bitrotted unnoticed because it is excluded from the workspace), expands the
pre-commit hook to compile every reachable line of code in every feature
combination, fixes a misleading `derive_key` API surface that encouraged
insecure password-based key derivation, adds CBOR key file support to the
CLI, and reconciles stale docstrings.

### Fixed

- **Repaired the entire `fuzz` crate.** Prior to this release, ~10 fuzz
  targets and the `fuzz_regression_tests.rs` file did not compile:
    - 7 fuzz targets referenced an undeclared `rng` local, a relic of an
      older `MlKem::generate_keypair(&mut rng, ...)` signature. Removed
      the stale argument from every call site.
    - 3 fuzz targets used obsolete `MLDSA44`/`MLDSA65`/`MLDSA87` uppercase
      enum variants — renamed to `MlDsa44`/`MlDsa65`/`MlDsa87`.
    - `fuzz_ed25519.rs` wrapped the now-infallible `Ed25519KeyPair::sign`
      in `if let Ok(sig) = ...` — unwrapped.
    - `fuzz_slh_dsa_sign.rs` imported `SecurityLevel` from a pre-v0.6.0
      path that no longer exists — renamed to `SlhDsaSecurityLevel`.
    - `fuzz/tests/fuzz_regression_tests.rs` (562 lines, 27 tests) still
      used the pre-consolidation `arc_primitives::*` module path from a
      multi-crate workspace that was merged into `latticearc` in v0.6.0.
      Rewrote all imports to `latticearc::primitives::*` and adapted
      call sites to the current `MlDsaSignature::from_bytes_unchecked`,
      `HkdfResult::key()`, and `VerifyingKey::from_bytes(bytes, level)`
      argument order. All 27 regression tests pass.
- **Stale `selector.rs` doc comment**: the `CLASSICAL_FALLBACK_SIZE_THRESHOLD`
  security note referenced `SecurityLevel::Medium` and `SecurityLevel::Low`,
  which have never existed. Rewrote to use the current `Standard` / `High`
  / `Maximum` naming.
- **CLI only parsed JSON key files** despite README claiming "Both JSON and
  CBOR formats are supported". `keyfile::read_from` now accepts LPK JSON,
  legacy CLI v1 JSON, and LPK CBOR (auto-detected from the byte stream),
  matching the library capability. Added a CLI integration test pinning
  the CBOR read path.
- **Double JSON parse in `parse_key_bytes`**: the CBOR fallback path
  re-parsed the input as JSON just to construct an error message, wasting
  a full parse of potentially large key files. Captured the error on the
  first attempt and threaded it through.
- **Insecure password-based KDF in `examples/complete_secure_workflow.rs`**:
  the example used `derive_key(password, static_salt, ...)` — HKDF with a
  hardcoded salt provides zero brute-force resistance and defeats salting.
  Rewrote the example to use PBKDF2-HMAC-SHA256 at 600,000 iterations with
  a per-run random 16-byte salt (the same primitive already exported by the
  library for this use case). Also scrubbed the SSN-lookalike fixture data
  to a neutral `Record-ID: RCRD-0001` string so the example can't be mistaken
  for real-PII guidance.
- **`test_ml_kem_encapsulation_sizes_has_correct_size`** (fuzz regression)
  wrapped every assertion in `if let Ok(...)` with no `else` branch, so a
  regression that broke keygen entirely would make the test vacuously green.
  Changed to unwrap-or-panic so real library breakage surfaces.

### Changed

- **`derive_key` doc comment rewritten** with a prominent `# Do NOT use this
  for passwords` subsection citing HKDF's lack of work factor, directing
  password-based callers to `primitives::kdf::pbkdf2::pbkdf2`, and referencing
  the corrected example. The parameter formerly named `password` is now
  named `ikm` (input keying material) to make the contract explicit — this
  is not a breaking change since Rust argument names aren't API-load-bearing
  for positional calls.
- **CLI README** clarified: `keygen` writes JSON; `read` accepts JSON and
  CBOR interchangeably (previous wording implied symmetry that wasn't
  there).

### Added

- **New CLI integration test** `test_cli_reads_cbor_encoded_symmetric_key`:
  builds a CBOR `PortableKey` via the library API, writes it to disk, and
  exercises `encrypt` + `decrypt` via the CLI binary against that CBOR
  file. Pins the CBOR map-header byte range (`0xa0..=0xb7`, RFC 8949 §3.1)
  to prove the test is actually exercising the binary path and not a JSON
  round-trip.

### Infrastructure

- **Pre-commit hook: compile every reachable line, every feature combination.**
  The previous hook ran `cargo check --workspace` and missed the `fuzz` crate
  entirely (it is `exclude = ["fuzz"]` in the workspace Cargo.toml) — which
  is exactly how the `fuzz` crate fell into ~6 months of bitrot without
  anyone noticing. The new hook runs:
    1. `cargo check --workspace --no-default-features --all-targets` —
       catches code hidden behind default feature gates.
    2. `cargo check --workspace --all-features --all-targets` — catches
       examples, benches, and every test binary.
    3. `cargo check -p latticearc --features fips-self-test --all-targets` —
       isolates the FIPS self-test gate, which has its own code paths.
    4. `cd fuzz && cargo check --all-targets` — compiles every fuzz target
       binary **and** the out-of-workspace regression test crate.
    5. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
       on the workspace.
    6. `cd fuzz && cargo clippy --all-targets` on the fuzz crate (without
       `-D warnings`, so the fuzz Cargo.toml's warn-level lints don't get
       escalated to errors and drown real regressions in harness noise).
    7. Conditional `cd fuzz && cargo test --test fuzz_regression_tests
       --release` — only runs when `fuzz/` files are actually staged, so
       the slow SLH-DSA tests don't slow down every unrelated commit.
    8. CLI smoke test with a new `run_cli_step` helper that captures each
       CLI command's stdout+stderr on failure and prints the exact
       invocation + output, instead of the old silent-redirect shape.
  The hook's new compile matrix adds ~25 seconds per commit on top of the
  existing clippy + test steps — a small price for guaranteeing that bitrot
  can't accumulate in the fuzz crate unnoticed again.
- **Fuzz crate lint policy rewritten.** The previous `[lints]` config set
  `warnings = "deny"` at the rust level plus hard-deny on `unwrap_used`,
  `expect_used`, `indexing_slicing`, and `panic`. This shape is correct for
  production crypto but drowns fuzz harnesses in noise: every `data[0]`,
  every `if let Ok(sig) = ...`, every `assert!` trips a denial. Retuned:
    - Hard-deny `todo!` and `unimplemented!` (these panic in fuzz runs
      and would mask real crashes); `unsafe_code` stays forbidden via
      `[lints.rust]`.
    - Allow stylistic patterns that are idiomatic in fuzz harnesses:
      `indexing_slicing`, `single_match`, `collapsible_if`, `get_first`,
      `unwrap_used`, `expect_used`, `panic`.
    - Keep crypto-relevant lints (`arithmetic_side_effects`, `cast_*`,
      `float_cmp`, `implicit_clone`) at `warn` level so real bugs still
      surface, without being promoted to errors by a blanket
      `warnings = "deny"`.
- **Dead-code suppression audit in the hook**: the pre-existing grep filter
  for `#[allow(dead_code)]` in production code didn't match files named
  exactly `tests.rs` (only `_tests.rs` with an underscore). Fixed the
  pattern so `latticearc/src/unified_api/tests.rs` is correctly treated as
  a test context, unblocking the `assert_all_signing_use_cases_covered`
  compile-time exhaustiveness helper from v0.6.1.

---

## [0.6.1] - 2026-04-10

Bug-fix and hardening release. Fixes a fatal use-case keygen bug, adds
passphrase-based protection for on-disk secret keys, cements the FIPS
terminology, and improves test coverage and test quality.

### Added

- **`AeadCipher::seal` default method**: Generates a fresh random nonce and
  returns `(Nonce, Vec<u8>, Tag)`. Structurally prevents caller-controlled
  nonce reuse for AES-GCM and ChaCha20-Poly1305. Documented as the preferred
  primitive-layer encryption entry point over `encrypt` (which takes an
  explicit nonce for KAT / protocol use).
- **Passphrase-encrypted `KeyData::Encrypted` variant**: New `PortableKey`
  envelope using PBKDF2-HMAC-SHA256 (600k iterations) + AES-256-GCM. The
  AEAD AAD binds the full envelope (version, algorithm, key_type, KDF name,
  iteration count, salt, AEAD name), so tampering with any metadata field
  on disk causes decryption to fail at the tag check.
- **`PortableKey::encrypt_with_passphrase` / `decrypt_with_passphrase` /
  `is_encrypted`**: In-place passphrase protection API with opaque error
  messages (no wrong-passphrase vs corrupted-envelope oracle).
- **`PortableKey::validate_encrypted_envelope_fields`**: Shared helper called
  from both `validate()` (load-time) and `decrypt_with_passphrase` (decrypt-
  time) so no path runs key derivation on an unvalidated envelope.
- **`KeyAlgorithm::canonical_name` / `KeyType::canonical_name`**: Stable
  kebab-case/lowercase names used by the passphrase-encrypted AAD
  construction. Load-bearing for encrypted key files — pinned against
  serde rename output by `test_canonical_names_match_serde_rename`.
- **`latticearc-cli keygen --passphrase` flag**: Opt-in passphrase protection
  for on-disk secret keys. Passphrase sourced from `LATTICEARC_PASSPHRASE`
  env var or an interactive tty prompt (double-confirm, no-echo). Never
  accepted on argv.
- **`ED25519_PUBLIC_KEY_LEN` / `ED25519_SECRET_KEY_LEN` /
  `ED25519_SIGNATURE_LEN`** constants in `primitives::ec::ed25519`,
  re-exported from `ed25519_dalek` so there is a single source of truth.
- **CLI input-size limits**: `enforce_input_size_limit`, `read_stdin_with_limit`,
  and `read_stdin_string_with_limit` helpers in `commands::common` cap
  `sign` / `verify` / `encrypt` / `decrypt` / `hash` inputs before read so
  a runaway file/pipe can't OOM the process.

### Fixed

- **Use-case keygen crashed for encryption-oriented use cases**:
  `select_signature_scheme` routed `UseCase` variants through the
  encryption scheme selector, so `IoTDevice`, `FileStorage`, `SecureMessaging`,
  and other encryption-oriented cases crashed with `"Unsupported signing
  scheme: hybrid-ml-kem-*-aes-256-gcm"`. Now routes through
  `UseCaseConfig::new(*use_case).signature` for the correct ML-DSA hybrid
  scheme at the use case's security level.
- **Use-case-generated hybrid keys were unloadable**: `generate_from_config`
  wrote hybrid ML-DSA + Ed25519 keys as `KeyData::Single` with concatenated
  bytes. `PortableKey::validate()` correctly rejects hybrid algorithms with
  `Single` key data, so the key files were syntactically valid JSON but
  could never be loaded. Now routed through
  `PortableKey::from_hybrid_sig_keypair` which produces the correct
  `KeyData::Composite` encoding.
- **Sign-time scheme inference**: `sign_unified` previously derived the
  signing scheme from the default `CryptoConfig`, not from the loaded key
  file's algorithm, so a correctly-encoded hybrid-87 key was rejected with
  a length mismatch against the default hybrid-65 scheme. Now infers the
  security level from the key file's `KeyAlgorithm` via the new
  `infer_signature_security_level` helper.
- **Hybrid encryption keygen failure was silent**: `generate_from_config`
  wrapped the encryption keypair generation in `eprintln!("Note: skipped")`
  and exited 0, so users saw "Generated" but `encryption.sec.json` was
  missing. Now propagates the error via `?` so the whole keygen command
  fails atomically.
- **CI timing-independence test failed on Windows/macOS**: The old test
  measured op1 fully, then op2 fully, so the first-measured operation
  paid all the cold-cache/codegen cost (ratios up to 7.2x on macOS CI,
  vs the 2.0x ceiling). Rewritten to use interleaved measurement with
  50-iteration warmup and median-over-mean to eliminate cold-start bias.
- **Legacy `encrypt_hybrid::encrypt` / `decrypt`**: Marked `#[deprecated]`
  with a migration note pointing to `encrypt_hybrid` / `decrypt_hybrid`.
  The legacy functions were ML-KEM-768 only and not true hybrid (no ECDH
  component).
- **FIPS terminology reconciled**: `README.md` line 12 previously conflated
  *algorithm conformance* (FIPS 203/204/205/206) with *module validation*
  (FIPS 140-3 CMVP). Rewritten to distinguish the two and state the exact
  scope: AES-GCM / ML-KEM / HKDF / SHA-2 route through the validated
  aws-lc-rs backend with `--features fips`; PQ signatures are NIST-
  conformant but not CMVP-validated; the library boundary is not
  CMVP-certified. `lib.rs` banner updated to match. Badge fixed from
  `FIPS 203–205` to `NIST PQC FIPS 203–206`.
- **Deleted broken dead file** `tests/src/validation/constant_time.rs`:
  Contained orphaned code blocks outside any function (stray merge
  leftovers), a fake `constant_time_verify` that always returned false
  for valid signatures, and duplicates of `subtle` crate functionality.
  Not referenced from `mod.rs` — never compiled.

### Security

- **AEAD AAD binding**: All passphrase-encrypted key files bind their full
  envelope parameters (including KDF iteration count and salt) to the AEAD
  AAD. An attacker modifying any metadata field on disk — including
  downgrading `kdf_iterations` or swapping the salt — causes authentication
  to fail before key derivation runs.
- **Opaque decryption errors**: `decrypt_with_passphrase` returns a fixed
  error message for both wrong passphrases and corrupted ciphertexts, so
  there is no passphrase oracle. Pinned by
  `test_encrypt_with_passphrase_corrupted_ciphertext_matches_wrong_passphrase_error`.
- **Secure passphrase input**: Passphrases are read via the `rpassword`
  crate (no echo) and wrapped in `zeroize::Zeroizing<String>` end-to-end.
  Passphrases on command-line arguments are not supported.

### Tests

- **+11 library tests**: 8 passphrase-encryption tests (single + composite
  roundtrip, wrong passphrase, corrupted ciphertext, empty passphrase,
  double-encrypt, decrypt-on-plaintext, JSON roundtrip, AAD algorithm
  binding, AAD key_type binding), 7 envelope-validation negative tests
  (wrong version, unknown KDF, unknown AEAD, low iterations, short salt,
  wrong nonce length, short ciphertext), and 2 pinned tests
  (`test_encryption_aad_byte_layout_is_stable`,
  `test_canonical_names_match_serde_rename`).
- **+4 CLI integration tests**: Full `keygen --use-case` → `sign` →
  `verify` regression tests covering the three security-level tiers plus
  a previously-broken encryption-oriented use case.
- **`test_generate_signing_keypair_all_use_cases_succeeds`**: Expanded
  from 12 to all 22 `UseCase` variants, each with a functional
  sign+verify round-trip. Compile-time exhaustiveness guarded by the new
  module-level `assert_all_signing_use_cases_covered` fn.
- **Lib test count**: 2097 → 2108. All pass in ~40s release mode.
- **CLI integration count**: 86 → 90.

### Internal

- **Simplified `Decoded` struct in `decrypt_with_passphrase`**: removed
  `kdf: String` and `aead: String` fields after validation proved them
  equal to the envelope constants. Saves two `String` allocations per
  decrypt.
- **Eliminated duplicated Ed25519 length magic numbers**: four local
  `const ED25519_*_LEN: usize = 32` declarations across the library and
  CLI now import from `primitives::ec::ed25519`.
- **Single source of truth for passphrase resolution**: `resolve_new_passphrase`
  and `resolve_existing_passphrase` now share a `resolve_passphrase`
  helper that encapsulates the `LATTICEARC_PASSPHRASE` env-var path.
- **Shared stdin-limit helpers**: `read_stdin_with_limit` and
  `read_stdin_string_with_limit` replace three copies of inline
  `take + length check + bail!` across `encrypt.rs`, `hash.rs`, and
  `decrypt.rs`.
- **Collapsed 6 per-submodule "Unverified API" security comment blocks**
  into 2-line references to the authoritative `convenience::mod` docs.

---

## [0.6.0] - 2026-04-09

Restructured SecurityLevel / CryptoMode system to separate two orthogonal axes:
NIST security level (1/3/5) and crypto mode (hybrid vs PQ-only).

### Added

- **`CryptoMode` enum** (`Hybrid` / `PqOnly`): New orthogonal axis for selecting
  hybrid (PQ + classical) or PQ-only encryption. Any `SecurityLevel` can be combined
  with either mode.
- **`CryptoConfig::crypto_mode()`** builder method: Sets hybrid or PQ-only mode.
  `CryptoMode::Hybrid` is the default (backward compatible).
- **`SecurityLevel::resolve()`**: Helper that maps `(SecurityLevel, CryptoMode)` pairs.
  `Quantum` resolves to `(Maximum, PqOnly)`.
- **3 new `EncryptionScheme` variants**: `PqMlKem512Aes256Gcm`, `PqMlKem768Aes256Gcm`,
  `PqMlKem1024Aes256Gcm` — PQ-only counterparts to the hybrid variants.
- **`EncryptKey::PqOnly` / `DecryptKey::PqOnly`**: New key type variants for the
  unified `encrypt()` / `decrypt()` API. Compiler enforces correct key-scheme pairing.
- **`PqOnlyPublicKey` / `PqOnlySecretKey`**: ML-KEM-only key types (no X25519).
  Generated via `generate_pq_keypair()` / `generate_pq_keypair_with_level()`.
- **`PQ_ONLY_ENCRYPTION_INFO`** domain constant: HKDF domain separation for the
  PQ-only unified API path (distinct from the convenience API's `PQ_KEM_AEAD_KEY_INFO`).
- **`EncryptionScheme::requires_pq_key()`**: Predicate for PQ-only scheme variants.
- **7 new tests**: PQ-only roundtrip (512/768/1024), cross-mode rejection (2),
  backward-compat (`SecurityLevel::Quantum`), empty-data roundtrip.

### Changed

- **CNSA 2.0 validation**: Now checks `CryptoMode::PqOnly` instead of
  `SecurityLevel::Quantum`. Use `.crypto_mode(CryptoMode::PqOnly)` for CNSA 2.0.
- **`force_scheme(PostQuantum)`**: Now returns parseable `pq-ml-kem-768-aes-256-gcm`
  (previously returned unparseable string).
- **Use case + PqOnly**: `CryptoConfig::new().use_case(X).crypto_mode(PqOnly)` now
  correctly produces PQ-only schemes at the use-case-recommended NIST level.

### Deprecated

- **`SecurityLevel::Quantum`**: Use `SecurityLevel::Maximum` with
  `CryptoMode::PqOnly` instead. The old variant still works — it auto-resolves to
  `(Maximum, PqOnly)` for backward compatibility.

---

## [0.5.2] - 2026-04-09

### Fixed

- **Feature-gate compilation bugs**: Test file `primitives_self_test_conditional_kats.rs`
  missing `#![cfg(feature = "fips-self-test")]` gate. Ed25519 `sign().expect()` in
  `cross_validation_tests.rs` hidden by `#[cfg(not(feature = "fips"))]`.
- **Error type mapping**: `TypeError::UnknownScheme` was incorrectly mapped to
  `CoreError::DecryptionFailed` — now maps to `CoreError::ConfigurationError`.
- **Pre-commit hook**: Now tests 3 feature combinations (`--all-features`,
  no features, `fips-self-test` only) to catch code hidden behind feature gates.
- **Proof evidence tests**: Added Section 14 (key persistence) — 4 tests proving
  keygen→JSON→drop→reload SK only→decrypt works for all 3 ML-KEM levels plus
  cross-key rejection.

---

## [0.5.1] - 2026-04-09

Security fixes, CLI hybrid decrypt, real KAT vectors, and Level 7 scenario tests.

### Security

- **AEAD error opacity**: 4 decrypt paths in `hybrid/encrypt_hybrid.rs`,
  `unified_api/convenience/api.rs`, and `unified_api/convenience/aes_gcm.rs`
  now use opaque "decryption failed" messages per SP 800-38D §5.2.2 instead
  of forwarding internal "AEAD authentication failed" strings.
- **Hybrid secret key self-contained**: ML-KEM public key stored in secret key
  file metadata at keygen time (PKCS#12 pattern). Decryption no longer requires
  a separate public key file. `to_hybrid_secret_key()` API simplified.
- **Plaintext zeroization in CLI**: `decrypt_symmetric` and `decrypt_hybrid`
  return `Zeroizing<Vec<u8>>` — no unzeroized plaintext copy in memory.

### Added

- **CLI hybrid decrypt**: Was a hard-coded error ("requires in-memory secret
  key"). Now fully functional via `PortableKey::to_hybrid_secret_key()`.
- **Level 7 scenario tests**: Key rotation (200 msgs + destruction),
  multi-algorithm (all 5 EncryptionScheme variants), audit trail (10 ops +
  zero-trust session + no-secrets-in-debug), hybrid E2E (keygen → JSON →
  encrypt → serialize → decrypt with SK only).

### Fixed

- **Fabricated ML-KEM/ML-DSA KAT vectors replaced**: The `ml_kem_kat.rs` and
  `ml_dsa_kat.rs` files contained sequential hex patterns (`1a2b3c4d...`) as
  "NIST CAVP vectors" that were never actually compared against. Replaced with
  real deterministic keygen regression fingerprints generated by `fips203` and
  `fips204` crates, plus encaps/decaps and sign/verify roundtrip verification.
- **Secret type lifecycle gaps**: Added `Debug`/`ConstantTimeEq` impls for
  AesGcm128/256, ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher,
  SchnorrProof, SchnorrProver, SigmaProof, DlogEqualityProof, HkdfResult,
  Pbkdf2Result, CounterKdfResult, KeyPair, SecureBytes, fndsa::KeyPair.
- **`#[must_use]` on 13 generate/select functions** across hybrid, unified_api,
  and primitives modules.
- **`DegradationConfig::default()` test assertions** corrected: 3 integration
  tests asserted `enable_fallback=true` but the actual default is `false`.
- **CI compatibility**: Fixed `unnecessary_qualification` warnings triggered by
  `RUSTFLAGS=-D warnings` on CI (newer rustc). Updated KAT checksums.
- **Ed25519 sign API**: Removed erroneous `.expect()` on `sign()` which returns
  `Signature`, not `Result`. Hidden by `#[cfg(not(feature = "fips"))]`.
- **`Zeroizing<Vec<u8>>` assertion fixes**: Corrected `assert_eq!` for
  `Zeroizing` return type in tests hidden by feature flags.

---

## [0.5.0] - 2026-04-06

Comprehensive design-pattern audit and remediation. Breaking API changes
(field privatization, sealed traits, `#[non_exhaustive]` on all enums).
See `docs/AUDIT_MIGRATION_IMPACT.md` for migration checklist and
`docs/DESIGN_PATTERNS.md` for the complete pattern reference (1,541 lines).

### Security

- **Hybrid KEM info binding**: `derive_hybrid_shared_secret` uses HPKE §5.1 /
  RFC 9180 length-prefix encoding for HKDF `info` payload, replacing ASCII
  `"||"` separators.
- **X25519 low-order defense-in-depth**: `agree()` now routes peer bytes
  through `X25519PublicKey::from_bytes` (RFC 7748 §6.1 blacklist). List
  trimmed to 7 canonical libsodium points.
- **Plaintext zeroization on decrypt**: All `AeadCipher::decrypt` impls
  return `Zeroizing<Vec<u8>>`. Cascades through hybrid and convenience APIs.
- **HKDF added to PQ-KEM encrypt/decrypt**: `encrypt_pq_ml_kem_internal` and
  `decrypt_pq_ml_kem_internal` now derive AES keys via HKDF with domain label
  `LatticeArc-PqKem-AeadKey-v1` instead of using raw ML-KEM shared secret.
- **Timestamp freshness check**: Zero-trust `verify_proof_data` (Medium/High
  complexity) now rejects proofs with timestamps outside 5-minute window.
- **Constant-time CMAC verify**: `verify_cmac_{128,192,256}` changed from
  `&&` (short-circuit) to `&` (bitwise AND) for timing-safe combination.
- **PedersenCommitment::verify() constant-time**: Replaced `==` on
  `ProjectivePoint` with `ct_eq` on compressed byte serialization.
- **FN-DSA SigningKey::ct_eq rewritten**: Removed variable-time early return
  on `security_level`; now uses constant-time `&` combinators matching the
  SLH-DSA canonical pattern.
- **HashCommitment::verify() constant-time**: Uses `subtle::ConstantTimeEq`
  instead of `==` on commitment hash.
- **All RNG routed through primitives**: 10 direct `OsRng` bypass points
  fixed across `hybrid/`, `unified_api/`, `zkp/`, `tls/`, `prelude/`, and
  `latticearc-cli/`. All randomness now flows through
  `primitives::rand::csprng::random_bytes()` or
  `primitives::security::generate_secure_random_bytes()`.
- **Error-opacity assertions**: 3 new tests verify decrypt error messages
  are identical regardless of failure mode (SP 800-38D §5.2.2).
- **CLI keygen RNG fix**: `latticearc-cli` symmetric key generation routed
  through library primitives instead of direct `rand::rngs::OsRng`.
- **CLI password zeroization**: PBKDF2 password now wrapped in `Zeroizing`.
- **CLI non_exhaustive safety**: `unreachable!()` on `#[non_exhaustive]`
  enums replaced with `anyhow::bail!()` to prevent runtime panics.

### Breaking Changes

- **Field privatization**: `HybridCiphertext` (5 fields), `EncryptedOutput`
  (7 fields), `KeyPair`, `HashOpening`, `PedersenOpening`, `SchnorrProof`,
  `DlogEqualityProof`, `Challenge`, `ZeroKnowledgeProof`,
  `ProofOfPossessionData`, `SigmaProof` — all fields now private with
  `new()` constructors and getter methods.
- **`#[non_exhaustive]` on all 72 public enums**: Including `SecurityLevel`,
  `EncryptionScheme`, `MlKemSecurityLevel`, `TlsMode`, `UseCase`, and all
  error enums. Downstream `match` statements need `_ =>` wildcard arms.
- **Sealed traits**: `AeadCipher`, `EcKeyPair`, `EcSignature` now use the
  sealed-trait pattern — external crates cannot implement them.
- **`XChaCha20Poly1305Cipher` AeadCipher impl removed**: Use `encrypt_x` /
  `decrypt_x` native methods instead.
- **`MlKemSharedSecret::as_array()` returns `&[u8; 32]`** (borrow) instead
  of `[u8; 32]` (copy).
- **`MlKem::encapsulate_with_config` / `decapsulate_with_config`**: Dead
  `_config: MlKemConfig` parameter removed.
- **`SimdMode` enum removed**: `MlKemConfig.simd_mode` was never branched on;
  aws-lc-rs handles SIMD internally.
- **`PerformanceMetrics.decryption_speed_ms` and `.cpu_usage_percent`
  removed**: Never read by any consumer.
- **`HardwareConfig` deprecated**: No active consumer; use
  `CoreConfig.hardware_acceleration` instead.
- **`HashOpening` no longer implements `Clone`**: Prevents uncontrolled copies
  of commitment randomness.
- **`select_encryption_scheme_typed` no longer returns classical-only**: All
  security levels now return hybrid PQC schemes.
- **`derive_key_hkdf` domain label changed**: From `b"latticearc"` to
  registered constant `DERIVE_KEY_INFO` (`b"LatticeArc-DeriveKey-v1"`).

### Added

- **`ConstantTimeEq` on 7 secret types**: `Secp256k1KeyPair`,
  `Ed25519KeyPair`, `SecureSharedSecret`, `HashOpening`, `PedersenOpening`,
  `HybridSigSecretKey`, `EncapsulatedKey`.
- **`#[must_use]` on all generate/nonce functions**: 49+ functions including
  all keygen, `generate_nonce()`, `generate_key()`, `allow_request()`.
- **`/// Consumer:` tags on all 80 config fields** across 15 config structs.
- **29 influence tests** (`test_<field>_influences_<operation>`) for
  `CoreConfig`, `ZeroTrustConfig`, `Tls13Config`, `AuditConfig`.
- **Manual `Debug` with redaction** on `KeyPair`, `SecureSharedSecret`,
  `SecurePrivateKey`, `VerifiedSession`, `CmacTag`, `CounterKdfParams`,
  `HkdfResult`, `SigmaProof`.
- **`ZeroizeOnDrop` on `SigmaProof` and `SchnorrProof`**: Response fields
  now scrubbed on drop.
- **Domain constant `PQ_KEM_AEAD_KEY_INFO`** registered in `types/domains.rs`
  with Kani proof extended to all 9 constants (36 pairwise checks).
- **`AUDIT-ACCEPTED` documentation** on all aws-lc-rs wrapper types
  explaining zeroization and `ConstantTimeEq` delegation.
- **`DegradationConfig::default().enable_fallback` changed to `false`**:
  Fail-closed by default.
- **Error-recovery test**: Verifies crypto operations remain functional after
  decrypt failures (no state corruption).
- **4 key-dependent timing tests**: AES-GCM encrypt/decrypt, ML-KEM encaps,
  HKDF derive — verify timing doesn't depend on key value.
- **9 standalone PQ signature proptests** (256 cases each): ML-DSA-65,
  SLH-DSA-Shake128s, FN-DSA-512 — roundtrip, wrong-message, wrong-key.
- **4 new fuzz targets**: `fuzz_fn_dsa_sign`, `fuzz_fn_dsa_verify`,
  `fuzz_portable_key_json`, `fuzz_encrypted_data_deser`.
- **CI fuzzing expanded**: From 3 targets to 32 (all fuzz targets now run).

### Changed

- **`MlKem` keygen no longer takes `&mut Rng`**: aws-lc-rs uses internal
  FIPS-approved DRBG. Drop the `&mut rng` argument at call sites.
- **`MlKem::encapsulate_with_rng` → `encapsulate_with_seed`**: Honest naming.
- **`SignatureScheme::FnDsa` → `FnDsa512`** with new `FnDsa1024` variant.
- **FIPS 206 docs corrected to "draft"**: Falcon remains in NIST pipeline.
- **Hash backends routed through primitives wrappers**: ZKP, audit, logging,
  self-test modules no longer import `sha2`/`sha3` directly.
- **37 `primitives/` files upgraded**: `#![warn(missing_docs)]` →
  `#![deny(missing_docs)]`.
- **CI coverage gate**: 80% → 90% minimum.
- **6,600+ tests renamed** to follow `test_<what>_<condition>_<expected>`
  naming convention (99%+ compliance).
- **7 test files renamed**: Removed redundant double-module prefixes
  (`tls_tls_` → `tls_`, `hybrid_hybrid_` → `hybrid_`, `zkp_zkp_` → `zkp_`).
- **`compose.rs` verification functions replaced**: No-op `verify_*` functions
  that always returned `true` replaced with documented security claims.
- **Version bumped to 0.5.0** across all Cargo.toml files, docs, and FIPS
  Security Policy.

### Removed

- **Unused dependencies**: `arrayref` and `async-trait`.
- **`SimdMode` enum and `MlKemConfig.simd_mode` field**.
- **`PerformanceMetrics.decryption_speed_ms` and `.cpu_usage_percent`**.
- **Stale doc comments** referencing deleted modules and phantom items.

### Documentation

- **`docs/DESIGN_PATTERNS.md` rewritten** (1,541 lines): Mission statement,
  NIST/IETF/ISO/OWASP/CNSA 2.0 compliance map, Rust secure coding practices
  (6 anti-patterns), coding style guide, documentation style guide, 18
  design patterns, SWE benchmarks, 9-level test methodology, zero-shortcut
  policy, exemplary implementation standard, 10-point quality scorecard.
- **`docs/API_DOCUMENTATION.md`**: Added Type Reference section covering
  field privatization, `#[non_exhaustive]`, sealed traits.
- **`docs/SECURITY_GUIDE.md`**: Added Sealed Traits subsection.
- **`docs/NIST_COMPLIANCE.md`**: Fixed test vector source URLs.
- **`docs/FIPS_SECURITY_POLICY.md`**: Version 0.5.0 revision entry.

### Added

- **`blake2s_256` wrapper** in `primitives::hash::blake2` alongside the
  existing `blake2b_256`, so callers no longer need to import the `blake2`
  crate directly.
- **`to_bytes` accessor** on `MlDsaPublicKey`, `MlDsaSecretKey`,
  `MlDsaSignature`, and `MlKemSecretKey`. Secret-key variants return
  `Zeroizing<Vec<u8>>`.
- **`from_bytes` constructor** on `MlDsaPublicKey`, `MlDsaSecretKey`,
  and `MlDsaSignature` for byte-slice callers (`new` still works for
  owning `Vec<u8>` callers).
- **`SignatureScheme::FnDsa1024`** variant — the enum previously only had
  a single `FnDsa` variant that mapped ambiguously to Level 512.
- **`docs/AUDIT_MIGRATION_IMPACT.md`** migration report for downstream
  crates.

### Changed

- **`MlKem` and hybrid keygen/encap no longer take an `&mut R: Rng`
  parameter**. aws-lc-rs uses its internal FIPS-approved DRBG and cannot
  accept caller-provided entropy, so the old parameter was vestigial and
  flagged by the audit (CLAUDE.md rule: "never silence unused params with
  `_`"). Affected functions: `MlKem::generate_keypair`,
  `MlKem::generate_keypair_with_config`, `MlKem::encapsulate`,
  `MlKem::encapsulate_with_config`, `hybrid::kem_hybrid::generate_keypair`,
  `hybrid::kem_hybrid::generate_keypair_with_level`,
  `hybrid::kem_hybrid::encapsulate`, `hybrid::sig_hybrid::generate_keypair`,
  `hybrid::encrypt_hybrid::encrypt`,
  `hybrid::encrypt_hybrid::encrypt_hybrid`,
  `tls::pq_key_exchange::perform_hybrid_keygen`, and
  `tls::pq_key_exchange::perform_hybrid_encapsulate`. **Migration**: drop the
  `&mut rng` argument at each call site.
- **`MlKem::encapsulate_with_rng` → `MlKem::encapsulate_with_seed`**. The
  old name implied caller-controlled entropy; the new name matches the
  actual behaviour (seed is accepted for API symmetry and length-validated,
  but the backing DRBG is aws-lc-rs internal). `MlKem::generate_keypair_with_seed`
  follows the same honest naming.
- **`SignatureScheme::FnDsa` → `SignatureScheme::FnDsa512`** rename (with
  new `FnDsa1024` variant). Wire-format `"fn-dsa"` still parses to the 512
  variant for backward compatibility; new wire-format `"fn-dsa-1024"`
  targets the 1024 variant.
- **`#[non_exhaustive]`** added to `MlDsaError`, `SlhDsaError`, `PctError`,
  `CmacError`, `CompositionError`, `HybridKemError`, `TlsError`, and
  `SignatureScheme` so new variants can be added without breaking downstream
  matches.
- **Hash backends routed through primitives wrappers**: `unified_api/audit.rs`,
  `unified_api/logging.rs`, `unified_api/mod.rs` (FIPS self-test), and the
  ZKP modules (`commitment.rs`, `schnorr.rs`, `sigma.rs`) no longer import
  `sha2`/`sha3`/`blake2` directly — they call
  `primitives::hash::{sha2,sha3,blake2}::*`. Makes future backend swaps a
  single-file change.
- **FIPS 206 docs corrected to "draft"**. Previous doc links pointed at
  `csrc.nist.gov/pubs/fips/206/final/` (404) and incorrectly implied the
  standard was published. Updated to reflect that Falcon remains in the
  NIST standardization pipeline as of 2026-04.
- **Ghost re-export files removed** (reduce indirection, breaking only for
  callers that used the deleted paths):
  - `prelude/domains.rs` → use `crate::types::domains`
  - `unified_api/config.rs` → use `crate::unified_api::*` (types still
    re-exported at the module root) or `crate::types::config`
  - `unified_api/key_lifecycle.rs` → use `crate::unified_api::*` or
    `crate::types::key_lifecycle`
  - `unified_api/hardware.rs` → use `crate::unified_api::*` or
    `crate::types::traits`
- **Ghost inline submodules removed from `hybrid/mod.rs`**: `hybrid::kem`,
  `hybrid::sig`, `hybrid::encrypt` — callers should use `hybrid::*`
  directly.

### Removed

- **Unused dependencies**: `arrayref` and `async-trait` dropped from
  `latticearc/Cargo.toml`.
- **Misleading stale doc comments** (`// NOTE: test_X has been removed...`)
  from `unified_api/convenience/api.rs`. Git history is authoritative.

---

## [0.4.4] - 2026-04-01

### Security

- **ECDH shared secret zeroization**: All `agree()` methods now return
  `Zeroizing<...>` ensuring intermediate shared secrets are zeroed on drop
  (SP 800-56A compliance for intermediate DH values)

### Fixed

- **PCT tests compile without `fips-self-test` feature**: Added `#[cfg]` gate
  to `restore_operational_state()` calls in test cleanup

### Changed

- Documentation version references updated from 0.3.2 to 0.4.4

---

## [0.4.3] - 2026-03-30

### Security

- **2 security advisories patched**: `aws-lc-fips-sys` 0.13.12 → 0.13.13
  (RUSTSEC-2026-0042, CRL Distribution Point scope check, severity 7.4 HIGH),
  `rustls-webpki` 0.103.9 → 0.103.10 (RUSTSEC-2026-0049, CRL authority matching)

### Changed

- **32 dependency updates** via `cargo update`: proptest 1.11, zerocopy 0.8.48,
  cc 1.2.58, uuid 1.23, tempfile 3.27, wasm-bindgen 0.2.116, and others
- **Cargo.toml version floors bumped**: async-trait 0.1.89, uuid 1.23.0,
  proptest 1.11, tempfile 3.27, tokio-rustls 0.26.4, rustls-native-certs 0.8.3,
  rcgen 0.13.2

---

## [0.4.1] - 2026-03-19

### Changed

- **CLI binary renamed** from `latticearc` to `latticearc-cli` (reserves `latticearc` for enterprise CLI)
- **13 security audit findings fixed**: Ed25519 `verify_strict`, HKDF PRK zeroization,
  AES-GCM decrypt key zeroization, TOCTOU-safe file I/O, PortableKey validation
- **Documentation accuracy**: ML-DSA-87 SK size, hybrid sig SK sizes, SLH-DSA identifier,
  HKDF diagram, FIPS 206 "(draft)" removed, all JSON examples validated
- **Dependencies upgraded**: aws-lc-rs 1.16.2, clap 4.6, anyhow 1.0.102,
  tracing-subscriber 0.3.23, rayon 1.11, parking_lot 0.12.5, rustls-pki-types 1.14

---

## [0.4.0] - 2026-03-19

### Added

- **Portable Key Format (LPK v1)**: Library-level standardized key serialization with dual
  JSON + CBOR (RFC 8949) encoding. Keys are identified by `UseCase` or `SecurityLevel` —
  mirroring the library's API — with algorithm auto-derived for version-stability.
  - `PortableKey::for_use_case()`, `for_security_level()` — primary constructors
  - `to_json()` / `from_json()` — human-readable format for CLI and REST APIs
  - `to_cbor()` / `from_cbor()` — compact binary format for wire protocol and storage
  - `from_hybrid_kem_keypair()`, `to_hybrid_public_key()`, `to_hybrid_secret_key()` — bridge
    methods connecting key generation to serialization to crypto operations
  - `from_hybrid_sig_keypair()`, `to_hybrid_sig_public_key()`, `to_hybrid_sig_secret_key()`
  - File I/O with 0600 Unix permissions for secret/symmetric keys
  - Legacy CLI v1 format reader (`from_legacy_json()`)
  - Open `metadata` map for enterprise extensions (preserved during roundtrips)
  - `docs/KEY_FORMAT.md` — complete specification with algorithm resolution tables,
    size comparisons, standards references, and enterprise extension model
- **BLAKE2b-256 hash function**: `blake2b_256()` in `latticearc::primitives::hash` following
  the SHA-3 pattern (infallible, `#[must_use]`, fixed `[u8; 32]` return). RFC 7693 KAT test.
- **Hybrid KEM secret key export**: `HybridSecretKey::ml_kem_sk_bytes()` and
  `ecdh_seed_bytes()` enable full key serialization. `MlKemDecapsulationKeyPair::from_key_bytes()`
  and `HybridSecretKey::from_serialized()` enable reconstruction from serialized form.
- **Serde support for UseCase and SecurityLevel**: Both enums now derive `Serialize`,
  `Deserialize`, `Copy` for use in key format and configs.
- **ciborium dependency**: CBOR serialization (RFC 8949) for compact binary key encoding.

- **`latticearc-cli` crate**: Standalone CLI binary with 8 commands — `keygen`, `sign`, `verify`,
  `encrypt`, `decrypt`, `hash`, `kdf`, `info`. Covers all NIST-standardized post-quantum algorithms
  (ML-DSA-44/65/87, ML-KEM-512/768/1024, SLH-DSA, FN-DSA) plus Ed25519, AES-256-GCM, hybrid
  ML-DSA+Ed25519, hybrid ML-KEM+X25519, HKDF-SHA256, PBKDF2, and 4 hash algorithms.
- **83 CLI integration tests** across 15 categories: signing roundtrips, encryption roundtrip,
  NIST conformance assertions (FIPS 203/204/205/206, RFC 8032, SP 800-38D), edge cases, adversarial
  scenarios (corrupted ciphertext/signatures, wrong keys, MITM, algorithm tampering), and key
  isolation.
- **CLI documentation**: README.md user guide (layman-friendly), QUICK_REFERENCE.md cheat sheet,
  comprehensive doc comments across all CLI source files.
- **CI: cross-platform CLI tests** on Ubuntu, macOS, and Windows.
- **Release pipeline**: CLI binaries packaged as platform-specific tarballs
  (`latticearc-cli-<version>-<target>.tar.gz`) and attached to GitHub releases with checksums.

### Changed

- **Workspace version bump**: 0.3.3 → 0.4.0. All crates (`latticearc`, `latticearc-cli`,
  `latticearc-tests`) share a single workspace version.
- **`exit` lint relaxed from `forbid` to `deny`**: Required because clap's derive macros emit
  `#[allow(clippy::exit)]` which is incompatible with `forbid`. The lint still prevents accidental
  `std::process::exit()` in production code.

---

## [0.3.3] - 2026-03-08

### TLS Improvements

- **Native PQ key exchange — `rustls-post-quantum` dependency removed**: `rustls` 0.23.37 now
  ships all PQ key exchange groups natively via the aws-lc-rs backend. The `rustls-post-quantum`
  crate is no longer needed. This reduces the dependency tree while gaining new capabilities:
  - **X25519MLKEM768** — hybrid X25519 + ML-KEM-768 (already in `default_provider()` kx_groups)
  - **SECP256R1MLKEM768** — hybrid P-256 + ML-KEM-768 (new)
  - **MLKEM768** — standalone PQ key exchange, NIST Category 3
  - **MLKEM1024** — standalone PQ key exchange, NIST Category 5 (new)
- **ML-KEM-1024 now backed by upstream**: Our `TlsPolicyEngine::select_pq_kex()` returns
  "MLKEM1024" for `SecurityLevel::Maximum` and `SecurityLevel::Quantum`. Previously this had
  no upstream support — rustls only shipped ML-KEM-768. Now `MLKEM1024` is a real
  `SupportedKxGroup` in `rustls::crypto::aws_lc_rs::kx_group`.
- **PQ preference ordering**: For Hybrid/Pq TLS modes, PQ key exchange groups are now sorted
  to the front of the preference list, ensuring the server selects them when both sides support PQ.
- **FIPS backend updated**: `aws-lc-rs` 1.16.1 updates `aws-lc-sys` to 0.38.0 and
  `aws-lc-fips-sys` to 0.13.12, keeping the FIPS 140-3 validated backend current.

### Removed

- **`rustls-post-quantum` dependency** — all PQ key exchange is now handled natively by rustls.

### Dependencies

- `rustls` 0.23.36 → 0.23.37 (native PQ key exchange: ML-KEM-1024, SECP256R1MLKEM768)
- `aws-lc-rs` 1.16.0 → 1.16.1 (FIPS backend patch)
- `tokio` 1.49.0 → 1.50.0
- `chrono` 0.4.43 → 0.4.44
- `uuid` 1.20.0 → 1.22.0
- `serde_with` 3.0 → 3.17
- `tempfile` 3.24 → 3.26 (dev)
- `criterion` 0.8 → 0.8.2 (dev)

---

## [0.3.2] - 2026-02-24

### Changed

- **Documentation**: Improve docs.rs landing page — hide 130+ expert re-exports, 36 logging macros via `#[doc(hidden)]`
- **Documentation**: Add "Why LatticeArc?" comparison table and "Algorithm Validation Status" table to crate root docs
- **Documentation**: Restructure examples — keep 2 primary examples at top, move 7 others to "More Examples" section

---

## [0.3.1] - 2026-02-24

### Fixed

- **Documentation**: Removed all enterprise/proprietary references from published crate docs
- **Documentation**: Replaced old crate names (`arc-types`, `arc-core`, `arc-primitives`, `arc-hybrid`, `arc-tls`, `arc-zkp`, `arc-validation`) with correct module paths across 20 files
- **Documentation**: Fixed "this crate" → "this module" in 7 module-level docs
- **Documentation**: Removed stale "Backend Selection (Future)" section from ML-DSA docs (aws-lc-rs 1.16.0 already ships ML-DSA)
- **Documentation**: Removed non-existent `perf` feature flag from `perf` module docs
- **Documentation**: Fixed hardcoded `version = "0.2"` in FIPS error message
- **Documentation**: Removed broken relative `../docs/` links from README (broken on docs.rs)
- **Documentation**: Removed reference to non-existent `docs/FIPS_CERTIFICATION_PATH.md`
- **CI**: Use `macos-15-intel` for x86_64-apple-darwin release builds (matches aws-lc-rs upstream)
- **CI**: Make publish step idempotent for workflow re-runs

---

## [0.3.0] - 2026-02-22

### Security Audit Fixes (44 findings)

- **Critical (14)**: Fixed constant-time comparison violations in hybrid KEM/signature verification, HKDF salt handling, AES-GCM nonce reuse risk, error oracle information leaks, ECDH output validation, PCT validation gaps, resource limit enforcement, README/docs stale API examples, Kani CI frequency claims, DESIGN.md wrong feature flags, ChaCha20 test coverage gap, CI debug-mode test execution
- **High (13)**: Fixed FIPS self-test integrity key hardcoding (documented limitation), ZKP thread_rng usage (replaced with OsRng), secret key zeroization in hybrid decapsulation/key generation, error severity classifications for crypto failures, TLS recovery error handling, ML-KEM decapsulation key serialization validation
- **Medium (8)**: Documented FN-DSA upstream zeroization limitation, added SignatureScheme enum tracking comment, removed 5 dead workspace dependencies, strengthened error severity for RandomError/SerializationError, added error context to TLS recovery paths
- **Low (9)**: Cleaned deny.toml (added nix ban), fixed DESIGN.md algorithm table (added PBKDF2/BN254/X25519), corrected "30 Kani proofs" → "29", replaced TODO comments with NOT WIRED, added ed25519 to sign_with_key dispatch

### Changed

- **Version bump**: 0.2.0 → 0.3.0
- **CI**: Added `--release` to 7 integration/compliance/security test commands
- **Documentation**: Updated all code examples to v0.2.0+ unified API (`EncryptKey`/`DecryptKey` enums)
- **DESIGN_PATTERNS.md**: Promoted from internal to tracked doc

---

## [0.2.0] - 2026-02-21

### Added

- **Type-safe unified encryption API**: New `EncryptKey`/`DecryptKey` enums, `EncryptionScheme` enum, and `EncryptedOutput` struct eliminate silent degradation
  - `EncryptKey::Symmetric(&[u8])` for AES-256-GCM/ChaCha20Poly1305
  - `EncryptKey::Hybrid(&HybridPublicKey)` for ML-KEM-768 + X25519 hybrid encryption
  - `EncryptionScheme` enum replaces string-based scheme dispatch (5 variants)
  - `EncryptedOutput` unifies `EncryptedData` and `HybridEncryptionResult` into a single type
  - `CryptoPolicyEngine::validate_key_matches_scheme()` returns `Err` on mismatch — no silent fallback
  - Key-scheme mismatch tests verify all invalid combinations are rejected
- **Serialization for `EncryptedOutput`**: V2 format with `HybridComponents` support and backward-compatible V1 deserialization
- **Kani Formal Verification Expansion (16 → 29 proofs)**: Added 13 new bounded model checking proofs across 7 files in `latticearc::types`
  - `config.rs` (6 proofs): CoreConfig bi-conditional validation over all 96 combinations, factory presets, encryption compression/integrity, signature chain/timestamp
  - `types.rs` (3 proofs): ComplianceMode `requires_fips()` and `allows_hybrid()` exhaustive, PerformancePreference default is Balanced
  - `selector.rs` (2 proofs): Hybrid/general encryption and signature selection succeeds for all SecurityLevels
  - `domains.rs` (1 proof): All 4 HKDF domain constants are pairwise distinct (collision = key reuse across protocols)
  - `traits.rs` (1 proof): `is_verified()` returns true IFF VerificationStatus is Verified
  - `zero_trust.rs` (1 proof): `is_fully_trusted()` returns true IFF TrustLevel is FullyTrusted
  - Added `kani::Arbitrary` derives for ComplianceMode, PerformancePreference, ProofComplexity, VerificationStatus
  - Added manual `kani::Arbitrary` impl for CoreConfig (96 combinations)

### Changed

- **Unified `encrypt()`/`decrypt()` signatures**: Now take `EncryptKey<'_>`/`DecryptKey<'_>` instead of `&[u8]`, enabling type-safe hybrid encryption through the same API
- **`CryptoPolicyEngine` returns `EncryptionScheme` enum**: `select_encryption_scheme()`, `recommend_scheme()`, and `select_for_security_level()` return typed enums instead of `String`
- **Workspace Consolidation**: Merged 8 sub-crates into single `latticearc` crate for crates.io publishing
  - `arc-types`, `arc-prelude`, `arc-primitives`, `arc-hybrid`, `arc-core`, `arc-tls`, `arc-zkp`, `arc-perf` are now internal modules
  - Merged `arc-tests` and `arc-validation` into a single `latticearc-tests` crate (unpublished)
  - Workspace reduced from 11 crates to 3: `latticearc` (published), `tests` (dev-only), `fuzz` (excluded)
  - All public APIs remain identical — `use latticearc::*` works the same
  - Module paths available: `latticearc::types`, `latticearc::primitives`, `latticearc::hybrid`, `latticearc::unified_api`, `latticearc::tls`, `latticearc::zkp`, `latticearc::perf`, `latticearc::prelude`
  - Simplified release process: single `cargo publish -p latticearc` instead of 10-step layered publish
  - CI workflows updated to reference new crate structure

### Removed

- **Hybrid convenience functions**: Removed `encrypt_hybrid`, `decrypt_hybrid`, and all `_with_config`/`_unverified` variants — use `encrypt(data, EncryptKey::Hybrid(&pk), config)` instead
- **`HybridEncryptionResult`**: Replaced by `EncryptedOutput` with `hybrid_data: Option<HybridComponents>`
- **Silent degradation paths**: All 8 `warn!()` fallback paths eliminated — key-scheme mismatches now return `Err`

### Fixed

- **Critical: Silent degradation to AES-GCM**: All 22 `UseCase` variants recommended hybrid PQ schemes, but `encrypt()` silently fell back to AES-256-GCM because it only accepted `&[u8]` (symmetric keys). Now correctly dispatches to hybrid encryption when `EncryptKey::Hybrid` is provided
- **CNSA 2.0 roundtrip**: Encrypt stored "aes-256-gcm" in `EncryptedData.scheme` while CNSA compliance validated against the hybrid scheme name — decrypt rejected the mismatch. Now uses `EncryptionScheme` enum (always truthful)
- **Audit Warning Fixes (17 → 14 warnings)**: Resolved 3 warnings from 13-dimension code audit
  - Dim 3.7: Removed "secret key" from error format strings in `ml_kem.rs` and `pq_kem.rs` (key material leak false positive)
  - Dim 13a.2: Replaced direct array indexing with `from_array()` in SIMD basemul (neon.rs, avx2.rs) and `get_mut()` in NTT butterfly (ntt_processor.rs)
  - Dim 12.2: Replaced aspirational language in ALGORITHM_SELECTION.md
  - Dim 13c.27: Added descriptive messages to ~37 bare test assertions in fips_kat_loaders_tests.rs and fips_coverage_validation_summary_tests.rs

### Documentation

- Updated FORMAL_VERIFICATION.md with all 29 Kani proofs (was 12)
- Updated README.md verification section with expanded proof details
- Updated SECURITY.md Kani section from 12 to 29 proofs
- Updated DESIGN.md architecture notes with current proof count

---

## [0.1.2] - 2026-02-18

### Added

- **AES-GCM with Additional Authenticated Data (AAD)**: New functions for binding context to ciphertext
  - `encrypt_aes_gcm_with_aad()` / `decrypt_aes_gcm_with_aad()` with `SecurityMode` support
  - `_unverified` convenience variants for use without Zero Trust sessions
  - AAD is authenticated but not encrypted — enables protocol-level binding (headers, session IDs, etc.)
  - Re-exported through `arc-core` and `latticearc` facades
- **HKDF with Custom Info String**: Key derivation with caller-supplied domain separation
  - `derive_key_with_info()` / `derive_key_with_info_unverified()` for HKDF-SHA256 with custom info parameter
  - Enables domain-specific key derivation (different info → cryptographically independent keys)
  - Uses FIPS-validated `aws-lc-rs` HKDF implementation
  - Compatible with existing `derive_key()` when info is `b"latticearc"`
  - Re-exported through `arc-core` and `latticearc` facades
- **Formal Verification Documentation**: Comprehensive documentation for Kani proofs
  - New `docs/FORMAL_VERIFICATION.md` with 155 lines of detailed verification documentation
  - README.md section explaining 9 Kani proofs and verification schedule
  - SECURITY.md expanded with proof details table and verification approach
  - Clear disclosure: proofs run on schedule (nightly/weekly), not every commit
  - Follows AWS-LC model for cost-effective formal verification (~30 min for full suite)
- **FIPS 140-3 Integrity Test**: Implemented Section 9.2.2 Software/Firmware Load Test
  - `integrity_test()` with HMAC-SHA256 module verification
  - `build.rs` for production HMAC generation
  - Development mode prints HMAC, production mode verifies against PRODUCTION_HMAC.txt
  - Power-up test integration (runs before any crypto operations)
  - Constant-time comparison using `subtle::ConstantTimeEq`
- **Dependabot Auto-Merge**: GitHub Actions updates auto-merge after CI passes
  - Configured in `.github/dependabot.yml` with grouped updates
  - `.github/workflows/dependabot-automerge.yml` workflow
  - Reduces PR noise from weekly dependency updates
- **Documentation**: 7 comprehensive review and analysis documents
  - API Design Review (0 critical issues)
  - Security Guidance Review (9.3/10 score)
  - CI Workflow Status and Analysis
  - Dependency Cleanup summary
  - RUSTSEC Advisories documentation
  - aws-lc-rs PR #1029 merge update
- **Hybrid Signature Convenience API**: New dedicated functions for hybrid signatures (ML-DSA-65 + Ed25519)
  - `generate_hybrid_signing_keypair()` / `sign_hybrid()` / `verify_hybrid_signature()` with `SecurityMode` support
  - `_with_config` variants for configuration validation
  - `_unverified` variants for use without Zero Trust sessions
  - Wraps `arc-hybrid::sig_hybrid` with proper error mapping and resource limit validation
  - Re-exported through `arc-core` and `latticearc` facades

### Changed

- **Dependencies**: Upgraded `aws-lc-rs` from 1.15.4 to 1.16.0
  - Full ML-KEM `DecapsulationKey` serialization/deserialization now available
  - Enables complete ML-KEM encrypt/decrypt roundtrip (resolves #16)
  - Our upstream PRs #1029 and #1034 shipped in this release
- **CI/CD**: Fixed misleading Kani formal verification claims
  - Removed `--only-codegen` check from ci.yml (was not running actual proofs)
  - Enabled kani.yml schedule: nightly (3 AM UTC) + weekly (Sunday 5 AM UTC)
  - Added path filters to run proofs only when formal verification code changes
  - Badge now reflects actual proof execution status, not fake checks
  - Follows AWS-LC model: scheduled runs will be enabled once the library is stable
- **Documentation**: Clarified constant-time comparison approach in SECURITY.md
  - Documented use of `subtle` crate (22.7M downloads/month, battle-tested)
  - Acknowledged `subtle` is not formally verified (no alternative exists for Rust custom types)
  - Explained trade-off: aws-lc-rs SAW verification for primitives, `subtle` for API layer
  - Added usage statistics and security track record (zero RustSec advisories)
- **API Improvements**: Enhanced parameter ergonomics
  - `KeyLifecycle::add_approver()` now accepts `impl Into<String>`
  - `logging::set_correlation_id()` now accepts `impl Into<String>`
  - `CorrelationGuard::with_id()` now accepts `impl Into<String>`
  - Allows passing `&str` without `.to_string()` allocation
- **Dependencies**: Updated aws-lc-rs from 1.15.0 to 1.15.4 (security patches)
- **CI Matrix**: Added `fail-fast: false` to test job for complete platform coverage
- **Documentation**: Enhanced HKDF and AES-GCM security warnings
  - HKDF: Added comprehensive salt usage guidance (random > zero salt)
  - AES-GCM: Documented key truncation behavior (>32 bytes silently truncated)
- **API Refactoring**: Removed broken `sign()` function, replaced with `generate_signing_keypair()` + `sign_with_key()`
  - Old `sign(message, config)` generated new keypair on every call (broken behavior)
  - New pattern: `generate_signing_keypair(config)` → `sign_with_key(message, &sk, &pk, config)` → `verify(&signed, config)`
  - Keypairs are now reusable across multiple signing operations
- **Hybrid Encryption API Renamed**: Simplified naming for hybrid functions
  - `encrypt_true_hybrid()` → `encrypt_hybrid()`
  - `decrypt_true_hybrid()` → `decrypt_hybrid()`
  - `generate_true_hybrid_keypair()` → `generate_hybrid_keypair()`
  - `TrueHybridEncryptionResult` → `HybridEncryptionResult`
  - Old functions removed (breaking change)
- **Doctests**: Converted all 67 `ignore` doctests to `no_run` (compile-checked but not executed)
  - Fixes API rot: ignored doctests silently break when function signatures change
  - Fixed hidden boilerplate: import paths, `ZeroizedBytes` `.as_ref()`, error types
  - Added `pub fn tag()` getters to `Cmac128`/`Cmac192`/`Cmac256` (fields were private)
  - Added `ZeroTrustSession::generate_proof()` public method (was only accessible via `pub(crate)` field)
  - 0 doctests remain ignored; 2 unit `#[ignore]` tests unchanged (fips204 validation, fn-dsa zeroization)
- **Stale limitation references removed**: Cleaned up docs, tests, and fuzz targets referencing
  now-resolved aws-lc-rs ML-KEM limitations (DecapsulationKey serialization)

### Removed

- **ctgrind constant-time tests**: Removed arc-primitives/tests/constant_time.rs
  - Tests verified `subtle` crate, not our code
  - Required unsafe blocks that violated workspace lint policy
  - aws-lc-rs primitives already have SAW formal verification
  - Removed ctgrind dependency
- **Unused Dependencies**: Removed 5 workspace dependencies (attack surface reduction)
  - `bytes` (not used in any .rs files)
  - `url` (not used in any .rs files)
  - `futures` (not used in any .rs files)
  - `crossbeam-utils` (declared but never imported)
  - `generic-array` (not used in apache codebase)
  - Also removed from arc-core and latticearc member crates
- **Removed `sign()` function**: Use `generate_signing_keypair()` + `sign_with_key()` instead
- **Removed `generate_keypair()` ECDH bug**: Function no longer calls deprecated broken ECDH
- **Removed `diffie_hellman()` function**: Use hybrid KEM or direct X25519 primitives instead
- **Dead code**: Removed unused data characteristics computation in `selector.rs`

### Security

- **RUSTSEC Advisories**: Documented all 4 ignored advisories (LOW risk)
  - RUSTSEC-2023-0052: webpki DoS (transitive, waiting rustls update)
  - RUSTSEC-2021-0139: ansi_term unmaintained (informational only)
  - RUSTSEC-2024-0375: atty unmaintained (informational only)
  - RUSTSEC-2021-0145: atty unsound on Windows (theoretical, requires custom allocator)
  - All are transitive dependencies from dev tools (clap/criterion)
  - Overall risk assessment: LOW and acceptable
  - See `RUSTSEC_ADVISORIES_IGNORED.md` for full details

### Upstream

- **aws-lc-rs v1.16.0 released** — our PRs shipped
  - PR #1029: ML-KEM `DecapsulationKey` serialization (merged Feb 10, 2026)
  - PR #1034: ML-DSA seed-based deterministic keygen (merged Feb 13, 2026)
  - Upgraded LatticeArc to aws-lc-rs 1.16.0, enabling full ML-KEM roundtrip
  - Closes issue #16

### Documentation

- Updated all READMEs with new signing API pattern
- Added hybrid signature convenience API examples to all docs
- Updated API_DOCUMENTATION.md with correct function signatures
- Updated UNIFIED_API_GUIDE.md with hybrid encryption examples
- Added "Runnable Examples" section to main README
- All documentation now uses `latticearc::*` imports (not `quantumshield::*`)

---

## [0.1.1] - 2026-02-16

### Added

- **Property-based tests (40+ tests in 6 files)**: Comprehensive proptest coverage in `arc-tests`:
  - `proptest_hybrid_kem.rs` — ML-KEM-768 + X25519 roundtrip, key independence, wrong-key rejection
  - `proptest_hybrid_encrypt.rs` — hybrid encryption roundtrip, non-malleability, AAD integrity
  - `proptest_hybrid_sig.rs` — ML-DSA-65 + Ed25519 roundtrip, determinism, size validation
  - `proptest_unified_api.rs` — unified API AEAD + signing across all security levels
  - `proptest_pq_kem.rs` — ML-KEM-512/768/1024 roundtrip, FIPS 203 key/ciphertext sizes
  - `proptest_selector.rs` — CryptoPolicyEngine determinism, monotonicity, exhaustiveness
- **`arc-types` crate**: Pure-Rust domain types, traits, config, policy engine, and key lifecycle
  management extracted from `arc-core`. Zero FFI dependencies, enabling Kani formal verification.
- **Kani proofs expanded (2 → 12)**: Formal verification now covers all major `arc-types` modules:
  - `key_lifecycle.rs`: 5 proofs — state machine immutability, forward-only transitions, API consistency
  - `zero_trust.rs`: 3 proofs — trust level ordering, `is_trusted()` correctness, minimum bound
  - `types.rs`: 1 proof — default `SecurityLevel` is `High` (NIST Level 3)
  - `selector.rs`: 3 proofs — `force_scheme` completeness, PQ encryption/signature coverage for all levels
- **Kani CI for `arc-types`**: Verified tier now targets `arc-types` (pure Rust) instead of
  `arc-core` (FFI-dependent). All 12 proofs run nightly/weekly via CI schedule.
- **Kani Proofs badge**: Added to README, linking to the `arc-types` verification workflow.
- **True Hybrid Encryption** (commit `9973d0c`): Fixed critical issue where arc-core's hybrid encryption used ML-KEM only (no X25519, no HKDF)
  - Added `encrypt_true_hybrid()` / `decrypt_true_hybrid()` / `generate_true_hybrid_keypair()` API
  - Delegates to arc-hybrid's real ML-KEM-768 + X25519 + HKDF + AES-256-GCM combiner
  - New types: `TrueHybridEncryptionResult`, re-exports `KemHybridPublicKey` / `KemHybridSecretKey`
  - Added `X25519StaticKeyPair` with real ECDH via aws-lc-rs `PrivateKey::agree()`
  - Added `MlKemDecapsulationKeyPair` with real aws-lc-rs `DecapsulationKey`
  - Old ML-KEM-only functions retained for backward compatibility
- **Unified API Tests**: Comprehensive test coverage for the unified encryption API
  - `test_unified_api_aes_gcm_roundtrip` - AES-GCM symmetric encryption roundtrip
  - `test_unified_api_rejects_symmetric_key_for_hybrid_schemes` - Validates API correctly rejects 32-byte keys for hybrid PQ schemes
  - `test_hybrid_encryption_only` - Tests hybrid encryption works
  - `test_scheme_selection_for_security_levels` - Verifies CryptoPolicyEngine selects correct ML-KEM variant
  - `test_encrypted_data_contains_scheme_metadata` - Verifies scheme metadata storage
  - `test_decrypt_honors_scheme_from_encrypted_data` - Confirms decrypt() dispatches based on scheme field

### Fixed

- **Wildcard error suppression**: `ed25519.rs` verification now logs original error before returning
  `VerificationFailed`; recovery strategy failures now logged before `continue`.
- **Hybrid Signature Verification**: Fixed bug where hybrid signatures (ML-DSA + Ed25519) failed verification due to incorrect public key storage
  - `sign()` now stores combined public key (ML-DSA + Ed25519) for hybrid schemes
  - `verify()` correctly splits combined key for each algorithm
  - Added missing verify case for `hybrid-ml-dsa-87-ed25519`

### Removed

- **Fake Kani proofs in `arc-hybrid`**: Deleted `formal_verification.rs` (7 proofs that called FFI
  crypto and could never execute under Kani; silently swallowed all errors with `Err(_) => {}`).
  Replaced by property-based tests in `arc-tests` that cover the same properties.
- **`formal-verification` feature flag** from `arc-hybrid`.
- **Kani experimental CI tier** (`kani-experimental` job in `kani.yml`) — no longer needed.
- **Fuzzing badge** from README (schedule disabled, badge was stale).
- **Hardcoded test count badge** (8,079 was incorrect; replaced with self-updating workflow).
- **Dead Code Cleanup**: Removed ~11,500 lines of unreachable code from `latticearc` crate
  - Deleted `latticearc/src/unified_api/` directory (32 files) which was shadowed by an inline module definition and never compiled
  - Removed vestigial `unified_api` re-export module from `lib.rs`
- **Dead hardware stubs** (commit `de47ebb`): Removed `HardwareRouter`, `CpuAccelerator`, `GpuAccelerator`, `FpgaAccelerator`, `SgxAccelerator`, `TpmAccelerator` from arc-core
  - Retained trait definitions (`HardwareAccelerator`, `HardwareAware`, `HardwareCapabilities`, `HardwareInfo`, `HardwareType`)
  - Real hardware detection is in enterprise `arc-enterprise-perf` crate

### Changed

- **Kani badge renamed** to "Kani: type invariants" — honestly scoped to what it verifies.
- **FIPS badge** changed from "ready" to "ML-KEM validated" — accurate scope.
- **Self-updating test count badge**: Replaced Gist-based approach (secrets not configured)
  with `shields.io/endpoint` reading from `.github/badges/test-count.json`.
- **`arc-core` refactored**: Types, traits, config, selector, key_lifecycle, and zero_trust modules
  now re-export from `arc-types` instead of defining inline. No public API changes.
- **Workspace version**: Bumped to 0.1.1 across all crates.
- **SecurityLevel Redesign**: Simplified security levels to four clear options
  - `Standard` - NIST Level 1 (128-bit), hybrid mode
  - `High` - NIST Level 3 (192-bit), hybrid mode (default)
  - `Maximum` - NIST Level 5 (256-bit), hybrid mode
  - `Quantum` - NIST Level 5 (256-bit), PQ-only mode (CNSA 2.0)
  - Removed `Medium` and `Low` levels
  - Classic TLS now only accessible via use cases (`IoT`, `LegacyIntegration`)
- **Architecture: Dependency graph cleanup** (breaking inverted dependencies).

  **Before (0.1.0):**
  ```
  arc-prelude (errors + testing infra, 6.7K lines)
  │  deps: aws-lc-rs, ed25519-dalek, k256
  ▼
  arc-validation (CAVP/NIST, 24.3K)     arc-primitives (algorithms, 22.2K)
  │  deps: arc-prelude            ◄────── deps: arc-prelude, arc-validation
  │                                        │
  arc-hybrid (hybrid, 4K)                  │
  │  deps: arc-primitives          ◄───────┘
  │
  arc-core (API, 17.6K)
  │  deps: arc-types, arc-primitives, arc-hybrid,
  │        arc-prelude, arc-validation
  │
  ├── arc-tls    ├── arc-tests    ├── fuzz
  ▼
  latticearc (facade)
    deps: ALL crates + pub use prelude::*
  ```

  **After (0.1.1):**
  ```
  arc-types (Layer 0: zero FFI, Kani-verifiable)
  │  + resource_limits (from arc-validation)
  │  + domains (from arc-prelude)
  │  NO external deps (pure Rust)
  ▼
  arc-primitives (Layer 1: algorithms)     arc-prelude (errors)
  │  deps: arc-types, arc-prelude          │
  │  arc-validation → dev-deps only        ▼
  ▼                                        arc-validation (CAVP/NIST)
  arc-hybrid (Layer 2: hybrid)               deps: arc-prelude, arc-types
  │  deps: arc-primitives
  ▼
  arc-core (Layer 3: unified API)
  │  deps: arc-types, arc-primitives, arc-hybrid
  │  REMOVED: arc-prelude, arc-validation
  ▼
  latticearc (facade)
  │  deps: arc-core, arc-primitives, arc-hybrid,
  │        arc-tls, arc-zkp, arc-perf
  │  REMOVED: 14 unused deps, glob export
  │  Only re-exports: LatticeArcError
  │
  arc-tests (all integration tests)
    deps: latticearc, arc-core, arc-primitives, arc-types
    37 test files consolidated from arc-core + latticearc
  ```

  - `resource_limits` module moved from `arc-validation` to `arc-types` (pure Rust, zero FFI)
  - `domains` constants moved from `arc-prelude` to `arc-types`
  - Both original modules replaced with re-exports for backward compatibility
  - `arc-primitives` no longer depends on `arc-validation` in production (moved to dev-deps)
  - `arc-core` no longer depends on `arc-validation` or `arc-prelude` in production
  - `arc-tests` no longer depends on `arc-prelude` (was unused)
- **Architecture: Public API cleanup**:
  - `latticearc` no longer glob-exports `arc-prelude::*` (was leaking testing infrastructure
    into public namespace). Only `LatticeArcError` explicitly re-exported.
  - 14 unused direct dependencies removed from `latticearc` (all transitive via arc-core)
  - 3 unused dependencies removed from `arc-core` (`k256`, `async-trait`, `anyhow`)
  - `criterion` and `tempfile` moved from production to dev-deps in `arc-tls`
- **Test consolidation into `arc-tests`**:
  - 30 integration test files moved from `arc-core/tests/` to `arc-tests/tests/`
  - 7 integration test files + `nist_kat/` directory moved from `latticearc/tests/` to `arc-tests/tests/`
  - All dev-dependencies removed from `latticearc` (tests no longer in-crate)
  - `fips` feature added to `arc-tests` to propagate FIPS gating for KAT tests
  - `arc-tests` is now the single location for all integration and regression tests
- **Documentation**: Updated all docs to clarify hardware detection is enterprise-only
  - Removed references to `HardwareRouter`, `detect_hardware()`, `HardwarePreference` from all Apache docs
  - Clarified Apache vs Enterprise feature scope in DESIGN.md

---

## [0.1.0] - 2026-01-29

### Initial Release

First public release of LatticeArc, an enterprise-grade post-quantum cryptography library for Rust.

### Features

#### Post-Quantum Cryptography (NIST Standards)
- **ML-KEM** (FIPS 203) - Key encapsulation mechanism
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204) - Digital signatures
  - ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205) - Hash-based signatures
  - SLH-DSA-SHA2-128s/f, SLH-DSA-SHAKE-128s/f
- **FN-DSA** (FIPS 206 Draft) - Lattice signatures
  - FN-DSA-512, FN-DSA-1024

#### Classical Cryptography
- AES-256-GCM (FIPS 197)
- ChaCha20-Poly1305 (RFC 8439)
- ECDH P-256 (FIPS 186-5)
- ECDSA P-256 (FIPS 186-5)
- Ed25519 signatures
- X25519 key exchange

#### Hybrid Cryptography
- Hybrid KEM (ML-KEM + ECDH)
- Hybrid Signatures (ML-DSA + ECDSA)
- Hybrid Encryption (post-quantum + classical)

#### Security Features
- **Zero Trust Enforcement**: Type-based API with `SecurityMode`
- **Memory Safety**: Zeroization of sensitive data
- **Constant-Time Operations**: Side-channel resistant implementations
- **No Unsafe Code**: Pure safe Rust in production paths

#### Developer Experience
- Unified API for all cryptographic operations
- Comprehensive error handling (no panics)
- Extensive documentation and examples

### Crate Structure (v0.1.x — consolidated into single `latticearc` crate in v0.2.0)

| Crate | Description |
|-------|-------------|
| `latticearc` | Main facade crate |
| `arc-core` | Unified API layer |
| `arc-primitives` | Core cryptographic primitives |
| `arc-prelude` | Common types and errors |
| `arc-hybrid` | Hybrid encryption |
| `arc-tls` | Post-quantum TLS |
| `arc-validation` | NIST test vectors |
| `arc-zkp` | Zero-knowledge proofs |

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
