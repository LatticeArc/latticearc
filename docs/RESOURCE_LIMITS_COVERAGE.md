# Resource Limits — Coverage Audit

> ⚠️ **This document is load-bearing for the CI gate
> `scripts/ci/resource_limits_coverage.sh`.** The forward gate reads the
> "Known gaps" section to decide which functions are documented-but-unprotected
> and allows them through; the inverse check warns when names in this file no
> longer correspond to any `fn` in source. **Before removing an entry, read
> the gate script and confirm the corresponding function now calls a
> `validate_*` helper** — otherwise you will silently remove a DoS protection.

Tracks which public entry points enforce `primitives::resource_limits::validate_*`
before operating on attacker-controllable input lengths. The goal is to make
denial-of-service via oversized inputs structurally impossible from the outside
of the crate.

Global defaults (`primitives/resource_limits.rs`):

| Limit | Default |
|---|---|
| `max_encryption_size_bytes` | 100 MiB |
| `max_decryption_size_bytes` | 100 MiB |
| `max_signature_size_bytes` | 64 KiB |
| `max_key_derivations_per_call` | 1000 |

Runtime-configurable via `ResourceLimitsManager::update_limits`.

## Coverage by entry point

### Top-level unified API — `latticearc::unified_api::convenience::api`

| Entry point | Input validated | Validator called | Location |
|---|---|---|---|
| `encrypt` | plaintext length | `validate_encryption_size` | `api.rs:335` |
| `decrypt` | ciphertext length | `validate_decryption_size` | `api.rs:482` |
| `sign_message` | message length | `validate_signature_size` | `api.rs:666` |
| `verify` | signed-data length | `validate_signature_size` | `api.rs:791` |

Status: **covered**.

### Convenience facades

| Module | Entry points | Validator coverage |
|---|---|---|
| `convenience::pq_kem` | `encrypt_pq_ml_kem*`, `decrypt_pq_ml_kem*` | `validate_encryption_size` at one site (`pq_kem.rs:72`). **Gap**: the `*_unverified` and `*_with_config*` variants share internals but each public wrapper should verify before dispatch. |
| `convenience::pq_sig` | `sign_pq_{ml,slh,fn}_dsa*`, `verify_pq_{ml,slh,fn}_dsa*` | `validate_signature_size` at 6 sites (`pq_sig.rs:94,125,171,201,247,287`). Covers the primary `sign` / `verify` entry points; `*_unverified` variants share internals so the cap applies transitively. |
| `convenience::hybrid_sig` | `sign_hybrid*`, `verify_hybrid_signature*` | `validate_signature_size` at 2 sites (`hybrid_sig.rs:72,97`). |
| `convenience::hashing` | `derive_key`, `hmac`, `hmac_check` | `validate_key_derivation_count(1)` at 2 sites (`hashing.rs:75,130`). |
| `convenience::aes_gcm` | 12 public variants (`encrypt_aes_gcm*`, `decrypt_aes_gcm*`, `*_with_aad*`) | **Gap**: no top-level `validate_*` calls; the underlying AEAD primitive (`aead::aes_gcm`) does call `validate_encryption_size` / `validate_decryption_size` at the primitive layer (`aead/aes_gcm.rs:72,123`), so the cap applies — but not at the convenience-API boundary. Adding a validation step at the convenience layer would fail faster and uniformly with the rest of the API. |
| `convenience::ed25519` | 8 public variants | Signature output is fixed-size (64 B) so `validate_signature_size` is informational; the **data to be signed** is uncapped at the convenience layer. Add `validate_signature_size(data.len())` to be consistent with the ML-DSA / SLH-DSA sign paths. |
| `convenience::keygen` | 14 `generate_*` variants | N/A for size; `max_key_derivations_per_call` gates key-derivation call counts, not keygen. No input length to validate. |
| `convenience::hybrid` | `generate_hybrid_keypair*` | N/A — no input length. |

### Primitives layer

| Module | Validator coverage |
|---|---|
| `primitives::kem::ml_kem` | `validate_encryption_size` / `validate_decryption_size` at 4 sites (`ml_kem.rs:893,915,966,990`). Public keys and ciphertexts are fixed-size per parameter set, so the cap is a sanity check, not the primary defense. |
| `primitives::aead::aes_gcm` | `validate_encryption_size` / `validate_decryption_size` at 2 sites (`aes_gcm.rs:72,123`). Covers the main cipher object. |
| `primitives::aead::chacha20poly1305` | Same pattern (`chacha20poly1305.rs:71,116`). |
| `primitives::sig::ml_dsa` | `validate_signature_size` is enforced inside `MlDsaSecretKey::sign` on the message-length hot path (see `ml_dsa.rs::sign`). `generate_keypair` and `MlDsaPublicKey::verify` do not call it (keys are fixed-size; verify's cost is verification-only, not message-size-bounded). |
| `primitives::sig::slh_dsa`, `sig::fn_dsa` | **Gap**: same as `ml_dsa`. |
| `primitives::kdf::pbkdf2::verify_password` | **Gap**: `iterations` argument is attacker-controllable when derived from serialized parameter blocks. No upper-bound enforcement beyond the `max_key_derivations_per_call` global, and that only fires if the caller explicitly calls `validate_key_derivation_count(iterations)` — `pbkdf2` itself does not. Caps: see `iteration_bounds.md`. |
| `primitives::kdf::hkdf` | No input-length cap. HKDF-Expand output length is an `OutputLength` type parameter so it cannot exceed the algorithm maximum, but the `info` byte string is uncapped. Real-world attacks here require enormous `info` — not practical DoS, but worth documenting. |
| `primitives::mac::hmac`, `mac::cmac` | No input-length cap. Tag verify paths use `subtle::ConstantTimeEq` (correct). |

### Hybrid layer

| Module | Entry points | Validator coverage |
|---|---|---|
| `hybrid::encrypt_hybrid` | `encrypt_hybrid`, `decrypt_hybrid` | **Gap**: no `validate_encryption_size` / `validate_decryption_size` calls. The underlying AEAD primitive enforces it, but adding the check at the hybrid-layer entry point would be consistent. |
| `hybrid::pq_only` | `encrypt_pq_only`, `decrypt_pq_only`, `encrypt_pq_only_with_aad`, `decrypt_pq_only_with_aad` | **Gap**: same as `encrypt_hybrid`. The `_with_aad` siblings (added in the post-round-21 audit-fix wave) share internals with the base versions; the underlying AEAD primitive enforces the cap. |
| `hybrid::sig_hybrid` | `sign`, `verify` | **Gap**: no `validate_signature_size` at the hybrid layer; the inner ML-DSA / Ed25519 primitives do not enforce it either. |
| `hybrid::kem_hybrid` | `generate_keypair*`, `encapsulate`, `decapsulate`, `decapsulate_from_parts` | N/A — ML-KEM fixed-size inputs. The `decapsulate_from_parts` entry point (added in the post-round-21 audit-fix wave to remove the placeholder `EncapsulatedKey` hack) takes raw `&[u8]` slices but `MlKemCiphertext::new` validates the length against the parameter set's fixed ciphertext size before any work runs. |

## Remediation plan (v0.7.x)

Non-breaking fixes (same public API, just fail faster):

1. `hybrid::encrypt_hybrid::{encrypt_hybrid, decrypt_hybrid}` — call `validate_encryption_size(plaintext.len())` / `validate_decryption_size(ciphertext.len())` at entry.
2. `hybrid::pq_only::{encrypt_pq_only, decrypt_pq_only}` — same.
3. `hybrid::sig_hybrid::{sign, verify}` — call `validate_signature_size(message.len())`.
4. `convenience::aes_gcm::encrypt_aes_gcm*` / `decrypt_aes_gcm*` — mirror the primitive-layer call at the convenience boundary.
5. `convenience::ed25519::sign_ed25519*` / `verify_ed25519*` — add `validate_signature_size(data.len())`.
6. `primitives::sig::{ml_dsa, slh_dsa, fn_dsa}::sign` — call `validate_signature_size(message.len())`.
7. `primitives::kdf::pbkdf2` — hard-cap `iterations` at `max_key_derivations_per_call`; see `iteration_bounds.md` for the rationale and chosen upper bound.

All remediations are behavior-preserving for legitimate input (caps are well above any realistic crypto input) and convert oversized input into an early `ResourceExceeded` error instead of allowing allocation / iteration to proceed.

## Known gaps as of v0.7.0 (tracked for remediation)

The following public functions take `&[u8]` input but do not currently call a
`validate_*` function at their boundary. They are listed explicitly so the CI
coverage gate (`scripts/ci/resource_limits_coverage.sh`) recognises them as
documented, not undetected.

Primitives — MAC / KDF (caps applied at cipher layer but not at MAC boundary):

- `primitives::mac::cmac::cmac_128`, `cmac_192`, `cmac_256`
- `primitives::mac::cmac::verify_cmac_128`, `verify_cmac_192`, `verify_cmac_256`
- `primitives::mac::hmac::hmac_sha256`, `verify_hmac_sha256`

Primitives — ECDH public-key validators (semantic validation, not size):

- `primitives::kem::ecdh::validate_p256_public_key`, `validate_p384_public_key`, `validate_p521_public_key`

Unified API — AES-GCM convenience facade (primitive layer already caps; convenience layer does not):

- `convenience::aes_gcm::encrypt_aes_gcm_unverified`, `encrypt_aes_gcm_with_aad`, `encrypt_aes_gcm_with_aad_unverified`, `encrypt_aes_gcm_with_config`, `encrypt_aes_gcm_with_config_unverified`
- `convenience::aes_gcm::decrypt_aes_gcm_unverified`, `decrypt_aes_gcm_with_aad`, `decrypt_aes_gcm_with_aad_unverified`, `decrypt_aes_gcm_with_config`, `decrypt_aes_gcm_with_config_unverified`

Unified API — Ed25519 convenience facade:

- `convenience::ed25519::sign_ed25519_unverified`, `sign_ed25519_with_config`, `sign_ed25519_with_config_unverified`
- `convenience::ed25519::verify_ed25519_unverified`, `verify_ed25519_with_config`, `verify_ed25519_with_config_unverified`

Primitives — KDF (input `info`/`context` is attacker-influenced but output is length-bounded by `OutputLength`):

- `primitives::kdf::hkdf::hkdf_extract`, `hkdf_expand`, `hkdf_simple`
- `primitives::kdf::pbkdf2::pbkdf2_simple`
- `primitives::kdf::pbkdf2::pbkdf2_kat` — test-only KAT-replay entry
  point (gated behind `cfg(any(test, feature = "test-utils"))`).
  Delegates to the private `pbkdf2_with_floor` which performs all the
  same salt-length, all-zero-salt, key-length, and DoS iteration-cap
  checks as the public `pbkdf2`; the *only* validation it bypasses is
  the per-PRF OWASP iteration *floor* (so RFC 6070 / NIST CAVP
  vectors with low iteration counts can be replayed). Input is not
  attacker-controllable in production builds because the function is
  not exposed unless `test-utils` is enabled.
- `primitives::kdf::sp800_108_counter_kdf::counter_kdf`, `derive_encryption_key`, `derive_iv`, `derive_mac_key`, `derive_multiple_keys`

Hybrid layer — internal shared-secret derivation (fed from fixed-size inputs):

- `hybrid::encrypt_hybrid::derive_encryption_key`
- `hybrid::kem_hybrid::derive_hybrid_shared_secret`

ECDH ephemeral agreement (fixed-size inputs, no DoS vector):

- `primitives::kem::ecdh::agree_ephemeral`, `agree_ephemeral_p256`, `agree_ephemeral_p384`, `agree_ephemeral_p521`

Rationale for the KDF / hybrid / ECDH entries: output length is statically
bounded by the `OutputLength` / `SharedSecret` return type; input is either
fixed-size (keys, curve points) or statically constrained (`info` parameters
are typically ≤ 256 bytes in practice). No DoS amplification vector exists.
The functions are listed for transparency only.

Remediation order: v0.7.1 for the convenience-layer aes_gcm / ed25519 variants
(straight addition of a `validate_*` call, behaviour-preserving), v0.8 for the
primitive-layer MAC calls (changes error-type shape). The ECDH validators are
intentionally size-agnostic and will remain so — they verify curve-point
membership, not byte-count limits.

## How to keep this document honest

- Any new `pub fn` in `latticearc::hybrid::*`, `latticearc::primitives::{kem,sig,aead,mac,kdf}`, or `latticearc::unified_api::convenience::*` that takes a `&[u8]` must either (a) call a `validate_*` function at entry, (b) document in a doc comment why the input size is structurally bounded (e.g., fixed-size public keys), or (c) explicitly list the function in this document's "Gap" rows.
- The CI grep-level check (`scripts/ci/resource_limits_coverage.sh`) enforces that new `pub fn` names appearing in the grep denominator are reflected here.
