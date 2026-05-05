# Iteration Bounds — DoS Audit

Audits every `for` / `while` loop in `latticearc/src/primitives/` whose iteration
count is influenced by caller-controlled or attacker-controllable input.
Purpose: ensure that no loop can be made arbitrarily long by adversarial input,
preventing CPU-DoS of the OpenSSL `CVE-2024-4603` / `CVE-2023-5678` / `CVE-2023-6237` class.

## Summary

| Primitive | Loop driver | Bound source | Cap enforced? |
|---|---|---|---|
| PBKDF2 (`kdf/pbkdf2.rs`) | `iterations` param | caller-supplied | **Yes** — `MIN_ITERATIONS_SHA256 = 600_000` / `MIN_ITERATIONS_SHA512 = 210_000` ≤ `iter ≤ 10_000_000` (see `Pbkdf2Params::MIN_ITERATIONS_SHA256` and the upper-bound check in `pbkdf2()`). |
| PBKDF2 (`kdf/pbkdf2.rs`) | `key_length` param | caller-supplied | **Yes** — `key_length ≤ 1 MiB` (round-34 L10; see `PBKDF2_MAX_KEY_LEN` in `pbkdf2()`). |
| HKDF-Expand (`kdf/hkdf.rs`) | output `length` | caller-supplied | **Yes** — `length ≤ 255 × HashLen = 8160 bytes` per RFC 5869 (see `MAX_LEN` check in `hkdf_expand()`). |
| SP 800-108 Counter-KDF (`kdf/sp800_108_counter_kdf.rs`) | `key_length` | caller-supplied | **Yes** — `key_length ≤ max_len = (2^32) × HASH_LEN = 2^37 bytes` for the 32-bit counter and 256-bit hash (see `max_len` in `sp800_108_counter_kdf()`). |
| ML-KEM keygen/encaps/decaps (`kem/ml_kem.rs`) | polynomial coefficient loops | algorithm parameter set | **Yes** — fixed at 256 coefficients per polynomial by FIPS 203; not input-driven. |
| ML-DSA sign/verify (via `fips204` crate) | rejection sampling loop | internal, rejection-sampled | Delegated to `fips204`; upstream bounds enforced. |
| SLH-DSA sign/verify (via `fips205` crate) | Merkle tree traversal | fixed by parameter set | Delegated to `fips205`; depth is constant per level. |
| FN-DSA sign/verify (via `fn-dsa` crate) | rejection sampling | internal | Delegated to `fn-dsa`. |
| AES-GCM encrypt/decrypt (`aead/aes_gcm.rs`) | plaintext/ciphertext length | caller-supplied | **Yes** — `validate_encryption_size` / `validate_decryption_size` cap at 100 MiB (see calls inside `AesGcm::encrypt` / `AesGcm::decrypt`). |
| ChaCha20-Poly1305 (`aead/chacha20poly1305.rs`) | same as AES-GCM | caller-supplied | **Yes** — same 100 MiB cap (see calls inside `ChaCha20Poly1305::encrypt` / `decrypt`). |
| HMAC-SHA256/512 (`mac/hmac.rs`) | message length | caller-supplied | **No (known gap)** — no size cap on MAC input. HMAC is O(n); 100 MiB input ≈ few hundred ms. Not a practical amplification vector but worth aligning with AEAD for consistency. Listed in `RESOURCE_LIMITS_COVERAGE.md`. |
| CMAC (`mac/cmac.rs`) | message length | caller-supplied | **No (known gap)** — same as HMAC. |

> **Line references intentionally omitted.** Earlier revisions of this
> table cited specific `*.rs:LINE` anchors; those went stale across
> rounds 26–34. Cross-reference by symbol (`MIN_ITERATIONS_SHA256`,
> `MAX_LEN`, `validate_encryption_size`, etc.) instead — symbol grep
> survives line-number drift.

## Rationale for each cap

### PBKDF2 — 10M iterations hard cap

The iteration count for `pbkdf2` is deliberately attacker-controllable in one
scenario: when parameters are deserialized from an untrusted source (e.g., a
key-export format that carries the KDF parameter block). OWASP 2023 recommends
600,000 iterations minimum for PBKDF2-HMAC-SHA256 and 210,000 for
PBKDF2-HMAC-SHA512; we enforce both floors (per-PRF) and a single ceiling at
**10,000,000** iterations across both PRFs.

Why 10M: at ~2 µs per HMAC-SHA256 iteration (modern desktop CPU), 10M iterations
costs about 20 seconds of CPU time — high enough to discourage abuse, low
enough that a legitimate user migrating from an old password store can still
complete. Higher caps would enable a single malformed key-file to pin a server
core for minutes.

### HKDF — output length ≤ 255 × HashLen

This is the RFC 5869 algorithmic maximum (HKDF cannot produce more than
`255 * HashLen` bytes without collisions becoming possible). Rejecting longer
outputs at the API boundary prevents both the DoS case and the cryptographic
misuse case. For HMAC-SHA256, the cap is 8160 bytes.

### SP 800-108 Counter-KDF — `max_len = 2^37` bytes

NIST SP 800-108 bounds the output of the counter-based PRF at `2^r · hLen`
bytes where `r` is the counter size in bits and `hLen` is the hash output
length. For our 32-bit counter and 32-byte SHA-256 hash, that's
`2^32 × 32 = 2^37 ≈ 137 GiB` — astronomical for any realistic caller.
The cap is included for specification conformance rather than DoS defense.
The practical defense is that `key_length` is a `usize` and realistic
callers pass values ≤ 1 KiB.

### ML-KEM / ML-DSA / SLH-DSA / FN-DSA — fixed by parameter set

FIPS 203/204/205/206 specify fixed-size polynomial rings and Merkle trees per
parameter set. The library's job is to select a parameter set; once selected,
all loop bounds are compile-time constants. There is no attacker-influenced
iteration count.

### AES-GCM / ChaCha20-Poly1305 — 100 MiB cap

Both AEAD implementations call `validate_encryption_size` / `validate_decryption_size`
at their boundary, which enforces the `ResourceLimits.max_encryption_size_bytes` /
`max_decryption_size_bytes` cap (default 100 MiB). Exceeding triggers
`ResourceError::EncryptionSizeLimitExceeded` before any allocation.

## Known gaps (see `RESOURCE_LIMITS_COVERAGE.md`)

- **HMAC / CMAC** — no explicit size cap. These operations are linear in input
  length, so the DoS surface is bounded by the caller's ability to hand a
  large slice, but we should add a cap at the same 100 MiB as AEAD for API
  uniformity. Tracked for a future round; not yet shipped.

## How this document is kept honest

Any new `pub fn` in `latticearc/src/primitives/` or
`latticearc/src/unified_api/convenience/` that contains a `for` / `while` /
recursive call whose iteration count depends on a `&[u8]` or numeric input
must add a row to the table above and state the bound source. The CI gate
(`scripts/ci/resource_limits_coverage.sh`) covers the size-cap case; iteration
bounds are tracked here manually, per function.
