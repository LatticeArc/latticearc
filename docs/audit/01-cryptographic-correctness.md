# Dimension 1: Cryptographic Correctness

**Last audited:** 2026-02-15
**Auditor:** Agent a78f596 + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

None.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 1.1 KAT from NIST CAVP | `self_test.rs` | 380-390 | SHA-256 vector cited from NIST CAVP with source URL |
| 1.1 RFC vectors | `self_test.rs` | 421-448 | HKDF test from RFC 5869 Test Case 1 |
| 1.2 No fabricated vectors | `self_test.rs` | All KATs | All vectors cite standards (NIST, RFC) |
| 1.3 AES-GCM roundtrip | `aes_gcm.rs` | 390-413 | `encrypt()` then `decrypt()` test |
| 1.3 ML-KEM roundtrip | `self_test.rs` | 625-689 | `kat_ml_kem_768()` encapsulate/decapsulate |
| 1.3 ML-DSA roundtrip | `self_test.rs` | 713-782 | `kat_ml_dsa()` sign/verify |
| 1.3 FN-DSA roundtrip | `self_test.rs` | 903-1003 | `kat_fn_dsa()` sign/verify |
| 1.5 Production CSPRNG | `aes_gcm.rs` | 73, 168, 212, 307 | All use `OsRng.fill_bytes()` |
| 1.5 No thread_rng in production | workspace-wide | — | All `thread_rng()` usage in `#[cfg(test)]` or `#[kani::proof]` modules only |
| 1.8 AES-GCM params | `aes_gcm.rs` | 58, 197 | KEY_LEN constants match NIST SP 800-38D |
| 1.8 ML-KEM params | `ml_kem.rs` | 246-272 | Key/ciphertext sizes match FIPS 203 |
| 1.8 ML-DSA params | `ml_dsa.rs` | 92-117 | Sizes match FIPS 204 |
