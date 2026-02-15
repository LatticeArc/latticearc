# Dimension 3: Memory & Side-Channel Safety

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
| 3.1 No unsafe (workspace) | workspace | — | `#![deny(unsafe_code)]` in workspace lints |
| 3.2 CT compare SHA-256 KAT | `self_test.rs` | 397 | `result.ct_eq(&EXPECTED)` (subtle crate) |
| 3.2 CT compare HKDF KAT | `self_test.rs` | 441 | `result.key().ct_eq(&EXPECTED_OKM)` |
| 3.2 CT compare AES-GCM tag | `aes_gcm.rs` | 326-328 | `verify_tag_constant_time()` |
| 3.2 CT compare ML-KEM | `self_test.rs` | 673 | `ss_encap.as_bytes().ct_eq(ss_dec.as_bytes())` |
| 3.2 CT compare MlKemSecretKey | `ml_kem.rs` | 510-512 | `impl ConstantTimeEq` |
| 3.2 CT compare integrity test | `self_test.rs` | 1121 | `computed_hmac.ct_eq(expected_hmac)` |
| 3.5 No Copy on secret types | All secret types | — | No Copy derive on any secret key type |
| 3.6 No println in production | workspace | — | Only in `#[cfg(test)]`, doc comments, or arc-validation |
| 3.8 No keys in error msgs | `ml_kem.rs` | 186-199 | Errors reference sizes/types only |
| 3.8 No keys in AES errors | `aes_gcm.rs` | 62-64 | Reports "InvalidKeyLength" without key bytes |
| PBKDF2 iteration cap | `pbkdf2.rs` | — | Max 10M iterations prevents DoS (2026-02-15 fix) |
