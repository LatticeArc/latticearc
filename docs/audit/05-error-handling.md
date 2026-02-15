# Dimension 5: Error Handling

**Last audited:** 2026-02-15
**Auditor:** Agent a0a6676 + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

None.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 5.1 Specific error variants | `api.rs` | 192-193, 200-201, 228-234 | `CoreError::InvalidKeyLength`, `CoreError::InvalidInput` |
| 5.1 Non-exhaustive enums | `error.rs`, `types.rs`, `fips_error.rs` | — | `#[non_exhaustive]` on CoreError, LatticeArcError, FipsErrorCode (2026-02-15 fix) |
| 5.2 No secret leakage | workspace | — | Error messages contain scheme names/lengths, never key material |
| 5.3 No unwrap in production | `api.rs`, `keygen.rs` | — | All unwrap/expect in `#[cfg(test)]` only |
| 5.4 FIPS error state | `self_test.rs` | 1154-1173, 1390-1424 | `ModuleErrorCode` enum, `verify_operational()` checks error state |
| 5.8 No todo!/unimplemented! | workspace | — | Zero matches in production code |
| 5.9 Ok(()) functions verified | `pct.rs` | 132-157, 184-211, 251-276 | All PCT functions have real validation, return `PctError` on failure |
| 5.9 integrity_test() verified | `self_test.rs` | 1041-1133 | Full HMAC-SHA256 verification, not a placeholder |
