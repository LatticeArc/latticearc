# Dimension 4: API Boundary Safety

**Last audited:** 2026-02-15
**Auditor:** Agent a0a6676 + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

### F4-01: Missing `#[must_use]` on public crypto functions [VERIFIED]

**Severity:** LOW
**File:** `arc-core/src/convenience/api.rs`
**Issue:** Five public crypto functions lacked `#[must_use]`.
**Resolution:** Added `#[must_use]` to `encrypt`, `decrypt`, `generate_signing_keypair`, `sign_with_key`, `verify`.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 4.1 Input validation at entry | `api.rs` | 176-179, 290-291, 442-443 | `validate_encryption_size()`, `validate_decryption_size()`, `validate_signature_size()` |
| 4.2 Empty input explicit behavior | `api.rs` | tests 964-974, 1792-1798 | Empty data tests pass, no bypass |
| 4.3 Unknown scheme returns Err | `api.rs` | 227-234, 314-319 | `CoreError::InvalidInput` for unknown schemes |
| 4.4 No wildcard silent success | `api.rs` | All matches | All `_ =>` arms return explicit errors (2026-02-15 fix) |
| 4.6 All pub fns return Result | `api.rs` | 173, 284, 351, 431, 623 | encrypt, decrypt, generate_signing_keypair, sign_with_key, verify |
| 4.9 Prefer &[u8]/&str | `api.rs`, `keygen.rs` | All | All use `&[u8]` for data/keys, no `Vec<u8>`/`String` params |
| 4.4 Selector no fallback | `selector.rs` | 166-228, 412 | `UseCase` match arms return explicit schemes, error on unknown |
