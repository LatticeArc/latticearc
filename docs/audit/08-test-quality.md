# Dimension 8: Test Quality

**Last audited:** 2026-02-15
**Auditor:** Agent a0044cc + manual verification
**Method:** Actual file reads with line-number evidence

---

## Findings

### F8-01: Hardcoded `/tmp/` paths in arc-tls tests [VERIFIED]

**Severity:** LOW
**Issue:** 12 instances of hardcoded `/tmp/` paths in arc-tls tests and doc examples.
**Resolution:** All replaced with `std::env::temp_dir().join("filename")`.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 8.1 KAT vectors from NIST | `self_test.rs` | 374-404 | SHA-256 CAVP vector with source URL |
| 8.1 HKDF test vectors | `hkdf.rs` | 278-296 | RFC 5869 Test Case 1 |
| 8.1 PBKDF2 test vectors | `pbkdf2.rs` | 347-360 | Standard vectors |
| 8.4 No /tmp/ in core tests | workspace (excl. arc-tls) | — | Zero matches (2026-02-15 fix for audit.rs) |
| 8.6 All #[ignore] documented | workspace | — | 25 ignored tests, ALL have descriptive reason strings |
| 8.9 Test lint allows | `api.rs`, `aes_gcm.rs` | test modules | Comprehensive `#[allow(...)]` blocks |
| 8.11 CI-friendly thresholds | timing tests | — | CV: 2000%, difference_ratio: 0.50 |
