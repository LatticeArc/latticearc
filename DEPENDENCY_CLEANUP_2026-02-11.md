# Dependency Cleanup - February 11, 2026
**Scope:** Apache repository workspace dependencies
**Objective:** Remove unused workspace dependencies to reduce attack surface and build times

---

## Summary

**Removed 5 unused workspace dependencies** from apache_repo/Cargo.toml:

| Dependency | Reason | Impact |
|------------|--------|--------|
| `bytes = "1.9"` | Not used in any .rs files | ✅ Removed |
| `url = "2.5"` | Not used in any .rs files | ✅ Removed |
| `futures = "0.3"` | Not used in any .rs files | ✅ Removed |
| `crossbeam-utils = "0.8"` | Declared in 2 crates but never imported | ✅ Removed |
| `generic-array = "0.14"` | Not used in apache codebase | ✅ Removed |

**Also removed from member crates:**
- `arc-core/Cargo.toml`: removed `crossbeam-utils`
- `latticearc/Cargo.toml`: removed `crossbeam-utils`

---

## Verification

### Build Status
```bash
cargo check --workspace --all-features
```
**Result:** ✅ PASS - Finished in 3.60s

### Remaining Dependencies Verified In Use
- `blake2` - used in arc-core/src/logging.rs
- `parking_lot` - used in arc-validation, arc-core
- `lazy_static` - used in arc-validation, arc-core

---

## Files Modified

1. `apache_repo/Cargo.toml` - Removed 5 workspace dependencies
2. `apache_repo/arc-core/Cargo.toml` - Removed crossbeam-utils
3. `apache_repo/latticearc/Cargo.toml` - Removed crossbeam-utils

---

## Benefits

- **Reduced attack surface** - Fewer dependencies = fewer potential vulnerabilities
- **Faster builds** - Less code to compile
- **Cleaner Cargo.lock** - Fewer transitive dependency trees
- **Better supply chain security** - Smaller audit scope

---

## Notes

- **Proprietary repo not included** - Per user instruction: "work only on apache for these issues, propreitary is still in active development"
- **Conservative approach** - Only removed deps with zero code usage
- **Verification method** - Used ripgrep/grep to search for `use <crate>` and `<crate>::` patterns across all .rs files

---

**Next Steps:** Consider running `cargo deny check` and `cargo audit` to verify no new issues introduced

---

**Signed:** LatticeArc Dev Team <Dev@LatticeArc.com>
**Date:** February 11, 2026
