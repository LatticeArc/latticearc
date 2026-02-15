# Dimension 10: Supply Chain

**Last audited:** 2026-02-15
**Auditor:** Automated checks
**Method:** Direct command execution

---

## Findings

### F10-01: Yanked transitive dependency `keccak 0.1.5` [WONT_FIX]

**Severity:** LOW
**Dependency chain:** `keccak 0.1.5` ← `sha3 0.10.8` ← `latticearc`, `fips205`, `fips204`, `fips203`, `arc-zkp`, `arc-validation`, `arc-primitives`, `arc-core`
**Issue:** `keccak 0.1.5` has been yanked from crates.io. This is a warning, not a vulnerability — the crate was yanked (likely in favor of a newer version), not due to a security advisory.
**Justification:** `sha3 0.10.8` is the latest stable release. The only newer version is `0.11.0-rc.3` (release candidate). Multiple upstream crates (`fips203`, `fips204`, `fips205`) also depend on `sha3 0.10.8`. No fix possible without breaking changes.

---

## Verified OK

| Check | Evidence |
|-------|----------|
| 10.1 `cargo audit` | 1 yanked warning (keccak), zero vulnerabilities |
| 10.2 `cargo deny check all` | advisories OK, bans OK, licenses OK, sources OK |
| 10.4 Lock file committed | `Cargo.lock` present in repo |
| 10.7 License compatibility | All deps: MIT, Apache-2.0, BSD, ISC (no GPL/AGPL) |
| 10.8 Sources | Only crates.io (no git deps) |
