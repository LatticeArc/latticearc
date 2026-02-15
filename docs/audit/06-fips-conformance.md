# Dimension 6: Standards Conformance (FIPS 140-3)

**Last audited:** 2026-02-15
**Auditor:** Agent a0a6676 + manual verification
**Method:** Actual file reads with line-number evidence

---

## Design Decision

- **No FIPS feature flags in apache repo** — always FIPS behavior
- **Always hybrid or PQ-only** — never classical-only scheme selection
- Non-FIPS algorithms (ChaCha20, Ed25519, secp256k1) gated with `#[cfg(not(feature = "fips"))]`

---

## Findings

None.

---

## Verified OK

| Check | File | Lines | Evidence |
|-------|------|-------|----------|
| 6.1 Module boundary | `arc-primitives/src/lib.rs` | 89-90 | `#[cfg(not(feature = "fips"))]` on polynomial |
| 6.1 AEAD boundary | `aead/mod.rs` | 25-28 | ChaCha20Poly1305 gated |
| 6.1 EC boundary | `ec/mod.rs` | 27-28 | Ed25519, secp256k1 gated |
| 6.1 ZKP boundary | `latticearc/src/lib.rs` | 370 | arc-zkp re-export gated |
| 6.2 Always hybrid/PQ | `selector.rs` | 238-262, 272-277 | `force_scheme()` returns hybrid/PQ-only, no classical (2026-02-15 fix) |
| 6.2 Signature selection | `selector.rs` | 336-375 | Hybrid for Standard/High/Max, PQ-only for Quantum (2026-02-15 fix) |
| 6.3 Power-up KATs | `self_test.rs` | 141-196 | 9 KATs: SHA-256, HKDF, AES-GCM, SHA3-256, HMAC, ML-KEM-768, ML-DSA, SLH-DSA, FN-DSA |
| 6.4 Module integrity test | `self_test.rs` | 1041-1133 | HMAC-SHA256 with build-time HMAC, constant-time verify |
| 6.5 Error state machine | `self_test.rs` | 1139-1190 | `ModuleErrorCode` enum (8 states), `AtomicU32` storage |
| 6.6 PCT after keygen | `pct.rs` | 132-157, 184-211, 251-276, 317-345 | PCT for ML-DSA, ML-KEM, SLH-DSA, FN-DSA |
| 6.7 PCT failure → error state | `pct.rs` | 154-155, 208-209, 273-274, 342-343 | `enter_pct_error_state()` sets `ModuleErrorCode::SelfTestFailure` |
| 6.8 verify_operational() guards | `api.rs` | 174, 285, 354, 437, 624 | All 5 entry points guarded via `fips_verify_operational()` |
| 6.8 Lazy init on first call | `api.rs` | 63-73 | `Once::call_once` runs `initialize_and_test()` |
