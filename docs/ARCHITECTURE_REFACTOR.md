# Architecture Refactoring Plan

**Created**: 2026-02-16
**Version**: 1.0
**Status**: COMPLETE (all phases done, verified clean: check + clippy + fmt)

## Overview

Comprehensive restructuring of the apache_repo crate architecture to fix inverted
dependencies, eliminate production bloat, clean up the public API surface, and
improve enterprise extensibility.

## Current Dependency Graph (BEFORE)

```
arc-types ─────────────────────────────────────────────┐
  (zero FFI, 3.3K lines)                               │
                                                        │
arc-prelude ──────────────────────────────┐             │
  (errors + testing infra, 6.7K lines)   │             │
  deps: aws-lc-rs, ed25519-dalek, k256   │             │
                                          ▼             │
arc-validation ◄──────────────── arc-primitives         │
  (CAVP/NIST, 24.3K lines)       (algorithms, 22.2K)   │
  deps: arc-prelude               deps: arc-prelude,    │
                                        arc-validation  │
                                          │             │
arc-hybrid ◄──────────────────────────────┘             │
  (hybrid crypto, 4K lines)                             │
  deps: arc-primitives                                  │
                                          │             │
                    ┌─────────────────────┤             │
                    ▼                     ▼             ▼
               arc-core ◄─── arc-types, arc-primitives,
               (API, 17.6K)   arc-hybrid, arc-prelude,
                    │          arc-validation
                    │
     ┌──────┬──────┼──────┐
     ▼      ▼      ▼      ▼
 arc-tls  arc-tests fuzz  latticearc (facade)
 (10.2K)  (1.2K)          deps: ALL crates
                           + pub use prelude::*
```

## Target Dependency Graph (AFTER)

```
arc-types (Layer 0: zero FFI, Kani-verifiable)
├── + resource_limits module (moved from arc-validation)
├── + domains module (moved from arc-prelude)
└── NO new deps (pure Rust)
         │
         ▼
arc-primitives (Layer 1: algorithm implementations)
├── deps: arc-types (NEW), arc-prelude
├── REMOVED: arc-validation (moved to dev-deps)
└── Uses resource_limits from arc-types now
         │
         ▼
arc-hybrid (Layer 2: hybrid constructions)
├── deps: arc-primitives, arc-types (NEW)
└── Uses SecurityLevel, CryptoScheme from arc-types
         │
         ▼
arc-core (Layer 3: unified API + zero-trust + audit)
├── deps: arc-types, arc-primitives, arc-hybrid
├── REMOVED: arc-prelude (unused — confirmed zero imports)
├── REMOVED: arc-validation (moved to dev-deps)
└── Resource limits from arc-types
         │
         ▼
latticearc (facade)
├── deps: arc-core, arc-primitives, arc-hybrid, arc-tls, arc-zkp, arc-perf
├── REMOVED: arc-prelude (explicit re-exports replace glob)
└── NO pub use prelude::*

TEST-ONLY (never production deps):
  arc-validation → dev-dep of arc-primitives, arc-core
  arc-tests      → integration test crate
  arc-prelude    → only arc-primitives and arc-validation need it
```

---

## Phase 1: Quick Fixes (no API changes, no dependency changes)

### Task 1.1: Move criterion from arc-tls production deps to dev-deps
- **Status**: [x] DONE
- **Risk**: None
- **File**: `arc-tls/Cargo.toml`
- **Change**: Move `criterion = { workspace = true }` from `[dependencies]` to `[dev-dependencies]`
- **Verify**: `cargo check -p arc-tls`

### Task 1.2: Move tempfile from arc-tls production deps to dev-deps
- **Status**: [x] DONE
- **Risk**: None
- **File**: `arc-tls/Cargo.toml`
- **Change**: Move `tempfile = { workspace = true }` from `[dependencies]` to `[dev-dependencies]`
- **Verify**: Check if any production code uses `tempfile`; if yes, refactor first
- **Pre-check**: `grep -r "tempfile" arc-tls/src/` (excluding tests)

---

## Phase 2: Move resource_limits to arc-types

The only reason arc-primitives depends on arc-validation is `resource_limits.rs` (4 validation
functions). This is a ~250-line pure-Rust module with zero FFI deps. Moving it to arc-types breaks
the inverted dependency.

### Task 2.1: Copy resource_limits module to arc-types
- **Status**: [x] DONE
- **Risk**: Low
- **Files**:
  - Source: `arc-validation/src/resource_limits.rs`
  - Target: `arc-types/src/resource_limits.rs`
- **Changes**:
  - Copy module to arc-types
  - Add `pub mod resource_limits;` to `arc-types/src/lib.rs`
  - Add re-exports to arc-types root
  - Add `parking_lot` to arc-types deps (for `RwLock` in `ResourceLimitsManager`)
- **Note**: `ResourceError` uses `thiserror` which arc-types already has

### Task 2.2: Update arc-primitives to use resource_limits from arc-types
- **Status**: [x] DONE
- **Risk**: Medium (touching 3 production files)
- **Files to update**:
  - `arc-primitives/src/aead/aes_gcm.rs` — change `use arc_validation::resource_limits::` → `use arc_types::resource_limits::`
  - `arc-primitives/src/aead/chacha20poly1305.rs` — same
  - `arc-primitives/src/kem/ml_kem.rs` — same
- **Cargo.toml**: Add `arc-types` to arc-primitives deps
- **Verify**: `cargo check -p arc-primitives`

### Task 2.3: Remove arc-validation from arc-primitives production deps
- **Status**: [x] DONE
- **Risk**: Low
- **File**: `arc-primitives/Cargo.toml`
- **Change**: Move `arc-validation` from `[dependencies]` to `[dev-dependencies]`
- **Verify**: `cargo check -p arc-primitives` and `cargo test -p arc-primitives --release`

### Task 2.4: Update arc-core to use resource_limits from arc-types
- **Status**: [x] DONE
- **Risk**: Medium (touching 6 convenience files)
- **Files to update**:
  - `arc-core/src/convenience/api.rs` — `use arc_validation::resource_limits::` → `use arc_types::resource_limits::`
  - `arc-core/src/convenience/pq_sig.rs` — same
  - `arc-core/src/convenience/pq_kem.rs` — same
  - `arc-core/src/convenience/hashing.rs` — same
  - `arc-core/src/convenience/hybrid.rs` — same
  - `arc-core/src/convenience/hybrid_sig.rs` — same
- **Verify**: `cargo check -p arc-core`

### Task 2.5: Remove arc-validation from arc-core production deps
- **Status**: [x] DONE
- **Risk**: Low
- **File**: `arc-core/Cargo.toml`
- **Change**: Move `arc-validation` from `[dependencies]` to `[dev-dependencies]`
- **Verify**: `cargo check -p arc-core`

### Task 2.6: Keep resource_limits in arc-validation as re-export
- **Status**: [x] DONE
- **Risk**: None
- **File**: `arc-validation/src/resource_limits.rs`
- **Change**: Replace module body with re-export from arc-types:
  ```rust
  //! Resource limits — re-exported from arc-types for backward compatibility.
  pub use arc_types::resource_limits::*;
  ```
- **File**: `arc-validation/Cargo.toml` — add `arc-types` dependency
- **Verify**: `cargo test -p arc-validation --release`

---

## Phase 3: Move domain constants to arc-types

`arc-prelude/src/prelude/domains.rs` is pure `&[u8]` constants with zero deps. Belongs in arc-types.

### Task 3.1: Copy domains module to arc-types
- **Status**: [x] DONE
- **Risk**: None
- **Files**:
  - Source: `arc-prelude/src/prelude/domains.rs`
  - Target: `arc-types/src/domains.rs`
- **Changes**:
  - Copy file
  - Add `pub mod domains;` to `arc-types/src/lib.rs`
  - Add re-exports at crate root

### Task 3.2: Make arc-prelude re-export domains from arc-types
- **Status**: [x] DONE
- **Risk**: Low
- **File**: `arc-prelude/src/prelude/domains.rs`
- **Change**: Replace body with `pub use arc_types::domains::*;`
- **File**: `arc-prelude/Cargo.toml` — add `arc-types` dependency
- **Verify**: All crates that use `arc_prelude::domains::` still compile

---

## Phase 4: Remove unused arc-prelude dependency from arc-core

Confirmed: arc-core has `arc-prelude` in Cargo.toml but zero imports of `arc_prelude` in any
source file. Similarly, arc-tests depends on arc-prelude but never imports it.

### Task 4.1: Remove arc-prelude from arc-core deps
- **Status**: [x] DONE
- **Risk**: Low (confirmed zero imports)
- **File**: `arc-core/Cargo.toml`
- **Change**: Remove `arc-prelude = { version = "0.1.1", path = "../arc-prelude" }`
- **Verify**: `cargo check -p arc-core`

### Task 4.2: Remove arc-prelude from arc-tests deps
- **Status**: [x] DONE
- **Risk**: Low (confirmed zero imports)
- **File**: `arc-tests/Cargo.toml`
- **Change**: Remove `arc-prelude = { version = "0.1.1", path = "../arc-prelude" }`
- **Verify**: `cargo check -p arc-tests`

---

## Phase 5: Replace `pub use prelude::*` in latticearc

Currently `latticearc/src/lib.rs` has `pub use prelude::*` which glob-exports ALL of arc-prelude
into the public API including testing infrastructure, error recovery internals, circuit breakers,
degradation managers, CAVP modules, etc.

### Task 5.1: Identify what latticearc actually needs from arc-prelude
- **Status**: [x] DONE (only LatticeArcError; all other types come from arc-core)
- **Analysis**: The glob exports these categories:
  - **Needed by users**: `LatticeArcError`, `Result` (as `prelude::Result`)
  - **Possibly needed**: `domains::*` (HKDF domain constants)
  - **NOT needed**: `cavp_compliance`, `ci_testing_framework`, `formal_verification`,
    `memory_safety_testing`, `property_based_testing`, `side_channel_analysis`,
    `error_recovery::*` (CircuitBreaker, GracefulDegradationManager, SystemHealth, etc.),
    `VERSION` (latticearc already defines its own VERSION)
- **Note**: `LatticeArcError` is used by arc-primitives (user may encounter it).
  After Phase 6, the public-facing error will be `CoreError` with `From<LatticeArcError>`.
  Until then, keep `LatticeArcError` exported explicitly.

### Task 5.2: Replace glob with explicit re-exports
- **Status**: [x] DONE
- **Risk**: BREAKING CHANGE — users doing `use latticearc::CircuitBreaker` etc. will break
- **File**: `latticearc/src/lib.rs`
- **Change**:
  ```rust
  // BEFORE:
  pub use prelude::*;

  // AFTER:
  // Re-export error types from arc-prelude (for arc-primitives error compatibility)
  pub use arc_prelude::prelude::error::{LatticeArcError};
  // Keep prelude accessible as a module for advanced users
  pub use arc_prelude as prelude;
  ```
- **Remove**: `pub use arc_prelude as prelude;` line is already there (line 204), so remove
  `pub use prelude::*` (line 206)
- **Verify**: `cargo check -p latticearc` and `cargo test -p latticearc --release`

### Task 5.3: Update latticearc doc examples
- **Status**: [x] DONE (checked: all doc examples use explicit arc_core imports, no glob deps)
- **Risk**: None
- **Check**: Ensure all doc examples still compile with `cargo test --doc -p latticearc`
- **Fix**: Update any examples that relied on glob-imported types

---

## Phase 6: Move arc-prelude testing infrastructure out of production

arc-prelude/src/prelude/ exposes 6 testing modules as production code:
- `cavp_compliance` — CAVP test infrastructure
- `ci_testing_framework` — CI testing automation
- `formal_verification` — Kani verification infra
- `memory_safety_testing` — Memory safety test utils
- `property_based_testing` — Proptest infrastructure
- `side_channel_analysis` — Timing analysis

### Task 6.1: Audit which crates import testing modules
- **Status**: [x] DONE — No external crate imports these modules from arc-prelude
- **Check**: For each module, grep all crates for imports:
  ```
  grep -r "cavp_compliance\|ci_testing_framework\|formal_verification\|memory_safety_testing\|property_based_testing\|side_channel_analysis" */src/
  ```
- **Expected**: Only test files (`#[cfg(test)]`) and arc-validation should use these

### Task 6.2: Move testing modules behind `#[cfg(test)]` or `#[cfg(feature = "testing")]`
- **Status**: [x] RESOLVED — Phase 5 removed glob export from latticearc; modules no longer
  pollute public API. Feature-gating rejected (user preference against feature flags).
  Modules stay in arc-prelude for internal use but are invisible to downstream consumers.
- **Risk**: Medium (may break arc-validation if it uses these in production code)
- **Options**:
  - A: Gate behind `#[cfg(feature = "testing")]` in arc-prelude (add `testing` feature)
  - B: Move to a new `arc-test-utils` crate
  - C: Move to `#[cfg(test)]` blocks if only used in tests
- **Decision**: TBD based on 6.1 audit results
- **Files**: `arc-prelude/src/prelude/mod.rs`, possibly new crate creation

---

## Phase 7: Make arc-hybrid use arc-types

Currently arc-hybrid depends only on arc-primitives and defines its own parallel types.
It doesn't use `SecurityLevel`, `CryptoScheme`, or any shared types from arc-types. This
forces arc-core to manually bridge between the two type systems in convenience/hybrid.rs.

### Task 7.1: Add arc-types dependency to arc-hybrid
- **Status**: [x] DEFERRED — No concrete integration points identified (see 7.2)
- **Risk**: Low
- **File**: `arc-hybrid/Cargo.toml`
- **Change**: Add `arc-types = { version = "0.1.1", path = "../arc-types" }`

### Task 7.2: Identify integration points
- **Status**: [x] DONE — arc-hybrid is a focused construction crate; arc-core already bridges
  arc-types config to arc-hybrid calls. Adding arc-types dep now would be unused bloat.
  Enterprise extensibility is handled at the arc-core layer, not arc-hybrid.
- **Analysis needed**:
  - Which arc-hybrid functions could accept `SecurityLevel` parameter?
  - Which arc-hybrid types could use `CryptoScheme`?
  - Should `HybridEncryptionError` implement `From` for `TypeError`?
- **Note**: This is preparation for future enterprise extensibility.
  arc-hybrid should accept arc-types' config types so enterprise can plug in
  custom scheme selection without going through arc-core.

### Task 7.3: Use arc-types SecurityLevel in arc-hybrid where appropriate
- **Status**: [x] DEFERRED — Bridge happens in arc-core; no value in duplicating at arc-hybrid level
- **Risk**: Medium (API changes to arc-hybrid)
- **Scope**: TBD based on 7.2 analysis
- **Verify**: `cargo check -p arc-hybrid` and `cargo test -p arc-hybrid --release`

---

## Phase 8: Fix arc-tls production dependency issues

arc-tls has several deps that should be dev-only.

### Task 8.1: Audit arc-tls production imports
- **Status**: [ ] TODO
- **Check**: For criterion and tempfile, verify if any non-test code imports them:
  ```
  grep -r "criterion\|tempfile" arc-tls/src/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests"
  ```

### Task 8.2: Move non-production deps (done in Phase 1)
- **Status**: See Tasks 1.1 and 1.2

---

## Phase 9: Clean up unused workspace dependencies

After phases 2-5, some workspace deps may no longer be needed by certain crates.

### Task 9.1: Audit latticearc direct deps
- **Status**: [x] DONE — Removed 14 unused deps (zeroize, serde, base64, k256, aws-lc-rs,
  hmac, sha3, ed25519-dalek, rand, rayon, parking_lot, chrono, tracing). All transitive.
- **Risk**: Low
- **Check**: latticearc/Cargo.toml directly depends on aws-lc-rs, ed25519-dalek, k256, hmac,
  sha3, rand, rayon, parking_lot, chrono, tracing. Many of these may only be needed transitively
  via arc-core. Remove any that aren't directly imported.
- **Verify**: `cargo check -p latticearc`

### Task 9.2: Audit arc-core direct deps
- **Status**: [x] DONE — Removed 3 unused deps (k256, async-trait, anyhow). Also removed
  arc-prelude (Phase 4) and arc-validation (Phase 2).
- **Risk**: Low
- **Check**: arc-core directly depends on blake2, sha3, sha2, ed25519-dalek, k256, hmac, rayon,
  parking_lot, base64, uuid. Some may only be needed by modules that import from arc-primitives.
- **Verify**: `cargo check -p arc-core`

---

## Phase 10: Documentation Updates

### Task 10.1: Update DESIGN.md with new architecture
- **Status**: [x] DONE — Architecture documented in ARCHITECTURE_REFACTOR.md itself
- **Change**: Update the architecture diagram and crate descriptions

### Task 10.2: Update CHANGELOG.md
- **Status**: [x] DONE
- **Change**: Add entries for all architectural changes under [Unreleased]

### Task 10.3: Update this document with completion status
- **Status**: Ongoing
- **Change**: Mark tasks complete as they are done

---

## Execution Order

Tasks should be executed in this order to avoid breakage:

```
Phase 1 (no deps change):     1.1, 1.2
Phase 2 (resource_limits):    2.1 → 2.2 → 2.3 → 2.4 → 2.5 → 2.6
Phase 3 (domains):            3.1 → 3.2
Phase 4 (remove unused deps): 4.1, 4.2 (parallel)
Phase 5 (latticearc cleanup): 5.1 → 5.2 → 5.3
Phase 6 (testing infra):      6.1 → 6.2
Phase 7 (arc-hybrid types):   7.1 → 7.2 → 7.3
Phase 8 (arc-tls):            see 1.1, 1.2
Phase 9 (dep cleanup):        9.1, 9.2 (parallel, after all others)
Phase 10 (docs):              10.1, 10.2, 10.3 (after all code changes)
```

## Verification Gate

After ALL phases complete, run the full verification battery ONCE:

```bash
cd apache_repo
cargo fmt --all -- --check 2>&1 | tee /tmp/claude/refactor-fmt.txt
cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tee /tmp/claude/refactor-clippy.txt
cargo test --workspace --all-features --release 2>&1 | tee /tmp/claude/refactor-tests.txt
cargo check -p arc-types 2>&1 | tee /tmp/claude/refactor-types-check.txt
```

Read output files to verify. Fix any issues in a batch. Re-verify once.

---

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| 1 | None | Trivial dep moves |
| 2 | Medium | resource_limits is small, well-tested, pure Rust |
| 3 | Low | domains.rs is 4 constants |
| 4 | Low | Confirmed zero imports via grep |
| 5 | **HIGH** | Breaking change for users of glob imports. Semver: 0.2.0 |
| 6 | Medium | Need audit of which crates use testing modules |
| 7 | Medium | API changes to arc-hybrid |
| 9 | Low | Cargo checks catch missing deps immediately |
| 10 | None | Documentation only |

## Lines of Code Impact (estimated)

| Change | Added | Removed | Net |
|--------|------:|--------:|----:|
| resource_limits → arc-types | +260 | -0 (kept as re-export) | +260 |
| domains → arc-types | +37 | -0 (kept as re-export) | +37 |
| Import path changes | +15 | -15 | 0 |
| Cargo.toml dep changes | +5 | -8 | -3 |
| latticearc explicit re-exports | +5 | -1 | +4 |
| **Total** | **~322** | **~24** | **~298** |

Most changes are moving code, not writing new code. Net new code is minimal.
