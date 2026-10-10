# Tracked Tech-Debt

A single registry for tech-debt that has a known remediation path but
is currently parked. Round-20 audit fix #19 surfaced multiple "revisit
when X" notes scattered across `deny.toml` and CI workflows that had no
deadline and no tracking — this file gives each one an explicit target
and owner.

When a row's target date is reached, either the remediation lands or
the row gets a one-line update with the new target and the reason. A
row with no update for >2 quarters past its target is a process failure
and should be treated as a finding.

## Open

| ID | What | Target | Owner | Why parked |
|----|------|--------|-------|------------|
| TRK-001 | Remove `RUSTSEC-2021-0139` (ansi_term unmaintained) ignore | 2026-Q4 | maintainers | Reviewed 2026-10-09: the latest published dudect-bencher is still 0.7.0 and uses clap 2; the previous claim that 0.8+ was available was incorrect. Replace the harness CLI dependency if no maintained upstream release arrives this quarter, then drop the ignore. |
| TRK-002 | Remove `RUSTSEC-2024-0375` (atty unmaintained) ignore | 2026-Q4 | maintainers | Reviewed 2026-10-09: same dependency blocker and remediation as TRK-001. |
| TRK-003 | Remove `RUSTSEC-2021-0145` (atty Windows unsoundness) ignore | 2026-Q4 | maintainers | Reviewed 2026-10-09: same dependency blocker as TRK-001. The Windows-only soundness bug is gated by `dudect.yml` running on `ubuntu-latest`; removing the dependency remains the remediation. |
| TRK-004 | Remove `RUSTSEC-2024-0436` (paste unmaintained) ignore | 2026-Q4 | maintainers | Pulled in transitively by `pqcrypto-mldsa` dev-dep (cross-impl validation tests). Wait for pqcrypto-mldsa upstream to drop the dep, OR vendor a minimal alternative for the validation tests. |
| TRK-006 | Remove the `dudect-bencher` clap 2 dependency | 2026-Q4 | maintainers | Reviewed 2026-10-09: [0.7.0 is still the latest published release](https://docs.rs/crate/dudect-bencher/latest). Upgrade when a maintained CLI dependency is available, or replace the harness CLI this quarter while retaining the statistical tests. Unblocks TRK-001/002/003. |
| TRK-007 | Promote `self_test::roundtrip_ml_kem_768` to a true KAT | 2026-Q4 | security-team | Round-47 promoted ML-DSA-44 and SLH-DSA-SHAKE-192s power-up tests to real ACVP fixed-input KATs (`kat_ml_dsa` / `kat_slh_dsa`) by feeding the upstream `fips204` / `fips205` `try_keygen_with_rng` a deterministic RNG; `aws-lc-rs` does not expose a deterministic seed-keygen API for ML-KEM (its FIPS-approved DRBG adds internal entropy by design — confirmed by the test comment at `ml_kem.rs:1561`), so ML-KEM-768 stays as `roundtrip_ml_kem_768` until upstream lands a seed-input API. When that lands, wire ACVP `keyGen` / `encapDecap` vectors from <https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json> through a `FixedBytesRng` (already available in `self_test/kat.rs`) and rename to `kat_ml_kem_768`. |

## Closed (kept here briefly for traceability — remove after one round)

| ID | What | Closed by |
|----|------|-----------|
| TRK-005 | Promote `wildcards = "warn"` to `"deny"` in `deny.toml` | Round-20 fix #20 (commit `f279351b1`) — promoted to `deny` with `allow-wildcard-paths = true`. Round-21 audit fix #17 surfaced this row was stale. |

## Conventions

- Every entry must have a target quarter (or earlier date) and a named owner.
- "When X drops Y" without a target date is **not** acceptable — the dependency owner has no obligation to your timeline; if you wait for them, set a date by which you switch to a workaround.
- Entries removed from this file go in the corresponding fix-commit body, not deleted silently.

## Policy intent

This file exists because successive audits surfaced "park" notes (RUSTSEC ignores, `continue-on-error: true` blocks, `// revisit when …` source comments) that had no deadline and stayed parked indefinitely. The recurring pattern was: a workaround ships with a comment "remove when X happens"; X eventually happens; nobody notices; the workaround stays. Each future PR that introduces a similar park note must add a row here in the same commit.
