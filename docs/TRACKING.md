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
| TRK-001 | Remove `RUSTSEC-2021-0139` (ansi_term unmaintained) ignore | 2026-Q3 | maintainers | dudect-bencher 0.8+ supports clap 4; migrate or replace the CT-bench harness, then drop the ignore. |
| TRK-002 | Remove `RUSTSEC-2024-0375` (atty unmaintained) ignore | 2026-Q3 | maintainers | Same provenance as TRK-001 — landed by the same migration. |
| TRK-003 | Remove `RUSTSEC-2021-0145` (atty Windows unsoundness) ignore | 2026-Q3 | maintainers | Same provenance as TRK-001. The Windows-only soundness bug is gated by `dudect.yml` running on `ubuntu-latest`, but removing the dep removes the question entirely. |
| TRK-004 | Remove `RUSTSEC-2024-0436` (paste unmaintained) ignore | 2026-Q4 | maintainers | Pulled in transitively by `pqcrypto-mldsa` dev-dep (cross-impl validation tests). Wait for pqcrypto-mldsa upstream to drop the dep, OR vendor a minimal alternative for the validation tests. |
| TRK-005 | Promote `wildcards = "warn"` to `"deny"` in `deny.toml` | 2026-Q3 | maintainers | Round-20 audit fix #20: comment in deny.toml says "Promote to deny once the dep tree has been audited." Currently one wildcard reported (workspace path-dep `latticearc-cli → latticearc`); the audit + skip-list update is straightforward. |
| TRK-006 | Migrate `dudect-bencher` to v0.8+ (clap 4) | 2026-Q3 | maintainers | Unblocks TRK-001/002/003 in one step. |

## Conventions

- Every entry must have a target quarter (or earlier date) and a named owner.
- "When X drops Y" without a target date is **not** acceptable — the dependency owner has no obligation to your timeline; if you wait for them, set a date by which you switch to a workaround.
- Entries removed from this file go in the corresponding fix-commit body, not deleted silently.

## Policy intent

This file exists because round-19 + round-20 audits both surfaced "park" notes (RUSTSEC ignores, `continue-on-error: true` blocks, "revisit when") that had no deadline and stayed parked indefinitely. The pattern was: a workaround ships with a comment "remove when X happens"; X eventually happens; nobody notices; the workaround stays. Each future PR that introduces a similar park note must add a row here in the same commit.
