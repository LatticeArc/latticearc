# Git Hooks

This directory is the canonical source for git hooks that enforce code
quality automatically. There is one source of truth — these scripts —
and `core.hooksPath` is pointed at this directory directly.

## Why Git Hooks?

Manual checklists are unreliable. These hooks enforce critical quality
gates automatically before code reaches the repository.

## Installation

From the repository root, after cloning:

```bash
./hooks/install.sh
```

The script sets `git config core.hooksPath hooks` (a one-time, repo-local
config) so that git invokes `hooks/pre-commit` and `hooks/pre-push`
directly from the working tree on every commit/push.

**Why config-only and not copy-into-`.git/hooks/`?**

- Edits to these scripts take effect on the next commit/push — no need
  to re-run `install.sh` after every change.
- The hooks survive `.git/hooks/` being wiped (e.g. during a `.git`
  recovery). Only `.git/config` matters, and that is preserved.
- There is no drift risk between "the script in source" and "the script
  git is actually running" — they are the same file.

The install script also removes any pre-existing
`.git/hooks/{pre-commit,pre-push}` from the older copy-based install so
they cannot silently shadow these scripts if `core.hooksPath` is ever
unset.

## Available Hooks

### pre-commit

Runs **before every `git commit`**. Enforces all heavy checks:

1. **Auto-format** (`cargo fmt --all`) — formats and re-stages changed files
2. **Compilation matrix** (`cargo check`, all-features / fips / no-default-features / fuzz) — must compile
3. **Clippy lints** (`cargo clippy -D warnings`, workspace + fuzz) — no warnings allowed
4. **Dead-code suppression scan** — production paths
5. **Full workspace tests** (`cargo test --workspace --all-features --release`) — all tests must pass
6. **CLI rebuild + smoke test** (default features)

**Timing**: ~15–25 minutes on a cold cache, ~8–12 on a warm cache. The
"2–3 min" figure from an older version of this doc was optimistic — a
full workspace compile in release mode alone is 5–6 min before any tests
run. Plan your iteration cycle accordingly.

### Critical: pre-flight the test suite BEFORE attempting commit

**Do not** rely on the hook to find your failures — each failed commit
costs ~15+ minutes. Run this exact command locally first:

```bash
RUST_MIN_STACK=16777216 cargo test --workspace --all-features --release 2>&1 > /tmp/test.log
grep -E "^test .* FAILED$|test result: FAILED" /tmp/test.log
```

If that grep returns anything, fix it before `git commit`.
`cargo test -p latticearc --lib` is **not** sufficient — it skips the
integration suites in `tests/`, `latticearc/tests/`, and
`latticearc-cli/tests/` that the hook does run.

**Piping commit output** (e.g. `git commit -m "..." 2>&1 | tail -N`)
**swallows failures** — the specific `test foo::bar ... FAILED` line
gets pushed out of the tail window and the pipe exit code is `tail`'s
`0`, not cargo's `1`. Redirect to a file instead if you need to capture
output.

### pre-push

Runs **before every `git push`**. Calls `scripts/audit.sh --quick` and
adds a CHANGELOG reminder:

1. **`scripts/audit.sh --quick`** — quick supply-chain + feature-flag audit
   (cargo audit, cargo deny, banned-crate scan, feature-flag liveness,
   orphan-cfg check)
2. **CHANGELOG.md update reminder** — warning only

**Timing**: ~10–15 seconds.

**Why moved away from the old "lightweight pre-push"?** The audit script
was added in 659a7d2aa but never actually ran for ~2 months because the
copy-install model + an unrelated script bug silently broke the chain.
Fixing the bug (936f570f3) and switching to `core.hooksPath` removes the
two failure modes simultaneously.

## Bypassing Hooks (FORBIDDEN by project policy)

```bash
git commit --no-verify   # Skip pre-commit — DO NOT
git push --no-verify     # Skip pre-push — DO NOT
```

`--no-verify` is **forbidden** by the global project policy
(`CLAUDE.md`). If a hook is misfiring, fix the hook or the underlying
issue — do not bypass.

## Troubleshooting

### Hook not running

```bash
# Confirm the install
git config --get core.hooksPath    # should print: hooks

# Re-run install if not set
./hooks/install.sh
```

### Hook fails on format

```bash
cargo fmt --all
git add -u
git commit
```

### Hook fails on clippy

```bash
# See all warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
# Fix and retry
```

### Hook fails on tests

```bash
# Pre-flight per "Critical: pre-flight" above
RUST_MIN_STACK=16777216 cargo test --workspace --all-features --release 2>&1 > /tmp/test.log
grep -E "^test .* FAILED$|test result: FAILED" /tmp/test.log
# Fix failures, then retry the commit
```

### Hook fails on `scripts/audit.sh --quick`

```bash
# Run the audit directly to see which check failed
./scripts/audit.sh --quick
```

If the failure is in `cargo audit` / `cargo deny`, ensure
`.cargo/audit.toml` and `deny.toml` are in sync — they share an ignore
list and must mirror each other.

## Updating Hooks

Edits to `hooks/pre-commit` or `hooks/pre-push` take effect on the next
commit/push automatically — no `install.sh` re-run needed. Just commit
the changes:

```bash
git add hooks/
git commit -m "chore(hooks): <what changed and why>"
git push
```

## Hook Philosophy

**Trust but verify**: hooks enforce objective quality gates (format,
tests, lints). They do not replace code review, but catch mistakes
before human reviewers see them.

**Fail early**: better to catch issues locally than in CI or production.

## Related Documentation

- `.github/workflows/` — CI pipeline (mirrors hook checks)
- `SECURITY.md` — security policy and reporting
- `CONTRIBUTING.md` — contribution guidelines
- `scripts/audit.sh` — the script invoked by `pre-push`
