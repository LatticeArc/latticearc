# Git Hooks

This directory contains git hooks that enforce code quality automatically.

## Why Git Hooks?

Manual checklists are unreliable. These hooks enforce critical quality gates automatically before code reaches the repository.

## Installation

From the repository root:

```bash
./hooks/install.sh
```

This copies hooks from `hooks/` to `.git/hooks/` and makes them executable.

Alternatively, use the `.githooks/` directory directly:

```bash
git config core.hooksPath .githooks
```

## Available Hooks

### pre-commit

Runs **before every `git commit`**. Enforces all heavy checks:

1. **Auto-format** (`cargo fmt --all`) - Formats and re-stages changed files
2. **Compilation matrix** (`cargo check --all-features`, all feature combos, workspace + fuzz) - Must compile
3. **Clippy lints** (`cargo clippy -D warnings`, workspace + fuzz) - No warnings allowed
4. **Dead-code suppression scan**
5. **Full workspace tests** (`cargo test --workspace --all-features --release`) - All tests must pass
6. **CI-target verification**
7. **CLI rebuild + smoke test** (default features)

**Timing**: ~15-25 minutes on a cold cache, ~8-12 on a warm cache. The "2-3 min" figure from an older version of this doc was optimistic — a full workspace compile in release mode alone is 5-6 min before any tests run. Plan your iteration cycle accordingly.

### Critical: pre-flight the test suite BEFORE attempting commit

**Do not** rely on the hook to find your failures — each failed commit costs ~15+ minutes.
Run this exact command locally first:

```bash
RUST_MIN_STACK=16777216 cargo test --workspace --all-features --release 2>&1 > /tmp/test.log
grep -E "^test .* FAILED$|test result: FAILED" /tmp/test.log
```

If that grep returns anything, fix it before `git commit`. `cargo test -p latticearc --lib` is
**not** sufficient — it skips the integration suites in `tests/`, `latticearc/tests/`, and
`latticearc-cli/tests/` that the hook does run.

**Piping commit output** (e.g. `git commit -m "..." 2>&1 | tail -N`) **swallows failures** —
the specific `test foo::bar ... FAILED` line gets pushed out of the tail window and the pipe
exit code is `tail`'s `0`, not cargo's `1`. Redirect to a file instead if you need to capture
output.

### pre-push

Runs **before every `git push`**. Lightweight sanity check only:

1. **CHANGELOG.md updated** (warning) - Reminds to document changes
2. **Format check** (`cargo fmt --check`) - Catches uncommitted format drift

**Timing**: ~5 seconds

**Why lightweight?** Heavy checks (tests, clippy) moved to pre-commit to avoid
SSH connection timeouts during push. The pre-commit hook runs locally with no
time pressure; pre-push runs during an active SSH session to GitHub.

## Bypassing Hooks (NOT RECOMMENDED)

```bash
git commit --no-verify   # Skip pre-commit
git push --no-verify     # Skip pre-push
```

**This violates project policy** and may be rejected in code review. Only use in emergencies.

## Hook Behavior

### Test Failures

- **Known issue**: TLS and validation tests may fail in sandbox environments
- **Behavior**: Hook filters out these known failures and allows commit
- **Rationale**: These failures are environmental, not code-related
- **All other test failures block commit**

## Troubleshooting

### Hook not running

```bash
# Check which hooks path is active
git config core.hooksPath

# If using .githooks/ (recommended):
git config core.hooksPath .githooks

# If using .git/hooks/:
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
# Run locally to see failures
cargo test --workspace --all-features --release
# Fix failures and retry
```

### Emergency bypass (last resort)

```bash
# Only if:
# 1. CI is broken and blocking urgent fix
# 2. Hook has false positive (report bug)
# 3. Discussed with team lead

git commit --no-verify  # Add comment in commit message explaining why
```

## Updating Hooks

After modifying hooks in `hooks/` or `.githooks/`:

```bash
# If using .git/hooks/, reinstall:
./hooks/install.sh

# Commit hook changes
git add hooks/ .githooks/
git commit -m "chore(hooks): Update hooks"
git push
```

## Hook Philosophy

**Trust but verify**: Hooks enforce objective quality gates (format, tests, lints). They don't replace code review, but catch mistakes before human reviewers see them.

**Fail early**: Better to catch issues locally than in CI or production.

## Related Documentation

- `.github/workflows/` - CI pipeline (mirrors hook checks)
- `SECURITY.md` - Security policy and reporting
- `CONTRIBUTING.md` - Contribution guidelines
