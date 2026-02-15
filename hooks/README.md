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
2. **Compilation** (`cargo check --all-features`) - Must compile
3. **Clippy lints** (`cargo clippy -D warnings`) - No warnings allowed
4. **Full test suite** (`cargo test --release`) - All tests must pass

**Timing**: ~2-3 minutes (tests run in release mode for crypto performance)

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

- **Known issue**: arc-tls and arc-validation tests fail in sandbox environments
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
