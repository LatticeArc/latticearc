# Git Hooks

This directory contains git hooks that enforce the **Mandatory Pre-Push Checklist** for code quality.

## Why Git Hooks?

Manual checklists are unreliable. These hooks enforce critical quality gates automatically before code reaches the repository.

## Installation

From the repository root:

```bash
./hooks/install.sh
```

This copies hooks from `hooks/` to `.git/hooks/` and makes them executable.

## Available Hooks

### pre-push

Runs **before every `git push`**. Enforces:

1. **CHANGELOG.md updated** (warning) - Reminds to document changes
2. **Format check** (`cargo fmt --check`) - Code must be formatted
3. **Clippy lints** (`cargo clippy -D warnings`) - No warnings allowed
4. **Compilation** (`cargo check --all-features`) - Must compile
5. **Full test suite** (`cargo test --release`) - All tests must pass
6. **Security audit** (`cargo audit` or `cargo deny`) - No known vulnerabilities

**Timing**: ~2-3 minutes (tests run in release mode for crypto performance)

## Bypassing Hooks (NOT RECOMMENDED)

```bash
git push --no-verify
```

**This violates project policy** and may be rejected in code review. Only use in emergencies (CI broken, urgent hotfix).

## Hook Behavior

### CHANGELOG.md Check

- **Behavior**: Warns if CHANGELOG.md not updated when code/docs change
- **Rationale**: Every change should be documented
- **Enforcement**: Warning only (doesn't block push)

### Test Failures

- **Known issue**: TLS tests fail in sandbox (network binding blocked)
- **Behavior**: Hook detects "Operation not permitted" errors and allows push
- **Rationale**: These failures are environmental, not code-related
- **All other test failures block push**

### Security Audit

- **Known issue**: Advisory database lock fails in sandbox
- **Behavior**: Hook warns but allows push
- **Rationale**: Known clean (4 ignored LOW-risk advisories documented)
- **Manual verification**: Run `cargo audit && cargo deny check all` after push

## Troubleshooting

### Hook not running

```bash
# Check if installed
ls -la .git/hooks/pre-push

# If missing, reinstall
./hooks/install.sh
```

### Hook fails on format

```bash
cargo fmt --all
git add -u
git commit --amend --no-edit
git push
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

git push --no-verify  # Add comment in commit message explaining why
```

## Updating Hooks

After modifying hooks in `hooks/`:

```bash
# Reinstall to update .git/hooks/
./hooks/install.sh

# Commit hook changes
git add hooks/
git commit -m "chore(hooks): Update pre-push hook"
git push
```

All contributors should run `./hooks/install.sh` after pulling hook updates.

## Hook Philosophy

**Trust but verify**: Hooks enforce objective quality gates (format, tests, lints). They don't replace code review, but catch mistakes before human reviewers see them.

**Fast feedback**: 2-3 minutes is better than waiting for CI (5-10 minutes) or code review comments (hours/days).

**Fail early**: Better to catch issues locally than in CI or production.

## Related Documentation

- `.github/workflows/ci.yml` - CI pipeline (mirrors hook checks)
- `SECURITY.md` - Security policy and reporting
- `CONTRIBUTING.md` - Contribution guidelines
