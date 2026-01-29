# CI/CD Workflows

This document describes the GitHub Actions workflows used in LatticeArc.

## Overview

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| CI | Push, PR | Build, test, lint |
| Security | Push, PR, Schedule | Security scanning |
| Release | Tag | Publish to crates.io |
| Fuzz | Schedule | Continuous fuzzing |

## Main CI Workflow

**File:** `.github/workflows/ci.yml`

### Jobs

#### `build`

Builds the workspace on multiple platforms:

- Linux x86_64 (Ubuntu latest)
- macOS x86_64
- macOS aarch64 (Apple Silicon)
- Windows x86_64

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, macos-14, windows-latest]
    rust: [stable, beta]
```

#### `test`

Runs the full test suite:

```bash
cargo test --workspace --all-features
```

#### `lint`

Runs code quality checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

#### `docs`

Builds documentation:

```bash
cargo doc --workspace --all-features --no-deps
```

#### `coverage`

Generates code coverage report:

```bash
cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info
```

Uploads to Codecov for tracking.

### Required Checks

PRs cannot merge unless these pass:
- `build` (all platforms)
- `test`
- `lint`
- `coverage` (minimum 80%)

## Security Workflow

**File:** `.github/workflows/security.yml`

### Jobs

#### `audit`

Checks for known vulnerabilities:

```bash
cargo audit --deny warnings
```

#### `deny`

Checks licenses and bans:

```bash
cargo deny check all
```

#### `secret-scan`

Scans for accidentally committed secrets using TruffleHog.

### Schedule

Runs daily at midnight UTC to catch newly disclosed vulnerabilities.

## Release Workflow

**File:** `.github/workflows/release.yml`

### Trigger

Triggered by pushing a version tag:

```bash
git tag v0.1.0
git push --tags
```

### Steps

1. **Verify**: Run full test suite
2. **Publish**: Publish to crates.io in dependency order
3. **Release**: Create GitHub release with changelog
4. **Announce**: Post to Discord/Twitter (if configured)

### Publish Order

Crates are published in dependency order:

1. `arc-prelude`
2. `arc-primitives`
3. `arc-core`
4. `arc-hybrid`
5. `arc-tls`
6. `arc-validation`
7. `arc-zkp`
8. `arc-perf`
9. `latticearc`

## Fuzz Workflow

**File:** `.github/workflows/fuzz.yml`

### Schedule

Runs nightly for continuous fuzzing.

### Targets

Fuzzes all targets in `arc-fuzz/`:

```bash
cargo +nightly fuzz run fuzz_ml_kem -- -max_total_time=3600
cargo +nightly fuzz run fuzz_ml_dsa -- -max_total_time=3600
# ... other targets
```

### Crash Handling

If a crash is found:
1. Artifact saved
2. Issue opened automatically
3. Maintainers notified

## Workflow Configuration

### Secrets Required

| Secret | Purpose |
|--------|---------|
| `CARGO_REGISTRY_TOKEN` | Publish to crates.io |
| `CODECOV_TOKEN` | Upload coverage |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_BACKTRACE` | Enable backtraces |
| `CARGO_TERM_COLOR` | Colored output |

## Local Verification

Before pushing, run the same checks locally:

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Test
cargo test --workspace --all-features

# Security
cargo audit
cargo deny check all
```

## Adding New Workflows

1. Create `.github/workflows/<name>.yml`
2. Follow existing patterns
3. Add required checks to branch protection
4. Document in this file

## Troubleshooting

### CI is slow

- Check if caching is working
- Consider splitting into more parallel jobs
- Use `cargo-chef` for better Docker layer caching

### Tests pass locally but fail in CI

- Check Rust version matches
- Verify all features are enabled
- Look for environment-specific issues

### Security scan finds false positive

- Add to `.cargo-audit.toml` ignore list
- Document justification in `SECURITY.md`
- Open issue with advisory DB if invalid
