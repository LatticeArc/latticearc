#!/bin/bash
# Install git hooks from hooks/ directory into .git/hooks/
# This enforces the mandatory pre-commit checklist

set -e

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

echo "Installing Git Hooks"
echo "===================="
echo ""
echo "Source: $HOOKS_DIR"
echo "Target: $GIT_HOOKS_DIR"
echo ""

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "Installed: pre-commit hook (fmt, check, clippy, tests)"
else
    echo "Error: hooks/pre-commit not found"
    exit 1
fi

# Install pre-push hook
if [ -f "$HOOKS_DIR/pre-push" ]; then
    cp "$HOOKS_DIR/pre-push" "$GIT_HOOKS_DIR/pre-push"
    chmod +x "$GIT_HOOKS_DIR/pre-push"
    echo "Installed: pre-push hook (changelog, format check)"
else
    echo "Error: hooks/pre-push not found"
    exit 1
fi

echo ""
echo "Git hooks installed successfully!"
echo ""
echo "Pre-Commit Hook (runs before every commit):"
echo "   1. cargo fmt --all (auto-format + re-stage)"
echo "   2. cargo check --workspace --all-features"
echo "   3. cargo clippy -D warnings"
echo "   4. cargo test --workspace --all-features --release"
echo ""
echo "Pre-Push Hook (lightweight, runs before every push):"
echo "   1. CHANGELOG.md updated (warning)"
echo "   2. cargo fmt --check (sanity)"
echo ""
echo "Alternative: git config core.hooksPath .githooks"
echo ""
