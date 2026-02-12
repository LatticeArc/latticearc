#!/bin/bash
# Install git hooks from hooks/ directory into .git/hooks/
# This enforces the mandatory pre-push checklist

set -e

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"

echo "🔧 Installing Git Hooks"
echo "======================"
echo ""
echo "Source: $HOOKS_DIR"
echo "Target: $GIT_HOOKS_DIR"
echo ""

# Install pre-push hook
if [ -f "$HOOKS_DIR/pre-push" ]; then
    cp "$HOOKS_DIR/pre-push" "$GIT_HOOKS_DIR/pre-push"
    chmod +x "$GIT_HOOKS_DIR/pre-push"
    echo "✅ Installed: pre-push hook"
else
    echo "❌ Error: hooks/pre-push not found"
    exit 1
fi

echo ""
echo "✅ Git hooks installed successfully!"
echo ""
echo "📋 Pre-Push Hook Enforces:"
echo "   1. CHANGELOG.md updated (warning)"
echo "   2. cargo fmt --check"
echo "   3. cargo clippy"
echo "   4. cargo check"
echo "   5. cargo test --workspace --all-features --release"
echo "   6. cargo audit / cargo deny (warning if sandbox blocks)"
echo ""
echo "⚠️  To bypass hooks (NOT RECOMMENDED): git push --no-verify"
echo "   This violates project policy and may be rejected in code review."
echo ""
