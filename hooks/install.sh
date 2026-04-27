#!/bin/bash
# Install git hooks by pointing core.hooksPath at the in-tree hooks/ directory.
#
# This is intentionally a config-only install (no copy step). Edits to
# `hooks/pre-commit` / `hooks/pre-push` take effect on the next commit/push
# without re-running this script, and `.git/hooks/` being wiped (e.g. on a
# `.git` recovery) cannot leave the repo with a stale or missing hook —
# `core.hooksPath` is stored in `.git/config` and survives independently.
#
# Run once after cloning:
#   ./hooks/install.sh
#
# To uninstall:
#   git config --unset core.hooksPath
#
# Pre-existing copies in `.git/hooks/{pre-commit,pre-push}` (from the older
# cp-based install) are removed so they cannot shadow the in-tree scripts if
# `core.hooksPath` is ever unset.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sanity-check we're inside the repo we expect.
case "$HOOKS_DIR" in
    "$REPO_ROOT/hooks") ;;
    *)
        echo "Error: this install.sh must be run from the apache_repo/hooks/ directory."
        echo "       repo root:  $REPO_ROOT"
        echo "       hooks dir:  $HOOKS_DIR"
        exit 1
        ;;
esac

REL_HOOKS="hooks"

echo "Installing Git Hooks"
echo "===================="
echo ""
echo "Method:  git config core.hooksPath = $REL_HOOKS"
echo "Source:  $HOOKS_DIR"
echo ""

# Verify the canonical hook scripts exist before pointing git at them.
for hook in pre-commit pre-push; do
    if [ ! -x "$HOOKS_DIR/$hook" ]; then
        if [ -f "$HOOKS_DIR/$hook" ]; then
            chmod +x "$HOOKS_DIR/$hook"
            echo "Made executable: hooks/$hook"
        else
            echo "Error: hooks/$hook not found in $HOOKS_DIR"
            exit 1
        fi
    fi
done

# Point git at the in-tree hooks. Repo-local config; does not affect other
# clones of this repo on the same machine.
git config core.hooksPath "$REL_HOOKS"

# Remove the old copy-based installs from .git/hooks/ so they cannot
# silently shadow the in-tree scripts if core.hooksPath is ever cleared.
GIT_HOOKS_DIR="$(git rev-parse --git-dir)/hooks"
for hook in pre-commit pre-push; do
    if [ -f "$GIT_HOOKS_DIR/$hook" ] && [ ! -L "$GIT_HOOKS_DIR/$hook" ]; then
        rm -f "$GIT_HOOKS_DIR/$hook"
        echo "Removed stale copy: $GIT_HOOKS_DIR/$hook"
    fi
done

echo ""
echo "Git hooks installed successfully!"
echo ""
echo "Pre-Commit Hook (runs before every commit) — hooks/pre-commit:"
echo "   1. cargo fmt --all (auto-format + re-stage)"
echo "   2. cargo check --workspace (default + fips + no-default + fuzz)"
echo "   3. cargo clippy -D warnings"
echo "   4. cargo test --workspace --all-features --release"
echo "   5. CLI smoke tests"
echo ""
echo "Pre-Push Hook (runs before every push) — hooks/pre-push:"
echo "   1. scripts/audit.sh --quick (audit/deny + feature-flag audit)"
echo "   2. CHANGELOG.md update reminder (warning only)"
echo ""
echo "Verify with:  git config --get core.hooksPath  # → $REL_HOOKS"
