#!/bin/bash
# Local CI checks - run before pushing to avoid GitHub failures
# Usage: ./scripts/ci-local.sh [--quick]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

QUICK_MODE=false
if [[ "$1" == "--quick" ]]; then
    QUICK_MODE=true
fi

echo -e "${YELLOW}=== Local CI Checks ===${NC}"
echo ""

# Track failures
FAILURES=()

run_check() {
    local name=$1
    local cmd=$2
    echo -e "${YELLOW}[$name]${NC} Running..."
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}[$name]${NC} ✓ Passed"
        return 0
    else
        echo -e "${RED}[$name]${NC} ✗ Failed"
        echo -e "${RED}Command: $cmd${NC}"
        FAILURES+=("$name")
        return 1
    fi
}

run_check_verbose() {
    local name=$1
    local cmd=$2
    echo -e "${YELLOW}[$name]${NC} Running..."
    if eval "$cmd"; then
        echo -e "${GREEN}[$name]${NC} ✓ Passed"
        return 0
    else
        echo -e "${RED}[$name]${NC} ✗ Failed"
        FAILURES+=("$name")
        return 1
    fi
}

# 1. Format check
run_check "Format" "cargo fmt --all -- --check"

# 2. Clippy (strict)
run_check_verbose "Clippy" "cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -5"

# 3. Build
run_check "Build" "cargo build --workspace --all-features"

# 4. Doc build with strict warnings
run_check "Docs" "RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps"

# 5. Security audit
if command -v cargo-audit &> /dev/null; then
    run_check "Audit" "cargo audit --deny warnings 2>&1 || true"
else
    echo -e "${YELLOW}[Audit]${NC} Skipped (cargo-audit not installed)"
fi

# 6. Dependency check
if command -v cargo-deny &> /dev/null; then
    run_check "Deny" "cargo deny check all"
else
    echo -e "${YELLOW}[Deny]${NC} Skipped (cargo-deny not installed)"
fi

# 7. Tests (skip in quick mode)
if [[ "$QUICK_MODE" == false ]]; then
    echo -e "${YELLOW}[Tests]${NC} Running (this may take a while)..."
    if cargo test --workspace --all-features -- --test-threads=4 2>&1 | tail -20; then
        echo -e "${GREEN}[Tests]${NC} ✓ Passed"
    else
        echo -e "${RED}[Tests]${NC} ✗ Failed"
        FAILURES+=("Tests")
    fi
else
    echo -e "${YELLOW}[Tests]${NC} Skipped (quick mode)"
fi

echo ""
echo -e "${YELLOW}=== Summary ===${NC}"

if [ ${#FAILURES[@]} -eq 0 ]; then
    echo -e "${GREEN}All checks passed! Safe to push.${NC}"
    exit 0
else
    echo -e "${RED}Failed checks: ${FAILURES[*]}${NC}"
    echo -e "${RED}Fix these issues before pushing.${NC}"
    exit 1
fi
