#!/bin/bash
# =============================================================================
# LatticeArc Audit Script v2.1 — CODE_AUDIT_METHODOLOGY.md v1.9
# =============================================================================
#
# ~70 automated checks across all 13 audit dimensions.
# Each check references its methodology doc ID (e.g., "1.5", "2.3").
#
# Usage:
#   ./scripts/audit.sh          # Full audit (~2-3 min with cargo commands)
#   ./scripts/audit.sh --quick  # Pre-push fast checks only (< 30s)
#
# Exit code: number of FAILURES (warnings don't cause non-zero exit)
# This script is called by the pre-push hook automatically.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

FAILURES=0
WARNINGS=0
PASSES=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; PASSES=$((PASSES + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
section() { echo -e "\n${BOLD}[$1] $2${NC}"; }

# =============================================================================
# Helper: filter_prod_only — removes grep hits inside #[cfg(test)] blocks
# =============================================================================
# Input:  grep output lines in format "file:linenum:content"
# Output: only lines from PRODUCTION code (before #[cfg(test)] in each file)
# Compatible with macOS bash 3.x (no associative arrays).
filter_prod_only() {
    local input="$1"
    if [ -z "$input" ]; then
        return
    fi

    local cache_files=""
    local cache_lines=""
    local result=""

    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        local file line_num
        file=$(echo "$hit" | cut -d: -f1)
        line_num=$(echo "$hit" | cut -d: -f2)

        case "$line_num" in
            ''|*[!0-9]*) continue ;;
        esac

        local test_start
        test_start=$(echo "$cache_files" | grep -n "^${file}$" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -n "$test_start" ]; then
            test_start=$(echo "$cache_lines" | sed -n "${test_start}p")
        else
            local ts
            ts=$(grep -n '#\[cfg(test)\]' "$file" 2>/dev/null | head -1 | cut -d: -f1)
            ts="${ts:-0}"
            cache_files="${cache_files}${file}"$'\n'
            cache_lines="${cache_lines}${ts}"$'\n'
            test_start="$ts"
        fi

        if [ "$test_start" -eq 0 ] || [ "$line_num" -lt "$test_start" ]; then
            result="$result$hit"$'\n'
        fi
    done <<< "$input"

    echo -n "$result" | sed '/^$/d'
}

# =============================================================================
# Helper: filter_debug_assertions — removes hits inside cfg(debug_assertions)
# =============================================================================
filter_debug_assertions() {
    local input="$1"
    if [ -z "$input" ]; then
        return
    fi
    local result=""
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        local file line_num
        file=$(echo "$hit" | cut -d: -f1)
        line_num=$(echo "$hit" | cut -d: -f2)
        case "$line_num" in
            ''|*[!0-9]*) continue ;;
        esac
        local start=$((line_num - 10))
        [ "$start" -lt 1 ] && start=1
        if sed -n "${start},${line_num}p" "$file" 2>/dev/null | grep -q 'cfg(debug_assertions)'; then
            continue
        fi
        result="$result$hit"$'\n'
    done <<< "$input"
    echo -n "$result" | sed '/^$/d'
}

# =============================================================================
# Helper: prod_grep — grep in production code, filtering test/doc/comments
# Returns: filtered results (empty = no matches)
# =============================================================================
prod_grep() {
    local pattern="$1"
    local path="${2:-latticearc/src/}"
    local raw
    raw=$(grep -rn "$pattern" --include="*.rs" "$path" 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    filter_prod_only "$raw"
}

# =============================================================================
# Setup
# =============================================================================
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

SRC="latticearc/src"
if [ ! -d "$SRC" ]; then
    echo "ERROR: $SRC not found. Run from repository root."
    exit 1
fi

QUICK=false
if [ "${1:-}" = "--quick" ]; then
    QUICK=true
fi

START_TIME=$(date +%s)

# =============================================================================
# Dimension 1: Cryptographic Correctness
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 1" "Cryptographic Correctness"

    # 1.5: No thread_rng in production code
    THREAD_RNG_FILES=$(grep -rl 'thread_rng' --include="*.rs" $SRC/ 2>/dev/null || true)
    THREAD_RNG_PROD=""
    for f in $THREAD_RNG_FILES; do
        LINES=$(grep -n 'thread_rng' "$f" | cut -d: -f1)
        TEST_START=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | head -1 | cut -d: -f1)
        for line in $LINES; do
            if [ -z "${TEST_START:-}" ] || [ "$line" -lt "$TEST_START" ]; then
                THREAD_RNG_PROD="$THREAD_RNG_PROD\n$f:$line"
            fi
        done
    done
    if [ -z "$THREAD_RNG_PROD" ]; then
        pass "1.5 No thread_rng() in production code"
    else
        fail "1.5 thread_rng() found in production code:"
        echo -e "$THREAD_RNG_PROD" | head -5
    fi

    # 1.2: KAT test vector sources documented (heuristic: hex strings in tests without source comment)
    KAT_FILES=$(grep -rl 'hex!\|from_hex\|hex::decode' --include="*.rs" tests/ $SRC/ 2>/dev/null || true)
    UNDOCUMENTED_VECS=""
    for f in $KAT_FILES; do
        HITS=$(grep -n 'hex!\|from_hex\|hex::decode' "$f" 2>/dev/null | grep -v 'NIST\|RFC\|CAVP\|Wycheproof\|test vector\|Known Answer' | head -3 || true)
        if [ -n "$HITS" ]; then
            UNDOCUMENTED_VECS="$UNDOCUMENTED_VECS$f\n"
        fi
    done
    UNDOCUMENTED_VECS=$(echo -en "$UNDOCUMENTED_VECS" | sed '/^$/d')
    if [ -z "$UNDOCUMENTED_VECS" ]; then
        pass "1.2 All test vector files have source documentation"
    else
        COUNT=$(echo -e "$UNDOCUMENTED_VECS" | wc -l | tr -d ' ')
        warn "1.2 $COUNT file(s) may have undocumented test vectors (verify manually):"
        echo -e "$UNDOCUMENTED_VECS" | head -5
    fi

    # 1.8: Algorithm parameter constants exist (check for key/nonce/tag size definitions)
    PARAM_DEFS=$(grep -rn 'KEY_SIZE\|NONCE_SIZE\|TAG_SIZE\|KEY_LEN\|NONCE_LEN' --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$PARAM_DEFS" -gt 0 ]; then
        pass "1.8 Algorithm parameter constants defined ($PARAM_DEFS definitions)"
    else
        warn "1.8 No algorithm parameter size constants found"
    fi
fi

# =============================================================================
# Dimension 2: Key Lifecycle
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 2" "Key Lifecycle"

    # 2.2: Secret types must derive Zeroize
    SECRET_NO_ZERO=$(grep -rn '#\[derive(' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -iE '(Secret|Private)' | grep -v 'Zeroize' | grep -v '/// ' | grep -v '// ' || true)
    SECRET_NO_ZERO=$(filter_prod_only "$SECRET_NO_ZERO")
    if [ -z "$SECRET_NO_ZERO" ]; then
        pass "2.2 All Secret/Private types derive Zeroize"
    else
        fail "2.2 Secret/Private types missing Zeroize derive:"
        echo "$SECRET_NO_ZERO" | head -5
    fi

    # 2.3: No Clone on secret key types
    CLONE_SECRETS=$(grep -rn 'derive.*Clone' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -iE '(secret|private)' | grep -v '/// ' | grep -v '// ' || true)
    CLONE_SECRETS=$(filter_prod_only "$CLONE_SECRETS")
    if [ -z "$CLONE_SECRETS" ]; then
        pass "2.3 No Clone on Secret/Private types"
    else
        warn "2.3 Clone derived on Secret/Private types (verify no unzeroized copies):"
        echo "$CLONE_SECRETS" | head -5
    fi

    # 2.4: No Debug that leaks key material
    DEBUG_LEAK_RAW=$(grep -rn 'derive.*Debug' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -iE 'secret|private|key' | grep -v 'REDACTED' || true)
    DEBUG_LEAK=$(filter_prod_only "$DEBUG_LEAK_RAW")
    if [ -z "$DEBUG_LEAK" ]; then
        pass "2.4 No Debug derives on secret/key types (or redacted)"
    else
        warn "2.4 Check these Debug derives on key-related types:"
        echo "$DEBUG_LEAK" | head -5
    fi

    # 2.5: into_bytes() returning bare Vec<u8> (should be Zeroizing<Vec<u8>> for secret types)
    BARE_VEC=$(prod_grep 'fn into_bytes.*Vec<u8>')
    if [ -z "$BARE_VEC" ]; then
        pass "2.5 No into_bytes() returning bare Vec<u8>"
    else
        warn "2.5 into_bytes() returns Vec<u8> (should be Zeroizing<Vec<u8>> for secrets):"
        echo "$BARE_VEC" | head -5
    fi

    # 2.7: Key length checks using < instead of != (allows oversized keys)
    KEY_LEN_LT=$(prod_grep 'key.*len().*<\|\.len().*<.*32\|\.len().*<.*16\|\.len().*<.*64')
    if [ -z "$KEY_LEN_LT" ]; then
        pass "2.7 No key length checks using < (should use != or ==)"
    else
        warn "2.7 Key length checks use < instead of != (may allow oversized keys):"
        echo "$KEY_LEN_LT" | head -5
    fi

    # 2.9: Serialize on key types (keys shouldn't be serializable unless required)
    SERIALIZE_KEYS=$(grep -rn 'derive.*Serialize' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -iE 'secret|private|key' | grep -v '/// ' | grep -v '// ' || true)
    SERIALIZE_KEYS=$(filter_prod_only "$SERIALIZE_KEYS")
    if [ -z "$SERIALIZE_KEYS" ]; then
        pass "2.9 No Serialize on secret/key types"
    else
        warn "2.9 Serialize derived on secret/key types (verify intentional):"
        echo "$SERIALIZE_KEYS" | head -5
    fi
fi

# =============================================================================
# Dimension 3: Memory & Side-Channel Safety
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 3" "Memory & Side-Channel Safety"

    # 3.1 / 13a.1: No unsafe blocks in production code
    UNSAFE_RAW=$(grep -rn 'unsafe\s*{' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    UNSAFE_PROD=$(filter_prod_only "$UNSAFE_RAW")
    if [ -z "$UNSAFE_PROD" ]; then
        pass "3.1 No unsafe blocks in production code"
    else
        fail "3.1 unsafe block found in production code:"
        echo "$UNSAFE_PROD" | head -5
    fi

    # 3.2: No non-constant-time secret comparisons in crypto code
    SECRET_EQ_RAW=$(grep -rn 'secret.*==' --include="*.rs" $SRC/primitives $SRC/unified_api $SRC/hybrid $SRC/tls $SRC/zkp 2>/dev/null \
        | grep -v '\.md' | grep -v 'ct_eq' || true)
    SECRET_EQ=$(filter_prod_only "$SECRET_EQ_RAW")
    if [ -z "$SECRET_EQ" ]; then
        pass "3.2 No non-constant-time secret comparisons in crypto code"
    else
        warn "3.2 Potential timing vulnerability — check these comparisons:"
        echo "$SECRET_EQ" | head -5
    fi

    # 3.5 / 13a.6: No Copy on types containing secrets
    COPY_SECRETS=$(grep -rn 'derive.*Copy' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -iE '(secret|private|key.*struct|shared)' | grep -v '/// ' | grep -v '// ' || true)
    COPY_SECRETS=$(filter_prod_only "$COPY_SECRETS")
    if [ -z "$COPY_SECRETS" ]; then
        pass "3.5 No Copy on types containing secrets"
    else
        warn "3.5 Copy derived on secret-containing types (prevents zeroization):"
        echo "$COPY_SECRETS" | head -5
    fi

    # 3.7/3.8: Log/error messages do not include key material
    KEY_IN_FORMAT=$(prod_grep 'format!.*secret\|format!.*private_key\|format!.*key_bytes')
    if [ -z "$KEY_IN_FORMAT" ]; then
        pass "3.7 No key material in format!/log strings"
    else
        warn "3.7 Possible key material in format strings (verify manually):"
        echo "$KEY_IN_FORMAT" | head -5
    fi
fi

# =============================================================================
# Dimension 4: API Boundary Safety
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 4" "API Boundary Safety"

    # 4.4 / 13a.10: No wildcard _ => match arms in production code (silently accepts invalid input)
    WILDCARD_RAW=$(grep -rn '_ =>' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    WILDCARD_PROD=$(filter_prod_only "$WILDCARD_RAW")
    if [ -z "$WILDCARD_PROD" ]; then
        pass "4.4 No wildcard _ => match arms in production code"
    else
        WCOUNT=$(echo "$WILDCARD_PROD" | wc -l | tr -d ' ')
        warn "4.4 $WCOUNT wildcard _ => match arm(s) (verify exhaustive handling):"
        echo "$WILDCARD_PROD" | head -5
    fi

    # 4.9: String parameters that should be &str
    STRING_PARAMS=$(prod_grep 'pub fn.*String)')
    if [ -z "$STRING_PARAMS" ]; then
        pass "4.9 No pub fn with owned String params (prefer &str)"
    else
        warn "4.9 pub fn takes owned String (consider &str):"
        echo "$STRING_PARAMS" | head -5
    fi

    # 4.10: pub(crate) fields on pub structs (incomplete public API)
    PUBCRATE_RAW=$(grep -rn 'pub(crate)' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '// ' | grep -v 'tests\.rs:' || true)
    PUBCRATE_PROD=$(filter_prod_only "$PUBCRATE_RAW")
    if [ -z "$PUBCRATE_PROD" ]; then
        pass "4.10 No pub(crate) fields (API fully public or private)"
    else
        PCCOUNT=$(echo "$PUBCRATE_PROD" | wc -l | tr -d ' ')
        warn "4.10 $PCCOUNT pub(crate) item(s) — verify documented workflows don't need them:"
        echo "$PUBCRATE_PROD" | head -5
    fi
fi

# =============================================================================
# Dimension 5: Error Handling
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 5" "Error Handling"

    # 5.3: No unwrap/expect in production code
    UNWRAP_RAW=$(grep -rn '\.unwrap()' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    UNWRAP_PROD=$(filter_prod_only "$UNWRAP_RAW")
    if [ -z "$UNWRAP_PROD" ]; then
        pass "5.3 No .unwrap() in production code"
    else
        fail "5.3 .unwrap() found in production code:"
        echo "$UNWRAP_PROD" | head -5
    fi

    EXPECT_RAW=$(grep -rn '\.expect(' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    EXPECT_PROD=$(filter_prod_only "$EXPECT_RAW")
    if [ -z "$EXPECT_PROD" ]; then
        pass "5.3 No .expect() in production code"
    else
        fail "5.3 .expect() found in production code:"
        echo "$EXPECT_PROD" | head -5
    fi

    # 5.5: No anyhow in library code (use specific error types)
    ANYHOW=$(grep -rn 'anyhow' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '// ' | grep -v 'tests\.rs:' || true)
    ANYHOW=$(filter_prod_only "$ANYHOW")
    if [ -z "$ANYHOW" ]; then
        pass "5.5 No anyhow in library code"
    else
        fail "5.5 anyhow found in library code (use specific error enums):"
        echo "$ANYHOW" | head -5
    fi

    # 5.8: No todo!/unimplemented! in production code
    TODO_RAW=$(grep -rn 'todo!\|unimplemented!' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    TODO_PROD=$(filter_prod_only "$TODO_RAW")
    if [ -z "$TODO_PROD" ]; then
        pass "5.8 No todo!/unimplemented! in production code"
    else
        fail "5.8 todo!/unimplemented! found in production code:"
        echo "$TODO_PROD" | head -5
    fi

    # 5.9: Error suppression patterns (.ok(), .unwrap_or, let _ =)
    SUPPRESS_RAW=$(grep -rn '\.ok()\|\.unwrap_or\|\.unwrap_or_default\|let _ =' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    SUPPRESS_PROD=$(filter_prod_only "$SUPPRESS_RAW")
    if [ -z "$SUPPRESS_PROD" ]; then
        pass "5.9 No error suppression patterns (.ok(), .unwrap_or, let _ =)"
    else
        SCOUNT=$(echo "$SUPPRESS_PROD" | wc -l | tr -d ' ')
        warn "5.9 $SCOUNT error suppression pattern(s) — verify intentional:"
        echo "$SUPPRESS_PROD" | head -5
    fi

    # 5.1: Silent Ok(()) — functions that always return Ok without doing meaningful work
    SILENT_OK=$(prod_grep 'Ok(())')
    if [ -z "$SILENT_OK" ]; then
        pass "5.1 No silent Ok(()) returns"
    else
        OKCOUNT=$(echo "$SILENT_OK" | wc -l | tr -d ' ')
        warn "5.1 $OKCOUNT Ok(()) return(s) — verify they're not placeholder implementations:"
        echo "$SILENT_OK" | head -5
    fi

    # 5.2: TODO/FIXME comments in production (completeness concern)
    FIXME_RAW=$(grep -rn 'TODO\|FIXME\|HACK\|XXX' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' \
        | grep -v 'tests\.rs:' || true)
    FIXME_PROD=$(filter_prod_only "$FIXME_RAW")
    if [ -z "$FIXME_PROD" ]; then
        pass "5.2 No TODO/FIXME/HACK/XXX comments in production code"
    else
        FCOUNT=$(echo "$FIXME_PROD" | wc -l | tr -d ' ')
        warn "5.2 $FCOUNT TODO/FIXME comment(s) in production code:"
        echo "$FIXME_PROD" | head -5
    fi

    # 5.6: Context erasure in map_err (loses original error info)
    CONTEXT_ERASURE=$(prod_grep 'map_err(|_|')
    if [ -z "$CONTEXT_ERASURE" ]; then
        pass "5.6 No bare map_err(|_|) context erasure"
    else
        CECOUNT=$(echo "$CONTEXT_ERASURE" | wc -l | tr -d ' ')
        warn "5.6 $CECOUNT map_err(|_|) pattern(s) — preserves no error context:"
        echo "$CONTEXT_ERASURE" | head -5
    fi
fi

# =============================================================================
# Dimension 6: Standards Conformance (FIPS 140-3)
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 6" "FIPS Conformance"

    # 6.1: FIPS feature gates exist in source
    FIPS_GATES=$(grep -rn 'feature = "fips"' --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$FIPS_GATES" -gt 0 ]; then
        pass "6.1 FIPS feature has $FIPS_GATES cfg gate(s) in source"
    else
        fail "6.1 No FIPS feature gates found in source code"
    fi

    # 6.3: Power-up KAT self-tests exist
    KAT_FUNS=$(grep -rn 'fn kat_\|fn self_test\|fn power_up' --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$KAT_FUNS" -gt 0 ]; then
        pass "6.3 KAT/self-test functions found ($KAT_FUNS definitions)"
    else
        warn "6.3 No KAT/self-test functions found in source"
    fi

    # 6.11: Non-FIPS algorithms gated out in FIPS mode
    NON_FIPS_GATE=$(grep -rn 'cfg(not(feature = "fips"))' --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$NON_FIPS_GATE" -gt 0 ]; then
        pass "6.11 Non-FIPS modules gated with cfg(not(feature = \"fips\")) ($NON_FIPS_GATE gates)"
    else
        warn "6.11 No cfg(not(feature = \"fips\")) gates found — non-FIPS algorithms may be accessible in FIPS mode"
    fi

    # 6.8: verify_operational guard exists
    VERIFY_OP=$(grep -rn 'verify_operational' --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$VERIFY_OP" -gt 0 ]; then
        pass "6.8 verify_operational() called ($VERIFY_OP occurrences)"
    else
        warn "6.8 No verify_operational() guard found in crypto entry points"
    fi

    # 6.10: FIPS Security Policy document exists
    if [ -f docs/FIPS_SECURITY_POLICY.md ]; then
        pass "6.10 FIPS Security Policy document exists"
    else
        warn "6.10 docs/FIPS_SECURITY_POLICY.md not found"
    fi
fi

# =============================================================================
# Dimension 7: Documentation Accuracy
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 7" "Documentation Accuracy"

    # 7.5: Check for ignored doctests (rust,ignore bypasses compilation)
    IGNORED_DOCTESTS=$(grep -rn 'rust,ignore\|```ignore' --include="*.rs" $SRC/ 2>/dev/null || true)
    if [ -z "$IGNORED_DOCTESTS" ]; then
        pass "7.5 No ignored doctests (all examples compile-checked)"
    else
        IDCOUNT=$(echo "$IGNORED_DOCTESTS" | wc -l | tr -d ' ')
        warn "7.5 $IDCOUNT ignored doctest(s) — prefer no_run over ignore:"
        echo "$IGNORED_DOCTESTS" | head -5
    fi

    # 7.11 / 12.15: Verify internal markdown links resolve
    BROKEN_LINKS=""
    for md in README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md; do
        if [ -f "$md" ]; then
            LINKS=$(grep -oE '\]\([^http#][^)]*\.md[^)]*\)' "$md" 2>/dev/null | sed 's/\](//;s/)$//' || true)
            for link in $LINKS; do
                # Strip anchor fragments (#section) before checking file existence
                file_path="${link%%#*}"
                if [ ! -f "$file_path" ]; then
                    BROKEN_LINKS="${BROKEN_LINKS}${md} -> ${link}"$'\n'
                fi
            done
        fi
    done
    # Also check docs/ directory
    for md in docs/*.md; do
        if [ -f "$md" ]; then
            LINKS=$(grep -oE '\]\([^http#][^)]*\.md[^)]*\)' "$md" 2>/dev/null | sed 's/\](//;s/)$//' || true)
            for link in $LINKS; do
                # Strip anchor fragments (#section) before checking file existence
                file_path="${link%%#*}"
                # Resolve relative to the doc file's directory
                target="$(dirname "$md")/$file_path"
                if [ ! -f "$target" ] && [ ! -f "$file_path" ]; then
                    BROKEN_LINKS="${BROKEN_LINKS}${md} -> ${link}"$'\n'
                fi
            done
        fi
    done
    BROKEN_LINKS=$(echo -n "$BROKEN_LINKS" | sed '/^$/d')
    if [ -z "$BROKEN_LINKS" ]; then
        pass "7.11 All internal markdown links resolve"
    else
        BLCOUNT=$(echo "$BROKEN_LINKS" | wc -l | tr -d ' ')
        warn "7.11 $BLCOUNT broken internal link(s):"
        echo "$BROKEN_LINKS" | head -5
    fi

    # 7.12: Version consistency — doc versions must match workspace Cargo.toml
    WORKSPACE_VER=$(grep -m1 '^version = ' Cargo.toml 2>/dev/null | sed 's/version = "//;s/"//')
    if [ -n "$WORKSPACE_VER" ]; then
        VER_STALE=""
        # Check FIPS Security Policy module version
        if [ -f docs/FIPS_SECURITY_POLICY.md ]; then
            FIPS_VER=$(grep -m1 'Module Version.*[0-9]' docs/FIPS_SECURITY_POLICY.md 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
            if [ -n "$FIPS_VER" ] && [ "$FIPS_VER" != "$WORKSPACE_VER" ]; then
                VER_STALE="${VER_STALE}  FIPS_SECURITY_POLICY.md: $FIPS_VER (expected $WORKSPACE_VER)\n"
            fi
        fi
        # Check API documentation version
        if [ -f docs/API_DOCUMENTATION.md ]; then
            API_VER=$(grep -m1 'Version.*[0-9]\|version.*[0-9]' docs/API_DOCUMENTATION.md 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
            if [ -n "$API_VER" ] && [ "$API_VER" != "$WORKSPACE_VER" ]; then
                VER_STALE="${VER_STALE}  API_DOCUMENTATION.md: $API_VER (expected $WORKSPACE_VER)\n"
            fi
        fi
        # Check SECURITY.md supported version
        if [ -f SECURITY.md ]; then
            SEC_VER=$(grep -m1 "${WORKSPACE_VER%.*}" SECURITY.md 2>/dev/null || true)
            if [ -z "$SEC_VER" ]; then
                VER_STALE="${VER_STALE}  SECURITY.md: no ${WORKSPACE_VER%.*}.x version line found\n"
            fi
        fi
        if [ -z "$VER_STALE" ]; then
            pass "7.12 Doc versions match workspace version ($WORKSPACE_VER)"
        else
            warn "7.12 Version mismatch in docs (workspace is $WORKSPACE_VER):"
            echo -e "$VER_STALE" | head -5
        fi
    fi

    # 7.13: Kani proof count — docs must match actual #[kani::proof] count in source
    ACTUAL_PROOFS=$(grep -rc '#\[kani::proof\]' $SRC/types/*.rs 2>/dev/null | awk -F: '{s+=$2}END{print s}')
    ACTUAL_PROOFS="${ACTUAL_PROOFS:-0}"
    PROOF_STALE=""
    for doc in README.md SECURITY.md docs/FORMAL_VERIFICATION.md docs/DESIGN.md; do
        if [ -f "$doc" ]; then
            # Look for the total count: largest number near "proof"/"Kani"/"bounded model"
            # Use max to avoid matching sub-category counts like "3 proofs" in breakdown
            DOC_COUNT=$(grep -oE '[0-9]+ (bounded model|Kani|kani|proofs)' "$doc" 2>/dev/null \
                | grep -oE '^[0-9]+' | sort -rn | head -1 || true)
            if [ -n "$DOC_COUNT" ] && [ "$DOC_COUNT" != "$ACTUAL_PROOFS" ]; then
                PROOF_STALE="${PROOF_STALE}  $doc: claims $DOC_COUNT proofs (actual: $ACTUAL_PROOFS)\n"
            fi
        fi
    done
    if [ -z "$PROOF_STALE" ]; then
        pass "7.13 Kani proof count in docs matches source ($ACTUAL_PROOFS proofs)"
    else
        warn "7.13 Kani proof count mismatch:"
        echo -e "$PROOF_STALE"
    fi

    # 7.14: Backend version alignment — aws-lc-rs version in docs matches Cargo.lock
    if [ -f Cargo.lock ]; then
        LOCK_AWSLC=$(grep -A1 '^name = "aws-lc-rs"' Cargo.lock 2>/dev/null \
            | grep 'version' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
        if [ -n "$LOCK_AWSLC" ]; then
            AWSLC_STALE=""
            for doc in docs/ALGORITHM_SELECTION.md docs/FIPS_SECURITY_POLICY.md; do
                if [ -f "$doc" ]; then
                    DOC_AWSLC=$(grep -oE 'aws-lc-rs[^0-9]*[0-9]+\.[0-9]+\.[0-9]+' "$doc" 2>/dev/null \
                        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u || true)
                    for v in $DOC_AWSLC; do
                        if [ "$v" != "$LOCK_AWSLC" ]; then
                            AWSLC_STALE="${AWSLC_STALE}  $doc: references aws-lc-rs $v (lock: $LOCK_AWSLC)\n"
                        fi
                    done
                fi
            done
            if [ -z "$AWSLC_STALE" ]; then
                pass "7.14 aws-lc-rs version in docs matches Cargo.lock ($LOCK_AWSLC)"
            else
                warn "7.14 aws-lc-rs version mismatch in docs:"
                echo -e "$AWSLC_STALE"
            fi
        fi
    fi
fi

# =============================================================================
# Dimension 8: Code Quality (compile + lint + test quality)
# =============================================================================
section "Dim 8" "Code Quality"

if ! cargo fmt --all -- --check > /dev/null 2>&1; then
    fail "8.x cargo fmt check failed"
else
    pass "8.x Code formatted (cargo fmt)"
fi

if ! cargo clippy --workspace --all-targets --all-features -- -D warnings > /dev/null 2>&1; then
    fail "8.x Clippy warnings found"
else
    pass "8.x Clippy clean"
fi

if [ "$QUICK" = false ]; then
    # 8.4: No hardcoded temp paths in tests
    HARDCODED_PATHS=$(grep -rn '/tmp/claude\|/tmp/' --include="*.rs" tests/ $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '// ' || true)
    if [ -z "$HARDCODED_PATHS" ]; then
        pass "8.4 No hardcoded /tmp paths in tests (use std::env::temp_dir())"
    else
        HCOUNT=$(echo "$HARDCODED_PATHS" | wc -l | tr -d ' ')
        warn "8.4 $HCOUNT hardcoded /tmp path(s) — use std::env::temp_dir():"
        echo "$HARDCODED_PATHS" | head -5
    fi

    # 8.6: No #[ignore] without documented reason
    IGNORED_TESTS=$(grep -rn '#\[ignore' --include="*.rs" $SRC/ tests/ 2>/dev/null || true)
    if [ -z "$IGNORED_TESTS" ]; then
        pass "8.6 No #[ignore] tests without justification"
    else
        ICOUNT=$(echo "$IGNORED_TESTS" | wc -l | tr -d ' ')
        warn "8.6 $ICOUNT #[ignore] test(s) — each needs documented reason:"
        echo "$IGNORED_TESTS" | head -5
    fi
fi

# =============================================================================
# Dimension 9: Build & Infrastructure
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 9" "Build & Infrastructure"

    # 9.x: missing_docs check (enforced at compile time via workspace lints)
    if cargo check --workspace --all-features 2>&1 | grep -q "missing_docs"; then
        fail "9.x Missing documentation on public items"
    else
        pass "9.x missing_docs check passes (enforced at compile time)"
    fi

    # 9.3: Pre-push hooks installed
    HOOKS_PATH=$(git config core.hooksPath 2>/dev/null || true)
    if [ -n "$HOOKS_PATH" ] && [ -f "$HOOKS_PATH/pre-push" ]; then
        pass "9.3 Pre-push hook installed (path: $HOOKS_PATH)"
    elif [ -f ".git/hooks/pre-push" ]; then
        pass "9.3 Pre-push hook installed (.git/hooks/)"
    else
        warn "9.3 No pre-push hook found — run ./hooks/install.sh"
    fi

    # 9.5: No target-cpu=native in CI
    NATIVE_CPU=$(grep -rn 'target-cpu=native' --include="*.yml" --include="*.yaml" .github/ 2>/dev/null || true)
    if [ -z "$NATIVE_CPU" ]; then
        pass "9.5 No target-cpu=native in CI workflows"
    else
        fail "9.5 target-cpu=native in CI (causes SIGILL on different hardware):"
        echo "$NATIVE_CPU" | head -3
    fi
fi

# =============================================================================
# Dimension 10: Supply Chain — Dependencies & Feature Flags
# =============================================================================
section "Dim 10" "Supply Chain & Dependencies"

# 10.1: cargo audit
if command -v cargo-audit > /dev/null 2>&1; then
    if cargo audit --deny warnings > /dev/null 2>&1; then
        pass "10.1 cargo audit clean"
    else
        warn "10.1 cargo audit found advisories"
    fi
else
    warn "10.1 cargo-audit not installed, skipping"
fi

# 10.2: cargo deny
if command -v cargo-deny > /dev/null 2>&1; then
    if cargo deny check all > /dev/null 2>&1; then
        pass "10.2 cargo deny clean"
    else
        warn "10.2 cargo deny found issues"
    fi
else
    warn "10.2 cargo-deny not installed, skipping"
fi

# 10.3: Banned crates check (libc, nix per deny.toml)
BANNED_IMPORTS=$(grep -rn 'use libc\|use nix\b\|extern crate libc\|extern crate nix' --include="*.rs" $SRC/ 2>/dev/null || true)
if [ -z "$BANNED_IMPORTS" ]; then
    pass "10.3 No banned crate imports (libc, nix)"
else
    fail "10.3 Banned crate import found:"
    echo "$BANNED_IMPORTS" | head -3
fi

# 10.4: Lock file committed
if [ -f Cargo.lock ]; then
    pass "10.4 Cargo.lock exists"
else
    fail "10.4 Cargo.lock missing"
fi

# 10.5: Unused dependencies (basic grep check)
if [ "$QUICK" = false ]; then
    section "Dim 10" "Unused Dependency Check"

    DEPS=$(sed -n '/^\[dependencies\]/,/^\[/p' latticearc/Cargo.toml \
        | grep -E '^\w' | grep -v 'optional' | sed 's/ *=.*//' | sort -u)

    for dep in $DEPS; do
        crate_name=$(echo "$dep" | sed 's/-/_/g')
        USAGE=$(grep -r "$crate_name" --include="*.rs" $SRC/ 2>/dev/null | grep -v '^\s*//' | head -1 || true)
        if [ -z "$USAGE" ]; then
            fail "10.5 Dependency '$dep' may be unused (no '$crate_name' reference in src/)"
        fi
    done
fi

# 10.10: Every feature flag has matching cfg gates
section "Dim 10" "Feature Flag Audit"

FEATURES=$(sed -n '/^\[features\]/,/^\[/p' latticearc/Cargo.toml \
    | grep -E '^\w' | sed 's/ *=.*//' | grep -v '^default$')

for feature in $FEATURES; do
    CFG_COUNT=$(grep -r "feature = \"$feature\"" --include="*.rs" $SRC/ 2>/dev/null | wc -l | tr -d ' ')
    if [ "$CFG_COUNT" -eq 0 ]; then
        fail "10.10 Feature '$feature' has 0 cfg gates in source code (DEAD)"
    else
        pass "10.10 Feature '$feature' has $CFG_COUNT cfg gate(s)"
    fi
done

# 10.11: Orphan cfg gates
section "Dim 10" "Orphan cfg Gate Check"

DEFINED_FEATURES=$(sed -n '/^\[features\]/,/^\[/p' latticearc/Cargo.toml \
    | grep -E '^\w' | sed 's/ *=.*//' | sort -u)
CODE_FEATURES=$(grep -roh 'feature = "[a-zA-Z0-9_-]*"' $SRC/ --include="*.rs" 2>/dev/null \
    | sed 's/feature = "//;s/"//' | sort -u)

FEATURE_WHITELIST="avx2 aes neon"
ORPHANS_FOUND=false
for cf in $CODE_FEATURES; do
    if echo "$FEATURE_WHITELIST" | grep -qw "$cf"; then
        continue
    fi
    if ! echo "$DEFINED_FEATURES" | grep -qx "$cf"; then
        fail "10.11 cfg(feature = \"$cf\") in code but not in [features] — orphan or mismatch"
        ORPHANS_FOUND=true
    fi
done
if [ "$ORPHANS_FOUND" = false ]; then
    pass "10.11 No orphan cfg gates found"
fi

# 10.12: Feature flags documented in lib.rs or README
if [ "$QUICK" = false ]; then
    UNDOCUMENTED_FEATURES=""
    for feature in $FEATURES; do
        # Check if feature is mentioned in lib.rs docs or README
        IN_LIB=$(grep -c "$feature" $SRC/lib.rs 2>/dev/null || true)
        IN_LIB="${IN_LIB:-0}"
        IN_README=$(grep -c "$feature" README.md 2>/dev/null || true)
        IN_README="${IN_README:-0}"
        if [ "$IN_LIB" -eq 0 ] && [ "$IN_README" -eq 0 ]; then
            UNDOCUMENTED_FEATURES="${UNDOCUMENTED_FEATURES}${feature} "
        fi
    done
    if [ -z "$UNDOCUMENTED_FEATURES" ]; then
        pass "10.12 All features documented in lib.rs or README"
    else
        warn "10.12 Undocumented features (not in lib.rs or README): $UNDOCUMENTED_FEATURES"
    fi
fi

# =============================================================================
# Dimension 12: External Documentation Accuracy
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 12" "Documentation Accuracy"

    # 12.18: Check for stale crate references (both dash and underscore style)
    # Dash-style: crate names in Cargo.toml, markdown text (arc-core, arc-primitives)
    # Underscore-style: Rust imports in code examples (arc_core::, arc_primitives::)
    STALE_REFS=$(grep -rn 'arc-types\|arc-prelude\|arc-primitives\|arc-hybrid\|arc-core\b\|arc-tls\|arc-validation\|arc-zkp\|arc-perf\|arc-tests\|arc_core::\|arc_types::\|arc_prelude::\|arc_primitives::\|arc_hybrid::\|arc_tls::\|arc_validation::\|arc_zkp::\|arc_perf::' \
        --include="*.md" --include="*.yml" --include="*.yaml" . 2>/dev/null \
        | grep -v 'node_modules' | grep -v '.git/' \
        | grep -v 'CHANGELOG' | grep -v 'CODE_AUDIT' | grep -v 'SESSION_SUMMARY' \
        | grep -v 'latticearc-tests' || true)
    if [ -z "$STALE_REFS" ]; then
        pass "12.18 No stale crate references in docs/CI"
    else
        SRCOUNT=$(echo "$STALE_REFS" | wc -l | tr -d ' ')
        warn "12.18 $SRCOUNT stale crate reference(s) found (old arc-*/arc_* names):"
        echo "$STALE_REFS" | head -10
    fi

    # 12.2: Aspirational language in documentation
    ASPIRATIONAL=$(grep -rn 'may support\|can be configured\|will be added\|coming soon\|planned\|TODO' \
        --include="*.md" . 2>/dev/null \
        | grep -v 'CHANGELOG' | grep -v 'CODE_AUDIT' | grep -v 'SESSION_SUMMARY' \
        | grep -v 'node_modules' | grep -v '.git/' | grep -v '.claude/' || true)
    if [ -z "$ASPIRATIONAL" ]; then
        pass "12.2 No aspirational language in documentation"
    else
        ACOUNT=$(echo "$ASPIRATIONAL" | wc -l | tr -d ' ')
        warn "12.2 $ACOUNT aspirational phrase(s) in docs (verify accurate):"
        echo "$ASPIRATIONAL" | head -5
    fi

    # 12.7: Stale PR references
    STALE_PR=$(grep -rn 'under review\|pending review\|awaiting review' \
        --include="*.md" . 2>/dev/null \
        | grep -v 'CODE_AUDIT' | grep -v '.git/' | grep -v '.claude/' || true)
    if [ -z "$STALE_PR" ]; then
        pass "12.7 No stale PR review references"
    else
        warn "12.7 Stale PR references found:"
        echo "$STALE_PR" | head -5
    fi

    # 12.19: Date freshness — "Last Updated" / "Date" in docs should not be >30 days stale
    # compared to the last git commit that touched that file
    DATE_STALE=""
    NOW_EPOCH=$(date +%s)
    for doc in docs/API_DOCUMENTATION.md docs/FIPS_SECURITY_POLICY.md docs/ALGORITHM_SELECTION.md; do
        if [ -f "$doc" ]; then
            # Extract date from doc (formats: "February 20, 2026" or "2026-02-20")
            DOC_DATE=$(grep -iE 'last updated|^date:|^\*\*date\*\*' "$doc" 2>/dev/null | head -1 || true)
            if [ -z "$DOC_DATE" ]; then
                DOC_DATE=$(grep -iE 'February|January|March|April|May|June|July|August|September|October|November|December' "$doc" 2>/dev/null \
                    | grep -iE '[0-9]{1,2},? 202[0-9]' | head -1 || true)
            fi
            if [ -n "$DOC_DATE" ]; then
                # Extract ISO-ish date for comparison
                DOC_ISO=$(echo "$DOC_DATE" | grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' | head -1 || true)
                if [ -z "$DOC_ISO" ]; then
                    # Try "Month Day, Year" format
                    DOC_ISO=$(echo "$DOC_DATE" | grep -oE '(January|February|March|April|May|June|July|August|September|October|November|December) [0-9]{1,2},? 20[0-9]{2}' | head -1 || true)
                    if [ -n "$DOC_ISO" ]; then
                        DOC_ISO=$(date -j -f "%B %d, %Y" "$(echo "$DOC_ISO" | sed 's/,//')" "+%Y-%m-%d" 2>/dev/null \
                            || date -j -f "%B %d %Y" "$(echo "$DOC_ISO" | sed 's/,//')" "+%Y-%m-%d" 2>/dev/null || true)
                    fi
                fi
                if [ -n "$DOC_ISO" ]; then
                    DOC_EPOCH=$(date -j -f "%Y-%m-%d" "$DOC_ISO" "+%s" 2>/dev/null || true)
                    if [ -n "$DOC_EPOCH" ]; then
                        DAYS_OLD=$(( (NOW_EPOCH - DOC_EPOCH) / 86400 ))
                        if [ "$DAYS_OLD" -gt 30 ]; then
                            DATE_STALE="${DATE_STALE}  $doc: date $DOC_ISO is ${DAYS_OLD} days old\n"
                        fi
                    fi
                fi
            fi
        fi
    done
    if [ -z "$DATE_STALE" ]; then
        pass "12.19 Doc dates are fresh (within 30 days)"
    else
        warn "12.19 Stale dates in documentation:"
        echo -e "$DATE_STALE"
    fi

    # 12.20: CHANGELOG has entry for current version
    if [ -f CHANGELOG.md ]; then
        WORKSPACE_VER_CL=$(grep -m1 '^version = ' Cargo.toml 2>/dev/null | sed 's/version = "//;s/"//')
        if grep -q "\[${WORKSPACE_VER_CL}\]" CHANGELOG.md 2>/dev/null; then
            pass "12.20 CHANGELOG has entry for current version ($WORKSPACE_VER_CL)"
        else
            warn "12.20 CHANGELOG missing entry for version $WORKSPACE_VER_CL"
        fi
    fi
fi

# =============================================================================
# Dimension 13a: Secure Coding Patterns
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 13a" "Secure Coding Patterns"

    # 13a.2: Direct array indexing in production code (should use .get())
    # Pattern: identifier[identifier] or identifier[number] — excludes attributes, types, slices
    INDEX_RAW=$(grep -rn '[a-z_][a-z0-9_]*\[[a-z_][a-z0-9_]*\]' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' \
        | grep -v '#\[' | grep -v 'feature\[' | grep -v 'cfg\[' \
        | grep -v '\.get(' || true)
    INDEX_PROD=$(filter_prod_only "$INDEX_RAW")
    if [ -z "$INDEX_PROD" ]; then
        pass "13a.2 No direct array indexing in production (uses .get())"
    else
        IXCOUNT=$(echo "$INDEX_PROD" | wc -l | tr -d ' ')
        warn "13a.2 $IXCOUNT direct index access(es) — prefer .get() with error handling:"
        echo "$INDEX_PROD" | head -5
    fi

    # 13a.4: Unchecked as casts (truncation/precision loss)
    AS_CASTS=$(prod_grep ' as u8\| as u16\| as u32\| as i8\| as i16\| as i32\| as usize')
    if [ -z "$AS_CASTS" ]; then
        pass "13a.4 No unchecked as casts (u8/u16/u32/i8/i16/i32/usize)"
    else
        ACCOUNT=$(echo "$AS_CASTS" | wc -l | tr -d ' ')
        warn "13a.4 $ACCOUNT potential truncating as cast(s) — verify safe:"
        echo "$AS_CASTS" | head -5
    fi

    # 13a.11: Bare Vec<u8> for secret data (should be Zeroizing<Vec<u8>>)
    # Only check secret/private key functions, NOT public key functions
    BARE_SECRET_VEC=$(prod_grep 'fn.*secret.*-> Vec<u8>\|fn.*private.*-> Vec<u8>' | grep -v 'public_key' || true)
    if [ -z "$BARE_SECRET_VEC" ]; then
        pass "13a.11 No bare Vec<u8> returns for secret/private key functions"
    else
        fail "13a.11 Secret/private function returns bare Vec<u8> (use Zeroizing<Vec<u8>>):"
        echo "$BARE_SECRET_VEC" | head -5
    fi

    # 13a.14: No global mutable state in crypto paths
    STATIC_MUT=$(prod_grep 'static mut\|lazy_static')
    if [ -z "$STATIC_MUT" ]; then
        pass "13a.14 No static mut / lazy_static in production code"
    else
        fail "13a.14 Global mutable state in production code (thread safety risk):"
        echo "$STATIC_MUT" | head -5
    fi

    # 13a.8: No unsafe-adjacent patterns
    UNSAFE_ADJ=$(prod_grep 'from_utf8_unchecked\|transmute')
    if [ -z "$UNSAFE_ADJ" ]; then
        pass "13a.8 No unsafe-adjacent patterns (transmute, from_utf8_unchecked)"
    else
        fail "13a.8 Unsafe-adjacent pattern in production code:"
        echo "$UNSAFE_ADJ" | head -5
    fi
fi

# =============================================================================
# Dimension 13b: Coding Style Consistency
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 13b" "Coding Style"

    # 13b.12: No commented-out code in production
    COMMENTED_CODE=$(grep -rn '^\s*//\s*\(fn \|let \|pub \|impl \|struct \|enum \|use \)' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v 'tests\.rs:' || true)
    COMMENTED_CODE=$(filter_prod_only "$COMMENTED_CODE")
    if [ -z "$COMMENTED_CODE" ]; then
        pass "13b.12 No commented-out code in production"
    else
        CCCOUNT=$(echo "$COMMENTED_CODE" | wc -l | tr -d ' ')
        warn "13b.12 $CCCOUNT commented-out code line(s) — delete dead code:"
        echo "$COMMENTED_CODE" | head -5
    fi

    # 13b.14: All crates use workspace lints
    MISSING_WORKSPACE_LINTS=""
    if [ -f latticearc/Cargo.toml ]; then
        if ! grep -q 'workspace = true' latticearc/Cargo.toml 2>/dev/null; then
            MISSING_WORKSPACE_LINTS="latticearc"
        fi
    fi
    if [ -f tests/Cargo.toml ]; then
        if ! grep -q 'workspace = true' tests/Cargo.toml 2>/dev/null; then
            MISSING_WORKSPACE_LINTS="$MISSING_WORKSPACE_LINTS tests"
        fi
    fi
    if [ -z "$MISSING_WORKSPACE_LINTS" ]; then
        pass "13b.14 All crates use workspace lints"
    else
        warn "13b.14 Missing workspace lint inheritance: $MISSING_WORKSPACE_LINTS"
    fi
fi

# =============================================================================
# Dimension 13c: Cryptographic Test Methodology (subset)
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 13c" "Crypto Test Methodology"

    # 13c.14: Fuzz targets exist
    if [ -d fuzz/fuzz_targets ]; then
        FUZZ_COUNT=$(ls fuzz/fuzz_targets/*.rs 2>/dev/null | wc -l | tr -d ' ')
        if [ "$FUZZ_COUNT" -gt 10 ]; then
            pass "13c.14 $FUZZ_COUNT fuzz targets found"
        else
            warn "13c.14 Only $FUZZ_COUNT fuzz targets — expected >10 for full API coverage"
        fi
    else
        fail "13c.14 No fuzz/fuzz_targets/ directory found"
    fi

    # 13c.17: Fuzz targets should not use unwrap/expect (must handle all errors)
    if [ -d fuzz/fuzz_targets ]; then
        FUZZ_UNWRAP=$(grep -rn '\.unwrap()\|\.expect(' --include="*.rs" fuzz/ 2>/dev/null || true)
        if [ -z "$FUZZ_UNWRAP" ]; then
            pass "13c.17 Fuzz targets handle errors gracefully (no unwrap/expect)"
        else
            FUCOUNT=$(echo "$FUZZ_UNWRAP" | wc -l | tr -d ' ')
            warn "13c.17 $FUCOUNT unwrap/expect in fuzz targets (should use Result):"
            echo "$FUZZ_UNWRAP" | head -5
        fi
    fi

    # 13c.27: Assertions without descriptive messages in test files
    # Uses 4-line lookahead to handle multiline assertions with messages on subsequent lines
    ASSERT_MATCHES=$(grep -rn 'assert!\|assert_eq!\|assert_ne!' --include="*.rs" tests/ 2>/dev/null \
        | grep -v '/// ' | grep -v '// ' | grep -v 'prop_assert' || true)
    BARE_ASSERTS=""
    if [ -n "$ASSERT_MATCHES" ]; then
        while IFS=: read -r _file _linenum _rest; do
            [ -z "$_linenum" ] && continue
            _end=$((_linenum + 3)) || continue
            if ! sed -n "${_linenum},${_end}p" "$_file" 2>/dev/null | grep -qE '(, "|[[:space:]]+"[A-Za-z0-9])'; then
                BARE_ASSERTS="${BARE_ASSERTS}${_file}:${_linenum}:${_rest}
"
            fi
        done <<< "$ASSERT_MATCHES"
    fi
    BARE_ASSERTS=$(printf '%s' "$BARE_ASSERTS" | sed '/^$/d' | head -20 || true)
    if [ -z "$BARE_ASSERTS" ]; then
        pass "13c.27 All assertions have descriptive messages"
    else
        BACOUNT=$(printf '%s\n' "$BARE_ASSERTS" | wc -l | tr -d ' ')
        warn "13c.27 $BACOUNT assertion(s) without descriptive message:"
        printf '%s\n' "$BARE_ASSERTS" | head -5
    fi
fi

# =============================================================================
# Dimension 13: Secure Coding — Production Code Checks
# =============================================================================
if [ "$QUICK" = false ]; then
    section "Dim 13" "Secure Coding Practices"

    # No println/eprintln in library code (excluding test modules, doc comments, debug_assertions)
    PRINT_RAW=$(grep -rn 'println!\|eprintln!' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    PRINT_PROD=$(filter_prod_only "$PRINT_RAW")
    PRINT_PROD=$(filter_debug_assertions "$PRINT_PROD")
    if [ -z "$PRINT_PROD" ]; then
        pass "13.x No println!/eprintln! in library code"
    else
        fail "13.x println!/eprintln! found in library code:"
        echo "$PRINT_PROD" | head -5
    fi

    # No dbg! in production code
    DBG_RAW=$(grep -rn 'dbg!' --include="*.rs" $SRC/ 2>/dev/null \
        | grep -v '/// ' | grep -v '//!' | grep -v '// ' \
        | grep -v 'tests\.rs:' || true)
    DBG_PROD=$(filter_prod_only "$DBG_RAW")
    if [ -z "$DBG_PROD" ]; then
        pass "13.x No dbg! in production code"
    else
        fail "13.x dbg! found in production code:"
        echo "$DBG_PROD" | head -5
    fi
fi

# =============================================================================
# Summary
# =============================================================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
TOTAL=$((PASSES + FAILURES + WARNINGS))

echo ""
echo "============================================"
if [ "$FAILURES" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}AUDIT PASSED${NC} — $TOTAL checks: $PASSES pass, 0 failures, 0 warnings (${ELAPSED}s)"
elif [ "$FAILURES" -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}AUDIT PASSED WITH WARNINGS${NC} — $TOTAL checks: $PASSES pass, 0 failures, $WARNINGS warning(s) (${ELAPSED}s)"
else
    echo -e "${RED}${BOLD}AUDIT FAILED${NC} — $TOTAL checks: $PASSES pass, $FAILURES failure(s), $WARNINGS warning(s) (${ELAPSED}s)"
fi
echo "============================================"
echo ""
if [ "$QUICK" = true ]; then
    echo "  (Quick mode — run without --quick for full 13-dimension audit)"
fi

exit $FAILURES
