#!/usr/bin/env bash
# Resource-limits coverage gate.
#
# Fails CI if a new `pub fn` taking `&[u8]` appears in
# latticearc/src/{hybrid,primitives/{kem,sig,aead,mac,kdf},unified_api/convenience}
# without either:
#   - calling a `validate_{encryption_size,decryption_size,signature_size,key_derivation_count}`
#     function in its body, OR
#   - being documented as intentionally uncapped in docs/RESOURCE_LIMITS_COVERAGE.md
#
# This is a grep-level gate, not a semantic one. It catches the common case:
# "Someone added a new public crypto fn and forgot the size check." It cannot
# detect indirect dispatch; for that, see the proptest suite in
# tests/tests/proptest_invariants.rs and the allocation budget tests in
# tests/tests/allocation_budgets.rs.

set -euo pipefail

# Resolve repo root regardless of where the script is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COVERAGE_DOC="docs/RESOURCE_LIMITS_COVERAGE.md"
if [ ! -f "$COVERAGE_DOC" ]; then
  echo "FAIL: missing $COVERAGE_DOC — the coverage audit must exist."
  exit 1
fi

# Modules in scope.
SCOPE=(
  "latticearc/src/hybrid"
  "latticearc/src/primitives/kem"
  "latticearc/src/primitives/sig"
  "latticearc/src/primitives/aead"
  "latticearc/src/primitives/mac"
  "latticearc/src/primitives/kdf"
  "latticearc/src/unified_api/convenience"
)

VIOLATIONS=0
TOTAL=0
DETAIL=$(mktemp)
STALE=$(mktemp)
STALE_MISSES="${STALE}.misses"
# Single trap covers every tempfile we create; declared once so a later `trap`
# doesn't silently replace the earlier cleanup.
trap 'rm -f "$DETAIL" "$STALE" "$STALE_MISSES" "${STALE}.candidates"' EXIT

# A `pub fn` with a `&[u8]` parameter.
# Body check is permissive: the file must reference one of the validators
# anywhere OR the function name must appear in the coverage doc.
for dir in "${SCOPE[@]}"; do
  if [ ! -d "$dir" ]; then continue; fi
  while IFS= read -r file; do
    # Extract `pub fn NAME(` lines that reference `&[u8]`.
    while IFS= read -r fn_name; do
      TOTAL=$((TOTAL + 1))
      if grep -qE 'validate_(encryption_size|decryption_size|signature_size|key_derivation_count)' "$file"; then
        continue
      fi
      if grep -qE "\b${fn_name}\b" "$COVERAGE_DOC"; then
        continue
      fi
      echo "$file :: $fn_name" >> "$DETAIL"
      VIOLATIONS=$((VIOLATIONS + 1))
    done < <(
      # Join continuation lines so a `pub fn` signature spanning multiple
      # lines becomes a single record, then grep for &[u8] and extract the
      # function name. POSIX-awk only (no match() with array arg).
      awk '
        /^pub fn / {
          sig = $0
          while (sig !~ /\{/ && sig !~ /;/) {
            if ((getline line) <= 0) break
            sig = sig " " line
          }
          if (sig ~ /&\[u8\]/) print sig
        }
      ' "$file" | sed -E 's/^pub fn +([A-Za-z0-9_]+).*/\1/'
    )
  done < <(find "$dir" -type f -name '*.rs' -not -path '*/tests/*')
done

echo "resource_limits_coverage: scanned $TOTAL pub fn with &[u8] input"

if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "FAIL: $VIOLATIONS public fn(s) take &[u8] but neither call a validate_*"
  echo "      function nor appear in $COVERAGE_DOC:"
  echo ""
  sort -u "$DETAIL" | sed 's/^/  - /'
  echo ""
  echo "Fix: either add a validate_* call in the file, or document the fn in"
  echo "     $COVERAGE_DOC with a rationale (e.g., fixed-size input)."
  exit 1
fi

echo "resource_limits_coverage: OK"

# Inverse check: every function name in the "Known gaps" section of the doc
# must still exist in the source tree. Catches the case where a source-level
# rename leaves a stale allowlist entry behind (which would silently pass the
# forward gate, since the old name still appears in the doc).
#
# Strategy: extract `` `...::fn_name` `` tokens from the doc, keep only the
# final identifier, and require each to appear as `fn <name>(` in the
# source tree. The `(` match is critical — without it, `fn foo_bar` matches
# `fn foo_bar_baz()` too, which would hide a genuine stale name.
: > "$STALE_MISSES"
grep -oE '`[a-zA-Z_][a-zA-Z0-9_:]*`' "$COVERAGE_DOC" \
  | tr -d '`' \
  | awk -F '::' '{print $NF}' \
  | grep -E '^[a-z_][a-z0-9_]+$' \
  | sort -u \
  > "${STALE}.candidates"

STALE_COUNT=0
while IFS= read -r name; do
  # Only check names that look like full function identifiers — at least two
  # underscores and ≥ 10 chars. This filters module names (e.g. `ml_dsa`,
  # `hybrid_sig`) and struct-field references (e.g. `max_encryption_size_bytes`
  # — listed in the doc as struct fields, not fn names).
  if [ "${#name}" -lt 10 ]; then continue; fi
  # Require ≥ 2 underscores (typical for our fn names: verb_noun_variant).
  UCOUNT=$(echo "$name" | tr -cd '_' | wc -c | tr -d ' ')
  if [ "$UCOUNT" -lt 2 ]; then continue; fi
  # Skip struct-field names we know are documented (not fns).
  case "$name" in
    max_*_size_bytes|max_key_derivations_per_call) continue ;;
  esac
  # Require `fn NAME(` — the `(` prevents prefix matches like
  # `fn foo_bar` eating `fn foo_bar_extended`.
  if ! grep -rqE "\bfn[[:space:]]+${name}[[:space:]]*\(" latticearc/ 2>/dev/null; then
    echo "$name" >> "$STALE_MISSES"
    STALE_COUNT=$((STALE_COUNT + 1))
  fi
done < "${STALE}.candidates"

if [ "$STALE_COUNT" -gt 0 ]; then
  echo ""
  echo "WARN: $STALE_COUNT function name(s) in $COVERAGE_DOC no longer match"
  echo "      any 'fn NAME(' in latticearc/. They may be stale (renamed or"
  echo "      removed in source). Please reconcile the doc:"
  echo ""
  sed 's/^/  - /' < "$STALE_MISSES"
  echo ""
  echo "This is a warning, not a hard failure, to allow the doc to carry"
  echo "contextual references that are not strictly function names."
fi
