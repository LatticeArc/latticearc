#!/usr/bin/env bash
# Secret-type invariant audit (CI gate).
#
# For each struct in `latticearc/src/` whose name contains
#   Secret | Private | Signing | KeyPair | Keypair
# this gate enforces the four invariants from
# `docs/SECRET_TYPE_INVARIANTS.md`:
#
#   I-1: Wipe on drop
#        - Definition file contains `Zeroize` / `ZeroizeOnDrop` / `Zeroizing`,
#          OR the struct's fields are themselves secret-wrapping types
#          (transitive composition; e.g., `PrivateKey(SecretVec)`).
#
#   I-2: Constant-time equality (conditional on equality being defined at all)
#        - `impl ConstantTimeEq for THIS_STRUCT` exists in the same file, OR
#        - `latticearc/tests/no_partial_eq_on_secret_types.rs` or the type's
#          own `#[cfg(test)]` module contains
#          `assert_not_impl_any!(THIS_STRUCT: PartialEq, Eq)`, which is
#          compile-time enforcement of I-6 (no `==` operator). A type with
#          no equality operator cannot leak through equality timing, so
#          I-2 is satisfied vacuously.
#
#   I-3: Redacted Debug
#        - `impl <fmt::>Debug for THIS_STRUCT` exists in the same file, AND
#        - no `#[derive(...Debug...)]` attribute applies to THIS_STRUCT
#          (checked against the 10 lines preceding the struct definition,
#          which is where rustfmt puts attributes).
#
#   I-4: Sealed accessor
#        - The file exposes the secret via a method whose name matches
#          `expose_[a-z_]*secret` (covers both single-secret holders with
#          `expose_secret` and multi-secret holders that split the
#          accessor by component, e.g., `expose_ml_dsa_secret` /
#          `expose_ed25519_secret` for hybrid signature secret keys).
#        - KeyPair composition wrappers are exempt — their secret material
#          is reached through inner-field accessors that each provide their
#          own `expose_secret`.
#
# Companion to invariant I-6, which is enforced by the type-check gate
# `latticearc/tests/no_partial_eq_on_secret_types.rs`. Together they cover
# the five mechanical invariants. The remaining invariants (I-5 mlock,
# I-7 mem::take refusal, I-8 no AsRef<[u8]>) are reviewed manually because
# their enforcement requires semantic analysis a grep gate cannot do.
#
# Exit codes:
#   0 — all matching structs satisfy I-1 through I-4
#   1 — at least one violation; details on stderr

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

VIOLATIONS=0
AUDITED=0
DETAIL=$(mktemp)
trap 'rm -f "$DETAIL"' EXIT

# Types whose presence inside a struct body satisfies the I-1 transitive
# composition rule (each of these zeroizes its own contents on drop).
SECRET_WRAPPERS_RE='SecretBytes|SecretVec|PrivateKey|SymmetricKey|Zeroizing'

# Struct names that match the regex but are not secret holders. Each
# entry is a "name|reason" pair so `git blame` shows why the exemption
# was added. Bash 3.2-compatible (no associative arrays — Apple ships 3.2
# as `/bin/bash` and we run this both there and on Linux CI).
#
# HybridSharedSecretInputs : borrow-only input bundle holding &-references
#   to externally-owned secrets; the references themselves carry no
#   secret bytes, and the referenced secret types enforce their own
#   invariants at their definition sites.
# SerializableKeyPair      : serialization-format DTO holding public-key
#   bytes plus an opaque private-key blob whose secret-type wrapping
#   happens at the deserialization boundary (UnifiedKeyPair).
EXEMPT_NAMES=(
    "HybridSharedSecretInputs"
    "SerializableKeyPair"
)

is_exempt() {
    local needle="$1"
    local n
    for n in "${EXEMPT_NAMES[@]}"; do
        if [ "$n" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

while IFS= read -r file; do
    # Build "<line>\t<name>" records for each in-scope struct in this file.
    while IFS=$'\t' read -r line_no name; do
        [ -z "$name" ] && continue
        if is_exempt "$name"; then
            continue
        fi
        AUDITED=$((AUDITED + 1))

        # I-3: no derive(Debug) — inspect attributes in the 10 lines preceding
        # the struct line (rustfmt always places attrs immediately above).
        start=$((line_no - 10))
        if [ "$start" -lt 1 ]; then start=1; fi
        attr_block=$(sed -n "${start},${line_no}p" "$file")
        if echo "$attr_block" | grep -qE '#\[derive\([^)]*\bDebug\b[^)]*\)\]'; then
            echo "$file:$line_no :: $name :: I-3 violated — #[derive(Debug)] on a secret type" >> "$DETAIL"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi

        # I-3: manual Debug impl present.
        if ! grep -qE "^impl[^{]*\bfmt::Debug\b[^{]*for[[:space:]]+${name}\b" "$file" \
            && ! grep -qE "^impl[^{]*\bDebug\b[^{]*for[[:space:]]+${name}\b" "$file"; then
            echo "$file:$line_no :: $name :: I-3 violated — missing manual Debug impl" >> "$DETAIL"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi

        # I-2: ConstantTimeEq impl present OR I-6 equality-forbidden assertion
        # exists (no `==` operator means no timing channel to protect).
        if ! grep -qE "^impl[^{]*\bConstantTimeEq\b[^{]*for[[:space:]]+${name}\b" "$file"; then
            if ! grep -rqE "assert_not_impl_any!\(${name}([[:space:]]*<[^>]*>)?[[:space:]]*:[[:space:]]*PartialEq" \
                latticearc/tests latticearc/src 2>/dev/null; then
                echo "$file:$line_no :: $name :: I-2 violated — no impl ConstantTimeEq and no assert_not_impl_any!(…: PartialEq) anywhere" >> "$DETAIL"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        fi

        # I-1: Zeroize coverage — direct (Zeroize text in file) or transitive
        # (struct body references a known secret-wrapping type).
        if ! grep -qE '\b(Zeroize|ZeroizeOnDrop|Zeroizing)\b' "$file"; then
            # Take the next 25 lines after the struct opener to scan field types.
            struct_body=$(sed -n "${line_no},$((line_no + 25))p" "$file")
            if ! echo "$struct_body" | grep -qE "\b(${SECRET_WRAPPERS_RE})\b"; then
                echo "$file:$line_no :: $name :: I-1 violated — no Zeroize impl in file and no secret-wrapper field" >> "$DETAIL"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        fi

        # I-4: sealed accessor — KeyPair compositions exempt. Pattern matches
        # both `expose_secret` (single-secret holders) and `expose_*_secret`
        # (multi-secret hybrid types).
        case "$name" in
            *KeyPair|*Keypair) ;;
            *)
                if ! grep -qE 'fn[[:space:]]+expose_[a-z_]*secret\b' "$file"; then
                    echo "$file:$line_no :: $name :: I-4 violated — no expose_secret-style accessor in file" >> "$DETAIL"
                    VIOLATIONS=$((VIOLATIONS + 1))
                fi
                ;;
        esac
    done < <(
        grep -nE '^(pub )?struct [A-Za-z0-9_]*(Secret|Private|Signing|Keypair|KeyPair)[A-Za-z0-9_]*\b' "$file" \
        | awk -F: '
            {
                line = $1
                rest = ""
                for (i = 2; i <= NF; i++) rest = (rest == "") ? $i : rest ":" $i
                sub(/^[[:space:]]*pub[[:space:]]+struct[[:space:]]+/, "", rest)
                sub(/^[[:space:]]*struct[[:space:]]+/, "", rest)
                name = rest
                sub(/[^A-Za-z0-9_].*/, "", name)
                print line "\t" name
            }'
    )
done < <(find latticearc/src -type f -name '*.rs' -not -path '*/tests/*')

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "" >&2
    echo "secret_type_audit: FAIL — $VIOLATIONS invariant violation(s) across $AUDITED secret-typed struct(s):" >&2
    sort -u "$DETAIL" | sed 's/^/  - /' >&2
    echo "" >&2
    echo "See docs/SECRET_TYPE_INVARIANTS.md for the full invariant catalogue and remediation guidance." >&2
    exit 1
fi

echo "secret_type_audit: OK ($AUDITED secret-typed struct(s) audited, all four invariants satisfied)"
