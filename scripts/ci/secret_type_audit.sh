#!/usr/bin/env bash
# Secret-type invariant audit (CI gate).
#
# For each struct in `latticearc/src/` whose name contains
#   Secret | Private | Signing | KeyPair | Keypair
# this gate enforces the four invariants from
# `docs/SECRET_TYPE_INVARIANTS.md`:
#
#   I-1: Wipe on drop
#        Satisfied per-struct (NOT file-wide — see history note below) by any
#        one of:
#        - `#[derive(...Zeroize...)]` or `#[derive(...ZeroizeOnDrop...)]` on
#          the struct itself, OR
#        - an explicit `impl Zeroize for THIS_STRUCT` or
#          `impl ZeroizeOnDrop for THIS_STRUCT` in the same file, OR
#        - the struct's fields are themselves secret-wrapping types
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
#   I-4: Sealed accessor (per-struct, NOT file-wide)
#        - The struct's own impl block(s) (inherent or trait, in this file)
#          define a method whose name matches `expose_[a-z_]*secret`. Covers
#          both single-secret holders with `expose_secret` and multi-secret
#          holders that split the accessor by component, e.g.,
#          `expose_ml_dsa_secret` / `expose_ed25519_secret` for hybrid
#          signature secret keys. A method declared on a *different* struct
#          in the same file no longer satisfies this invariant.
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
# History (read before changing the I-1 or I-4 logic): an earlier revision
# of this script used `grep -qE … "$file"` for both I-1 and I-4. That made
# both invariants file-wide: a single Zeroize impl or `expose_secret`
# accessor anywhere in the file passed every other secret struct in that
# file. Round-6's M5 fix established that file-wide grep is the wrong shape
# for per-struct invariants; this script now scopes both I-1 and I-4 to the
# specific struct via attribute-block scanning, per-struct `impl … for
# NAME` matching, and (for I-4) awk-driven impl-target walking. The
# self-test mode (`--self-test`) regresses both reproducers.
#
# Exit codes:
#   0 — all matching structs satisfy I-1 through I-4
#   1 — at least one violation; details on stderr
#
# Modes:
#   secret_type_audit.sh             — audit the live tree
#   secret_type_audit.sh --self-test — exit 0 if the gate catches synthetic
#                                       I-1 and I-4 violations; exit 1 if
#                                       any planted violation slips past.
#                                       Used by CI to prevent silent
#                                       regression of M-NEW-1.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# --self-test : plant synthetic M-NEW-1 reproducers, recurse into this same
# script with the scan directory overridden, and verify the gate catches
# both planted violations. This is the regression guard for the
# file-wide-grep anti-pattern.
if [ "${1:-}" = "--self-test" ]; then
    SCRATCH=$(mktemp -d)
    trap 'rm -rf "$SCRATCH"' EXIT

    # Reproducer A: I-1 file-wide grep.
    # The file contains a Zeroize derive on one struct AND an in-file
    # `impl Zeroize for` line for it. A pre-fix gate (file-wide grep)
    # would short-circuit and pass every other struct. The planted
    # `PlantedFileWideSecretKey` has no Zeroize coverage of its own and
    # must be reported as I-1 violated.
    cat >"$SCRATCH/i1_repro.rs" <<'REPRO_EOF'
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecoyGoodSecretKey {
    bytes: [u8; 32],
}

impl DecoyGoodSecretKey {
    pub fn expose_secret(&self) -> &[u8; 32] { &self.bytes }
}

impl std::fmt::Debug for DecoyGoodSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecoyGoodSecretKey { [REDACTED] }")
    }
}

impl ConstantTimeEq for DecoyGoodSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice { self.bytes.ct_eq(&other.bytes) }
}

// Planted I-1 violation: no derive, no impl Zeroize, no wrapper field.
pub struct PlantedFileWideSecretKey {
    raw: [u8; 32],
}

impl PlantedFileWideSecretKey {
    pub fn expose_secret(&self) -> &[u8; 32] { &self.raw }
}

impl std::fmt::Debug for PlantedFileWideSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlantedFileWideSecretKey { [REDACTED] }")
    }
}

impl ConstantTimeEq for PlantedFileWideSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice { self.raw.ct_eq(&other.raw) }
}
REPRO_EOF

    # Reproducer B: I-4 file-wide grep.
    # The file's decoy struct defines `expose_secret`. A pre-fix gate
    # would let the planted struct ride the file-wide grep. The planted
    # `PlantedFileWideSigningKey` has no expose_*secret accessor of its
    # own and must be reported as I-4 violated.
    cat >"$SCRATCH/i4_repro.rs" <<'REPRO_EOF'
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecoyAccessorSecretKey {
    bytes: [u8; 32],
}

impl DecoyAccessorSecretKey {
    pub fn expose_secret(&self) -> &[u8; 32] { &self.bytes }
}

impl std::fmt::Debug for DecoyAccessorSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecoyAccessorSecretKey { [REDACTED] }")
    }
}

impl ConstantTimeEq for DecoyAccessorSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice { self.bytes.ct_eq(&other.bytes) }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlantedFileWideSigningKey {
    raw: [u8; 32],
}

// Note: no expose_*secret method anywhere in this impl block.
impl PlantedFileWideSigningKey {
    pub fn raw_bytes_dangerous(&self) -> &[u8; 32] { &self.raw }
}

impl std::fmt::Debug for PlantedFileWideSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlantedFileWideSigningKey { [REDACTED] }")
    }
}

impl ConstantTimeEq for PlantedFileWideSigningKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice { self.raw.ct_eq(&other.raw) }
}
REPRO_EOF

    output=$(LATTICEARC_AUDIT_SCAN_DIR="$SCRATCH" bash "$0" 2>&1) && rc=0 || rc=$?

    fail=0
    if [ "$rc" -eq 0 ]; then
        echo "self-test FAIL: audit exited 0; M-NEW-1 reproducers slipped past" >&2
        fail=1
    fi
    if ! echo "$output" | grep -q "PlantedFileWideSecretKey :: I-1"; then
        echo "self-test FAIL: I-1 reproducer not caught (M-NEW-1 regression in I-1 path)" >&2
        fail=1
    fi
    if ! echo "$output" | grep -q "PlantedFileWideSigningKey :: I-4"; then
        echo "self-test FAIL: I-4 reproducer not caught (M-NEW-1 regression in I-4 path)" >&2
        fail=1
    fi
    if [ "$fail" -ne 0 ]; then
        echo "" >&2
        echo "audit output was:" >&2
        echo "$output" >&2
        exit 1
    fi
    echo "secret_type_audit self-test: OK (I-1 and I-4 file-wide-grep reproducers both caught)"
    exit 0
fi

# Scan target: defaults to the live source tree. The self-test mode
# above overrides this to a scratch dir containing planted violators.
SCAN_TARGET="${LATTICEARC_AUDIT_SCAN_DIR:-latticearc/src}"

VIOLATIONS=0
AUDITED=0
DETAIL=$(mktemp)
trap 'rm -f "$DETAIL"' EXIT

# Types whose presence inside a struct body satisfies the I-1 transitive
# composition rule (each of these zeroizes its own contents on drop).
#
# In-house wrappers:
#   SecretBytes, SecretVec, PrivateKey, SymmetricKey — derive Zeroize +
#     ZeroizeOnDrop at their definition sites in `latticearc/src/types/`.
#   MlKemSecretKey                                   — `impl Zeroize` +
#     `impl ZeroizeOnDrop` at `latticearc/src/primitives/kem/ml_kem.rs:641`.
#
# aws-lc-rs wrappers (zeroize via aws-lc-rs's own Drop; see SECURITY.md
# "aws-lc-rs-Wrapped Secret Types" and the doc comments above each
# composing struct):
#   EphemeralPrivateKey — fields of X25519KeyPair, EcdhP{256,384,521}KeyPair
#   DecapsulationKey    — field of MlKemDecapsulationKeyPair
#
# Stdlib wrapper:
#   Zeroizing — explicit drop-clears its contents.
SECRET_WRAPPERS_RE='SecretBytes|SecretVec|PrivateKey|SymmetricKey|MlKemSecretKey|EphemeralPrivateKey|DecapsulationKey|Zeroizing'

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
# HybridKemSecretKey       : composition of MlKemDecapsulationKeyPair and
#   X25519StaticKeyPair (both `*KeyPair`-suffixed and exempt-by-rule from
#   I-4 themselves). Secret access goes through `ml_kem_sk_bytes()` /
#   `ecdh_seed_bytes()` returning `Zeroizing<…>`; the naming convention
#   tracks the underlying aws-lc-rs primitive (`*_sk_bytes`) rather than
#   the `expose_*secret` convention used for in-house secret holders.
#   The sealed-accessor invariant is satisfied; only the regex naming
#   match is not.
EXEMPT_NAMES=(
    "HybridSharedSecretInputs"
    "SerializableKeyPair"
    "HybridKemSecretKey"
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

        # I-1: Zeroize coverage — PER-STRUCT (file-wide grep was the M-NEW-1
        # regression). Satisfied if any one of:
        #   (a) `#[derive(...Zeroize...)]` or `#[derive(...ZeroizeOnDrop...)]`
        #       appears in the 10-line attribute block immediately above the
        #       struct, OR
        #   (b) the file contains an explicit
        #       `impl Zeroize for ${name}` / `impl ZeroizeOnDrop for ${name}`
        #       (per-struct match against the type after `for`), OR
        #   (c) the struct body's first 25 lines reference a known
        #       secret-wrapping type (`SecretBytes`/`SecretVec`/`PrivateKey`/
        #       `SymmetricKey`/`Zeroizing`).
        has_zeroize=0
        if echo "$attr_block" | grep -qE '#\[derive\([^)]*\b(Zeroize|ZeroizeOnDrop)\b[^)]*\)\]'; then
            has_zeroize=1
        fi
        if [ "$has_zeroize" = "0" ] \
            && grep -qE "^impl([[:space:]]*<[^>]*>)?[[:space:]]+(Zeroize|ZeroizeOnDrop)([[:space:]]*<[^>]*>)?[[:space:]]+for[[:space:]]+${name}\b" "$file"; then
            has_zeroize=1
        fi
        if [ "$has_zeroize" = "0" ]; then
            struct_body=$(sed -n "${line_no},$((line_no + 25))p" "$file")
            if echo "$struct_body" | grep -qE "\b(${SECRET_WRAPPERS_RE})\b"; then
                has_zeroize=1
            fi
        fi
        if [ "$has_zeroize" = "0" ]; then
            echo "$file:$line_no :: $name :: I-1 violated — no Zeroize derive on struct, no impl Zeroize/ZeroizeOnDrop for ${name}, and no secret-wrapper field" >> "$DETAIL"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi

        # I-4: sealed accessor — PER-STRUCT (file-wide grep was the M-NEW-1
        # regression). KeyPair compositions exempt. The accessor must be
        # defined inside an impl block whose target type is this struct
        # (inherent `impl NAME { ... }` or trait `impl TRAIT for NAME
        # { ... }`). A method declared on a different struct in the same
        # file no longer satisfies I-4.
        case "$name" in
            *KeyPair|*Keypair) ;;
            *)
                has_expose=$(awk -v name="$name" '
                    function impl_target(line,    head) {
                        head = line
                        sub(/^impl/, "", head)
                        sub(/\{.*$/, "", head)
                        # Strip one leading <...> (the impl-block generics
                        # like <T> or <const N: usize>). Nested generics in
                        # impl-block generic params are not handled (rare in
                        # this codebase); add another sub() if introduced.
                        sub(/^[[:space:]]*<[^<>]*>/, "", head)
                        if (head ~ /[[:space:]]for[[:space:]]/) {
                            sub(/.*[[:space:]]for[[:space:]]+/, "", head)
                        }
                        # Strip generics from the target type itself.
                        sub(/<.*$/, "", head)
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", head)
                        return head
                    }
                    BEGIN { in_impl = 0; found = 0 }
                    {
                        if (in_impl == 0) {
                            if ($0 ~ /^impl[[:space:]<]/ && impl_target($0) == name) {
                                in_impl = 1
                            }
                        } else {
                            if ($0 ~ /^\}[[:space:]]*$/) {
                                in_impl = 0
                            } else if ($0 ~ /fn[[:space:]]+expose_[a-z_]*secret([^A-Za-z0-9_]|$)/) {
                                # POSIX awk has no `\b`; use explicit
                                # non-identifier terminator so `expose_secret(`
                                # and `expose_secret <` both match while
                                # `expose_secretly` (hypothetical) would not.
                                found = 1
                            }
                        }
                    }
                    END { print found }
                ' "$file")
                if [ "$has_expose" != "1" ]; then
                    echo "$file:$line_no :: $name :: I-4 violated — no impl for ${name} defines an expose_*secret accessor" >> "$DETAIL"
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
done < <(find "$SCAN_TARGET" -type f -name '*.rs' -not -path '*/tests/*')

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "" >&2
    echo "secret_type_audit: FAIL — $VIOLATIONS invariant violation(s) across $AUDITED secret-typed struct(s):" >&2
    sort -u "$DETAIL" | sed 's/^/  - /' >&2
    echo "" >&2
    echo "See docs/SECRET_TYPE_INVARIANTS.md for the full invariant catalogue and remediation guidance." >&2
    exit 1
fi

echo "secret_type_audit: OK ($AUDITED secret-typed struct(s) audited, all four invariants satisfied)"
