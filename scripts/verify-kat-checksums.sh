#!/bin/bash
# Verify KAT test vector source file checksums
#
# This script computes SHA-256 checksums of all NIST KAT source files
# and compares them against the committed manifest. If vectors are
# modified (accidentally or maliciously), this check fails.
#
# Usage:
#   ./scripts/verify-kat-checksums.sh          # Verify checksums
#   ./scripts/verify-kat-checksums.sh --update  # Update manifest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KAT_DIR="$REPO_ROOT/tests/src/validation/nist_kat"
MANIFEST="$KAT_DIR/CHECKSUMS.sha256"

# KAT source files to checksum (excludes mod.rs, runner.rs, PROVENANCE.md)
KAT_FILES=(
    "aes_gcm_kat.rs"
    "chacha20_poly1305_kat.rs"
    "hkdf_kat.rs"
    "hmac_kat.rs"
    "ml_dsa_kat.rs"
    "ml_kem_kat.rs"
    "sha2_kat.rs"
)

if [[ "${1:-}" == "--update" ]]; then
    echo "Updating KAT checksum manifest..."
    > "$MANIFEST"
    for f in "${KAT_FILES[@]}"; do
        if [[ -f "$KAT_DIR/$f" ]]; then
            shasum -a 256 "$KAT_DIR/$f" | sed "s|$KAT_DIR/||" >> "$MANIFEST"
        else
            echo "WARNING: $f not found" >&2
        fi
    done
    echo "Manifest updated: $MANIFEST"
    cat "$MANIFEST"
    exit 0
fi

# Verify mode
if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: Checksum manifest not found: $MANIFEST"
    echo "Run: ./scripts/verify-kat-checksums.sh --update"
    exit 1
fi

echo "Verifying KAT test vector checksums..."
FAILED=0

while IFS= read -r line; do
    expected_hash=$(echo "$line" | awk '{print $1}')
    filename=$(echo "$line" | awk '{print $2}')
    filepath="$KAT_DIR/$filename"

    if [[ ! -f "$filepath" ]]; then
        echo "FAIL: $filename — file not found"
        FAILED=$((FAILED + 1))
        continue
    fi

    actual_hash=$(shasum -a 256 "$filepath" | awk '{print $1}')

    if [[ "$expected_hash" == "$actual_hash" ]]; then
        echo "  OK: $filename"
    else
        echo "FAIL: $filename — checksum mismatch"
        echo "  Expected: $expected_hash"
        echo "  Actual:   $actual_hash"
        FAILED=$((FAILED + 1))
    fi
done < "$MANIFEST"

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo "ERROR: $FAILED KAT file(s) have modified checksums!"
    echo "If intentional, run: ./scripts/verify-kat-checksums.sh --update"
    exit 1
else
    echo ""
    echo "All KAT vector checksums verified."
fi
