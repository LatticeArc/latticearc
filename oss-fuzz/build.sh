#!/bin/bash -eu
# OSS-Fuzz build script for LatticeArc
# Builds fuzz targets for continuous fuzzing

cd $SRC/latticearc

# Build fuzz targets with cargo-fuzz
cargo +nightly fuzz build --release

# Discover the active host triple instead of hardcoding it. Previously this
# script assumed `x86_64-unknown-linux-gnu`; on any other host (aarch64,
# musl, ...) the cp below silently produced zero artifacts and the build
# step completed "successfully" with an empty $OUT. Failing-closed on a
# missing binary makes the same misconfiguration loud.
HOST_TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
if [ -z "$HOST_TRIPLE" ]; then
    echo "ERROR: could not determine host triple from rustc -vV" >&2
    exit 1
fi
FUZZ_TARGET_DIR="fuzz/target/${HOST_TRIPLE}/release"

# Copy fuzz targets to output directory
# Note: Adjust target names based on actual fuzz targets in fuzz/
FUZZ_TARGETS=(
    "fuzz_aes_gcm"
    "fuzz_chacha20_poly1305"
    "fuzz_ml_kem"
    "fuzz_ml_dsa"
    "fuzz_hybrid_encrypt"
    "fuzz_hkdf"
    "fuzz_ed25519"
    "fuzz_x25519"
)

for target in "${FUZZ_TARGETS[@]}"; do
    if [ -f "${FUZZ_TARGET_DIR}/$target" ]; then
        cp "${FUZZ_TARGET_DIR}/$target" "$OUT/"
        echo "Copied: $target"
    else
        echo "ERROR: Fuzz target $target not found under ${FUZZ_TARGET_DIR}" >&2
        exit 1
    fi
done

# Copy seed corpus if available
if [ -d "fuzz/corpus" ]; then
    for target in "${FUZZ_TARGETS[@]}"; do
        if [ -d "fuzz/corpus/$target" ]; then
            zip -r "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"
        fi
    done
fi

# Copy dictionaries if available
if [ -d "fuzz/dictionaries" ]; then
    cp fuzz/dictionaries/*.dict "$OUT/" 2>/dev/null || true
fi

echo "OSS-Fuzz build complete"
