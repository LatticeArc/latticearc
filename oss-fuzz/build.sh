#!/bin/bash -eu
# OSS-Fuzz build script for LatticeArc
# Builds fuzz targets for continuous fuzzing

cd $SRC/latticearc

# Build fuzz targets with cargo-fuzz
cargo +nightly fuzz build --release

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
    if [ -f "fuzz/target/x86_64-unknown-linux-gnu/release/$target" ]; then
        cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
        echo "Copied: $target"
    else
        echo "Warning: Fuzz target $target not found"
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
