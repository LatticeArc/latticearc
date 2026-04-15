#!/bin/bash -eu
# OSS-Fuzz build entrypoint for latticearc.
#
# Invoked inside the image from Dockerfile. Builds every `[[bin]]`
# defined in `fuzz/Cargo.toml` with the currently-selected sanitizer
# (OSS-Fuzz sets `$SANITIZER` per build), then copies the resulting
# libFuzzer binaries into `$OUT/` where OSS-Fuzz picks them up.
#
# Ref: https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

cd "$SRC/latticearc/fuzz"

# When OSS-Fuzz asks for MemorySanitizer, tell aws-lc-sys to compile its
# C sources with `-fsanitize=memory` so MSan can follow through the FFI
# boundary. Required by aws-lc-rs >= 1.16.3; silently ignored for other
# sanitizers. See aws/aws-lc-rs#1077 / PR #1100.
if [ "${SANITIZER:-}" = "memory" ]; then
    export AWS_LC_SYS_SANITIZER=msan
fi

# `cargo fuzz build` compiles every declared bin target. `-O` enables
# release optimizations; the libFuzzer engine still gets its sanitizer
# instrumentation via RUSTFLAGS set by the OSS-Fuzz base image.
# `--debug-assertions` keeps `debug_assert!` active — valuable for
# catching invariant violations in crypto code paths without the
# perf cost of a full debug build.
cargo +nightly fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR="target/x86_64-unknown-linux-gnu/release"

# Iterate every .rs file in fuzz_targets/ and copy its built binary.
# Using `find` over the source files (rather than the output dir) so
# the loop doesn't accidentally grab a stale binary from a cache.
for target_src in fuzz_targets/*.rs; do
    target_name="$(basename "$target_src" .rs)"
    if [ -f "$FUZZ_TARGET_OUTPUT_DIR/$target_name" ]; then
        cp "$FUZZ_TARGET_OUTPUT_DIR/$target_name" "$OUT/"
    else
        echo "WARNING: fuzz target '$target_name' has no built binary" >&2
    fi
done

# Optional: seed corpora. OSS-Fuzz picks up `$OUT/<target>_seed_corpus.zip`.
# We don't ship seed corpora today — fuzzing from scratch is effective
# enough for these targets. Add zips here if a target needs a warm start.
