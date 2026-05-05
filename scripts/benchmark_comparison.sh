#!/bin/bash
# LatticeArc vs liboqs Benchmark Comparison Script
# Run this on a clean AWS EC2 instance for reproducible results
#
# Recommended instance types:
#   - c6i.xlarge (Intel Ice Lake) - x86_64
#   - c7g.xlarge (ARM Graviton3) - aarch64
#
# Usage: ./scripts/benchmark_comparison.sh

# Round-35 L8: stricter shell hygiene. `-u` rejects unset variables
# (catches typos that previously expanded to empty strings), `-o
# pipefail` propagates failures through pipelines, and `LIBOQS_DIR`
# is now an `mktemp` directory instead of a hardcoded `/tmp/liboqs`
# path that a symlink-race could divert before the `rm -rf`. The
# trap line cleans it up on exit.
set -euo pipefail

echo "=============================================="
echo "LatticeArc vs liboqs Benchmark Comparison"
echo "=============================================="
echo ""

# System info
echo "=== System Information ==="
uname -a
echo ""
if [ -f /proc/cpuinfo ]; then
    grep "model name" /proc/cpuinfo | head -1
    grep "cpu MHz" /proc/cpuinfo | head -1
fi
echo ""

# Build liboqs in a per-run mktemp directory. The previous
# `/tmp/liboqs` hardcoded path let a pre-existing symlink at that
# name divert the `rm -rf` to an arbitrary target.
LIBOQS_DIR="$(mktemp -d -t liboqs.XXXXXXXX)"
trap 'rm -rf "$LIBOQS_DIR"' EXIT
RESULTS_DIR="./benchmark_results"
mkdir -p "$RESULTS_DIR"

echo "=== Building liboqs (mktemp dir: $LIBOQS_DIR) ==="
echo "Installing liboqs build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq cmake ninja-build libssl-dev

git clone --depth 1 https://github.com/open-quantum-safe/liboqs "$LIBOQS_DIR"
cd "$LIBOQS_DIR"
mkdir -p build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
cd -
echo ""

echo "=== Running liboqs Benchmarks ==="
echo "--- ML-KEM-768 ---"
"$LIBOQS_DIR/build/tests/speed_kem" ML-KEM-768 2>/dev/null | tee "$RESULTS_DIR/liboqs_mlkem768.txt"
echo ""
echo "--- ML-DSA-65 ---"
"$LIBOQS_DIR/build/tests/speed_sig" ML-DSA-65 2>/dev/null | tee "$RESULTS_DIR/liboqs_mldsa65.txt"
echo ""

echo "=== Running LatticeArc Benchmarks ==="
cd "$(dirname "$0")/.."
# Round-20 audit fix #18: package was `arc-primitives` historically;
# renamed to `latticearc` during the workspace consolidation. The script
# silently failed for every run between the rename and now.
cargo run --package latticearc --example crypto_timing --release 2>/dev/null | tee "$RESULTS_DIR/latticearc.txt"
echo ""

echo "=== Results Summary ==="
echo ""
echo "liboqs ML-KEM-768:"
grep -E "keygen|encaps|decaps" "$RESULTS_DIR/liboqs_mlkem768.txt" 2>/dev/null || echo "  (check $RESULTS_DIR/liboqs_mlkem768.txt)"
echo ""
echo "liboqs ML-DSA-65:"
grep -E "keygen|sign|verify" "$RESULTS_DIR/liboqs_mldsa65.txt" 2>/dev/null || echo "  (check $RESULTS_DIR/liboqs_mldsa65.txt)"
echo ""
echo "LatticeArc results saved to: $RESULTS_DIR/latticearc.txt"
echo ""
echo "=============================================="
echo "Benchmark complete! Results in: $RESULTS_DIR/"
echo "=============================================="
