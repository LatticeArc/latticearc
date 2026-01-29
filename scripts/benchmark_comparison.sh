#!/bin/bash
# LatticeArc vs liboqs Benchmark Comparison Script
# Run this on a clean AWS EC2 instance for reproducible results
#
# Recommended instance types:
#   - c6i.xlarge (Intel Ice Lake) - x86_64
#   - c7g.xlarge (ARM Graviton3) - aarch64
#
# Usage: ./scripts/benchmark_comparison.sh

set -e

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

# Check if liboqs is available
LIBOQS_DIR="/tmp/liboqs"
RESULTS_DIR="./benchmark_results"
mkdir -p "$RESULTS_DIR"

echo "=== Building liboqs (if needed) ==="
if [ ! -f "$LIBOQS_DIR/build/tests/speed_kem" ]; then
    echo "Installing liboqs..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq cmake ninja-build libssl-dev

    rm -rf "$LIBOQS_DIR"
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs "$LIBOQS_DIR"
    cd "$LIBOQS_DIR"
    mkdir -p build && cd build
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
    ninja
    cd -
else
    echo "liboqs already built"
fi
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
cargo run --package arc-primitives --example crypto_timing --release 2>/dev/null | tee "$RESULTS_DIR/latticearc.txt"
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
