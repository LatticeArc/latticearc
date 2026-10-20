#!/usr/bin/env bash
# Run Rust test executables built for aarch64-apple-ios-sim on a booted iOS
# simulator.
#
# Usage: scripts/ci/ios-simulator-run-tests.sh <file-with-one-test-binary-per-line>
#
# Approach (sources):
#   - `xcrun simctl create` + `xcrun simctl boot` + `xcrun simctl spawn <udid> <binary>`
#     to run a bare, unbundled Rust executable on the simulator is the pattern
#     the Rust project documents for running std's test suite on the iOS
#     simulator: https://rustc-dev-guide.rust-lang.org/tests/running.html#testing-on-emulators
#   - `simctl spawn` returns the child's exit status, and spawned simulator
#     processes run on the host kernel with access to the host filesystem;
#     cargo-apple-runner relies on both when it uses `simctl spawn` as a cargo
#     test runner: https://github.com/madsmtm/cargo-apple-runner/blob/main/src/simctl.rs
#   - Environment variables reach the child only with a `SIMCTL_CHILD_` prefix:
#     https://github.com/madsmtm/cargo-apple-runner#limitations
#
# Every binary is run even if an earlier one fails; the script exits non-zero
# if any binary failed so the job reports every failing suite at once.
set -euo pipefail

BIN_LIST="${1:?usage: $0 <test-binary-list>}"

# Pick the newest available iOS runtime and an iPhone device type it supports.
# `simctl list --json` schema: see the Xcode 26 fixture in cargo-apple-runner,
# https://github.com/madsmtm/cargo-apple-runner/blob/main/src/simctl/xcode_26.json
SELECTION="$(
  xcrun simctl list --json | python3 -I -c '
import json, sys
data = json.load(sys.stdin)
runtimes = [
    r for r in data["runtimes"]
    if r.get("platform") == "iOS" and r.get("isAvailable")
]
if not runtimes:
    sys.exit("no available iOS simulator runtime")
runtimes.sort(key=lambda r: tuple(int(p) for p in r["version"].split(".")))
rt = runtimes[-1]
phones = [t for t in rt.get("supportedDeviceTypes", []) if t.get("productFamily") == "iPhone"]
if not phones:
    sys.exit("runtime %s supports no iPhone device type" % rt["identifier"])
print(rt["identifier"], phones[0]["identifier"])
'
)"
read -r RUNTIME_ID DEVICE_TYPE_ID <<< "${SELECTION}"
echo "Runtime: ${RUNTIME_ID}"
echo "Device type: ${DEVICE_TYPE_ID}"

UDID="$(xcrun simctl create latticearc-ci "${DEVICE_TYPE_ID}" "${RUNTIME_ID}")"
cleanup() {
  xcrun simctl shutdown "${UDID}" >/dev/null 2>&1 || true
  xcrun simctl delete "${UDID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

xcrun simctl boot "${UDID}"
xcrun simctl list devices "${UDID}"

# Ask Rust's test harness for a backtrace on failure inside the simulator.
export SIMCTL_CHILD_RUST_BACKTRACE=1

failed=()
total=0
while IFS= read -r bin <&3; do
  [[ -z "${bin}" ]] && continue
  total=$((total + 1))
  echo "::group::$(basename "${bin}")"
  if xcrun simctl spawn "${UDID}" "${bin}" < /dev/null; then
    echo "::endgroup::"
  else
    status=$?
    echo "::endgroup::"
    echo "::error::$(basename "${bin}") failed on the iOS simulator (exit ${status})"
    failed+=("$(basename "${bin}")")
  fi
done 3< "${BIN_LIST}"

echo "Ran ${total} test binaries on the iOS simulator; ${#failed[@]} failed."
if [[ ${total} -eq 0 ]]; then
  echo "::error::no test binaries were run"
  exit 1
fi
if [[ ${#failed[@]} -gt 0 ]]; then
  printf 'failed: %s\n' "${failed[@]}"
  exit 1
fi
