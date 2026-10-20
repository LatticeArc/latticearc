#!/usr/bin/env bash
# Run Rust test executables built for an Android target on a running
# emulator (or device) via adb.
#
# Usage: scripts/ci/android-emulator-run-tests.sh <file-with-one-test-binary-per-line>
#
# Each binary is pushed to /data/local/tmp, made executable, run with
# `adb shell`, and deleted again so the emulator's /data partition only ever
# holds one LTO-sized test binary at a time.
#
# The KAT and CAVP vectors are compiled into the test binaries (Rust source
# under tests/src/validation/nist_kat and fixtures pulled in with
# `include_str!`), so no vector files need to be pushed. Tests that create
# scratch files use `tempfile`, which resolves `std::env::temp_dir()`; on
# Android that is /data/local/tmp when TMPDIR is unset
# (https://doc.rust-lang.org/std/env/fn.temp_dir.html), and we set TMPDIR
# explicitly below anyway.
#
# The remote exit status is captured with an explicit marker line instead of
# relying on adb propagating it, so a failing test can never be reported as
# success by an adb that drops the status.
#
# Every binary is run even if an earlier one fails; the script exits non-zero
# if any binary failed.
#
# This file is invoked as a single line from reactivecircus/android-emulator-runner,
# whose `script` input runs each line in a separate `sh -c`
# (https://github.com/ReactiveCircus/android-emulator-runner/blob/v2.38.0/src/main.ts),
# which is why the loop lives here rather than inline in the workflow.
set -euo pipefail

BIN_LIST="${1:?usage: $0 <test-binary-list>}"
REMOTE_DIR=/data/local/tmp/latticearc-ci

adb wait-for-device
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}/tmp"

failed=()
total=0
while IFS= read -r bin <&3; do
  [[ -z "${bin}" ]] && continue
  total=$((total + 1))
  name="$(basename "${bin}")"
  echo "::group::${name}"
  adb push "${bin}" "${REMOTE_DIR}/${name}" >/dev/null < /dev/null
  # The binary list is read on fd 3 and every adb call gets /dev/null as
  # stdin, so `adb shell` cannot swallow the rest of the list.
  out_file="$(mktemp "${TMPDIR:-/tmp}/adb-out.XXXXXX")"
  # adb's own exit code is recorded but not trusted; the marker line below is
  # the source of truth, and a missing marker counts as a failure.
  adb_rc=0
  adb shell "cd ${REMOTE_DIR} && chmod 755 ./${name} && \
    TMPDIR=${REMOTE_DIR}/tmp RUST_BACKTRACE=1 ./${name}; \
    echo __LATTICEARC_EXIT__=\$?" < /dev/null | tee "${out_file}" || adb_rc=$?
  status="$(tr -d '\r' < "${out_file}" | sed -n 's/^__LATTICEARC_EXIT__=//p' | tail -n 1)"
  rm -f "${out_file}"
  adb shell "rm -f ${REMOTE_DIR}/${name}" < /dev/null
  echo "::endgroup::"
  if [[ "${status}" != "0" ]]; then
    echo "::error::${name} failed on the Android emulator (exit ${status:-missing}, adb ${adb_rc})"
    failed+=("${name}")
  fi
done 3< "${BIN_LIST}"

echo "Ran ${total} test binaries on the Android emulator; ${#failed[@]} failed."
if [[ ${total} -eq 0 ]]; then
  echo "::error::no test binaries were run"
  exit 1
fi
if [[ ${#failed[@]} -gt 0 ]]; then
  printf 'failed: %s\n' "${failed[@]}"
  exit 1
fi
