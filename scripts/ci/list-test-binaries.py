#!/usr/bin/env python3
"""Print the test executables from `cargo test --no-run --message-format=json*`.

Reads cargo's JSON message stream on stdin and prints one absolute path per
line for every `compiler-artifact` whose profile is a test profile and that
produced an executable. Examples (also built by `cargo test`) are skipped
because their profile has `test: false`.

The workflow uses `--message-format=json-render-diagnostics`, so compiler
warnings and errors still reach stderr in human-readable form while only the
JSON artifact messages arrive here.

Used by .github/workflows/mobile.yml: the mobile targets cannot execute test
binaries on the build host, so the workflow builds them with `--no-run` and
then runs each one on the iOS simulator or the Android emulator.

Exits non-zero when no test executable was found, so a silently empty run
(for example after a cargo output-format change) fails the job instead of
passing with zero tests.
"""

import json
import sys


def main() -> int:
    seen: set[str] = set()
    for raw in sys.stdin:
        line = raw.strip()
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        if not msg.get("profile", {}).get("test", False):
            continue
        exe = msg.get("executable")
        if exe and exe not in seen:
            seen.add(exe)
            print(exe)
    if not seen:
        print("error: no test executables in cargo output", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
