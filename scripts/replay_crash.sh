#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

scripts/build_fuzzers.sh

set +e
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -runs=1 \
  experiments/fuzzing/results/F-001_crash_input \
  > /tmp/asynchttpserver_replay_crash.log 2>&1
STATUS=$?
set -e

cat /tmp/asynchttpserver_replay_crash.log

if grep -q "SUMMARY: libFuzzer: fuzz target exited" /tmp/asynchttpserver_replay_crash.log; then
  echo "Expected crash reproduced."
  exit 0
fi

echo "Expected crash was not reproduced. Exit code: $STATUS" >&2
exit 1
