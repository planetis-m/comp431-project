#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_TIME="${1:-60}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

scripts/build_fuzzers.sh

mkdir -p "$WORKDIR/corpus" "$WORKDIR/results/original" "$WORKDIR/results/fixed"
cp experiments/fuzzing/corpus/* "$WORKDIR/corpus/"

set +e
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -max_total_time="$MAX_TIME" \
  -artifact_prefix="$WORKDIR/results/original/" \
  "$WORKDIR/corpus" \
  > "$WORKDIR/results/original/run.log" 2>&1
ORIGINAL_STATUS=$?
set -e

ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer_fixed \
  -runs=1 \
  experiments/fuzzing/results/F-001_crash_input \
  > "$WORKDIR/results/fixed/replay.log" 2>&1

ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer_fixed \
  -max_total_time="$MAX_TIME" \
  "$WORKDIR/corpus" \
  > "$WORKDIR/results/fixed/run.log" 2>&1

echo "Temporary results: $WORKDIR"
echo "Original harness exit code: $ORIGINAL_STATUS"
echo "Original run summary:"
grep -E "ERROR|SUMMARY|DONE|artifact_prefix|Base64|#[0-9]+.*(REDUCE|NEW|DONE)" "$WORKDIR/results/original/run.log" | tail -n 20 || true
echo
echo "Fixed harness replay summary:"
tail -n 8 "$WORKDIR/results/fixed/replay.log"
echo
echo "Fixed harness run summary:"
grep -E "ERROR|SUMMARY|DONE|#[0-9]+.*DONE" "$WORKDIR/results/fixed/run.log" | tail -n 20 || true
