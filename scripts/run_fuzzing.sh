#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_TIME="${1:-60}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

scripts/build_fuzzers.sh

mkdir -p "$WORKDIR/corpus" "$WORKDIR/results"
cp experiments/fuzzing/corpus/* "$WORKDIR/corpus/"

set +e
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -print_final_stats=1 \
  -max_total_time="$MAX_TIME" \
  -artifact_prefix="$WORKDIR/results/" \
  "$WORKDIR/corpus" \
  > "$WORKDIR/results/run.log" 2>&1
STATUS=$?
set -e

echo "Temporary results: $WORKDIR"
echo "Harness exit code: $STATUS"
echo "Run summary:"
grep -E "ERROR|SUMMARY|DONE|artifact_prefix|Base64|stat::number_of_executed_units|#[0-9]+.*(REDUCE|NEW|DONE)" \
  "$WORKDIR/results/run.log" | tail -n 24 || true
