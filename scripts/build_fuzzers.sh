#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMMON=(
  --cc:clang
  -d:noSignalHandler
  -d:useMalloc
  --noMain:on
  --passC:-fsanitize=fuzzer,address,undefined
  --passC:-g
  --passL:-fsanitize=fuzzer,address,undefined
  --passL:-g
)

nim c "${COMMON[@]}" experiments/fuzzing/harness/asynchttpserver_fuzzer.nim
nim c "${COMMON[@]}" experiments/fuzzing/harness/asynchttpserver_fuzzer_fixed.nim
