# COMP431 Security Project

This project compares two vulnerability-discovery methods on Nim's
`std/asynchttpserver`: coverage-guided fuzzing and AI-assisted code review.

## Contents

- `reports/final_report.md` - final student report.
- `reports/presentation.md` - 7-minute class presentation outline with speaker notes.
- `reports/presentation.html` - finished class presentation.
- `reports/presentation_assets/` - local SVG visuals used by the presentation.
- `experiments/fuzzing/` - fuzzing harnesses, seed corpus, saved logs, and crash artifact.
- `ai_findings/` - model prompt, model outputs, and extracted AI findings.
- `validation/` - confirmed finding summary and minimal reproducer.
- `docs/` - course PDFs, extracted text copies, and project notes.

## Reproduce the Main Finding

Prerequisites:

- Nim compiler
- Clang with libFuzzer/ASan/UBSan support

Build the fuzzers:

```bash
scripts/build_fuzzers.sh
```

Replay the saved crash against the vulnerable harness:

```bash
scripts/replay_crash.sh
```

Run a short fresh fuzzing experiment:

```bash
scripts/run_fuzzing.sh 60
```

The saved experiment logs used in the report are in `experiments/fuzzing/results/`.
