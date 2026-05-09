# LLM-Assisted Security Audit and Fuzzing of Nim `std/asynchttpserver`

## 1. Project Overview

This project is a local security-audit prototype for Nim's standard-library
HTTP server module, `std/asynchttpserver`. The goal was to compare two
vulnerability-discovery techniques:

1. Coverage-guided fuzzing with libFuzzer and sanitizers.
2. AI-assisted static review using an LLM prompt and manual validation.

The project follows the "LLM-assisted Security Audit" topic from the course
project list. It implements a working local auditing setup, runs simulated
attacks against parsing code, records evidence, and evaluates the usefulness of
each technique. No remote system was tested.

The main result was a confirmed denial-of-service bug in the HTTP protocol
parser. A malformed request-line protocol token that lacks a minor version
(such as `HTTP/` or `HTTP/1`) can raise an uncaught `IndexDefect` and crash a
process using this parser. This vulnerability has since been fixed upstream in
the Nim repository (PR #25793), which validates our finding as a real,
previously existing bug. For this project, we used an older Nim version
intentionally — the goal is to study vulnerability discovery techniques, not to
exploit live systems.

## 2. Target and Background

The audited file was:

```text
Nim/lib/pure/asynchttpserver.nim
```

This module implements an asynchronous HTTP server. It is not intended to be a
production web server directly exposed to the Internet, but applications may
still use it locally or behind another service. Since HTTP request data is
attacker-controlled, request parsing is still a meaningful security boundary.

The most important parsing path is `processRequest`, which reads:

- the request line,
- headers,
- optional body data from `Content-Length`,
- optional chunked body data,
- connection-management headers.

The most relevant helper for the confirmed crash is `parseProtocol`, which
parses strings such as `HTTP/1.1` into a tuple containing the original string,
major version, and minor version.

## 3. Threat Model and Risk Analysis

The attacker model is an unauthenticated client who can open a connection to an
application using `std/asynchttpserver` and send malformed HTTP data. The
attacker controls bytes in the request line, headers, and body.

The main risks considered were:

| Risk | Why It Matters |
|---|---|
| Process crash | One malformed request can terminate the server process, causing denial of service. |
| Memory exhaustion | Large or repeated inputs can force the server to allocate memory. |
| Connection exhaustion | Slow reads without timeouts can hold sockets open. |
| HTTP logic errors | Incorrect handling of headers or bodies can confuse applications using the server. |

This project did not attempt remote code execution or exploitation of any
third-party deployment. The evaluation was a local defensive audit.

## 4. Prototype Design

The prototype has four parts:

| Component | Purpose | Location |
|---|---|---|
| Fuzz harness | Exercises the full request parser with generated input | `experiments/fuzzing/harness/` |
| Seed corpus | Small benign starting inputs for libFuzzer | `experiments/fuzzing/corpus/` |
| Saved evidence | Crash input | `experiments/fuzzing/results/` |
| AI review notes | Prompt, raw model outputs, extracted findings | `ai_findings/` |

The fuzz harness does not start a real network server. Instead, it directly
invokes the full request parsing logic that would normally receive data from a
client. The harness calls `parseFullRequestOriginal`, which exercises all the
parsing stages in sequence: method, URI, protocol, headers, and body. This
makes the test faster and more deterministic, while still exercising the code
that handles attacker-controlled HTTP strings.

The harness also supports a **standalone replay mode** (`-d:fuzzStandalone`)
that reads crash inputs from command-line file arguments and replays them
through the same parsing code — without libFuzzer, without coverage tracking,
without mutation. This is how we verify crash artifacts independently.

## 5. Security Techniques Used

### 5.1 Coverage-Guided Fuzzing

The first technique is fuzz testing. libFuzzer mutates inputs and uses coverage
feedback to explore new program paths. The harness was compiled with Clang,
libFuzzer, AddressSanitizer, and UndefinedBehaviorSanitizer.

This is an attack simulation because it repeatedly sends malformed local inputs
to code that normally processes untrusted HTTP data.

### 5.2 AI-Assisted Static Review

The second technique is LLM-assisted review. A single structured prompt asked
the model to inspect `asynchttpserver.nim` and report findings with title,
vulnerability type, location, triggering input, root cause, exploitability, and
classification.

DeepSeek, GLM-5.1, and Kimi K2.6 produced usable transcripts for this
submission.

The AI output was treated as a set of hypotheses. I checked the source code and
the fuzzing evidence before classifying each claim.

## 6. Experimental Methodology

### 6.1 Building the Fuzzer

The build command lives in `scripts/build_fuzzers.sh`. The key ideas behind the
compilation flags:

- **`--cc:clang`** — libFuzzer requires Clang. GCC does not recognize
  `-fsanitize=fuzzer`.
- **`-d:noSignalHandler`** — Disables Nim's signal handlers so that
  AddressSanitizer (not Nim) detects and reports crashes.
- **`-d:useMalloc`** — Uses the system allocator so ASan can instrument memory
  accesses. Nim's own allocator would bypass this instrumentation.
- **`--noMain:on`** — libFuzzer provides its own `main()`. Without this flag
  we get a duplicate-symbol linker error.
- **`--passC/--passL -fsanitize=fuzzer,address,undefined`** — Links the
  fuzzer engine, AddressSanitizer (buffer overflows, use-after-free), and
  UndefinedBehaviorSanitizer (integer overflow, null dereference).
- **`-g`** — Debug symbols for readable stack traces.

The build produces an executable at
`experiments/fuzzing/harness/asynchttpserver_fuzzer`.

### 6.2 The Seed Corpus

libFuzzer starts from small, valid inputs and mutates them to discover crashes.
We prepared three seed files in `experiments/fuzzing/corpus/` — plain HTTP
requests fed directly to the full request parser:

- **`seed_get_http11`** — A minimal GET request exercising the request-line,
  protocol parser, and header detection.
- **`seed_post_content_length`** — A POST with `Content-Length`, exercising body
  reading and header parsing.
- **`seed_post_chunked`** — A POST with chunked transfer encoding, exercising
  the chunked body parsing path.

### 6.3 Running the Fuzzer

The run command lives in `scripts/run_fuzzing.sh`. It builds the fuzzer, copies
the seed corpus into a temporary working directory, and invokes:

```bash
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -print_final_stats=1 \
  -max_total_time=60 \
  -artifact_prefix="$WORKDIR/results/" \
  "$WORKDIR/corpus"
```

Key points:

- **`ASAN_OPTIONS=detect_leaks=0`** — The fuzzer intentionally never frees
  memory. Leak reports would be false positives.
- **`-max_total_time=60`** — 60 seconds is enough for this educational
  experiment. Real campaigns run for hours or days.
- **`-artifact_prefix`** — Where to save crash inputs.

### 6.4 Interpreting the Fuzzer Output

A typical run that found the crash produced output like this:

```
#2373  REDUCE cov: 3798 ft: 8650 corp: 106/4434b lim: 67 exec/s: 0 rss: 58Mb
==67332== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
artifact_prefix='/tmp/tmp.XXXXXX/results/'; Test unit written to .../crash-bc01f5feb2d0b6b6e46410cfcc0082629a815e22
Base64: R0VUIC0gSFRUUC8gSFRUUC8xLjEgSA==
stat::number_of_executed_units: 2847
```

What matters here:

- **`REDUCE`** — libFuzzer is *minimizing* the crash: trying to shrink the
  input to the smallest version that still crashes. This is one of libFuzzer's
  most useful features — it turns a potentially large mutated blob into
  something a human can reason about.
- **`cov: 3798`** — 3,798 unique code edges reached. Higher means more of the
  target code explored.
- **`SUMMARY: libFuzzer: fuzz target exited`** — The harness terminated
  unexpectedly (called `quit(70)` on a `Defect`). A normal run says `DONE`.
- **`Base64: R0VUIC0gSFRUUC8gSFRUUC8xLjEgSA==`** — Decodes to
  `GET - HTTP/ HTTP/1.1 H`, a request whose protocol field is `HTTP/` (no
  version digits).

### 6.5 The Crash Artifact

The saved crash file at `experiments/fuzzing/results/F-001_crash_input` is a
34-byte mutated HTTP request. Its request line, when split by spaces, has
`HTTP/1` as the protocol field — a string with a major version but no
dot-separator or minor version.

The `parseProtocolOriginal` function accepts the `HTTP/` prefix, parses the
major version `1`, then unconditionally increments `i` to skip the dot
separator. Since there is no dot, `i` moves past the end of the string, and the
subsequent call to `parseSaturatedNatural` for the minor version triggers
`IndexDefect`.

The root cause is identical to the simpler case of `HTTP/` (no version digits
at all): the unconditional `i.inc` that skips the dot separator.

### 6.6 Verifying the Crash with Standalone Replay

A crash artifact from a fuzzer is evidence, but we should verify it
independently. The fuzzer could have crashed due to a sanitizer false positive,
a harness bug, or an environment issue.

The harness supports standalone replay mode. Building with `-d:fuzzStandalone`
produces a binary that reads file paths from its arguments and feeds each
file's contents to `LLVMFuzzerTestOneInput` directly — no libFuzzer, no
coverage tracking, no mutation:

```bash
nim c -d:fuzzStandalone --panics:on --mm:arc \
  experiments/fuzzing/harness/asynchttpserver_fuzzer.nim

./experiments/fuzzing/harness/asynchttpserver_fuzzer \
  experiments/fuzzing/results/F-001_crash_input
```

Output:

```
StandaloneFuzzTarget: running 1 inputs
Error: unhandled exception: index out of bounds: 7..5 notin 0..5 [IndexDefect]
```

The stack trace shows the exact call chain: harness → `parseFullRequestOriginal`
→ `parseProtocolOriginal` → `parseSaturatedNatural` → crash. For comparison,
replaying the well-formed seed corpus produces exit code 0 with no crash.

### 6.7 How the AI Review Was Conducted

The AI workflow was separate from the fuzzing:

1. **Wrote a structured prompt** (`ai_findings/VULN_DISCOVERY_PROMPT.txt`) with
   the target file, an output format requiring title/type/location/input/cause/
   exploitability/classification, 13 attack surfaces to examine, and rules to be
   evidence-based.
2. **Submitted the same prompt** to DeepSeek V4 Pro, GLM-5.1, and Kimi K2.6
   through their chat interfaces.
3. **Saved raw outputs** in `ai_findings/<model>/output.txt`.
4. **Extracted findings** into `ai_findings/<model>/findings_extracted.md`.
5. **Validated each finding** against source code and fuzzing evidence.

### 6.8 How to Distinguish a Real Bug from a False Positive

This is one of the most important skills in vulnerability research. The
checklist we used:

1. **Can we replay the crash independently?** The standalone replay is the
   strongest form of evidence. The saved artifact crashes the same parsing code
   without the fuzzer engine.
2. **Can we trace the code path from input to failure?** If the static trace is
   valid but we cannot produce a dynamic reproducer, we classify as *likely*.
3. **Is the AI misreading runtime behavior?** AI models analyze code statically.
   When a model's predicted behavior contradicts actual runtime evidence, the
   finding is a *false positive* regardless of confidence.
4. **Is the claim bounded by existing limits?** Some findings are technically
   true but practically harmless. For example, `split(' ')` allocations are
   bounded by `maxLine` (8,192 bytes).
5. **Does the fuzzer agree?** If the fuzzer reaches the same code but does not
   crash, and the AI claims a crash is possible, the AI is likely wrong.

## 7. Confirmed Vulnerability

### F-001: `parseProtocol` IndexDefect

Relevant source (from the vulnerable version we tested):

```nim
proc parseProtocol(protocol: string): tuple[orig: string, major, minor: int] =
  result = default(tuple[orig: string, major, minor: int])
  var i = protocol.skipIgnoreCase("HTTP/")
  if i != 5:
    raise newException(ValueError, "Invalid request protocol. Got: " & protocol)
  result.orig = protocol
  i.inc protocol.parseSaturatedNatural(result.major, i)
  i.inc
  i.inc protocol.parseSaturatedNatural(result.minor, i)
```

Expected behavior:

- `HTTP/1.1` should parse successfully.
- Incomplete version values such as `HTTP/` should not crash the process.
  Raising `ValueError` (which the caller catches) would be acceptable, but
  escaping the caller's error handling is not.

Actual behavior (for `HTTP/`):

- The prefix check passes (`i == 5`), but the string is only 5 characters.
- `parseSaturatedNatural` reads zero digits at position 5, leaving `i` at `5`.
- The unconditional `i.inc` (skip the dot) moves `i` to `6` — past the end.
- The second `parseSaturatedNatural` starts at position `6`, which is out of
  bounds. Nim raises `IndexDefect`.
- `processRequest` catches only `ValueError`. The `IndexDefect` escapes and
  crashes the process.

The same crash occurs for `HTTP/1` (the fuzzer's saved artifact): after parsing
major version `1`, `i` is at position 6 (end of the 6-character string), and
the unconditional increment pushes it to 7 — out of bounds.

### Why This Is a Real Bug, Not a False Positive

1. **Standalone replay confirms the crash.** The saved artifact crashes the
   harness with a full stack trace pointing to `parseProtocolOriginal`.
2. **The root cause is clear and fixable.** One unconditional `i.inc` that
   should be guarded by `if i < protocol.len`.
3. **The upstream maintainers agreed and merged a fix.** Nim PR #25793 changes
   `i.inc # Skip .` to `if i < protocol.len: inc i # Skip .` — exactly the
   minimal fix.
4. **The error message is precise.** `index out of bounds: 7..5 notin 0..5`
   (for `HTTP/1`) or `6..4 notin 0..4` (for `HTTP/`) tells us exactly what
   went wrong.

## 8. Fuzzing Results

The fuzzing campaign found the crash. A representative run:

```
#2373  REDUCE cov: 3798 ft: 8650 corp: 106/4434b lim: 67 exec/s: 0 rss: 58Mb
==67332== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
Base64: R0VUIC0gSFRUUC8gSFRUUC8xLjEgSA==
stat::number_of_executed_units: 2847
```

The crash was triggered after approximately 2,847 executions. The Base64-decoded
crash input is `GET - HTTP/ HTTP/1.1 H`, a request with protocol field `HTTP/`
(missing version digits). The saved artifact `F-001_crash_input` is a 34-byte
variant triggering the same defect through protocol field `HTTP/1`.

Summary:

| Campaign | Harness | Result | Executions | Coverage |
|---|---|---|---:|---:|
| 1 | Original parser | Crash found | ~2,847 | 3,798 |

### How to Replay a Crash

`scripts/replay_crash.sh` replays the saved crash artifact against the fuzzer
binary in single-run mode (`-runs=1`). This verifies the crash is reproducible
and not a fluke. The standalone replay mode (Section 6.6) serves the same
purpose without the fuzzer engine.

## 9. AI-Assisted Review Results

Three models produced usable transcripts: DeepSeek V4 Pro, GLM-5.1, and Kimi
K2.6. DeepSeek reported eight findings, checked against source code and fuzzing
results.

DeepSeek validation summary:

| Result | Count |
|---|---:|
| Confirmed | 0 |
| Likely | 6 |
| Unlikely | 1 |
| False positive | 1 |

| AI Finding | Model Claim | My Classification | Reason |
|---|---|---|---|
| Chunked body has no `maxBody` check | Confirmed DoS | Likely | Static trace valid, no memory-exhaustion reproducer. |
| No receive timeouts | Confirmed DoS | Likely | No timeout on `recvLineInto`, but no live slow-client test. |
| Header limit checked after storing | Likely DoS | Likely | Stores header before checking `headerLimit`; bounded but real. |
| `Connection` header first-value logic | Likely logic issue | Likely | `HttpHeaderValues` returns first value only. |
| Chunked body only handled for POST | Likely logic issue | Likely | `hasChunkedEncoding` returns true only for `HttpPost`. |
| Case-sensitive `chunked` check | Likely logic issue | Likely | Transfer coding comparison is exact string matching. |
| `split(' ')` allocation amplification | Speculative DoS | Unlikely | Bounded by `maxLine`. |
| `HTTP/` accepted as version `0.0` | Speculative logic issue | False positive | Fuzzing and replay show it crashes instead. |

The most important AI error was about the same area as the fuzzing crash.
DeepSeek claimed that `HTTP/` would be accepted as version `0.0`. The actual
program crashes with `IndexDefect`.

GLM-5.1 reported ten candidate findings (including two self-withdrawn).

GLM validation summary:

| Result | Count |
|---|---:|
| Confirmed | 0 |
| Likely | 5 |
| Unlikely | 1 |
| False positive / withdrawn | 4 |

GLM made the same mistake as DeepSeek around `HTTP/`, concluding no crash
occurs and that the parser accepts version `0.0`.

Kimi K2.6 produced five candidate findings, all marked confirmed by the model,
downgraded to likely since no dynamic reproducers were built. Its useful
findings overlapped with the other models on chunked body growth and missing
receive timeouts.

Kimi did not report the confirmed fuzzing crash. None of the three models
correctly identified the bug that the fuzzer confirmed.

Overall AI validation summary:

| Model | Usable transcript | Candidates | Confirmed | Likely | False positives / withdrawn |
|---|---|---:|---:|---:|---:|
| DeepSeek V4 Pro | Yes | 8 | 0 | 6 | 1 |
| GLM-5.1 | Yes | 10 | 0 | 5 | 4 |
| Kimi K2.6 | Yes | 5 | 0 | 5 | 0 |

## 10. Evaluation

Fuzzing was better at producing confirmed evidence. It gave a minimized input,
a crash log, and a way to replay the result.

AI review was useful in a different role. It found broader design concerns that
a parser fuzzer does not model: timeout behavior, long-running chunked body
growth, header storage before limit checks. However, the AI outputs needed
manual checking because none correctly identified the confirmed crash, and two
made the wrong claim that `HTTP/` would be accepted as version `0.0`.

| Criterion | Fuzzing | AI-Assisted Review |
|---|---|---|
| Confirmed bugs | 1 | 0 |
| Main strength | Reproducible runtime evidence | Broad static hypothesis generation |
| Main weakness | Limited to modeled parser paths | Can misread runtime behavior |
| Evidence quality | Crash input, stack trace, replay | Source-level reasoning requiring validation |

AI review output should be used like a review checklist. Each item needs either
a reproducer, a complete static trace, or a clear reason why it is not
exploitable.

## 11. Remediation Discussion

The crash is caused by one unconditional index increment. The minimal fix is to
skip the dot only when there is still a character to skip:

```nim
i.inc protocol.parseSaturatedNatural(result.major, i)
if i < protocol.len:
  inc i # Skip .
i.inc protocol.parseSaturatedNatural(result.minor, i)
```

This keeps the existing behavior for non-HTTP prefixes (they raise the handled
`ValueError`). It only prevents the parser from manufacturing an out-of-bounds
index when the version is incomplete.

### Upstream Fix Confirmation

The Nim project merged this exact fix in [PR #25793](https://github.com/nim-lang/Nim/pull/25793).

- **Old**: `i.inc # Skip .`
- **New**: `if i < protocol.len: inc i # Skip .`

The fact that upstream merged a fix identical to what we identified
independently validates both the finding and our root-cause analysis.

## 12. Limitations

The fuzzer does not run a complete server. It tests parser paths but does not
model real socket timing, slow clients, simultaneous connections, callback
behavior, or OS file-descriptor limits.

The three AI model outputs were validated manually. The report compares fuzzing
against a small sample of AI-assisted review runs.

The confirmed impact is denial of service. No evidence of memory corruption or
remote code execution was found.

## 13. Lessons Learned

**Reproducible evidence matters.** A crash claim is strongest when it includes
the exact input, the fuzzer log, and an independent replay that produces the
same crash through the same code path.

**Distinguish tools from evidence.** A fuzzer produces direct runtime evidence.
An AI model produces static hypotheses. Both are useful, but they serve
different roles. A finding is not "confirmed" because a model sounds confident
— it is confirmed because you can reproduce it.

**Minimization is valuable.** libFuzzer's automatic crash minimization reduced
the input to something a human can reason about. The protocol field `HTTP/1` is
clearly missing the dot-separator and minor version, pointing directly to the
unconditional `i.inc`.

**LLMs can point toward interesting code but misread runtime behavior.** In
this project, DeepSeek and GLM noticed the suspicious `HTTP/` case but reached
the opposite conclusion from the actual program, while Kimi missed the crash
entirely.

## 14. Conclusion

The project implemented a working local security-audit prototype and used it to
find a real crash in Nim's `std/asynchttpserver`. Fuzzing produced the strongest
confirmed result: an uncaught `IndexDefect` from `parseProtocol`. The upstream
Nim project has since merged a fix for this exact issue (PR #25793), confirming
that our methodology found a genuine, previously existing bug.

AI-assisted review produced useful likely findings but no confirmed finding.
All usable model outputs required validation, and all over-claimed at least
some findings as confirmed. The best workflow is to use AI for broad review and
hypothesis generation, then use fuzzing and replay to validate the claims. The
useful unit is not "AI found a bug" — it is a reproducible pipeline that turns
a suspicious idea into a tested input and a verified fix.
