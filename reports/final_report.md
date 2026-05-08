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
parser. A malformed request-line protocol token, `HTTP/`, can raise an uncaught
`IndexDefect` and crash a process using this parser. This vulnerability has
since been fixed upstream in the Nim repository (PR #25793), which validates our
finding as a real, previously existing bug. For this project, we used an older
Nim version intentionally — the goal is to study vulnerability discovery
techniques, not to exploit live systems.

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
| Fuzz harnesses | Exercise selected parser paths with generated input | `experiments/fuzzing/harness/` |
| Seed corpus | Small benign starting inputs for libFuzzer | `experiments/fuzzing/corpus/` |
| Saved evidence | Fuzz logs, crash input, fixed replay log | `experiments/fuzzing/results/` |
| AI review notes | Prompt, raw model outputs, extracted findings | `ai_findings/` |

The fuzz harness does not start a real network server. Instead, it directly
calls the parsing logic that would normally receive data from a client. This
makes the test faster and more deterministic, while still exercising the code
that handles attacker-controlled HTTP strings.

The fuzzer input uses a leading mode byte:

| Mode | Parser Exercised |
|---:|---|
| 0 | HTTP protocol parser |
| 1 | request-line parser |
| 2 | header parser |
| 3 | URI parser |
| 4 | `Content-Length` parser |
| 5 | chunk-size parser |

For example, the saved crash input is:

```text
0HTTP/
```

The first character, `0`, selects mode 0. The actual parser payload is `HTTP/`.

Two harnesses are included. `asynchttpserver_fuzzer.nim` keeps the original
vulnerable parser behavior. `asynchttpserver_fuzzer_fixed.nim` uses the minimal
fix: it still rejects tokens that do not start with `HTTP/`, but it only skips
the `.` separator if that character is actually present.

## 5. Security Techniques Used

### 5.1 Coverage-Guided Fuzzing

The first technique is fuzz testing. libFuzzer mutates inputs and uses coverage
feedback to explore new program paths. The harness was compiled with:

- Clang,
- libFuzzer,
- AddressSanitizer,
- UndefinedBehaviorSanitizer.

This is an attack simulation because it repeatedly sends malformed local inputs
to code that normally processes untrusted HTTP data.

### 5.2 AI-Assisted Static Review

The second technique is LLM-assisted review. A single structured prompt asked
the model to inspect `asynchttpserver.nim` and report findings with:

- title,
- vulnerability type,
- location,
- triggering input,
- root cause,
- exploitability,
- classification.

DeepSeek, GLM-5.1, and Kimi K2.6 produced usable transcripts for this
submission.

The AI output was treated as a set of hypotheses. I checked the source code and
the fuzzing evidence before classifying each claim.

## 6. Experimental Methodology: Step-by-Step Walkthrough

This section documents exactly what commands were run, what each one does, what
output was observed, and the reasoning behind each step. The goal is to show how
a student can go from "I want to find bugs" to "here is a confirmed crash with
evidence" using real tools.

### 6.1 Building the Fuzzer

The build command lives in `scripts/build_fuzzers.sh`. The core compilation
command is:

```bash
nim c \
  --cc:clang \
  -d:noSignalHandler \
  -d:useMalloc \
  --noMain:on \
  --passC:-fsanitize=fuzzer,address,undefined \
  --passC:-g \
  --passL:-fsanitize=fuzzer,address,undefined \
  --passL:-g \
  experiments/fuzzing/harness/asynchttpserver_fuzzer.nim
```

What each flag means, and why we used it:

- **`nim c`** — Invokes the Nim compiler to produce a C-compilable output, then
  compiles it to a native binary. Unlike `nim r` (compile-and-run), this creates
  a reusable executable that we can pass to libFuzzer.

- **`--cc:clang`** — Forces Nim to use the Clang C compiler instead of GCC.
  libFuzzer is distributed as part of the LLVM project and is designed to work
  with Clang. If we tried to use GCC, the `-fsanitize=fuzzer` flag would not be
  recognized and the build would fail.

- **`-d:noSignalHandler`** — Disables Nim's default signal handlers for
  crashes (SIGSEGV, SIGABRT, etc.). Without this flag, Nim would catch those
  signals and print a stack trace, which prevents AddressSanitizer from
  detecting the crash and producing its own detailed report. We want ASan to be
  the one detecting and reporting crashes.

- **`-d:useMalloc`** — Tells Nim to use the system's `malloc`/`free` instead of
  Nim's own garbage-collected memory allocator. This is necessary because
  AddressSanitizer instruments the system allocator to detect buffer overflows,
  use-after-free, and other memory errors. Nim's own allocator would bypass this
  instrumentation.

- **`--noMain:on`** — Suppresses Nim's default `main()` function generation.
  libFuzzer provides its own `main()` that runs the fuzzing loop. If Nim also
  generates a `main()`, we would get a linker error about duplicate symbols.

- **`--passC:-fsanitize=fuzzer,address,undefined`** — Passes flags directly to
  the C compiler. The `fuzzer` flag links in libFuzzer's coverage-guided
  mutation engine. The `address` flag enables AddressSanitizer, which detects
  buffer overflows, use-after-free, and out-of-bounds memory access. The
  `undefined` flag enables UndefinedBehaviorSanitizer, which catches integer
  overflow, null pointer dereference, and other undefined behavior.

- **`--passC:-g`** and **`--passL:-g`** — Include debug symbols in the binary.
  This is not strictly required for fuzzing, but it is essential for getting
  readable stack traces when a crash occurs. Without debug symbols, the crash
  report would only show hex addresses, making it much harder to locate the
  vulnerable code.

- **`--passL:-fsanitize=fuzzer,address,undefined`** — Passes the same sanitizer
  flags to the linker. The linker needs these flags to resolve the sanitizer
  instrumentation and link the fuzzer runtime.

The build produces an executable at
`experiments/fuzzing/harness/asynchttpserver_fuzzer`. This binary is a
standalone fuzz target that libFuzzer will repeatedly invoke.

### 6.2 The Seed Corpus

Before running the fuzzer, we need a **seed corpus** — a set of small, valid
inputs that exercise the code paths we want to test. libFuzzer starts from these
inputs and mutates them to discover new paths and crashes.

We prepared three seed files in `experiments/fuzzing/corpus/`:

- **`seed_get_http11`** — A minimal valid GET request:
  ```
  GET / HTTP/1.1

  ```
  This exercises the request-line parser, protocol parser, and header detection.

- **`seed_post_content_length`** — A POST request with `Content-Length`:
  ```
  POST /submit HTTP/1.1
  Host: example.local
  Content-Length: 5

  hello
  ```
  This exercises the `Content-Length` body reading path and header parsing.

- **`seed_post_chunked`** — A POST request with chunked transfer encoding:
  ```
  POST /upload HTTP/1.1
  Transfer-Encoding: chunked

  5
  hello
  0

  ```
  This exercises the chunked body parsing path.

The seeds are intentionally well-formed. The fuzzer's job is to mutate them into
malformed inputs that trigger crashes or unexpected behavior.

### 6.3 Running the Fuzzer

The run command lives in `scripts/run_fuzzing.sh`. The actual fuzzer invocation
is:

```bash
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -print_final_stats=1 \
  -max_total_time=60 \
  -artifact_prefix=experiments/fuzzing/results/ \
  experiments/fuzzing/corpus/
```

What each part does:

- **`ASAN_OPTIONS=detect_leaks=0`** — An environment variable controlling
  AddressSanitizer behavior. We disable leak detection because the fuzzer
  intentionally never frees memory to maximize speed. Memory leaks in a fuzz
  target are normal and not a bug, so we suppress those reports to avoid false
  positives.

- **`experiments/fuzzing/harness/asynchttpserver_fuzzer`** — The binary we built
  in step 6.1. libFuzzer will call our `LLVMFuzzerTestOneInput` function
  repeatedly with mutated inputs.

- **`-print_final_stats=1`** — When the fuzzer finishes (or crashes), print a
  summary of execution statistics: total runs, coverage edges discovered,
  corpus size, and execution speed.

- **`-max_total_time=60`** — Run for at most 60 seconds. Without this, the
  fuzzer runs indefinitely. In a real security audit, fuzzing campaigns can run
  for hours or days, but 60 seconds is enough for this educational experiment.

- **`-artifact_prefix=experiments/fuzzing/results/`** — When a crash is found,
  save the crashing input to this directory with a generated filename. This is
  how we collect evidence.

- **`experiments/fuzzing/corpus/`** — The directory containing our seed inputs.
  libFuzzer reads everything in this directory as its starting point.

### 6.4 Interpreting the Fuzzer Output

The fuzzer prints status lines as it runs. Each line shows the current state:

```
#47319 REDUCE cov: 3840 ft: 11321 corp: 348/4129b ...
SUMMARY: libFuzzer: fuzz target exited
artifact_prefix='experiments/fuzzing/results/'
Base64: MEhUVFAv
```

Let's decode each part:

- **`#47319`** — The fuzzer has executed 47,319 test cases so far. This counter
  increments rapidly — libFuzzer can test thousands of inputs per second.

- **`REDUCE`** — libFuzzer is shrinking the crashing input to find the smallest
  version that still crashes. This is called *minimization*, and it is one of
  libFuzzer's most useful features. Instead of a 500-byte crash input, the
  fuzzer tries removing bytes one at a time until it finds the minimal set that
  still triggers the crash. This makes the bug much easier to understand and
  reproduce.

- **`cov: 3840`** — 3,840 unique code edges have been reached. Code coverage is
  measured at the basic-block level: every branch (if/else, loop entry/exit,
  function call) is an "edge." The higher this number, the more of the target
  code the fuzzer has explored.

- **`ft: 11321`** — libFuzzer has discovered 11,321 distinct *features*
  (combinations of code edges). Features are used internally by libFuzzer to
  decide which inputs are interesting enough to keep in the corpus.

- **`corp: 348/4129b`** — The corpus currently contains 348 saved inputs, taking
  up 4,129 bytes total. The corpus grows as the fuzzer finds inputs that trigger
  new coverage.

- **`SUMMARY: libFuzzer: fuzz target exited`** — This means the target process
  terminated unexpectedly (the harness called `quit(70)` when a `Defect` was
  caught). A normal exit would say `DONE` instead.

- **`Base64: MEhUVFAv`** — The crashing input encoded in Base64. We can decode
  this to see what triggered the crash. Decoding `MEhUVFAv` gives us the bytes
  `0HTTP/`.

### 6.5 The Crash Artifact

The saved crash file at `experiments/fuzzing/results/F-001_crash_input` contains
the bytes that crashed the parser. We can inspect it with a hex dump:

```bash
xxd experiments/fuzzing/results/F-001_crash_input
```

Output:

```
00000000: 3048 5454 502f                           0HTTP/
```

The bytes are:
- `30` (0x30) → ASCII `0` — mode selector byte, choosing protocol parser
- `48 54 54 50 2f` → ASCII `HTTP/` — the actual payload

So the input is: mode byte `0` followed by the string `HTTP/`. This means: "use
mode 0 (protocol parser) and parse the string `HTTP/`."

### 6.6 Verifying the Crash with a Direct Reproducer

A crash artifact from a fuzzer is evidence, but we should verify it
independently. The fuzzer could have crashed due to a sanitizer false positive,
a harness bug, or an environment issue. The gold standard is a *minimal
standalone reproducer* that calls the vulnerable code directly.

We wrote `validation/reproducers/parse_protocol_index_defect.nim`:

```nim
import std/parseutils

proc parseProtocol(protocol: string): tuple[orig: string, major, minor: int] =
  result = default(tuple[orig: string, major, minor: int])
  var i = protocol.skipIgnoreCase("HTTP/")
  if i != 5:
    raise newException(ValueError, "Invalid request protocol. Got: " & protocol)
  result.orig = protocol
  i.inc protocol.parseSaturatedNatural(result.major, i)
  i.inc
  i.inc protocol.parseSaturatedNatural(result.minor, i)

for protocol in ["HTTP/1.1", "HTTP/"]:
  echo "Input: ", protocol
  let parsed = parseProtocol(protocol)
  echo "Parsed: ", parsed
```

We compile and run it:

```bash
nim c --panics:on --mm:arc -r validation/reproducers/parse_protocol_index_defect.nim
```

Why these flags:

- **`--panics:on`** — Makes Nim turn `IndexDefect` (the crash we found) into a
  fatal error that terminates the program. Without this flag, Nim's default
  behavior is to raise `IndexDefect` as an exception that could be caught. We
  want to reproduce the exact crash that happens in production where `Defect`
  exceptions escape because the caller only catches `ValueError`.

- **`--mm:arc`** — Uses Nim's ARC memory management. This is the default for
  modern Nim programs, and it matches what users of `asynchttpserver` would use.

The output confirms the crash:

```
Input: HTTP/1.1
Parsed: (orig: "HTTP/1.1", major: 1, minor: 1)
Input: HTTP/
Error: unhandled exception: index out of bounds: 6..4 notin 0..4 [IndexDefect]
```

The first test case (`HTTP/1.1`) works correctly, showing that our reproducer is
valid. The second case (`HTTP/`) crashes with `IndexDefect`, reproducing exactly
what the fuzzer found. The error message is specific: the index `6..4` means
the code tried to access a substring from position 6 to 4 in a string of length
4 (indices 0..4). This tells us immediately that an index went past the end of
the string.

### 6.7 How the AI Review Was Conducted

The AI workflow was separate from the fuzzing. Here is exactly what we did:

1. **Wrote a structured prompt** (`ai_findings/VULN_DISCOVERY_PROMPT.txt`). The
   prompt lists:
   - The target file and dependencies,
   - An output format requiring title, type, location, input, root cause,
     exploitability, and classification (CONFIRMED / LIKELY / SPECULATIVE),
   - 13 specific attack surfaces to examine (protocol parsing, request-line
     splitting, header parsing, `Content-Length`, chunked encoding, URI parsing,
     connection handling, timeouts, etc.),
   - Rules: be evidence-based, trace code paths, state confidence.

2. **Submitted the same prompt** to three different LLMs: DeepSeek V4 Pro,
   GLM-5.1, and Kimi K2.6. This was done through their respective chat
   interfaces (not programmatically). Each model received the prompt and the
   441-line source file.

3. **Saved the raw outputs** in `ai_findings/<model>/output.txt`. These are the
   verbatim transcripts.

4. **Extracted findings** into a structured format in
   `ai_findings/<model>/findings_extracted.md`. Each finding was assigned a
   model ID, the original classification, and cross-referenced against the
   source code and fuzzing evidence.

5. **Validated each finding** by checking the source code and comparing against
   the fuzzer results. This is the critical step: the AI output is treated as a
   list of hypotheses, not as confirmed facts.

### 6.8 How to Distinguish a Real Bug from a False Positive

This is one of the most important skills in vulnerability research. When a tool
reports a "finding," you cannot simply trust it. Here is the checklist we used
to classify each finding as confirmed, likely, unlikely, or false positive:

1. **Can we produce a minimal standalone reproducer?** This is the strongest
   form of evidence. If a 5-line Nim program can trigger the crash, the bug is
   real and not a harness artifact. The `parseProtocol("HTTP/")` finding passed
   this test.

2. **Can we trace the code path from input to failure?** For each finding, we
   located the exact lines in `asynchttpserver.nim` and walked through the
   execution by hand. If the static trace is valid but we cannot produce a
   dynamic reproducer (e.g., because it requires a live network), we classify it
   as *likely*.

3. **Is the AI misreading runtime behavior?** AI models analyze code statically
   and can make wrong assumptions about how the program actually executes. For
   example, both DeepSeek and GLM noticed the `HTTP/` case but concluded it
   would be accepted as version `0.0`. The actual program crashes with
   `IndexDefect`. When a model's predicted behavior contradicts actual runtime
   evidence, the finding is a *false positive* regardless of how confident the
   model sounds.

4. **Is the claim bounded by existing limits?** Some findings are technically
   true but practically harmless. For example, `split(' ')` does create multiple
   heap allocations, but the `maxLine` limit of 8,192 bytes bounds the damage.
   We classified this as *unlikely*.

5. **Did the model withdraw its own finding?** Both GLM and DeepSeek sometimes
   proposed a finding and then, within their own analysis, explained why it was
   not exploitable. We counted these as *false positive / withdrawn* because the
   model's own reasoning contradicts the claim.

6. **Does the fuzzer agree?** The fuzzer provides complementary evidence. If the
   fuzzer reaches the same code but does not crash, and the AI claims a crash is
   possible, the AI is likely wrong.

## 7. Confirmed Vulnerability

### F-001: `parseProtocol` IndexDefect

The confirmed vulnerability is a crash in `parseProtocol`.

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

Actual behavior:

- `HTTP/` passes the prefix check (the first five characters match `HTTP/`),
- `i` becomes `5`,
- the string length is also `5` (five characters: H, T, T, P, /),
- the first numeric parse (`parseSaturatedNatural`) is called with `i == 5` and
  `protocol.len == 5`, so it starts reading at position 5 — which is at the end
  of the string. It consumes zero digits, leaving `i` at `5`.
- the original code then executes `i.inc` unconditionally (the line that says
  "skip the dot"). This moves `i` to `6`.
- `i` is now `6`, but the string has valid indices `0..4`. We are past the end.
- the second numeric parse starts at position `6`, which is out of bounds,
- Nim raises `IndexDefect`,
- `processRequest` catches only `ValueError` (the exception raised when the
  prefix check fails),
- the `IndexDefect` escapes and crashes the process.

### Why This Is a Real Bug, Not a False Positive

This finding meets every criterion for a confirmed vulnerability:

1. **Minimal standalone reproducer exists.** The file
   `validation/reproducers/parse_protocol_index_defect.nim` is 16 lines long
   and triggers the crash without any fuzzing harness.

2. **The root cause is clear and fixable.** One unconditional `i.inc` that
   should be guarded by `if i < protocol.len`. This is a simple off-by-one
   logic error, not a complex race condition or environmental issue.

3. **The fuzzer and reproducer agree.** Both the libFuzzer artifact and the
   direct reproducer produce the same crash with the same input.

4. **The upstream maintainers agreed and merged a fix.** The Nim project merged
   PR #25793, which changes the unconditional `i.inc # Skip .` to
   `if i < protocol.len: inc i # Skip .` — exactly the minimal fix we describe
   in Section 11.

5. **The error message is precise.** `index out of bounds: 6..4 notin 0..4`
   tells us exactly what went wrong: the code tried to access indices 6 through
   4 in a 5-character string. There is no ambiguity about what failed.

The direct reproducer output:

```text
Input: HTTP/1.1
Parsed: (orig: "HTTP/1.1", major: 1, minor: 1)
Input: HTTP/
Error: unhandled exception: index out of bounds: 6..4 notin 0..4 [IndexDefect]
```

The fuzzer rediscovered the same input. The saved artifact bytes are:

```text
30 48 54 54 50 2f
```

This is ASCII for:

```text
0HTTP/
```

The first byte selects the protocol-parser mode. The payload `HTTP/` is the
malformed attacker-controlled protocol string.

## 8. Fuzzing Results

The first fuzzing campaign found the crash:

```text
#47319 REDUCE cov: 3840 ft: 11321 corp: 348/4129b ...
SUMMARY: libFuzzer: fuzz target exited
artifact_prefix='experiments/fuzzing/results/'
Base64: MEhUVFAv
```

The second campaign tested the fixed harness:

```text
#625582 DONE cov: 4492 ft: 19642 corp: 700/77Kb lim: 1660 exec/s: 10255 rss: 544Mb
Done 625582 runs in 61 second(s)
```

Summary:

| Campaign | Harness | Result | Executions | Coverage | Peak RSS |
|---|---|---|---|---|---:|---:|
| 1 | Original parser | Crash found | 47,319 | 3,840 | 139 MB |
| 2 | Minimal protocol parser fix | No crash | 625,582 | 4,492 | 544 MB |

The fixed replay log showed that the saved crash input no longer crashed the
fixed harness. This supports the conclusion that the unconditional `i.inc`
before parsing the minor version was the root cause.

### How to Replay a Crash

The replay command lives in `scripts/replay_crash.sh`. It works by passing the
saved crash artifact back to the fuzzer in single-run mode:

```bash
ASAN_OPTIONS=detect_leaks=0 \
  experiments/fuzzing/harness/asynchttpserver_fuzzer \
  -runs=1 \
  experiments/fuzzing/results/F-001_crash_input
```

The `-runs=1` flag tells libFuzzer to run exactly one test (the given file) and
exit. This is useful for two purposes:

1. **Verification**: Does the saved input really crash the original harness
   consistently? If the crash is reproducible, this confirms it was not a fluke
   caused by a race condition or memory corruption from a previous test.

2. **Regression testing**: After applying a fix, replay the same input against
   the fixed binary. If it no longer crashes, the fix works.

In our experiment, the replay against the original harness produced the expected
crash output, and the replay against the fixed harness produced no crash.

## 9. AI-Assisted Review Results

The AI experiment used the same prompt for each model. The prompt listed the
target file, relevant dependencies, and 13 attack surfaces such as protocol
parsing, request-line splitting, header parsing, `Content-Length`, chunked
encoding, timeouts, and connection handling.

Three models produced usable transcripts: DeepSeek V4 Pro, GLM-5.1, and Kimi
K2.6. DeepSeek reported eight findings. I extracted each one into
`ai_findings/deepseek_v4_pro/findings_extracted.md` and checked it manually
against the source code and fuzzing results.

DeepSeek validation summary:

| Result | Count |
|---|---:|
| Confirmed | 0 |
| Likely | 6 |
| Unlikely | 1 |
| False positive | 1 |

The detailed classification was:

| AI Finding | Model Claim | My Classification | Reason |
|---|---|---|---|
| Chunked body has no `maxBody` check | Confirmed DoS | Likely | Static trace is valid, but no memory-exhaustion reproducer was built. |
| No receive timeouts | Confirmed DoS | Likely | Code has no timeout on `recvLineInto`, but live slow-client testing was not implemented. |
| Header limit checked after storing | Likely DoS | Likely | Code stores the header before checking `headerLimit`; impact is bounded but real. |
| `Connection` header first-value logic | Likely logic issue | Likely | `HttpHeaderValues` string conversion returns the first value only. |
| Chunked body only handled for POST | Likely logic issue | Likely | `hasChunkedEncoding` returns true only for `HttpPost`. |
| Case-sensitive `chunked` check | Likely logic issue | Likely | Transfer coding comparison is exact string matching. |
| `split(' ')` allocation amplification | Speculative DoS | Unlikely | The behavior is bounded by `maxLine`, so impact is limited. |
| `HTTP/` accepted as version `0.0` | Speculative logic issue | False positive | Fuzzing and the reproducer show it crashes instead. |

The strongest useful AI findings were static observations:

1. Chunked request bodies are accumulated without enforcing `maxBody`.
2. `recvLineInto` calls do not use timeouts, which can support Slowloris-style
   connection holding.
3. Headers are stored before the `headerLimit` rejection check, creating bounded
   memory pressure.

These were classified as likely rather than confirmed because I did not build
separate live-network or memory-exhaustion reproducers for them.

The most important AI error was about the same area as the fuzzing crash.
DeepSeek claimed that `HTTP/` would be accepted as version `0.0`. The actual
reproducer and fuzzer show that it raises `IndexDefect`. This was classified as
a false positive.

GLM-5.1 also produced a usable transcript. It reported ten candidate findings,
including two that it withdrew inside its own analysis. I extracted them into
`ai_findings/glm_5_1/findings_extracted.md`.

GLM validation summary:

| Result | Count |
|---|---:|
| Confirmed | 0 |
| Likely | 5 |
| Unlikely | 1 |
| False positive / withdrawn | 4 |

The useful GLM findings overlapped with DeepSeek on chunked body growth and no
receive timeouts. GLM also pointed out low-impact parser strictness issues such
as malformed protocol separators and headers without colons.

GLM made the same important mistake as DeepSeek around `HTTP/`. It mentioned
the input `GET / HTTP/`, but concluded that no crash occurs and that the parser
accepts version `0.0`. The local reproducer and fuzzing logs show the opposite:
the input raises `IndexDefect`. Therefore GLM is not counted as finding the
confirmed fuzzing bug.

Kimi K2.6 produced a shorter transcript with five candidate findings. It marked
all five as confirmed, but I downgraded them to likely because I did not build
dynamic reproducers for them in this submission. Its useful findings overlapped
with the other models on chunked body growth and missing receive timeouts. Kimi
also reported two additional plausible parser issues: partially parsed
`Content-Length` values such as `0x10`, and malformed request lines on
persistent connections possibly reusing stale URL or protocol state.

Kimi did not report the confirmed `HTTP/` fuzzing crash. This makes the model
comparison clearer: the AI outputs were useful for review coverage, but none of
the usable model transcripts correctly identified the bug that the fuzzer
confirmed.

Overall AI validation summary:

| Model | Usable transcript | Reported candidates | Validated confirmed | Validated likely | False positives / withdrawn |
|---|---|---:|---:|---:|---:|---:|
| DeepSeek V4 Pro | Yes | 8 | 0 | 6 | 1 |
| GLM-5.1 | Yes | 10 | 0 | 5 | 4 |
| Kimi K2.6 | Yes | 5 | 0 | 5 | 0 |

## 10. Evaluation

Fuzzing was better at producing confirmed evidence. It gave a minimized input,
a crash log, and a way to replay the result. It also let me test the minimal
parser fix against the same saved input.

AI review was still useful, but in a different role. It found broader design
concerns that a small parser fuzzer does not fully model. For example, timeout
behavior and long-running chunked body growth are better evaluated with a live
server simulation than with the current harness. However, the AI outputs needed
manual checking because none of them correctly identified the confirmed crash,
and two of them made the wrong claim that `HTTP/` would be accepted as version
`0.0`.

My conclusion is that AI review is useful for generating hypotheses, but fuzzing
or targeted tests are needed before calling a finding confirmed.

The following table summarizes the comparison:

| Criterion | Fuzzing | AI-Assisted Review |
|---|---|---|
| Confirmed bugs | 1 | 0 |
| Main strength | Reproducible runtime evidence | Broad static hypothesis generation |
| Main weakness | Limited to modeled parser paths | Can misread runtime behavior |
| Evidence quality | Crash input, stack trace, replay | Source-level reasoning requiring validation |
| Best use in this project | Finding `parseProtocol("HTTP/")` crash | Identifying resource and protocol-design risks |

This result does not mean AI review is useless. It means the output should be
used like a review checklist. Each item needs either a reproducer, a complete
static trace, or a clear reason why it is not exploitable.

## 11. Remediation Discussion

The fix does not need to add many new error branches. The crash is caused by
one unconditional index increment. In the original code, `HTTP/` leaves `i` at
the end of the string. The parser then increments `i` to skip a dot even though
there is no dot, so the next numeric parse starts beyond the end of the string.

The minimal fix is to skip the dot only when there is still a character to
skip:

```nim
result = default(tuple[orig: string, major, minor: int])
var i = protocol.skipIgnoreCase("HTTP/")
if i != 5:
  raise newException(ValueError, "Invalid request protocol. Got: " & protocol)

result.orig = protocol
i.inc protocol.parseSaturatedNatural(result.major, i)
if i < protocol.len:
  inc i # Skip .
i.inc protocol.parseSaturatedNatural(result.minor, i)
```

This keeps the existing behavior for non-HTTP prefixes: they still raise the
handled `ValueError`. It only prevents the parser from manufacturing an
out-of-bounds index when the version is incomplete. For `HTTP/`, the numeric
version fields remain at their default zero values and the original token is
still preserved in `orig`. The fixed harness used this minimal behavior and
successfully replayed the crash input without terminating.

### Upstream Fix Confirmation

The Nim project merged this exact fix in [PR #25793](https://github.com/nim-lang/Nim/pull/25793).
The upstream change is:

- **Old**: `i.inc # Skip .`
- **New**: `if i < protocol.len: inc i # Skip .`

This is a one-character logic change (adding the bounds guard) that prevents the
out-of-bounds access. The fact that the upstream maintainers merged a fix
identical to what we identified independently validates both the finding and our
analysis of the root cause.

## 12. Limitations

The main limitation is that the fuzzer does not run a complete server. It tests
important parser paths but does not model:

- real socket timing,
- slow clients,
- many simultaneous connections,
- callback behavior,
- operating-system file-descriptor limits.

Also, the three AI model outputs were validated manually rather than treated as
ground truth. The report therefore compares fuzzing against a small sample of
AI-assisted review runs.

Finally, the confirmed impact is denial of service. I did not find evidence of
memory corruption or remote code execution.

## 13. Lessons Learned

The most important lesson was that **reproducible evidence matters**. A crash
claim is much stronger when it includes:

- the exact input,
- the command used to build the harness,
- the fuzzer log,
- a direct reproducer,
- and a fixed replay test.

The second lesson was about **distinguishing tools from evidence**. A fuzzer
produces direct runtime evidence (a crash log with an exact input). An AI model
produces static analysis (a hypothesis about code behavior). Both are useful in
a security audit, but they serve different roles. A finding is not "confirmed"
because a model sounds confident — it is confirmed because you can reproduce it.

The third lesson was about **the value of minimization**. libFuzzer's automatic
crash minimization turned what could have been a 500-byte mutated input into a
6-byte artifact (`0HTTP/`). This made the root cause obvious: remove the mode
byte and you get `HTTP/`, which anyone can immediately see is a protocol string
missing its version digits.

I also learned that an LLM can help organize an audit and point toward
interesting code paths, but it can be wrong about runtime behavior. In this
project, DeepSeek and GLM noticed the suspicious `HTTP/` case but reached the
opposite conclusion from the actual program, while Kimi missed that confirmed
crash entirely.

## 14. Conclusion

The project implemented a working local security-audit prototype and used it to
find a real crash in Nim's `std/asynchttpserver`. Fuzzing produced the strongest
confirmed result: an uncaught `IndexDefect` from `parseProtocol("HTTP/")`.
The upstream Nim project has since merged a fix for this exact issue (PR #25793),
confirming that our methodology found a genuine, previously existing bug.

AI-assisted review produced useful likely findings but no confirmed finding in
this run. All usable model outputs required validation, and all over-claimed at
least some findings as confirmed. The best workflow we found is to use AI for
broad review and hypothesis generation, then use fuzzing and targeted
reproducers to validate the claims. The useful unit is not "AI found a bug" —
it is a reproducible pipeline that turns a suspicious idea into a tested input
and a verified fix.
