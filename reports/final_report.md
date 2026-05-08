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
`IndexDefect` and crash a process using this parser.

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

## 6. Testing Procedure

The submitted scripts reproduce the build and tests:

```bash
scripts/build_fuzzers.sh
scripts/replay_crash.sh
scripts/run_fuzzing.sh 60
```

The saved experiment followed this procedure:

1. Build the original harness.
2. Run libFuzzer using only benign seed inputs.
3. Save the minimized crashing input.
4. Build the fixed harness with the minimal protocol parser fix.
5. Replay the crashing input against the fixed harness.
6. Run a second fuzzing campaign against the fixed harness.

The important saved evidence files are:

```text
experiments/fuzzing/results/campaign_1_original.log
experiments/fuzzing/results/F-001_crash_input
experiments/fuzzing/results/F-001_fixed_replay.log
experiments/fuzzing/results/campaign_2_fixed.log
```

## 7. Confirmed Vulnerability

### F-001: `parseProtocol` IndexDefect

The confirmed vulnerability is a crash in `parseProtocol`.

Relevant source:

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
- incomplete version values such as `HTTP/` should not crash the process.

Actual behavior:

- `HTTP/` passes the prefix check,
- `i` becomes `5`,
- the string length is also `5`,
- the first numeric parse consumes no digits,
- the original code still increments `i` to skip `.`,
- `i` moves past the end of the string,
- the second numeric parse starts out of bounds,
- Nim raises `IndexDefect`,
- `processRequest` catches only `ValueError`,
- the defect escapes and crashes the process.

The direct reproducer in `validation/reproducers/parse_protocol_index_defect.nim`
prints:

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
|---|---|---|---:|---:|---:|
| 1 | Original parser | Crash found | 47,319 | 3,840 | 139 MB |
| 2 | Minimal protocol parser fix | No crash | 625,582 | 4,492 | 544 MB |

The fixed replay log showed that the saved crash input no longer crashed the
fixed harness. This supports the conclusion that the unconditional `i.inc`
before parsing the minor version was the root cause.

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
|---|---:|---:|---:|---:|---:|
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

The most important lesson was that reproducible evidence matters. A crash claim
is much stronger when it includes:

- the exact input,
- the command used to build the harness,
- the fuzzer log,
- a direct reproducer,
- and a fixed replay test.

I also learned that an LLM can help organize an audit and point toward
interesting code paths, but it can be wrong about runtime behavior. In this
project, DeepSeek and GLM noticed the suspicious `HTTP/` case but reached the
opposite conclusion from the actual program, while Kimi missed that confirmed
crash entirely.

## 14. Conclusion

The project implemented a working local security-audit prototype and used it to
find a real crash in Nim's `std/asynchttpserver`. Fuzzing produced the strongest
confirmed result: an uncaught `IndexDefect` from `parseProtocol("HTTP/")`.

AI-assisted review produced useful likely findings but no confirmed finding in
this run. All usable model outputs required validation, and all over-claimed at
least some findings as confirmed. The best workflow is to use AI for broad
review and hypothesis generation, then use fuzzing and targeted reproducers to
validate the claims.
