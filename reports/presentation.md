# 7-Minute Presentation: Fuzzing and AI Review of Nim `asynchttpserver`

## Timing Plan

| Slide | Topic | Time |
|---:|---|---:|
| 1 | Motivation and research question | 0:45 |
| 2 | Target and threat model | 0:55 |
| 3 | What fuzzing means here — with real commands | 1:00 |
| 4 | Confirmed fuzzing result | 1:10 |
| 5 | AI review setup and results | 1:15 |
| 6 | Fuzzing vs AI comparison | 1:00 |
| 7 | Conclusion | 0:45 |

Total: about 6:50, leaving a few seconds for transitions.

## Slide 1: Why This Project Matters

On slide:

- Real software is now being audited with both fuzzers and AI models.
- Mozilla reported using Claude Mythos Preview and other models to help harden
  Firefox.
- Project question: can a small student audit reproduce the same evidence
  pipeline?
- Target: Nim `std/asynchttpserver`.
- The reproduced bug has since been fixed upstream (Nim PR #25793).

Suggested visual:

- Mozilla security-fix chart:
  https://hacks.mozilla.org/wp-content/uploads/2026/05/security-bug-fixes-1-scaled.png

Speaker notes:

In May 2026, Mozilla published a post about hardening Firefox with Claude
Mythos Preview and other AI models. The interesting part is not just "AI found
bugs." Mozilla describes a pipeline where models generate hypotheses and test
cases, then the team validates and ships fixes. That motivated my project. I
wanted to compare two techniques we can run locally: coverage-guided fuzzing
and LLM-assisted code review. The question is which technique gives better
evidence on a smaller target. Important correction: this was not an original
first discovery by us. The contribution is that we reproduced and validated the
issue locally with a fuzzer, a standalone reproducer, and a fixed replay.

## Slide 2: Target and Threat Model

On slide:

- Target: request parsing in `std/asynchttpserver`.
- Attacker: unauthenticated client sending malformed HTTP.
- Main risks:
  - process crash,
  - memory exhaustion,
  - connection exhaustion,
  - parser logic mistakes.
- Scope: local defensive testing on an intentionally older Nim version. This is
  an educational reproduction and validation exercise, not an exploitation
  attempt or a claim of first discovery.

Suggested visual:

- `reports/presentation_assets/http_request_anatomy.svg`

Speaker notes:

The target is not a full production deployment. I focused on parser code inside
Nim's asynchronous HTTP server. The attacker controls the bytes in the request
line, headers, and body. That is enough to test denial of service and parsing
logic. We used an older Nim version intentionally. The goal is to study how
bugs can be reproduced and validated locally, not to exploit someone's
deployment and not to claim first discovery. I did not test a real remote
machine. The goal was to produce reproducible local evidence.

## Slide 3: What Fuzzing Means Here

On slide:

- Fuzzing = automatically trying many malformed inputs.
- libFuzzer is coverage-guided: mutate input → run parser → keep inputs that
  reach new code → stop on crash.
- The build command (explained):

```bash
nim c --cc:clang -d:noSignalHandler -d:useMalloc --noMain:on \
  --passC:-fsanitize=fuzzer,address,undefined \
  --passL:-fsanitize=fuzzer,address,undefined \
  experiments/fuzzing/harness/asynchttpserver_fuzzer.nim
```

- Key flags: `--cc:clang` (needed for libFuzzer), `-d:useMalloc` (for ASan
  instrumentation), `--noMain:on` (libFuzzer provides main), sanitizer flags
  detect buffer overflows and undefined behavior.
- Harness modes:

| Mode | Parser |
|---:|---|
| 0 | HTTP protocol |
| 1 | request line |
| 2 | headers |
| 4 | `Content-Length` |
| 5 | chunk size |

Suggested visual:

- `reports/presentation_assets/fuzzing_loop.svg`

Speaker notes:

Fuzzing is automated bug hunting through mutated inputs. Instead of manually
typing strange HTTP requests, libFuzzer mutates a small corpus and watches which
inputs reach new code. The build command is important to understand: we use
Clang because libFuzzer is part of the LLVM project. We disable Nim's signal
handlers so AddressSanitizer can detect the crash. We use the system malloc so
ASan can instrument memory operations. And we tell Nim not to generate a main
function because libFuzzer provides its own. The harness uses a first byte as a
mode selector — this lets one fuzzing binary exercise several parser paths
without starting a real network server.

## Slide 4: Reproduced Runtime Crash

On slide:

Reproduced crash: `parseProtocol("HTTP/")` raises `IndexDefect`.

Minimal payload:

```text
HTTP/
```

Fuzzer artifact:

```text
0HTTP/
```

Key code pattern (vulnerable version):

```nim
var i = protocol.skipIgnoreCase("HTTP/")
if i != 5:
  raise ValueError
i.inc protocol.parseSaturatedNatural(result.major, i)
i.inc             # ← unconditional dot skip
i.inc protocol.parseSaturatedNatural(result.minor, i)
```

The upstream fix (PR #25793):

```nim
if i < protocol.len: inc i   # ← guard the skip
```

Local validation:
- Direct reproducer: 16-line Nim program triggers the crash
- Fuzzer: reproduced after 47,319 executions, saved exact input
- Replay: same input against fixed binary has no crash
- Upstream: Nim project already merged the same one-line fix

Suggested visual:

- `reports/presentation_assets/fuzzer_crash_log.svg` as the main visual, with
  `reports/presentation_assets/crash_anatomy.svg` available if you want to
  explain the code path more slowly.

Speaker notes:

This slide is about a reproduced crash, not an original first discovery. The
parser checks that the string starts with `HTTP/`, but after the prefix check
passes, there's an unconditional `i.inc` meant to skip the dot between major and
minor version. For the input `HTTP/`, the index is already at the end of the
string. The unconditional increment moves it past the end, and the next numeric
parse raises `IndexDefect`. The caller only catches `ValueError`, so the defect
escapes and crashes the process.

We validated that this is real, not a harness artifact or false positive, in
several ways. First, a 16-line standalone Nim reproducer triggers the same crash
without the fuzzer. Second, the fuzzer and reproducer agree on the exact input.
Third, applying the minimal fix, one if-guard, makes the crash go away. Fourth,
upstream PR #25793 shows this was a real Nim issue already handled by the
maintainers.

Evidence summary:
- The local fuzzer reproduced it after 47,319 executions.
- Saved crash bytes: `30 48 54 54 50 2f` (ASCII: `0HTTP/`).
- Fixed harness replayed the same input with no crash.
- Fixed fuzzing run completed 625,582 executions in 61 seconds.
- Upstream fix: `i.inc # Skip .` → `if i < protocol.len: inc i # Skip .`

## Slide 5: AI Review Results

On slide:

| Model | Candidates | Confirmed | Likely | Main problem |
|---|---|---:|---:|---:|---|
| DeepSeek V4 Pro | 8 | 0 | 6 | Misread `HTTP/` |
| GLM-5.1 | 10 | 0 | 5 | Misread `HTTP/` |
| Kimi K2.6 | 5 | 0 | 5 | Over-claimed confirmation |

Useful likely findings:

- chunked body lacks `maxBody` limit,
- missing read timeouts,
- large chunk sizes may cause allocation pressure,
- partial `Content-Length` parsing,
- persistent-connection parser state issues.

AI workflow: one structured prompt → three models → manual validation against
source code and fuzzing evidence.

Suggested visual:

- `reports/presentation_assets/model_results.svg`

Speaker notes:

The AI models were useful, but not as direct proof. I used one structured
prompt asking for location, trigger input, root cause, and exploitability. The
key step most people skip is validation: every AI claim was manually checked
against the source code and runtime evidence before being classified.

Here's the striking result: DeepSeek and GLM both noticed the `HTTP/` area, but
both concluded the opposite of reality — they said it would be accepted as
version 0.0 without crashing. Kimi missed this reproduced crash entirely. Yet all
three models correctly identified broader resource-exhaustion issues (missing
timeouts, unbounded chunked body growth) that my small parser harness doesn't
fully model.

The takeaway for a student learning about security tools: an AI's confidence
level has nothing to do with correctness. The model that sounded most certain
about `HTTP/` was also the most wrong. Every claim needs independent
verification.

## Slide 6: Which Was Better?

On slide:

| Criterion | Fuzzing | AI review |
|---|---|---|
| Confirmed local crashes | 1 | 0 |
| Evidence | crash input and replay | reasoning to validate |
| Strength | proves runtime behavior | covers broader design risks |
| Weakness | limited by harness | can hallucinate or overstate |

Conclusion from experiment:

- Fuzzing was better for runtime evidence.
- AI was better for generating an audit checklist.
- Best workflow: AI hypotheses + fuzzing/reproducers.

Suggested visual:

- `reports/presentation_assets/evidence_pipeline.svg`

Speaker notes:

For this project, fuzzing was better at producing proof. It produced an exact
input and a replayable result. The AI models were still valuable because they
pointed to broader resource-exhaustion issues that my small parser harness did
not fully model, especially slow clients and chunked body growth. But the AI
outputs were not enough on their own.

The important distinction for anyone learning about security testing: a fuzzer
gives you runtime evidence (this input crashes the program). An AI gives you
static reasoning (this code looks suspicious). Both are tools in the toolbox,
but only runtime evidence provides direct proof. This supports Mozilla's broader
idea of a validated pipeline: AI proposes, fuzzer tests, developer validates.

## Slide 7: Final Takeaway

On slide:

- Reproduced one denial-of-service crash, already fixed upstream (PR #25793).
- Fuzzing gave the strongest evidence: exact input, replayable crash, verified
  fix.
- AI review found useful leads but required correction — zero confirmed crashes
  from AI alone.
- External lesson: modern security work is becoming a pipeline:
  - model proposes,
  - harness tests,
  - developer validates,
  - minimal fix is replayed.
- Key takeaway for students: tools produce leads, not conclusions. A finding
  is only confirmed when you can reproduce it.

Suggested visual:

- `reports/presentation_assets/evidence_pipeline.svg`, or a plain closing slide
  with the sentence: "Model proposes, harness tests, developer validates."

Speaker notes:

My final conclusion is that the tools are complementary. The fuzzer was the
best proof generator. The models were useful reviewers, but they needed
validation before their findings meant anything. The upstream Nim PR matters
because it confirms the issue was real. But the presentation should be honest:
we did not discover it first. Our contribution was building the local evidence
pipeline: fuzzing harness, saved crash input, standalone reproducer, and fixed
replay.

The main lesson I hope other students take from this: a finding is not confirmed
because a tool reported it, or because a model sounded confident. A finding is
confirmed because you can reproduce it. The useful unit in security research is
not "AI found a bug" or "the fuzzer crashed." The useful unit is a reproducible
pipeline that turns a suspicious idea into a tested input and a verified fix.

## References

- Brian Grinstead, Christian Holler, and Frederik Braun, "Behind the Scenes
  Hardening Firefox with Claude Mythos Preview," Mozilla Hacks, May 7, 2026:
  https://hacks.mozilla.org/2026/05/behind-the-scenes-hardening-firefox/
- LLVM Project, "libFuzzer - a library for coverage-guided fuzz testing":
  https://llvm.org/docs/LibFuzzer.html
- Clang documentation, "AddressSanitizer":
  https://clang.llvm.org/docs/AddressSanitizer.html
- OWASP Foundation, "Fuzzing":
  https://owasp.org/www-community/Fuzzing
- Nim PR #25793, "fixes DOS via malformed HTTP protocol":
  https://github.com/nim-lang/Nim/pull/25793
