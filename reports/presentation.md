# 7-Minute Presentation: Fuzzing and AI Review of Nim `asynchttpserver`

## Timing Plan

| Slide | Topic | Time |
|---:|---|---:|
| 1 | Motivation and research question | 0:45 |
| 2 | Target and threat model | 0:55 |
| 3 | What fuzzing means here, with real commands | 1:00 |
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
- Project question: can a course-scale audit reproduce the same evidence
  pipeline?
- Target: Nim `std/asynchttpserver`.
- The reproduced bug was already fixed upstream (Nim PR #25793).

Suggested visual:

- Mozilla security-fix chart:
  https://hacks.mozilla.org/wp-content/uploads/2026/05/security-bug-fixes-1-scaled.png

Speaker notes:

In security testing, the important question is not only whether code looks
suspicious. The important question is whether we can produce evidence.

For this project we compared two tools: fuzzing, which executes the program
with many malformed inputs, and AI review, which inspects code and suggests
possible weaknesses.

Main question: which approach gives stronger evidence for this target?

Our result: fuzzing produced runtime proof. AI produced useful leads, but those
leads still required validation.

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

An HTTP server receives text from a client. That text includes the request
line, headers, and sometimes a body.

In security terms, that input is attacker-controlled. If the parser handles it
badly, the server can crash or waste resources.

Everything here was local and defensive. We used an older version on purpose,
to study how a crash can be reproduced and validated.

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

Fuzzing means automatically executing a program with many generated or mutated
inputs. The goal is to explore edge cases faster than manual testing can.

If one input crashes the parser, the fuzzer saves that exact input. That makes
the result replayable, which is what turns a crash into usable evidence.

In this project, the harness tested parser functions directly, without running
a real web server.

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

We reproduced a denial-of-service crash in the HTTP protocol parser. The
minimal crashing input is `HTTP/`.

That input is incomplete. A safe parser should reject it cleanly. Instead, this
parser moved past the end of the string and raised `IndexDefect`.

Cybersecurity meaning: if malformed input can crash a service, that is denial
of service.

The important evidence is concrete: exact crashing input, small reproducer, and
a replay showing the fixed version does not crash.

## Slide 5: AI Review Results

On slide:

- AI result: useful review leads, but zero confirmed crashes without manual
  validation.
- Best role: checklist for what a security reviewer should test next.

Useful likely findings:

- chunked body lacks `maxBody` limit,
- missing read timeouts,
- large bodies may cause memory pressure,
- parser state needs careful validation.

AI workflow: one structured prompt → three models → manual validation against
source code and fuzzing evidence.

Suggested visual:

- `reports/presentation_assets/model_results.svg`

Speaker notes:

The AI models were useful for brainstorming possible risks. They pointed to
things a security reviewer should check, like timeouts and body-size limits.

But AI output is not evidence by itself. A model can sound confident and still
be wrong.

For the crash we reproduced, the AI models did not produce a confirmed result.
So in this project, AI worked best as a checklist generator, not as a proof
tool.

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

Fuzzing was better for proof. It gave us an input we could run again.

AI was better for coverage of ideas. It suggested areas worth checking, but
those suggestions still needed validation.

Core distinction: fuzzing says, "this input crashes the program." AI says,
"this code might be risky." For cybersecurity, that difference matters.

## Slide 7: Final Takeaway

On slide:

- Reproduced one denial-of-service crash, already fixed upstream (PR #25793).
- Fuzzing gave the strongest evidence: exact input, replayable crash, verified
  fix.
- AI review found useful leads but required correction, zero confirmed crashes
  from AI alone.
- External lesson: modern security work is becoming a pipeline:
  - model proposes,
  - harness tests,
  - developer validates,
  - minimal fix is replayed.
- Key takeaway: tools produce leads, not conclusions. A finding
  is only confirmed when you can reproduce it.

Suggested visual:

- `reports/presentation_assets/evidence_pipeline.svg`, or a plain closing slide
  with the sentence: "Model proposes, harness tests, developer validates."

Speaker notes:

The best workflow is not AI versus fuzzing. It is AI plus testing.

Use AI to suggest what might be wrong. Use fuzzing and reproducers to prove what
is actually wrong.

Final takeaway: in cybersecurity, a claim is not confirmed because a tool
reports it. A claim is confirmed when you can reproduce it.

That is the main lesson of this project.

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
