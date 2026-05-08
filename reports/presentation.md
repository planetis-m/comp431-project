# 7-Minute Presentation: Fuzzing and AI Review of Nim `asynchttpserver`

## Timing Plan

| Slide | Topic | Time |
|---:|---|---:|
| 1 | Motivation and research question | 0:45 |
| 2 | Target and threat model | 0:55 |
| 3 | What fuzzing means here | 1:00 |
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
- Project question: can a small student audit reproduce the same pattern?
- Target: Nim `std/asynchttpserver`.

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
evidence on a smaller target.

## Slide 2: Target and Threat Model

On slide:

- Target: request parsing in `std/asynchttpserver`.
- Attacker: unauthenticated client sending malformed HTTP.
- Main risks:
  - process crash,
  - memory exhaustion,
  - connection exhaustion,
  - parser logic mistakes.
- Scope: local defensive testing only.

Suggested visual:

- `reports/presentation_assets/http_request_anatomy.svg`

Speaker notes:

The target is not a full production deployment. I focused on parser code inside
Nim's asynchronous HTTP server. The attacker controls the bytes in the request
line, headers, and body. That is enough to test denial of service and parsing
logic. I did not test a real remote machine, and I did not claim remote code
execution. The goal was to produce reproducible local evidence.

## Slide 3: What Fuzzing Means Here

On slide:

- Fuzzing means automatically trying many malformed inputs.
- libFuzzer is coverage-guided:
  - mutate input,
  - run parser,
  - keep inputs that reach new code,
  - stop on crash.
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

Fuzzing is basically automated bug hunting through inputs. Instead of manually
typing strange HTTP requests, libFuzzer mutates a small corpus and watches which
inputs reach new code. If an input crashes the program, libFuzzer saves that
input. My harness used a first byte as a mode selector. That let one fuzzing
binary exercise several parser paths without starting a real network server.

## Slide 4: Confirmed Finding

On slide:

Confirmed vulnerability: `parseProtocol("HTTP/")` crashes.

Minimal payload:

```text
HTTP/
```

Fuzzer artifact:

```text
0HTTP/
```

Key code pattern:

```nim
var i = protocol.skipIgnoreCase("HTTP/")
if i != 5:
  raise ValueError
i.inc protocol.parseSaturatedNatural(result.major, i)
if i < protocol.len:
  inc i
i.inc protocol.parseSaturatedNatural(result.minor, i)
```

Suggested visual:

- `reports/presentation_assets/fuzzer_crash_log.svg` as the main visual, with
  `reports/presentation_assets/crash_anatomy.svg` available if you want to
  explain the code path more slowly.

Speaker notes:

The confirmed bug is small but real. The parser checks that the string starts
with `HTTP/`, but it does not check that there are digits after the slash. For
the input `HTTP/`, the index is already at the end of the string after the
first numeric parse. The original code then increments the index anyway to skip
a dot that is not present. The next numeric parse starts beyond the string and
raises `IndexDefect`, which escapes and can crash the process.

Evidence:

- Fuzzer found it after 47,319 executions.
- Saved crash bytes: `30 48 54 54 50 2f`.
- Base64: `MEhUVFAv`.
- Fixed harness replayed the same input with the minimal `if i < protocol.len`
  guard and no crash.
- Fixed fuzzing run completed 625,582 executions in 61 seconds.

## Slide 5: AI Review Results

On slide:

| Model | Candidates | Confirmed | Likely | Main problem |
|---|---:|---:|---:|---|
| DeepSeek V4 Pro | 8 | 0 | 6 | Misread `HTTP/` |
| GLM-5.1 | 10 | 0 | 5 | Misread `HTTP/` |
| Kimi K2.6 | 5 | 0 | 5 | Over-claimed confirmation |

Useful likely findings:

- chunked body lacks `maxBody` limit,
- missing read timeouts,
- large chunk sizes may cause allocation pressure,
- partial `Content-Length` parsing,
- persistent-connection parser state issues.

Suggested visual:

- `reports/presentation_assets/model_results.svg`

Speaker notes:

The AI models were useful, but not as direct proof. I used one structured
prompt asking for location, trigger input, root cause, and exploitability. All
usable outputs needed manual validation. DeepSeek and GLM noticed the `HTTP/`
area, but both concluded the opposite of reality: they said it would be
accepted as version 0.0. Kimi missed that confirmed crash and marked all its
own findings as confirmed, even though I did not have reproducers. So I counted
the AI results as likely findings, not confirmed vulnerabilities.

## Slide 6: Which Was Better?

On slide:

| Criterion | Fuzzing | AI review |
|---|---|---|
| Confirmed bugs | 1 | 0 |
| Evidence | crash input and replay | reasoning to validate |
| Strength | proves runtime behavior | covers broader design risks |
| Weakness | limited by harness | can hallucinate or overstate |

Conclusion from experiment:

- Fuzzing was better for confirmed evidence.
- AI was better for generating an audit checklist.
- Best workflow: AI hypotheses plus fuzzing/reproducers.

Suggested visual:

- `reports/presentation_assets/evidence_pipeline.svg`

Speaker notes:

For this project, fuzzing was better at proving a bug. It produced an exact
input and a replayable result. The AI models were still valuable because they
pointed to broader resource-exhaustion issues that my small parser harness did
not fully model, especially slow clients and chunked body growth. But the AI
outputs were not enough on their own. This supports Mozilla's broader idea of a
validated pipeline, not the idea that model output should be trusted directly.

## Slide 7: Final Takeaway

On slide:

- Found one confirmed denial-of-service bug.
- Fuzzing gave the strongest evidence.
- AI review found useful leads but required correction.
- External lesson: modern security work is becoming a pipeline:
  - model proposes,
  - harness tests,
  - developer validates,
  - minimal fix is replayed.

Suggested visual:

- Reuse `reports/presentation_assets/evidence_pipeline.svg`, or use a plain
  closing slide with the sentence: "Model proposes, harness tests, developer
  validates."

Speaker notes:

My final conclusion is that the tools are complementary. The fuzzer was the
best bug prover. The models were useful reviewers, but they needed validation
before their findings meant anything. My experiment is much smaller than
Mozilla's Firefox work, but it upholds the same engineering lesson: the useful
unit is not "AI found a bug." The useful unit is a reproducible pipeline that
turns a suspicious idea into a tested input and then a verified fix.

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
