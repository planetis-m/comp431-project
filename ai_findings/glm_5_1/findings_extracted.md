# GLM-5.1 Findings Extraction

## Run Status

- **Status**: USABLE_OUTPUT
- **Output file**: `ai_findings/glm_5_1/output.txt`
- **Findings/candidates reported by model**: 10
- **Validation basis**: current source at `lib/pure/asynchttpserver.nim`, `httpcore.nim`, fuzz logs under `experiments/fuzzing/results/`, and local reproducer output.

## Extracted and Validated Findings

| Model ID | Title | Model classification | Validated classification | Confidence | Notes |
|---|---|---|---|---:|---|
| F-001 | Chunked body unbounded; `maxBody` not enforced | CONFIRMED | LIKELY | 0.40 | Static trace is valid: chunked body data is appended at `asynchttpserver.nim:324` without an aggregate cap. No live memory-exhaustion reproducer was run. |
| F-002 | `parseHexInt` overflow / huge chunk size | LIKELY | LIKELY | 0.28 | Related to chunked body resource exhaustion. The strongest practical issue is large positive chunk sizes and missing aggregate body cap; no dynamic overflow reproducer was run. |
| F-003 | Extra spaces in request line cause rejection | CONFIRMED | UNLIKELY | 0.08 | Behavior is plausible, but this is protocol strictness/interoperability, not a meaningful security vulnerability. |
| F-004 | `Expect: 100-Continue` case sensitivity | Withdrawn | FALSE_POSITIVE | 0.00 | GLM correctly withdrew it: `HttpHeaderValues.contains` compares case-insensitively. |
| F-005 | No receive timeout / Slowloris | CONFIRMED | LIKELY | 0.40 | Static trace is valid: `recvLineInto` calls have no timeout. No live slow-client reproducer was run. |
| F-006 | `parseProtocol("HTTP/")` behavior | LIKELY | FALSE_POSITIVE | 0.00 | GLM mentioned the same input as the fuzz crash, but its explanation says no crash occurs and that version `0.0` is accepted. Fresh reproducer and fuzzing show an `IndexDefect` crash. |
| F-007 | `parseProtocol` does not validate dot separator | LIKELY | LIKELY | 0.16 | Static trace is valid for malformed protocol acceptance such as `HTTP/1X1`, but impact is low. |
| F-008 | Header line without colon is stored | CONFIRMED | LIKELY | 0.16 | Static trace is valid: `parseHeader` stores no-colon input as a key with empty value. Impact depends on application header handling. |
| F-009 | `Content-Length` saturation bypasses `maxBody` | Withdrawn | FALSE_POSITIVE | 0.00 | GLM correctly withdrew it: the `contentLength > server.maxBody` check catches saturated values under normal configuration. |
| F-010 | `FutureVar[Request]` shared race | SPECULATIVE | FALSE_POSITIVE | 0.00 | GLM's own analysis notes `await callback(request)` prevents overlap on one connection and each connection has its own request state. |

## Summary

| Validated category | Count |
|---|---:|
| CONFIRMED | 0 |
| LIKELY | 5 |
| UNLIKELY | 1 |
| FALSE_POSITIVE / withdrawn | 4 |

## Cross-Check Against Fuzzing

- **Exact confirmed match**: none.
- **Partial overlap**: GLM mentioned `GET / HTTP/`, but its runtime explanation was wrong, so it is not counted as an AI-confirmed match.
- **Fuzzer finding missed by GLM**: the actual `parseProtocol("HTTP/")` `IndexDefect` root cause.
- **AI-only likely findings**: chunked body cap, huge chunk sizes, no receive timeouts, malformed protocol separator acceptance, no-colon header storage.

## Assessment

GLM was useful for static review and found several of the same resource-oriented
risks as DeepSeek. However, it over-classified static issues as confirmed and
misread the confirmed `HTTP/` crash behavior. Its output is useful as a review
checklist, but not as final evidence without validation.
