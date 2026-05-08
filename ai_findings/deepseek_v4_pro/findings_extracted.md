# DeepSeek V4 Pro Findings Extraction

## Run Status

- **Status**: USABLE_OUTPUT
- **Output file**: `ai_findings/deepseek_v4_pro/output.txt`
- **Findings reported by model**: 8
- **Validation basis**: current source at `lib/pure/asynchttpserver.nim`, `httpcore.nim`, fuzz logs under `experiments/fuzzing/results/`, and local reproducer output.

## Extracted and Validated Findings

| Model ID | Title | Model classification | Validated classification | Confidence | Notes |
|---|---|---|---|---:|---|
| F-001 | Chunked encoding lacks `maxBody` enforcement | CONFIRMED | LIKELY | 0.40 | Static trace is valid: `Content-Length` is capped at `asynchttpserver.nim:288`, but chunked `request.body.add(chunk)` at line 324 has no equivalent aggregate cap. No dynamic memory-exhaustion reproducer was run. |
| F-002 | No receive timeouts / Slowloris DoS | CONFIRMED | LIKELY | 0.40 | Static trace is valid: `recvLineInto` calls at lines 203, 256, and 309 have no timeout. A network timing reproducer was not run. |
| F-003 | Header limit allows large pre-rejection allocation | LIKELY | LIKELY | 0.40 | Static trace is valid: header is stored at line 265, then `headers.len > headerLimit` is checked at line 267. Bounded by `maxLine` and `headerLimit`, but still sizable. |
| F-004 | Persistent connection checks only first `Connection` value | LIKELY | LIKELY | 0.16 | `HttpHeaderValues` converts to the first string at `httpcore.nim:170`; line 347 uses that converter. Security impact is limited connection-lifetime logic. |
| F-005 | Chunked bodies ignored for non-POST methods | LIKELY | LIKELY | 0.16 | Static trace is valid: `hasChunkedEncoding` returns true only for `HttpPost` at line 170, and the 411 fallback at line 332 also only covers POST. Impact is application/body-handling logic. |
| F-006 | Case-sensitive `chunked` transfer coding check | LIKELY | LIKELY | 0.16 | Static trace is valid: line 168 uses exact comparison. Impact is interoperability/body-handling logic rather than direct crash. |
| F-007 | `split(' ')` allocation amplification | SPECULATIVE | UNLIKELY | 0.08 | The allocation shape is real, but bounded by `maxLine = 8192`; no evidence of practical DoS beyond small per-request allocation overhead. |
| F-008 | `parseProtocol` accepts `HTTP/` without version digits | SPECULATIVE | FALSE_POSITIVE | 0.00 | Incorrect. Fresh reproducer and fuzzing show `HTTP/` raises `IndexDefect`; it is not accepted as `(0, 0)`. |

## Cross-Check Against Fresh Fuzzing

- **Matched fuzz finding**: none exactly.
- **Missed fuzz finding**: confirmed `parseProtocol("HTTP/")` crash. DeepSeek discussed the same area but reached the wrong behavior.
- **AI-only findings**: chunked body cap, no timeouts, header allocation, connection logic, non-POST chunked behavior, case-sensitive chunked handling.

## Assessment

DeepSeek was useful for static attack-surface review, especially resource and protocol-logic issues that the current parser-focused fuzz harness does not model well. It did not reproduce the concrete crash found by fuzzing and incorrectly classified the `HTTP/` behavior.
