# Validated Findings

## Confirmed Finding: F-001 `parseProtocol` IndexDefect

- **Classification**: CONFIRMED
- **Confidence**: 0.80 by rubric (`1.0 evidence * 1.0 exploitability * 0.8 DoS impact`)
- **Type**: Remote denial of service by unhandled `IndexDefect`
- **Affected code**: `lib/pure/asynchttpserver.nim:148-157`
- **Trigger**: request-line protocol token equal to `HTTP/`
- **Minimal request shape**: `GET / HTTP/`

### Static Trace

1. `processRequest` splits the request line at `asynchttpserver.nim:218`.
2. The third field is parsed by `parseProtocol` at line 242.
3. `parseProtocol("HTTP/")` calls `skipIgnoreCase("HTTP/")`, which returns `5`.
4. The guard at lines 151-153 passes because `i == 5`.
5. Line 155 calls `parseSaturatedNatural(result.major, i)` with
   `i == protocol.len`; this consumes no digits.
6. The original code then unconditionally increments `i` to skip `.`, moving
   it beyond the end of the string.
7. The next `parseSaturatedNatural(result.minor, i)` raises `IndexDefect`,
   not `ValueError`.
8. `processRequest` catches only `ValueError` at lines 243-245, so the defect
   escapes.

### Dynamic Confirmation

Reproducer:

```bash
nim c --panics:on --mm:arc -r validation/reproducers/parse_protocol_index_defect.nim
```

Observed result:

```text
Input: HTTP/1.1
Parsed: (orig: "HTTP/1.1", major: 1, minor: 1)
Input: HTTP/
Error: unhandled exception: index out of bounds: 6..4 notin 0..4 [IndexDefect]
```

### Fresh Fuzzing Confirmation

Fresh harness:

- `experiments/fuzzing/harness/asynchttpserver_fuzzer.nim`

Campaign 1 rediscovered the crash from benign seeds:

- Log: `experiments/fuzzing/results/campaign_1_original.log`
- Crash artifact: `experiments/fuzzing/results/F-001_crash_input`
- Artifact bytes: `30 48 54 54 50 2f` (`0HTTP/`; leading `0` selects the protocol parser mode)
- Executed units at crash: 47,319
- Coverage at crash: 3,840
- Peak RSS near crash: 139 MB

Campaign 2 used a patched harness with the minimal protocol parser fix:

- Harness: `experiments/fuzzing/harness/asynchttpserver_fuzzer_fixed.nim`
- Replay of the campaign 1 crash artifact: no crash
- Fuzz run: 625,582 executions in 61 seconds
- Final coverage: 4,492
- Result: no crash

## AI-Reported Likely Findings

These findings came from the DeepSeek, GLM, and Kimi transcripts and have
static support, but were not dynamically confirmed in this run:

| ID | Finding | Classification | Confidence |
|---|---|---|---:|
| AI-001 | Chunked request bodies are accumulated without `maxBody` enforcement | LIKELY | 0.40 |
| AI-002 | Request/header/chunk reads have no timeout, enabling Slowloris-style connection holding | LIKELY | 0.40 |
| AI-003 | Header limit check occurs after storing each header, allowing bounded pre-rejection memory pressure | LIKELY | 0.40 |
| AI-004 | Persistent connection logic checks only first `Connection` value | LIKELY | 0.16 |
| AI-005 | Chunked bodies are handled only for POST; non-POST chunked bodies are ignored | LIKELY | 0.16 |
| AI-006 | Transfer-Encoding `chunked` comparison is case-sensitive | LIKELY | 0.16 |
| AI-007 | Large chunk sizes can trigger excessive `recv` behavior | LIKELY | 0.28 |
| AI-008 | Malformed protocol separators such as `HTTP/1X1` are not handled consistently | LIKELY | 0.16 |
| AI-009 | Header lines without `:` are stored as empty-valued headers | LIKELY | 0.16 |
| AI-010 | `Content-Length` values with trailing junk can be partially parsed | LIKELY | 0.28 |
| AI-011 | Malformed persistent-connection request lines may reuse stale URL/protocol state | LIKELY | 0.28 |

DeepSeek also reported two weak findings:

- `split(' ')` allocation amplification: **UNLIKELY**, bounded by `maxLine`.
- `parseProtocol` accepting `HTTP/`: **FALSE_POSITIVE**, contradicted by reproducer and fuzzing.
