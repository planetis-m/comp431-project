# Kimi K2.6 Findings Extraction

Source transcript:

```text
ai_findings/kimi_k2_6/output.txt
```

Kimi K2.6 produced a usable transcript with five candidate findings. The model
classified all five as confirmed. I do not count them as confirmed in this
project because I did not build dynamic reproducers for these claims. They are
recorded as likely static findings where the source trace is plausible.

## Summary

| Result after validation | Count |
|---|---:|
| Confirmed | 0 |
| Likely | 5 |
| Unlikely | 0 |
| False positive / withdrawn | 0 |

## Findings

### KIMI-001: Large chunk size can cause excessive allocation or crash

- **Model classification**: CONFIRMED
- **Project classification**: LIKELY
- **Location**: chunked-body path in `processRequest`
- **Claimed trigger**: a chunk size such as `8000000000000000`
- **Reasoning**: Kimi argues that an overflowing or extremely large parsed
  chunk size can flow into `recv(bytesToRead)`, forcing an invalid or huge
  allocation.
- **Validation note**: This overlaps with GLM's large-chunk finding. It is a
  plausible resource-exhaustion/crash risk, but it was not dynamically
  reproduced in the submitted experiment.

### KIMI-002: Chunked bodies do not enforce `maxBody`

- **Model classification**: CONFIRMED
- **Project classification**: LIKELY
- **Location**: chunked-body accumulation in `processRequest`
- **Reasoning**: The `Content-Length` path checks `server.maxBody`, but the
  chunked loop appends chunks to `request.body` without checking cumulative
  body size.
- **Validation note**: This is statically supported and matches DeepSeek and
  GLM. It remains likely because no live memory-exhaustion reproducer was run.

### KIMI-003: `Content-Length` accepts partially parsed numeric values

- **Model classification**: CONFIRMED
- **Project classification**: LIKELY
- **Claimed trigger**: `Content-Length: 0x10` or `Content-Length: 5abc`
- **Reasoning**: `parseSaturatedNatural` reports how many characters were
  consumed. The caller rejects only the zero-consumption case, so a value with
  a numeric prefix can be accepted while trailing characters are ignored.
- **Validation note**: The static trace is plausible. The security impact
  depends on a front-end/proxy or client interpreting the same bytes
  differently, so I do not call it confirmed without an end-to-end reproducer.

### KIMI-004: Malformed request line may reuse stale fields

- **Model classification**: CONFIRMED
- **Project classification**: LIKELY
- **Claimed trigger**: `GET` or `GET /` on a persistent connection after a
  previous valid request
- **Reasoning**: Kimi claims the request-line split loop does not verify that
  method, URL, and protocol were all present, while some request state is
  reused across the keep-alive loop.
- **Validation note**: This is a plausible logic issue that needs a persistent
  connection reproducer before it can be confirmed.

### KIMI-005: Network reads have no timeout

- **Model classification**: CONFIRMED
- **Project classification**: LIKELY
- **Location**: `recvLineInto` and `recv` calls in `processRequest`
- **Reasoning**: A client can send bytes slowly and hold server resources for a
  long time because the read operations are not wrapped in a timeout.
- **Validation note**: This overlaps with DeepSeek and GLM. It is statically
  supported, but no live slow-client test was run.
