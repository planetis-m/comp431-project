# Attack Surface Analysis: std/asynchttpserver

## Module Overview

- **Source**: `lib/pure/asynchttpserver.nim`
- **Lines**: 441
- **Dependencies**: `std/asyncnet`, `std/asyncdispatch`, `std/parseutils`, `std/uri`, `std/strutils`, `std/httpcore`

## Entry Points

| Entry Point | Line | Description |
|---|---|---|
| `processRequest` | 173 | Main request parser — parses request line, headers, body |
| `processClient` | 359 | Per-connection loop — calls `processRequest` repeatedly |
| `acceptRequest` | 405 | Accepts one connection, spawns `processClient` |
| `serve` | 412 | Main server loop |
| `listen` | 382 | Binds socket |

## Attack Surface Table

| # | File:Line | Surface Type | Input | Validation | Failure Mode |
|---|---|---|---|---|---|
| 1 | asynchttpserver.nim:200-213 | recv | Empty lines before request | Skips up to 2 empty lines, then treats empty recv as close | DoS: slowloris-style connection holding |
| 2 | asynchttpserver.nim:209 | parse | Line exceeding maxLine (8192) | `>` check rejects lines > maxLine with 413 | Exact maxLine length accepted, possibly truncated by recvLineInto |
| 3 | asynchttpserver.nim:218 | parse | Request line split by spaces | `split(' ')` — unbounded allocations if many spaces; tabs not handled (HTTP spec allows OWS) | Memory exhaustion via many-space request line |
| 4 | asynchttpserver.nim:221-233 | parse | HTTP method string | Exact case-sensitive match against 9 methods; unknown → 400 | Non-standard: HTTP methods are case-sensitive per spec but server rejects lowercase; also rejects extension methods |
| 5 | asynchttpserver.nim:236 | parse | URI string | `parseUri` can raise ValueError, caught gracefully → 400 | URI length unbounded; `split(' ')` on request line means URI with spaces fails |
| 6 | asynchttpserver.nim:242 | parse | Protocol string | `parseProtocol` raises ValueError if not starting with "HTTP/", caught → 400. Uses `parseSaturatedNatural` for major/minor — saturates, no overflow. | `protocol.orig` stores raw string (could be malicious). Major/minor saturate to int.high |
| 7 | asynchttpserver.nim:264 | parse | Header line | `parseHeader` parses `Key: Value`. If no colon, key=line, value=[""]. Uses `parseList` for multi-value headers | Header names unbounded in length; value list unbounded |
| 8 | asynchttpserver.nim:267 | alloc | Header count | `headerLimit = 10_000` check | Hash table DoS prevented by limit; returns 400 via `sendStatus` (not `respondError`) |
| 9 | asynchttpserver.nim:284 | int | Content-Length value | `parseSaturatedNatural` — saturates on overflow, no crash | Saturated value compared to `server.maxBody` (default 8MB). Saturation to `int.high` → correctly rejected if `maxBody < int.high` |
| 10 | asynchttpserver.nim:291 | recv | Body data | `client.recv(contentLength)` — reads exactly contentLength bytes | Content-Length could be 0; no timeout; could be called with large `contentLength` if maxBody bypassed |
| 11 | asynchttpserver.nim:292-294 | logic | Body length mismatch | Compares `request.body.len != contentLength` | Reports mismatch but may have already consumed data |
| 12 | asynchttpserver.nim:295-330 | parse+alloc | Chunked transfer encoding | `hasChunkedEncoding` only true for POST. `parseHexInt` per chunk size. Body accumulates without max length check | **Missing maxBody check**: chunked body can exceed `server.maxBody`. Infinite loop if `parseHexInt` always succeeds non-zero |
| 13 | asynchttpserver.nim:311 | int | Chunk size hex | `parseHexInt` can raise ValueError → 411 | `parseHexInt` returns int; very large hex values saturate |
| 14 | asynchttpserver.nim:323-329 | recv | Chunk data + separator | `client.recv(bytesToRead)` then `client.recv(2)` for \r\n | No timeout; partial chunk data reads; separator check is exact |
| 15 | asynchttpserver.nim:274-278 | logic | Expect header | Checks for "100-continue" in Expect values. Case-sensitive comparison | Accepts "100-continue" but not "100-Continue" (should be case-insensitive per RFC) |
| 16 | asynchttpserver.nim:339 | logic | Connection upgrade | Checks "upgrade" in connection header values. `getOrDefault` with default `@[""]` | Empty default means upgrade never detected if connection header missing |
| 17 | asynchttpserver.nim:346-354 | logic | Persistent connection | Compares protocol version and connection header | `HttpVer11` constant not used directly — compares `protocol.major==1 and minor==1` |
| 18 | asynchttpserver.nim:148-157 | parse | Protocol parsing | `skipIgnoreCase("HTTP/")` then `parseSaturatedNatural` for versions | Index `i` manipulated without bounds checks after skipIgnoreCase |
