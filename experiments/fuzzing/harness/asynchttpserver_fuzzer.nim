## Fuzz harness for the HTTP request parser in Nim's asynchttpserver.
##
## Code sections copied from:
##   ~/Projects/Nim/lib/pure/asynchttpserver.nim
##   commit 115ec7a433a7c55b596f526b7ca9187cc50fc980 (2026-04-07, HEAD)
##
## The original async proc processRequest (lines 173-334) interleaves parsing
## with network I/O (await client.recvLineInto / await client.recv). This file
## extracts the same parsing logic into synchronous procs that operate on a
## contiguous string buffer, making it suitable for libFuzzer. HTTP error
## responses are replaced with ValueError raises.

import std/[httpcore, parseutils, strutils, uri]

const
  localMaxBody = 8 * 1024 * 1024
  localMaxLine = 8 * 1024

type ParsedRequest = object
  reqMethod: HttpMethod
  headers: HttpHeaders
  protocol: tuple[orig: string, major, minor: int]
  url: Uri
  body: string

# --- begin asynchttpserver.nim: parseProtocol (lines 148-157) ---

proc parseProtocolOriginal(protocol: string): tuple[orig: string, major, minor: int] =
  result = default(tuple[orig: string, major, minor: int])
  var i = protocol.skipIgnoreCase("HTTP/")
  if i != 5:
    raise newException(ValueError, "Invalid request protocol. Got: " & protocol)
  result.orig = protocol
  i.inc protocol.parseSaturatedNatural(result.major, i)
  i.inc
  i.inc protocol.parseSaturatedNatural(result.minor, i)

# --- end asynchttpserver.nim: parseProtocol ---

# --- begin asynchttpserver.nim: method dispatch (lines 221-233 of processRequest) ---

proc parseMethod(part: string): HttpMethod =
  case part
  of "GET": HttpGet
  of "POST": HttpPost
  of "HEAD": HttpHead
  of "PUT": HttpPut
  of "DELETE": HttpDelete
  of "PATCH": HttpPatch
  of "OPTIONS": HttpOptions
  of "CONNECT": HttpConnect
  of "TRACE": HttpTrace
  else:
    raise newException(ValueError, "unknown method")

# --- end asynchttpserver.nim: method dispatch ---

# nextLine: synchronous replacement for await client.recvLineInto.
# No counterpart in the original — the original reads from a network socket.

proc nextLine(input: string, pos: var int): string =
  if pos >= input.len:
    return ""

  let start = pos
  while pos < input.len and input[pos] notin {'\r', '\n'}:
    inc pos

  result = input[start ..< pos]

  if pos < input.len and input[pos] == '\r':
    inc pos
    if pos < input.len and input[pos] == '\n':
      inc pos
  elif pos < input.len and input[pos] == '\n':
    inc pos

# --- begin asynchttpserver.nim: hasChunkedEncoding (lines 162-171) ---

proc hasChunkedEncoding(request: ParsedRequest): bool =
  const transferEncoding = "Transfer-Encoding"

  if request.headers.hasKey(transferEncoding):
    for encoding in seq[string](request.headers[transferEncoding]):
      if "chunked" == encoding.strip:
        return request.reqMethod == HttpPost
  return false

# --- end asynchttpserver.nim: hasChunkedEncoding ---

# --- begin asynchttpserver.nim: processRequest (lines 173-334), de-asynced ---
#
# The original is an async proc using await client.recvLineInto / await client.recv.
# Here every await recv* is replaced by nextLine() or direct buffer indexing,
# and HTTP error responses are replaced by ValueError raises.
# The parsing decisions are otherwise the same step for step.

proc parseFullRequestOriginal(input: string) =
  var pos = 0
  var request = ParsedRequest(headers: newHttpHeaders(), url: initUri())
  var line = ""

  for _ in 0..1:
    line = nextLine(input, pos)
    if line == "":
      raise newException(ValueError, "empty request line")
    if line.len > localMaxLine:
      raise newException(ValueError, "request line too long")
    if line != "":
      break

  var i = 0
  for linePart in line.split(' '):
    case i
    of 0:
      request.reqMethod = parseMethod(linePart)
    of 1:
      parseUri(linePart, request.url)
    of 2:
      request.protocol = parseProtocolOriginal(linePart)
    else:
      raise newException(ValueError, "too many request line fields")
    inc i

  while true:
    line = nextLine(input, pos)
    if line == "":
      break
    if line.len > localMaxLine:
      raise newException(ValueError, "header line too long")

    let (key, value) = parseHeader(line)
    request.headers[key] = value
    if request.headers.len > headerLimit:
      raise newException(ValueError, "too many headers")

  if request.reqMethod == HttpPost:
    if request.headers.hasKey("Expect"):
      if "100-continue" notin request.headers["Expect"]:
        raise newException(ValueError, "expectation failed")

  if request.headers.hasKey("Content-Length"):
    var contentLength = 0
    if parseSaturatedNatural(request.headers["Content-Length"], contentLength) == 0:
      raise newException(ValueError, "invalid content length")
    if contentLength > localMaxBody:
      raise newException(ValueError, "body too large")
    if input.len - pos < contentLength:
      raise newException(ValueError, "content length mismatch")
    request.body = input[pos ..< pos + contentLength]
  elif hasChunkedEncoding(request):
    while true:
      line = nextLine(input, pos)
      let bytesToRead = line.parseHexInt
      if bytesToRead == 0:
        break
      if input.len - pos < bytesToRead + 2:
        raise newException(ValueError, "truncated chunk")
      request.body.add(input[pos ..< pos + bytesToRead])
      pos.inc bytesToRead
      if input[pos ..< min(pos + 2, input.len)] != "\r\n":
        raise newException(ValueError, "bad chunk separator")
      pos.inc 2
  elif request.reqMethod == HttpPost:
    raise newException(ValueError, "content length required")

# --- end asynchttpserver.nim: processRequest ---

proc LLVMFuzzerTestOneInput(data: ptr UncheckedArray[byte], len: csize_t): cint {.
    exportc, cdecl, raises: [].} =
  result = 0
  if len == 0:
    return

  let inputLen = int(len)
  var input = newString(inputLen)
  copyMem(addr input[0], data, inputLen)

  try:
    parseFullRequestOriginal(input)
  except ValueError:
    discard
  except Defect:
    quit(70)
  except CatchableError:
    discard

when defined(fuzzStandalone):
  import std/[cmdline, syncio]
  stderr.write "StandaloneFuzzTarget: running " & $paramCount() & " inputs\n"
  for i in 1..paramCount():
    var buf = readFile(paramStr(i))
    discard LLVMFuzzerTestOneInput(cast[ptr UncheckedArray[byte]](cstring(buf)), buf.len.csize_t)
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
