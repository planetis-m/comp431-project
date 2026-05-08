import std/[httpcore, parseutils, strutils, uri]

const localMaxBody = 8 * 1024 * 1024

type RequestLine = object
  reqMethod: HttpMethod
  url: Uri
  protocol: tuple[orig: string, major, minor: int]

proc parseProtocolOriginal(protocol: string): tuple[orig: string, major, minor: int] =
  result = default(tuple[orig: string, major, minor: int])
  var i = protocol.skipIgnoreCase("HTTP/")
  if i != 5:
    raise newException(ValueError, "Invalid request protocol. Got: " & protocol)
  result.orig = protocol
  i.inc protocol.parseSaturatedNatural(result.major, i)
  if i < protocol.len:
    inc i
  i.inc protocol.parseSaturatedNatural(result.minor, i)

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

proc parseRequestLineOriginal(line: string): RequestLine =
  var i = 0
  for part in line.split(' '):
    case i
    of 0:
      result.reqMethod = parseMethod(part)
    of 1:
      parseUri(part, result.url)
    of 2:
      result.protocol = parseProtocolOriginal(part)
    else:
      raise newException(ValueError, "too many request line fields")
    inc i

proc parseHeadersOriginal(input: string) =
  var headers = newHttpHeaders()
  for rawLine in input.splitLines():
    if rawLine.len == 0:
      break
    let (key, value) = parseHeader(rawLine)
    headers[key] = value
    if headers.len > headerLimit:
      raise newException(ValueError, "too many headers")

proc parseContentLengthOriginal(input: string) =
  var contentLength = 0
  let consumed = parseSaturatedNatural(input, contentLength)
  if consumed == 0:
    raise newException(ValueError, "invalid content length")
  if contentLength > localMaxBody:
    raise newException(ValueError, "body too large")

proc parseChunkSizeOriginal(input: string) =
  discard input.strip().parseHexInt

proc exercise(mode: int, payload: string) =
  case mode
  of 0:
    discard parseProtocolOriginal(payload)
  of 1:
    discard parseRequestLineOriginal(payload)
  of 2:
    parseHeadersOriginal(payload)
  of 3:
    var parsed = initUri()
    parseUri(payload, parsed)
  of 4:
    parseContentLengthOriginal(payload)
  of 5:
    parseChunkSizeOriginal(payload)
  else:
    discard

proc LLVMFuzzerTestOneInput(data: ptr UncheckedArray[byte], len: csize_t): cint {.
    exportc, cdecl, raises: [].} =
  result = 0
  if len == 0:
    return

  let inputLen = int(len)
  var input = newString(inputLen)
  copyMem(addr input[0], data, inputLen)

  let mode = int(data[0]) mod 6
  let payload =
    if inputLen > 1: input[1 .. ^1]
    else: ""

  try:
    exercise(mode, payload)
  except ValueError:
    discard
  except Defect:
    quit(70)
  except CatchableError:
    discard

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
