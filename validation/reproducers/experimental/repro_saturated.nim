import std/parseutils

var contentLength = 0
let consumed = parseSaturatedNatural("0x10", contentLength)
echo "consumed=", consumed, " contentLength=", contentLength

contentLength = 0
let consumed2 = parseSaturatedNatural("5abc", contentLength)
echo "consumed2=", consumed2, " contentLength=", contentLength
