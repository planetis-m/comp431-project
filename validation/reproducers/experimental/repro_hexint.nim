import std/strutils

# Reproducer for parseHexInt overflow
try:
  let val = parseHexInt("8000000000000000")
  echo "Parsed value: ", val
except ValueError as e:
  echo "ValueError: ", e.msg
