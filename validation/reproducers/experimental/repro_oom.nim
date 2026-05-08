proc test() =
  try:
    let s = newString(9223372036854775807)
    echo "allocated: ", s.len
  except OutOfMemError:
    echo "OutOfMemError"
  except RangeDefect:
    echo "RangeDefect"

test()
