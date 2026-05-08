proc myNewString(size: int): string =
  result = newString(size)

proc test() =
  let s = myNewString(-1)
  echo s.len

test()
