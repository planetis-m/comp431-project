// presentation_terminal_experiment.typ -- restrained CRT terminal deck experiment

#let phosphor = rgb("#b7ffbf")
#let phosphor2 = rgb("#78d88c")
#let amber = rgb("#e1c16a")
#let bg = rgb("#020402")
#let field = rgb("#071007")
#let line = rgb("#23402a")
#let dim = rgb("#63856b")
#let white = rgb("#e9f4ea")
#let danger = rgb("#ff7c69")

#set page(paper: "presentation-16-9", fill: bg)
#set text(font: "Liberation Mono", size: 12pt, fill: white)
#set par(leading: 0.62em, justify: false)

#show raw.where(block: true): it => block(
  width: 100%,
  fill: field,
  stroke: 0.65pt + line,
  inset: (x: 12pt, y: 9pt),
  radius: 0pt,
  it,
)
#show raw.where(block: true): set text(size: 8.6pt, fill: phosphor)
#show raw.where(block: false): set text(size: 10.5pt, fill: phosphor)
#show link: set text(fill: phosphor2)

#let rule(fill: line) = block(width: 100%, height: 0.55pt, fill: fill)

#let label(body, fill: dim) = text(size: 7.8pt, fill: fill, body)
#let small(body, fill: dim) = text(size: 9.4pt, fill: fill, body)
#let signal(body, fill: phosphor) = text(weight: "bold", fill: fill, body)
#let lead(body) = text(size: 19pt, fill: white, body)
#let quiet(body) = text(fill: dim, body)

#let frame(id, title, body, mode: "COMP431 RESEARCH TERMINAL") = page(
  margin: (top: 24pt, bottom: 24pt, left: 38pt, right: 38pt),
)[
  #block(width: 100%, height: 100%)[
    #grid(
      columns: (1fr, auto),
      align: (left, right),
      label(mode),
      label("TTY-" + id),
    )
    #v(5pt)
    #rule()
    #v(16pt)
    #label("FILE: " + title, fill: phosphor2)
    #v(8pt)
    #body
  ]
]

#let terminal(body, path: "/audit/session", width: 100%) = block(
  width: width,
  fill: field,
  stroke: 0.7pt + line,
  inset: (x: 13pt, y: 10pt),
  radius: 0pt,
)[
  #grid(columns: (1fr, auto), label(path), label("READY", fill: phosphor2))
  #v(5pt)
  #rule(fill: rgb("#1a2e20"))
  #v(8pt)
  #body
]

#let prompt(body, user: "audit") = [
  #text(size: 9.2pt, fill: phosphor2)[#user>]
  #text(size: 9.2pt, fill: white)[ #body]
]

#let stat(value, caption, fill: phosphor) = block(width: 100%)[
  #text(size: 36pt, weight: "bold", fill: fill)[#value]
  #v(3pt)
  #label(caption)
]

#let datum(name, value, fill: phosphor) = grid(
  columns: (1fr, auto),
  align: (left, right),
  gutter: 14pt,
  small(name),
  text(size: 12pt, weight: "bold", fill: fill, value),
)

#let step(n, title, body, active: false) = grid(
  columns: (20pt, 1fr),
  gutter: 12pt,
  align: (left, top),
  text(size: 12pt, weight: "bold", fill: if active { phosphor } else { dim }, n),
  [
    #text(size: 12pt, weight: "bold", fill: if active { white } else { phosphor2 })[#title]
    #v(3pt)
    #small(body)
  ],
)

#let thin-box(body, stroke: line, fill: none, inset: (x: 10pt, y: 8pt)) = block(
  width: 100%,
  fill: fill,
  stroke: 0.65pt + stroke,
  inset: inset,
  radius: 0pt,
)[#body]

#let arrow() = text(size: 18pt, fill: phosphor2)[->]

// 00
#frame("00", "PROJECT OPEN")[
  #v(34pt)
  #label("CLASSIFIED TRAINING RUN / LOCAL DEFENSIVE AUDIT")
  #v(16pt)
  #text(size: 34pt, weight: "bold", fill: white)[FUZZING VS AI REVIEW]
  #v(4pt)
  #text(size: 24pt, fill: phosphor)[NIM ASYNCHTTPSERVER]
  #v(30pt)
  #terminal(path: "/usr/local/audit")[
    #prompt([run comparison --target std/asynchttpserver])
    #v(7pt)
    #prompt([require evidence --payload --reproducer --replay])
  ]
]

// 01
#frame("01", "QUESTION")[
  #v(46pt)
  #lead[
    Which tool produced evidence that survived replay?
  ]
  #v(26pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 22pt,
    thin-box([
      #label("METHOD A")
      #v(8pt)
      #text(size: 22pt, fill: phosphor)[FUZZING]
      #v(8pt)
      #small([execute malformed inputs until behavior changes])
    ]),
    thin-box([
      #label("METHOD B")
      #v(8pt)
      #text(size: 22pt, fill: phosphor)[AI REVIEW]
      #v(8pt)
      #small([inspect source and propose risks to validate])
    ]),
  )
  #v(20pt)
  #label("Evaluation standard: exact input, direct reproducer, fixed-version replay.")
]

// 02
#frame("02", "RESULT SUMMARY")[
  #v(24pt)
  #grid(
    columns: (1fr, 1fr, 1fr),
    gutter: 28pt,
    stat("1", "confirmed runtime crash"),
    stat("0", "AI-confirmed crashes", fill: amber),
    stat("HTTP/", "minimal crashing protocol", fill: danger),
  )
  #v(32pt)
  #terminal(path: "/audit/result")[
    #prompt([fuzzer: saved crashing input])
    #v(5pt)
    #prompt([reviewer: reproduced crash locally])
    #v(5pt)
    #prompt([fixed build: replay no longer crashes])
  ]
]

// 03
#frame("03", "ATTACK SURFACE")[
  #grid(
    columns: (0.95fr, 1.05fr),
    gutter: 28pt,
    [
      #v(14pt)
      #lead[The boundary is plain text from an unauthenticated client.]
      #v(18pt)
      #datum("request line", "attacker controlled")
      #v(7pt)
      #datum("headers", "attacker controlled")
      #v(7pt)
      #datum("body", "attacker controlled")
      #v(20pt)
      #small([Scope: local defensive testing against an intentionally older Nim version.])
    ],
    terminal(path: "/net/input")[
      ```text
      GET /index.html HTTP/1.1
      Host: example.local
      Content-Length: 12

      optional-body
      ```
      #v(10pt)
      #thin-box([
        #signal([risk: malformed bytes reach parser state], fill: amber)
      ], stroke: amber)
    ],
  )
]

// 04
#frame("04", "FUZZING LOOP")[
  #v(12pt)
  #lead[Coverage guidance turns random input into a search process.]
  #v(28pt)
  #grid(
    columns: (1fr, auto, 1fr, auto, 1fr, auto, 1fr),
    gutter: 10pt,
    align: (center, horizon),
    thin-box([#signal([seed corpus]) #v(5pt) #small([valid HTTP fragments])]),
    arrow(),
    thin-box([#signal([mutate]) #v(5pt) #small([change bytes])]),
    arrow(),
    thin-box([#signal([run parser]) #v(5pt) #small([observe behavior])]),
    arrow(),
    thin-box([#signal([keep/reduce]) #v(5pt) #small([new path or crash])]),
  )
  #v(34pt)
  #terminal(path: "/build/fuzzer")[
    ```bash
    nim c --cc:clang -d:useMalloc --noMain:on \
      --passC:-fsanitize=fuzzer,address,undefined \
      --passL:-fsanitize=fuzzer,address,undefined \
      asynchttpserver_fuzzer.nim
    ```
  ]
]

// 05
#frame("05", "CRASH INPUT")[
  #v(30pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 30pt,
    [
      #label("MINIMAL REPRODUCER")
      #v(14pt)
      #text(size: 48pt, weight: "bold", fill: danger)[HTTP/]
      #v(16pt)
      #lead[An incomplete protocol token should be rejected, not crash the process.]
    ],
    terminal(path: "/replay/protocol")[
      #prompt([parseProtocol("HTTP/")])
      #v(12pt)
      #text(size: 14pt, fill: danger)[IndexDefect]
      #v(6pt)
      #small([index out of bounds after unconditional dot skip])
    ],
  )
]

// 06
#frame("06", "CODE PATH")[
  #v(10pt)
  #lead[The bug is a missing boundary check between two parse steps.]
  #v(22pt)
  #grid(
    columns: (1fr, 1fr),
    gutter: 22pt,
    terminal(path: "/src/vulnerable")[
      ```nim
      i.inc protocol.parseSaturatedNatural(result.major, i)
      i.inc
      i.inc protocol.parseSaturatedNatural(result.minor, i)
      ```
      #v(8pt)
      #signal([unconditional skip], fill: danger)
    ],
    terminal(path: "/src/fixed")[
      ```nim
      i.inc protocol.parseSaturatedNatural(result.major, i)
      if i < protocol.len: inc i
      i.inc protocol.parseSaturatedNatural(result.minor, i)
      ```
      #v(8pt)
      #signal([guarded skip])
    ],
  )
  #v(20pt)
  #label("Upstream reference: Nim PR #25793.")
]

// 07
#frame("07", "EVIDENCE CHAIN")[
  #v(8pt)
  #lead[A confirmed finding needs a chain, not a claim.]
  #v(24pt)
  #grid(
    columns: (1fr, 1fr, 1fr, 1fr),
    gutter: 14pt,
    step("01", "crash", [fuzzer saves exact input], active: true),
    step("02", "reduce", [minimal payload is isolated]),
    step("03", "reproduce", [small Nim program triggers the same defect]),
    step("04", "replay", [fixed version rejects safely]),
  )
  #v(34pt)
  #terminal(path: "/audit/evidence")[
    #prompt([artifact: 0HTTP/])
    #v(5pt)
    #prompt([minimal: HTTP/])
    #v(5pt)
    #prompt([status: confirmed local denial-of-service crash])
  ]
]

// 08
#frame("08", "AI REVIEW")[
  #grid(
    columns: (1fr, 1fr),
    gutter: 28pt,
    [
      #v(16pt)
      #lead[AI was useful before confirmation, not after it.]
      #v(22pt)
      #step("A", "generate", [possible risks and audit checklist])
      #v(12pt)
      #step("B", "triage", [compare claims with source and harness scope])
      #v(12pt)
      #step("C", "validate", [require a testcase before calling it a bug], active: true)
    ],
    terminal(path: "/models/summary")[
      #datum("reported leads", "23")
      #v(8pt)
      #datum("likely worth testing", "16", fill: amber)
      #v(8pt)
      #datum("confirmed crashes", "0", fill: danger)
      #v(18pt)
      #small([Best output: checklist material for a human security review.])
    ],
  )
]

// 09
#frame("09", "COMPARISON")[
  #v(12pt)
  #table(
    columns: (0.9fr, 1.2fr, 1.2fr),
    stroke: (_, y) => if y == 0 { (bottom: 0.7pt + phosphor2) } else { (bottom: 0.45pt + line) },
    inset: (x: 8pt, y: 8pt),
    fill: (_, y) => if y == 0 { field },
    table.header([#label("CRITERION", fill: phosphor2)], [#label("FUZZING", fill: phosphor2)], [#label("AI REVIEW", fill: phosphor2)]),
    [confirmed crashes], [#signal([1])], [0],
    [evidence], [crash input + replay], [reasoning to validate],
    [strength], [runtime behavior], [broad design coverage],
    [weakness], [harness scope], [overstatement risk],
  )
  #v(28pt)
  #lead[Fuzzing answered "what happened." AI helped decide "what to test next."]
]

// 10
#frame("10", "OPERATING PRINCIPLE")[
  #v(40pt)
  #terminal(path: "/doctrine/evidence")[
    #prompt([model proposes])
    #v(9pt)
    #prompt([harness tests])
    #v(9pt)
    #prompt([developer validates])
    #v(9pt)
    #prompt([fix is replayed])
  ]
  #v(30pt)
  #text(size: 24pt, weight: "bold", fill: phosphor)[A finding is confirmed only when it can be reproduced.]
]

// 11
#frame("11", "REFERENCES")[
  #v(10pt)
  #grid(
    columns: (auto, 1fr),
    gutter: 10pt,
    align: (left, top),
    label("[1]", fill: phosphor2),
    small([B. Grinstead, C. Holler, F. Braun, "Behind the Scenes Hardening Firefox with Claude Mythos Preview," Mozilla Hacks, May 2026.]),
    label("[2]", fill: phosphor2),
    small([LLVM Project, #link("https://llvm.org/docs/LibFuzzer.html")[libFuzzer documentation].]),
    label("[3]", fill: phosphor2),
    small([Clang documentation, #link("https://clang.llvm.org/docs/AddressSanitizer.html")[AddressSanitizer].]),
    label("[4]", fill: phosphor2),
    small([OWASP Foundation, #link("https://owasp.org/www-community/Fuzzing")[Fuzzing].]),
    label("[5]", fill: phosphor2),
    small([nim-lang/Nim, #link("https://github.com/nim-lang/Nim/pull/25793")[PR #25793: fix DOS via malformed HTTP protocol].]),
  )
]
