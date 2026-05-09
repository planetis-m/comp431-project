# Speaker Notes: Terminal Experiment Deck

## Slide 00 — Project Open

Core message:
This is a local audit experiment on an **already-fixed** Nim bug.

Visual anchor:
`FUZZING VS AI REVIEW`

Open slowly.

This project compares two ways to inspect parser code.

One executes malformed inputs.

One reviews source and proposes leads.

Pause on the terminal block.

The standard is evidence:
payload.
reproducer.
replay.

Important framing:
This is not a live-risk claim.

It is a controlled reproduction of a bug fixed upstream in Nim PR 25793.

Transition:
So the question is not "is this dangerous today."

The question is which method produced evidence.

---

## Slide 01 — Question

Core message:
The experiment is about **evidence**, not tool preference.

Visual anchor:
Question line at top.

Let the question sit for a beat.

Then contrast the two boxes.

Fuzzing:
runtime behavior.

AI review:
source-level hypotheses.

Do not oversell either side.

The important evaluation rule is at the bottom:
exact input.
direct reproducer.
fixed-version replay.

Emphasis moment:
Evidence has to survive **replay**.

Transition:
With that standard, the result becomes very simple.

---

## Slide 02 — Result Summary

Core message:
Fuzzing produced one confirmed historical crash; AI produced **zero** confirmed crashes.

Visual anchor:
The three large values: `1`, `0`, `HTTP/`.

Point first to `1`.

One confirmed runtime crash in the older tested version.

Point to `0`.

The model outputs were useful, but none produced a confirmed crash by themselves.

Point to `HTTP/`.

The whole confirmed case reduces to five characters.

Pause.

That minimal payload is why this is a clean teaching example.

Terminal anchor:
saved input.
local reproduction.
fixed replay.

Transition:
To understand why this matters, look at where the input enters the parser.

---

## Slide 03 — Attack Surface

Core message:
The historical bug lives at a parser boundary where client text becomes program state.

Visual anchor:
Left-side list: request line, headers, body.

Clarify scope immediately:
This was local defensive testing.

Older Nim version.

Already fixed upstream.

No remote system was tested.

Now explain the boundary.

The server receives text.

The parser decides what that text means.

In this project, the relevant area is the request-line protocol token.

Visual anchor:
Right terminal sample.

The interesting field is the `HTTP/1.1` part.

The old bug appears when that token becomes incomplete.

Emphasis moment:
Malformed input should fail **cleanly**.

Transition:
Fuzzing is how we searched that boundary automatically.

---

## Slide 04 — Fuzzing Loop

Core message:
Fuzzing turns malformed-input testing into a **search** process.

Visual anchor:
Four boxes: seed corpus -> mutate -> run parser -> keep/reduce.

Walk left to right.

Start with valid HTTP fragments.

Mutate bytes.

Run parser code directly.

Keep inputs that reach new behavior.

If a crash appears, libFuzzer reduces it.

Do not dwell on every compiler flag.

Use the command block as credibility:
Clang.
libFuzzer.
AddressSanitizer.
UndefinedBehaviorSanitizer.

Report detail:
The fuzzer reached the crash after 47,319 executions.

Transition:
The reduced input is the key moment.

---

## Slide 05 — Crash Input

Core message:
The minimized historical crash input was **HTTP/**.

Visual anchor:
Large red `HTTP/`.

Pause before explaining.

This token starts correctly.

It says HTTP slash.

Then it stops.

A robust parser should reject it or return a handled error.

In the older version, it raised `IndexDefect`.

Visual anchor:
Right terminal: `parseProtocol("HTTP/")`.

The direct reproducer confirmed:
`HTTP/1.1` parsed normally.

`HTTP/` triggered the defect.

Emphasis moment:
The issue is not complexity.

It is one missing **guard**.

Transition:
The next slide shows exactly where that guard belongs.

---

## Slide 06 — Code Path

Core message:
The root cause was an unconditional index increment after parsing the major version.

Visual anchor:
Left box: vulnerable.

In the old code, the parser reads the major version.

For `HTTP/`, there are no digits.

The index remains at the end of the string.

Then the code increments anyway.

That skip assumes a dot exists.

It does not.

Visual anchor:
Right box: fixed.

The upstream fix checks the boundary first.

Only skip if there is still a character.

Emphasis moment:
That tiny condition changes crash into **control**.

Important framing:
This is already merged upstream in Nim PR 25793.

Transition:
Now we can separate a real finding from a noisy report.

---

## Slide 07 — Evidence Chain

Core message:
A finding is confirmed by a **chain**, not by a claim.

Visual anchor:
Four steps across the middle.

Step 01:
Fuzzer saves exact input.

Step 02:
The input is reduced.

From `0HTTP/` to the actual parser payload: `HTTP/`.

Step 03:
A standalone Nim reproducer triggers the same defect.

Step 04:
Replay against the fixed harness no longer crashes.

Terminal anchor:
artifact.
minimal.
status.

This is the useful research pattern.

Not just "a tool reported something."

But a path from input to fix validation.

Transition:
Now compare that with the AI review output.

---

## Slide 08 — AI Review

Core message:
AI helped generate audit leads, but it did not confirm this crash.

Visual anchor:
Left steps: generate, triage, validate.

The models were used as hypothesis generators.

Same structured prompt.

Same target source.

Three usable transcripts:
DeepSeek.
GLM.
Kimi.

Visual anchor:
Right summary numbers.

23 reported leads.

16 likely worth testing.

0 confirmed crashes.

Important nuance:
Some AI findings were genuinely useful.

Chunked body growth.
missing receive timeouts.
header-limit behavior.

But those needed separate reproducers.

Emphasis moment:
AI output is not **evidence**.

Transition:
The comparison is not about dismissing AI.

It is about assigning the right job to each tool.

---

## Slide 09 — Comparison

Core message:
Fuzzing proved runtime behavior; AI broadened the checklist.

Visual anchor:
Comparison table.

Start with the first row.

Confirmed crashes:
fuzzing one.
AI zero.

Move to evidence row.

Fuzzing gave input plus replay.

AI gave reasoning to validate.

Move to strength row.

Fuzzing is narrow but concrete.

AI is broad but less reliable.

Move to weakness row.

Fuzzing depends on harness scope.

AI can misread runtime behavior.

Report detail:
DeepSeek and GLM noticed the `HTTP/` area but predicted the wrong outcome.

They thought version `0.0`.

Runtime showed `IndexDefect`.

Transition:
That leads to the operating principle of the whole project.

---

## Slide 10 — Operating Principle

Core message:
The best workflow is a validation **pipeline**.

Visual anchor:
Terminal sequence.

Model proposes.

Harness tests.

Developer validates.

Fix is replayed.

Slow this down.

This is the main lesson.

Tools produce leads.

Evidence confirms findings.

For this project, the fixed replay is what closes the loop.

It shows the saved input no longer crashes after the upstream-style guard.

Emphasis moment:
Reproduction is the **standard**.

Transition:
The final slide lists the sources behind that claim.

---

## Slide 11 — References

Core message:
The work is grounded in reproducible tooling and the upstream Nim fix.

Visual anchor:
Reference list.

Keep this brief.

Reference 1:
modern context for AI-assisted security review.

References 2 through 4:
fuzzing and sanitizer background.

Reference 5:
the key validation point.

Nim PR 25793 merged the same kind of bounds guard.

Closing line:
So the contribution here is not discovering an active risk.

It is demonstrating a clean evidence pipeline on a real, already-fixed parser bug.

End with:
Fuzzing found the behavior.

AI helped frame what else to inspect.

The confirmed result came from **replay**.
