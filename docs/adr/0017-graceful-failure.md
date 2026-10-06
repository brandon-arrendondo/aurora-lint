# 0017. A crash or a runaway costs one rule on one file, is always reported, and never passes as clean

## Status

Accepted

## Context

aurora-lint cannot promise it never crashes and never runs away. The most
it can claim is confidence on the code it is measured against: the Juliet
suite, the real-world corpora and the shadow benchmark set. Real code
eventually contains a construct that none of those exercise.

Before this decision, a failure anywhere ended the scan.

- **Crash.** MEM35-C sliced the text between the first `(` and the first `)`
  after `sizeof`. On `malloc(cb + (sizeof *new) + (sizeof pool->mark))`
  the first `)` comes first, so the slice panicked. The panic crossed the
  rayon worker and `collect` re-raised it on the main thread. The process
  exited 101, wrote no export, and lost every finding every other rule had
  already produced, in every file.
- **Hang.** A loop that never ends hangs the scan the same way, with no
  output and no indication of where.
- **Bound.** The analyses bound their own work in dozens of places: depth
  caps, fixpoint iteration caps, size caps, and recursion turned into
  iteration. [Inventory](../design/analysis-bounds-inventory.md) lists them
  all. Most of them, when hit, stop quietly and return what they have.
  What they have is often "nothing found" or "proven safe", and that is
  where the soundness problem lies: a bound that cuts an analysis short has
  not shown there is nothing to report.

## Decision

1. **Containment.** Each unit of work runs contained:
   - one rule's check of one file;
   - one file's reading, parsing and analysis around its rules;
   - one file's prescan, i.e. its contribution to cross-file facts.

   A unit that does not finish loses only its own results.
   - A failed rule check drops that rule's findings for that file. Every
     other finding stands.
   - A failed file drops that file's findings.
   - A failed prescan drops that file's cross-file facts. Those facts can
     change findings in other files in either direction, so this is
     reported as a separate stage.

2. **Escalation.** A rule that fails on **3** different files in one scan is
   abandoned for the rest of that scan.
   - Its remaining files are skipped.
   - **All** of its findings are withheld, including those from files where
     it succeeded.
   - Withholding all of them keeps the output identical regardless of the
     order parallel workers hit the failures.
   - One failure means the rule mishandles one construct. Three in one scan
     means it cannot be trusted on this code base.

3. **Hangs are bounded deterministically where possible.** Code that loops
   or recurses to an extent the input decides calls a checkpoint once per
   iteration. Each unit of work has a step budget: `--rule-step-limit`,
   default 50 million steps.
   - The budget counts steps, not time, so the same input stops at the same
     step on every machine.
   - New code with an input-dependent loop adds a checkpoint. The
     [inventory](../design/analysis-bounds-inventory.md) lists where the
     checkpoints are.

4. **A last resort for what a budget cannot see.**
   - **Wall-clock limit.** `--rule-time-limit` (default 300 s per unit) is
     checked at the checkpoints.
   - **Watchdog.** A watchdog thread ends the scan if a unit is still running
     at twice its limit, and at least 60 s past it. That case is a loop
     with no checkpoint in it. The watchdog names the unit on stderr and
     exits 3.
   - The time limit is nondeterministic by nature, so it is a backstop and
     never the primary bound.

5. **Hitting a bound is incomplete, never "no finding".**
   - A crash, a step budget, a time limit, or an analysis iteration cap that
     only a runaway should reach is reported the same way:
     - one stderr line per failure, giving stage, cause, rule, file, message
       and source location;
     - a summary line;
     - a SARIF `toolExecutionNotifications` entry, with
       `invocations[0].executionSuccessful: false`;
     - exit status **3**.
   - Two worklist caps that used to `break` silently now do this: reaching
     definitions and null state. Neither is reached on the Juliet suite or
     the real-world corpora, so reaching one means a runaway.
   - **Sound approximations are not incomplete.** A bound whose fallback over-approximates
     is the analysis working as designed: widening to the type's range, or
     "not proven, so report". It is not reported.
   - **Known non-convergence is a warning, not silence.** Some analyses
     reach their iteration caps on real code without converging, however
     many iterations they are given: they oscillate. Each one is a named,
     temporary exception, listed with its evidence in the inventory and
     tracked by the maintainer until its convergence is fixed. Reporting
     such a cap as incomplete would leave whole benchmark corpora
     unscorable. So for now an analysis on the list stops and keeps what it
     has, as before:
     - findings are unchanged;
     - every occurrence is counted;
     - the count is printed as a warning and written as a SARIF `warning`
       notification;
     - the run stays successful;
     - a benchmark run records the counts in its sidecar, so a result built
       on possibly unsound ranges carries the trace.

     Each analysis leaves this list when its convergence is fixed. Its cap
     then reports like the others.
   - The remaining silent truncations listed in the inventory are follow-up
     work. Each becomes either a sound fallback or a reported bound.

6. **Exit status.**

   | Status | Meaning |
   |---|---|
   | 0 | Clean, or no finding at or over the `--fail-on-*` threshold. |
   | 1 | A finding at or over a `--fail-on-*` threshold. |
   | 2 | The scan could not run: usage or configuration error. |
   | 3 | The scan completed but is incomplete. |

   - 3 outranks 1, and is returned with or without `--fail-on-*`. A partial
     scan never exits 0 or 1.
   - The findings that were produced are still printed and exported.
   - The JSON findings export stays a bare array of findings. Failures go to
     stderr and SARIF.

7. **What the unwind may leave behind.**
   - Process-wide state a check can reach must be panic-tolerant. A global
     `Mutex` recovers from poisoning:
     `lock().unwrap_or_else(|e| e.into_inner())`.
   - A per-thread buffer that spans a check is rolled back on failure.
   - An incomplete prescan is never saved as a cache, so no later scan
     inherits its gap silently.

8. **Release builds unwind.** Containment depends on it, and the build
   refuses `panic = "abort"` with a compile error.

9. **Input that is not source is refused before it is parsed.** Files are
   picked by extension, so an archive, a binary or a core dump named `.c`
   reaches the parser. Parsing it cannot produce a finding and can exhaust
   memory. An out-of-memory kill cannot be contained after the fact, so it
   must be prevented. One function (`input_guard::admit`) checks every
   scanned and prescanned file:
   - a size ceiling, `--max-file-size`, default 64 MiB. The largest file the
     corpora scan is about 4 MiB (raylib's `miniaudio.h`). The largest real
     C inputs a scanner meets are amalgamations and SDK headers of 9-10 MiB.
     64 MiB is several times either.
   - the shared parsing substrate's file classifier
     (`lang_parsing_substrate::classify_file`). It checks magic numbers
     (archives, compressed streams, ELF, PE, Mach-O, images, PDF, office
     documents, media, fonts), then the ratio of NUL, control and
     invalid-UTF-8 bytes in the first 8 KiB. It was calibrated so that no
     C-family file in the benchmark corpora or Juliet is classed binary. A
     UTF-16 byte-order mark is read as text. Empty files are admitted.

   A refused file is skipped and reported like any other failure: stage
   `input`, exit 3, a SARIF notification. Files the user excluded never get
   that far and are not reported. Files over 8 MiB are analysed one at a
   time, however many `--jobs` there are, so several huge inputs cannot be
   in memory together.

   The classifier lives in the substrate so that every tool built on it
   refuses input the same way; `admit` adds only this tool's policy. A
   per-process memory budget is not implemented. The one-at-a-time rule for
   huge files is the bound until it is.

## Consequences

- A contained crash is still a bug and is still fixed at its cause:
  ADR-0005 for a misfire, ADR-0006 for a text-for-AST read. Containment
  buys the rest of the scan, not permission to keep the bug.
- A benchmark scan that exits 3 is **not scored**. Its precision and recall
  would treat a crashed rule as a rule that chose not to report. The bench
  runner marks it INCOMPLETE and records what failed in the scan's sidecar.
- CI that treats any nonzero status as failure needs no change. CI that
  checks for exactly 1 must learn 3. The recommended CI handling is in
  [Error handling and exit codes](../error-handling.rst).
- A rule can lose good findings to escalation. That is deliberate:
  findings from a rule that failed three times in one scan are not trusted.
- The step budget's default is set orders of magnitude above anything the
  benchmark corpora reach; the inventory records the measurement. A unit
  that hits it is either a runaway or input far beyond anything measured.
  In both cases the user should hear about it rather than wait for it.
- What is deterministic. The findings, the exit status and the set of
  reported failures do not depend on how the parallel scan ordered its
  work. An abandoned rule is reported once, as abandoned, rather than once
  per file it reached before the decision. Only the time limit and the
  watchdog are nondeterministic, which is why they are the backstop.
- This does not make the analyses complete. A bound that degrades to a
  sound approximation stays silent, and the inventory's remaining silent
  truncations are known gaps until each is converted.
