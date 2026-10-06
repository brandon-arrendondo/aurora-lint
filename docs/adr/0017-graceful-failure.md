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
   - Today the checkpoints are in: the dataflow, null-state, init-state and
     value-range worklists; CFG construction; macro rescans; and the
     unknown-identifier repair loop.
   - New code with an input-dependent loop adds a checkpoint.

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
   - The four worklist caps that used to `break` silently (reaching
     definitions, null state, init state, value ranges) now do this.
   - **Sound approximations are not incomplete.** A bound whose fallback over-approximates
     is the analysis working as designed: widening to the type's range, or
     "not proven, so report". It is not reported.
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
- The step budget's default is far above anything the measured corpora
  reach. A unit that hits it is either a runaway or input far beyond
  anything measured. In both cases the user should hear about it rather
  than wait for it.
- This does not make the analyses complete. A bound that degrades to a
  sound approximation stays silent, and the inventory's remaining silent
  truncations are known gaps until each is converted.
