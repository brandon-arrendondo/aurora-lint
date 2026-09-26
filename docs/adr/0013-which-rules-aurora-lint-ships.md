# 0013. Which rules aurora-lint ships: decided by the rule's nature, not by benchmark counts

## Status

Accepted (Brandon, 2026-09-25).

## Context

aurora-lint implements most of CERT C's rules and recommendations. Not all
of them suit a deterministic static analyzer. The intended use is a
Claude-level reviewer, or a CI job, running aurora-lint as its
deterministic instrument over a codebase. For that to work, every rule the
tool ships has to be provable, exhaustive and repeatable. Some CERT
guidelines are judgment calls about intent, design or semantics that no
sound static check captures. A heuristic that approximates one of those
judgments produces findings that are mostly wrong on any codebase. Shipping
it costs every user noise and costs the tool credibility.

ADR-0002 already answers a different question: a rule with 0% true
positives on the real-world corpus is not therefore broken or unneeded,
because the corpus is mature code and the rule's value is catching the next
violation. That ADR has to stay intact. So the question here cannot be
decided by benchmark counts. If it were, it would contradict 0002.

## Decision

1. **A rule ships if a sound detector for it can ever find a true
   violation, and its findings are not structurally dominated by false
   positives on any codebase.** This is a question about the rule's
   nature: the CERT text, and whether what it asks for is decidable from
   the source under ADR-0011's bases. It is answered from the rule text and
   the detector's design. Benchmark numbers can illustrate a finding but
   never decide it. A rule that is rare on our corpus but decisive when it
   fires passes (ADR-0002).
2. **Each implemented rule gets exactly one disposition,** recorded in a
   per-rule table in `docs/design/`:
   - **Deterministic**: the tool can decide the violation soundly. Ships,
     on by default.
   - **Deterministic with review**: the tool finds every candidate soundly,
     but whether a candidate is a violation needs context a reviewer
     supplies (the existing manual-review marking). Ships; findings are
     presented as candidates for confirmation.
   - **Environment-gated**: deterministic, but only measurable with an
     environment the benchmark doesn't have yet (for example Windows
     headers). Ships; its figures say so.
   - **Unenforceable**: CERT itself says the guideline can't be checked
     automatically, or no sound detector is possible. Not shipped as a
     detector; documented as a known limit.
   - **Fails the criterion**: any checkable form of the rule can only
     approximate an intent or design judgment, so its findings are
     structurally FP-dominated. Not shipped. The row names why.
3. **Anything the Juliet suite covers ships.** Juliet was built to test
   deterministic static checkers, so a Juliet-mapped rule can never fall
   into "fails the criterion". If its detector is weak, that's a rewrite
   question (ADR-0002, ADR-0005), not a drop.
4. **"Not shipped" means removed from the tool,** not disabled by default.
   It gets a changelog "Removed" entry (ADR-0009). A configuration file
   that names a removed rule loads with a warning, not an error. The rule's
   name stays in the inventory and in the disposition table, with the
   reason.
5. **Each removal is its own change,** justified by its table row. Never in
   bulk.
6. **What the tool doesn't ship is published, prominently, with the
   reason.** Every rule that isn't shipped, and why, appears in README.md,
   in `docs/`, and in the paper. The naive approach is to ship everything;
   these are the hard-won reasons that approach doesn't work, and they
   explain why the tool is the way it is. They are a result, not a
   footnote (Brandon, 2026-09-25).
7. **Measurement stays separate.** A rule's real-world figures, its
   Juliet figures, and the count of rules the paper calls working
   detectors all come from the disposition table, so the paper and the tool
   agree on what "in play" means.

## Consequences

- "This rule has 0% TP, drop it" is still not an argument (ADR-0002). "This
  rule's checkable form can only approximate an intent judgment, here's
  why" is, and it goes through the table.
- A rule that fails today because its detector is a heuristic, when a sound
  detector is possible, is a rewrite (ADR-0002's INT02-C precedent), not a
  drop.
- The same criterion governs any new rule, CERT or not: a candidate that
  would land in "fails the criterion" doesn't get implemented.
- ADR-0011 defines what a finding may be judged against; this ADR decides
  which rules are asked the question at all.
- The disposition table is the input for the paper's "rules in play" and
  "never fire" accounting, replacing ad hoc counts.
