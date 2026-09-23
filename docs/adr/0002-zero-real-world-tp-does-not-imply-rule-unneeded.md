# 0002. A 0% real-world true-positive rate doesn't mean a rule is broken or unneeded

## Status

Accepted

## Context

Several CERT-C rules measure near-0% TP / high FP across aurora-lint's
real-world benchmark corpus (see `docs/testing-methodology.rst`). This
recurs often enough to get re-litigated: "if a rule has never found a real
bug across N mature codebases, is it worth the engineering investment, or
should it be disabled?"

The benchmark corpus is not a random sample of C code — it's deliberately
mature, widely-used, heavily-audited open-source projects (curl, sqlite,
hostap, mbedtls, and similar). A defect survives in a codebase like that
*because* it's rare and well-hidden. A rule finding zero true positives
there is a fact about the corpus's maturity as much as it is a fact about
the rule.

That said, a 0% isn't uniformly uninformative — there's a real difference
between a detector that attempts genuine analysis and comes up empty on hard
real-world shapes (EXP02-C, PRE31-C: the analysis is attempted and the
defect class may just be genuinely rare or hard to detect) and one that
never attempted real analysis in the first place (INT02-C, an early
implementation: every
branch was matching variable-name spellings from the CERT wiki's own
example, not resolving types — so its 0% said nothing about how often the
underlying defect occurs, only that this implementation couldn't see it).
The first kind is a legitimate invest-vs-deprioritize question. The second
kind is a correctness bug wearing a precision statistic — a rewrite
question, not a keep/drop one, and 1186 was decided as rewrite specifically
for that reason.

aurora-lint's primary deployment target is CI/CD on codebases under active
development — new code, refactors, feature branches — not a one-time audit
of code that has already been fuzzed, reviewed, and run in production for
years. A codebase that is CERT-C conforming for a given rule *by
construction* produces zero true positives for that rule going forward —
that's the rule succeeding, not evidence it should be removed. Its ongoing
value is catching the *next* violation a future change introduces, which is
exactly the population a static real-world benchmark snapshot cannot
measure.

## Decision

A rule's real-world benchmark TP rate alone is not grounds to deprioritize,
disable, or stop investing in the rule. Do not propose disabling a rule, or
treat "sustained 0% TP across N projects" by itself as sufficient
justification, without also weighing:

1. Whether corpus maturity — rather than the defect class being rare or the
   detector being broken — explains the 0%.
2. Whether the detector attempts real analysis and fails on hard cases
   (an investment question) versus never attempting real analysis at all (a
   rewrite question — see ADR-0001's note on detection bugs).
3. Whether the rule defends against a defect class that's rare in surviving
   code precisely *because* it's serious when it occurs.

Real-world FP volume is still fully actionable and drives ordinary
FP-reduction work — that's ADR-0001's territory. This ADR is specifically
about the inference "0 TP found ⇒ this rule doesn't matter," which does not
follow from the premise alone.

**This does not excuse leaving a misfire in place.** A finding that names a
construct not actually present in the code is a bug regardless of corpus
maturity — see ADR-0005 for the distinction between that and a judgment
false positive, which is what this ADR and ADR-0001 are actually about. Do
not read "0% TP doesn't mean the rule is unneeded" as a reason to decline a
real fix.

## Consequences

- "This rule is 0% TP on our benchmarks" is not a valid opening move for a
  task proposing to disable or deprioritize a rule. It's an observation that
  needs the three questions above answered before it becomes an argument.
- Juliet Test Suite precision/recall (synthetic, injected defects) remains
  the primary signal for whether a rule's *detection logic* works;
  real-world benchmarks measure noise and scale on mature code, not rule
  necessity — see `docs/testing-methodology.rst` ("Why both").
- FP-reduction work on a 0%-TP rule is still worth doing (it reduces CI/CD
  noise ahead of the rule's eventual real findings) but is a different task
  from questioning whether the rule should exist.
- Precedent: INT02-C — 431/431 FP historically across 8
  projects, decided as a rewrite rather than a disable, because the
  detector never attempted the real analysis in the first place.
