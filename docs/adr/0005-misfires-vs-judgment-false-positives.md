# 0005. Distinguish misfires from judgment false positives — only the former is always a rule bug

## Status

Accepted

## Context

ADR-0001 says noise is handled by suppression/config, not by softening
detection logic. ADR-0002 says a low real-world true-positive rate doesn't
mean a rule is broken. Read on their own, an agent can over-apply either one
in a way that protects an actual detection bug from being fixed.

This happened in practice on 2026-09-15: after being corrected on ADR-0002's
principle (real-world 0% TP isn't a failure signal), a session initially
started reconsidering whether to reverse two same-day fixes (both
earlier implementations) that had *removed* findings. Both removals were correct and
should not have been reconsidered — but the session couldn't tell that from
ADR-0002's text alone, because ADR-0002 doesn't distinguish two different
things that both show up as "this rule fires less than it used to":

- **A misfire**: the rule names a construct that is not actually present in
  the code. EXP05-C reported "cast away const" on a `memset` call
  with no cast anywhere near it, because its substring matching resolved
  the wrong declaration. INT02-C reported "multiplication of
  unsigned short" on a plain pointer dereference, because its only real
  check was "does the literal string `unsigned short` appear anywhere
  earlier in the file." Neither of these is a rule correctly detecting a
  defect that a codebase doesn't want reported — the rule is simply *wrong
  about what's on the line*. This is a bug regardless of the codebase, the
  corpus, or how mature the code is.
- **A judgment false positive**: the rule correctly identifies the
  construct it's designed to flag, and a human adjudicator or maintainer
  decides that instance isn't worth acting on (see ADR-0001 — this is where
  suppression and per-project manifests apply, and where ADR-0002's "don't
  read 0% as failure" caution is actually about).

## Decision

Before treating a rule change or a "this looks wrong" report as something
ADR-0001 or ADR-0002 might apply to, classify it first:

- **Misfire** — the finding's message describes a construct (a cast, a
  multiplication, a null check, whatever the rule is about) that a reader
  of the flagged line cannot find there. Fix it. This holds in every
  codebase, at every maturity level, on every corpus. Corpus selection bias
  (ADR-0002) is irrelevant to whether a misfire should be fixed — a rule
  that's wrong about what's in front of it doesn't become more right on
  less mature code.
- **Judgment FP** — the finding's message accurately describes a real
  instance of the construct the rule is about, and someone decided it
  doesn't matter here. This is ADR-0001's territory (suppress/configure,
  don't weaken the rule) and where ADR-0002's real-world-TP caution
  applies (a low hit rate on mature code doesn't mean the rule should stop
  looking).

The two are easy to conflate because both can be described as "the rule
fires too much" — but only a misfire's *fix* is unconditionally correct
regardless of corpus. A judgment-FP "fix" (narrowing what the rule reports)
is exactly the thing ADR-0001 says not to do.

### Right for the wrong reason

A finding must rest on sound evidence about the line it names. Sometimes
the tool reaches a real violation through evidence that is wrong: a
pointer judged NULL from a stale assignment the call never sees, or a file
chosen by hash order. Removing such a finding is a correctness fix, the
same as removing a misfire, even though the oracle records a violation on
that line. The oracle doesn't change; the run now misses the violation, so
it moves from TP to FN. That is a real loss of capability the tool only
appeared to have, and it is reported as lost recall, not avoided by
keeping the unsound path (Brandon, 2026-09-25). How the oracle and a run
combine into TP, FP, FN and TN is set out in ADR-0014.

### Juliet section scoring is not line truth

Juliet scores a finding by section: anything reported inside a flawed
("bad") function counts as a hit, whatever it says. That is much coarser
than the oracle (ADR-0014), which asks whether *this line* violates *this
rule*. A rule can hit Juliet's bad sections by firing near the flaw, or by
misfiring on an unrelated line inside the bad region, and look as if it
works. That illusion held for this project's early rules, which were judged
on Juliet hits and misses as other tools are. It fails the moment exact
violation lines have to be adjudicated. So a Juliet "TP" means "fired in the
flawed section", an approximation of the oracle, not a confirmed violation. A
misfire fix that removes such hits is still a fix, and reported Juliet
figures state the section-level scoring. This is separate from what Juliet
misses by design compared with real codebases (Brandon, 2026-09-25).

## Consequences

- When reviewing a same-session correction like the one that prompted this
  ADR, check which category the earlier change was before reversing
  anything. A misfire fix (fewer findings, strictly a subset of the old
  output, nothing new appears) doesn't get walked back because of ADR-0002.
- A **recall** decision (should the rule also flag cases it currently
  misses) is different again from both, and should not be scoped off
  real-world corpus silence either — see ADR-0002's "don't scope recall off
  the corpus miss rate" consequence and INT02-C's own recall extension
  for a worked example: Juliet and hand-written fixtures
  are the better check for whether a rule catches what it's supposed to.
- **What ADR-0002 does NOT license**: loosening constraints that are C
  language semantics rather than tuning — integer promotion of narrow
  operands, value-preserving conversions, an explicit cast being exempt
  because the conversion is written down. Making a rule report something
  that isn't actually true of the language is not "braver on immature
  code," it's wrong on every code. If a fix under discussion would make a
  rule's output stop matching the C standard's own rules, that's a
  misfire-shaped problem regardless of which direction it moves the
  finding count.
- Credit: this distinction and the caution about loosening real semantics
  came out of dev-180's own catch, the same day ADR-0002 was written —
  worth stating explicitly rather than learned per-agent per-session.
