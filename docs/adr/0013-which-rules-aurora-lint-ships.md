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
2. **Each checkable form of an implemented rule gets exactly one
   disposition,** recorded in a per-rule table in `docs/design/`. Most
   rules have one checkable form. When a rule's detector checks several
   distinct forms, each gets its own disposition (amended 2026-09-26,
   Brandon): the rule id carries the disposition of the form it keeps, and
   a form it drops is recorded in the same row as not shipped, with its
   reason. For example, a detector may report a construct the guideline
   names, plus a second construct that belongs to another rule or that only
   an intent judgment could separate. The dispositions:
   - **Deterministic**: the tool can decide the violation soundly. Ships,
     on by default.
   - **Deterministic with review**: the tool finds every candidate soundly,
     but whether a candidate is a violation needs context a reviewer
     supplies (the existing manual-review marking). Ships; findings are
     presented as candidates for confirmation. The review is the user's,
     not the oracle's (Decision 8).
   - **Environment-gated**: deterministic, but only measurable with an
     environment the benchmark doesn't have yet (for example Windows
     headers). Ships; its figures say so.
   - **Unenforceable**: CERT itself says the guideline can't be checked
     automatically, or no sound detector is possible. Not shipped as a
     detector; documented as a known limit.
   - **Fails the criterion**: any checkable form of the rule can only
     approximate an intent or design judgment, so its findings are
     structurally FP-dominated. Not shipped. The row names why.
   - **Covered by another rule** (amended 2026-09-25, Brandon): the
     guideline's only checkable form is what another shipped rule already
     reports, so a detector of its own would add no violation, only a
     second report of the same one. ERR00-C is the example. "Check error
     returns" is ERR33-C's (library calls) and EXP12-C's (any call), and
     the rest of it, a consistent error-handling policy, is a design
     judgment. Not shipped. The row names the covering rules. This is
     different from overlap between two rules with distinct checkable
     forms, where both keep firing (`docs/design/cross-rule-overlap.md`).
     **The covering rule has to report the construct already** (amended
     2026-09-26, Brandon). "Covered" is a claim about the tool, not only
     about CERT's text: a probe with the guideline's own noncompliant
     examples must show the covering rule firing on them. When it doesn't,
     the covering rule's false negative is fixed first, as its own change,
     and the removal depends on that fix. Otherwise the removal loses
     findings the tool had.
   - **Deprecated by CERT** (amended 2026-09-26, Brandon): CERT has
     deprecated or merged the guideline. The row says so, because that is
     the reason a reader of the README, the docs or the paper needs, and it
     names what replaced it: a successor guideline (the check moves into
     the successor's detector first, as for a covered rule), or a guarantee
     the standard now makes (the check becomes an environment contract
     under ADR-0015, reported only where the declared environment doesn't
     provide the guarantee). Not shipped under the deprecated id.
3. **Anything the Juliet suite covers ships.** Juliet was built to test
   deterministic static checkers, so a Juliet-mapped rule can never fall
   into "fails the criterion". If its detector is weak, that's a rewrite
   question (ADR-0002, ADR-0005), not a drop.
   - **The mapping has to be verified** (amended 2026-09-25, Brandon): a
     rule counts as Juliet-mapped only if the test cases for the CWE
     exercise what the rule checks. A CWE copied from CERT's related-CWE
     list isn't evidence on its own.
   - A rule **covered by another rule** keeps its Juliet coverage through
     the covering rule, which ships and is scored on that CWE.
4. **"Not shipped" means removed from the tool,** not disabled by default.
   It gets a changelog "Removed" entry (ADR-0009). A configuration file
   that names a removed rule loads with a warning, not an error. The rule's
   name stays in the inventory and in the disposition table, with the
   reason.
5. **Each removal is its own change,** justified by its table row. Never in
   bulk. A removal that relies on another rule (covered, deprecated with a
   successor, re-keyed) lands only after that rule reports the construct
   (Decision 2).
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
8. **A finding is labeled against the rule's written scope, never against
   intent** (amended 2026-09-25, Brandon). This holds for every
   disposition, including deterministic with review.
   - The disposition table row states the rule's checkable form: the
     construct it reports and the exceptions written into it, each with its
     source (the CERT text or its compliant examples).
   - A construct inside that scope is a violation, whether or not the author
     meant it. "Intentional" is not a label basis (ADR-0011). A reviewer
     who decides a candidate is acceptable suppresses it (ADR-0001). That
     judgment belongs to the project, and the oracle doesn't record it.
   - A guideline about understanding or intent gets its checkable form the
     way ISO/IEC TS 17961 builds one. The form presumes the risky reading
     and states its exceptions in the syntax of the code. TS 17961's rule
     against assignment in a controlling expression "makes the presumption
     that any use of = was intended to be ==", and its exceptions name
     code shapes, not intentions.
   - CERT marking a recommendation "Detectable: No" doesn't by itself make
     it unenforceable. The question is whether a checkable form exists whose
     violations are decidable. FLP00-C (floating-point limitations) is one:
     its checkable form is a floating-point `==` or `!=`, which several of
     the tools on CERT's own Automated Detection list report.
   - An exception that holds in every setting belongs in the row. One that
     only the default policy grants is a policy relaxation (ADR-0015).
   - Confirmed 2026-09-26 (Brandon): a "Detectable: No" recommendation that
     has such a checkable form ships as deterministic with review.
9. **The ruleset is CERT C, and each id means its CERT C guideline**
   (amended 2026-09-26, Brandon).
   - CERT C++ guidelines are out of scope for the CERT C ruleset. A rule
     shipped under a C++ id (for example an `FIO50-C` that is really CERT's
     `FIO50-CPP`) is removed as covered by its CERT C equivalent, after any
     better logic it has is ported to that rule. aurora-lint may carry a
     C++ ruleset one day; that would be a separate ruleset (ADR-0001), not
     C++ ids mixed into this one.
   - A check that isn't a CERT C guideline doesn't carry a CERT-looking id.
     It is renamed out of the CERT namespace or dropped.
   - A detector has to check the guideline its id names. A detector that
     checks a different guideline's construct is re-keyed to that
     guideline (its oracle rows move with it and are re-derived), and the
     id it left gets its own disposition like any other rule.
10. **A rule isn't dropped because CERT's examples contradict each other
    without research first** (amended 2026-09-26, Brandon). When CERT's
    compliant and noncompliant examples share one syntactic shape, any
    presumption reports one of them, which looks like "fails the
    criterion". But an example can simply be wrong, and the tools CERT
    lists or later research may have settled the guideline's checkable
    form anyway. So before such a rule is dropped, that evidence is
    gathered: how the listed tools check it, what ISO/IEC TS 17961 and
    MISRA C carry, and whether the conflict is a known error in CERT's
    page. If the rule is still dropped, the row records the inconsistency
    in CERT's own examples as the reason. That reasoning is worth
    publishing (Decision 6).

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
- Oracle rows labeled FP because the construct was "intentional" or
  "deliberate" rest on a rejected basis. They are re-derived against the
  rule's written scope (Decision 8).
