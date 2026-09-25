# 0014. The oracle is independent of the tool; TP, FP, FN and TN come from pairing it with a run

## Status

**Proposed. Draft for Brandon** (2026-09-25; the substance is his, stated
that evening). If accepted, change this line to "Accepted (Brandon,
<date>)".

## Context

The adjudication dataset stores verdicts as TP and FP, and the project has
talked about "TP labels" and "FP labels" for as long as it has had an
oracle. That vocabulary quietly ties each label to a finding aurora-lint
once produced. It has caused confusion as the tool improves:

- A finding the tool no longer reports still carries its old "FP" label.
  Is that label stale, wrong, or meaningless?
- A fix that removes a finding sitting on a line labeled "TP" looks like the
  label was wrong, when the tool was.
- Precision and recall get read as properties of the labels, when they are
  properties of one run measured against them.

## Decision

1. **The oracle is a statement about the code, independent of any tool.**
   For a pinned commit, each entry keyed `(project, commit, file, line,
   rule)` records whether the code at that place violates that CERT C rule
   as written, or doesn't. If aurora-lint didn't exist, the oracle could
   still exist. In principle one could take every line of a codebase and,
   for every rule, decide whether a static analyzer reporting that rule there
   would be right or wrong.
2. **TP, FP, FN and TN are defined only for a pairing of a run with the
   oracle,** and always for the rule the run reports:
   - **TP**: the run reports a violation of rule R, and the oracle says the
     code violates R there.
   - **FP**: the run reports a violation of rule R, and the oracle says it
     doesn't.
   - **FN**: the oracle says the code violates R there, and the run doesn't
     report it.
   - **TN**: the oracle says the code doesn't violate R there, and the run
     doesn't report it.
   Precision and recall are properties of the pairing, never of the oracle
   alone.
3. **The stored TP/FP vocabulary is kept for continuity** in Postgres and
   the public dataset. It means violation / not a violation. Renaming it
   would fork every historical row.
4. **Consequences of the pairing, stated so nobody reads them as label
   errors:**
   - A line the oracle marks "not a violation" that an older run reported
     (an FP then) and the current run doesn't report is now a **TN**. The
     tool improved.
   - A line the oracle marks "a violation" that an older run reported (a TP
     then) and the current run doesn't is now an **FN**. The tool lost a
     capability, or only appeared to have it (ADR-0005, right for the wrong
     reason).
   - Oracle entries on lines no run reports are not stale. They are the
     regression safety net. They are re-examined when a run reports the line
     again, not to keep up with new rulings.
   - An oracle verdict is revised only for the code's sake (a ruling that
     changes what counts as a violation, or a better reading of the code),
     never because a run changed.

## Consequences

- "The label flipped" and "the finding went away" are different events,
  and a changelog of the oracle (label churn) is separate from a
  comparison of runs.
- The oracle is only as complete as its adjudication. Lines no run has ever
  reported are mostly unadjudicated, so recall is measured against the
  violations the oracle knows about. That limit belongs in every recall
  figure's caveats.
- ADR-0007's clarification of what a label is follows this definition.
- A second tool's run can be scored against the same oracle, which is what
  makes cross-tool comparison on our corpora meaningful.
