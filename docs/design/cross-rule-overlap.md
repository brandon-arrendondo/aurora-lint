# Cross-rule overlap: policy and decision

**Status:** DECIDED (2026-08-27, task 625). Rollout DONE (2026-08-30, task 626).

## Rollout (task 626)

`[references] related = ["RULE-ID", ...]` (the sketch's default-outcome field)
is now populated in 27 rule TOMLs: the top measured co-located/disagreement
pairs from task 625's canonical queries, minus two clusters deliberately
excluded from this pass because they trace to a different root cause than
overlap —

- Every `API00-C`-anchored pair (587+ co-located lines): confirmed
  location-coincidence (both rules anchor to the same line for unrelated
  reasons), tracked as task 628. Re-run the co-location query after 628 lands
  before deciding whether any `API00-C` pair is genuine overlap.
- Every `MSC24-C`-anchored pair other than `STR31-C`/`STR32-C` (this doc's own
  counterexample): 97% of `MSC24-C`'s FPs trace to two rule-content bugs
  (task 629), which inflate its disagreement counts with other rules
  independent of genuine overlap. `MSC24-C`/`STR31-C`(+`STR32-C`) is kept
  since it's the flagship validated example above, not a task-629 symptom.

Tagged pairs (all `related`, none cleared the `defers_to` bar):
`ARR00-C`↔`ARR30-C`, `ARR38-C`↔`INT32-C`, `CON33-C`↔`CON34-C`,
`DCL15-C`↔`DCL19-C`, `ENV01-C`↔`MEM05-C`, `ERR00-C`↔`ERR33-C`,
`ERR07-C`↔`ERR34-C`, `INT13-C`↔`INT14-C`, `INT14-C`↔`INT34-C`,
`MSC24-C`↔`STR31-C`/`STR32-C`, and the `PRE00-C`/`PRE01-C`/`PRE02-C`/
`PRE10-C`/`PRE12-C` macro-hygiene cluster (all pairwise — CERT's own
macro-authoring recommendations naturally co-fire on the same badly-written
macro).

The `defers_to`+`rationale` schema (declared exceptions) exists in this doc's
sketch but was **not instantiated for any pair** — re-examining the 5 known
ad-hoc deference sites against this bar (below) found none of them clear it.
All 4 cross-rule sites were reclassified `related` (not `defers_to`) with
their code comments updated to point here; the 5th (`MEM30-C`'s own comment)
is intra-rule traversal-path dedup — the same rule would emit the literal
same finding twice via two internal code paths without it — not a cross-rule
policy matter, and was left as a code comment only.

No detection-behavior change shipped in this rollout (no rule's matched-call
list, type classification, or emitted violations changed) — `related` is
purely informational metadata, so no delta-adjudication is triggered by it.
The three no-op stubs among the 4 reclassified sites (`ARR38-C`'s
`check_unbounded_string_function`, `ERR33-C`'s excluded math-function list,
`INT08-C`'s excluded `int` type) remain no-ops; un-suppressing any of them
later **would** be a detection-behavior change requiring delta-adjudication,
and each updated comment says so.

## Policy

**Default: rules are allowed to overlap. Two rules independently firing on the
same defect is not a bug and does not need fixing.**

Suppressing one rule in favor of another is the exception, and requires a
written, evidence-backed case that the suppressed rule adds **zero**
information in **every** instance — not just most of them. Absent that case,
both findings are reported, optionally tagged as related so a downstream
consumer (a report, the paper's aggregate counts, a human triager) can choose
to collapse them, but sqc itself never hides one on the other's say-so.

This rejects decision option (3) from task 625's scoping ("central dedup at
aggregation, keep the higher-precedence rule") as a *general* mechanism. It
does not rule out a declared exception for a specific pair that clears the
bar below — but that bar is high enough that most candidate pairs will not
clear it, and CERT-C's own two-layer structure (rules vs. broader
recommendations covering the same defects) means overlap is expected, not
incidental.

## Why: the STR31-C / MSC24-C counterexample

Task 625's measurement (`docs/design/` — see appendix below for the full
query results) found 215 ground-truth-labeled lines where `MSC24-C` and
`STR31-C`/`STR32-C` disagree — and the disagreement runs **both directions**:

- `MSC24-C: TP` / `STR31-C: FP` (184 cases, e.g. lua's `lobject.c:521` —
  `strcpy` writes a `...` truncation ellipsis; STR31-C proves the specific
  call is buffer-safe given the codebase's invariants, but `MSC24-C` bans
  `strcpy` categorically per CERT's own rationale: a proof that holds today
  can break silently under maintenance).
- Elsewhere in the same overlap graph, the reverse also happens: a
  provably-unsafe-today call is a case where the buffer-safety rule is the
  one carrying the real signal and the categorical ban is comparatively
  uninteresting.

Neither rule is wrong. `MSC24-C` is answering "is this function banned by
policy, independent of this call site's apparent safety?" `STR31-C` is
answering "is this specific call's buffer math provably safe?" Those are
different questions a user can legitimately want answered, and **no static
precedence order resolves both directions correctly** — a hard-coded
"STR31-C wins" rule would wrongly suppress the 184 cases where the ban is
what mattered; "MSC24-C wins" would wrongly suppress the reverse cases
elsewhere in the corpus. This is the concrete case that rules out option (3)
as a default.

### A counter-lesson from the same investigation: not everything that looks
### like overlap is overlap

Digging into the two largest disagreement clusters before writing this
policy surfaced two *different* failure modes that are easy to mistake for
"cross-rule overlap" but are not:

1. **Location coincidence, not semantic overlap.** `API00-C` (missing
   NULL-check) and `DCL13-C` (missing `const`) co-locate on 587+ lines
   purely because both anchor to the same source line for unrelated reasons
   — `API00-C` reports at the function's declaration line, `DCL13-C` reports
   at the parameter's declaration line, and for a single-line signature
   those are the same line number. The two rules are not judging the same
   defect; they happen to point at the same line. Task 628 tracks this as an
   `API00-C`/`API05-C` precision problem, not an overlap-policy problem.
2. **One rule's own content bug masquerading as disagreement.** 97% of
   `MSC24-C`'s ground-truth false positives (61 of 63) trace to two concrete
   bugs: it bans `sscanf` (not actually on CERT's obsolescent-function list)
   and it doesn't consult dead-`#ifdef`-branch exclusion the way other rules
   do. Those inflate the raw `MSC24-C` vs. other-rule disagreement counts
   without reflecting a genuine two-valid-judgments case. Task 629 tracks
   the fix. Only the `STR31-C`/`STR32-C` slice of `MSC24-C`'s disagreements
   is the real overlap case this policy is about.

**Practical implication:** before treating any co-located pair as a policy
question, rule out (a) coincidental line-anchoring and (b) one side's own
detection bug. Only what's left after that triage is a genuine overlap
candidate.

## When an exception is justified

A suppression/deference exception for a specific ordered pair `(A defers to
B)` needs all of:

1. **A stated defect concept** both rules target — not just frequent
   co-location. ("Both flag the same string-copy call" is not a concept;
   "both are the codebase's only two mechanisms for catching X" is.)
2. **Empirical evidence of total subsumption**: every ground-truth-labeled
   instance where `A` fires, `B` also fires with the same verdict, across
   every project sampled — not a majority, not "the cases we happened to
   check." If even one instance shows `A` catching something `B` misses (or
   vice versa), it's not subsumption, it's overlap, and the default applies.
3. **A rationale for the direction** (why does `B` dominate `A` and not the
   reverse?) written down next to the exception, not left to be inferred
   from which rule happened to be authored second.
4. **A re-check trigger**: subsumption argued today can stop holding once
   either rule's detection logic changes. The exception's rationale should
   name what would invalidate it (e.g. "if `STR31-C` ever fires without a
   proof of safety, or `MSC24-C`'s ban list changes, re-verify").

Re: the five pre-existing ad-hoc deference comments (task 625's inventory) —
only two have any ground-truth-labeled co-located data at all
(`ARR38-C`→`STR31-C`: 8 labeled lines, all agree-FP; `INT08-C`→`INT32-C`: 16
labeled lines, all agree-FP), and even those samples are far too thin to
claim subsumption under bar #2 above — 8-16 lines is not "every instance."
`MSC14-C`→`INT13-C` and `ERR33-C`→`FLP32-C` have **zero** labeled co-located
data. **None of the five clear this bar today.** They should not be treated
as validated; task 626 should re-examine each with either more targeted
sampling or an argument from the rules' own detection logic (not just "no
counterexample found yet in a sample this small").

## Where the relationship is recorded

Sketch only — task 626 owns the actual schema and rollout:

- **Related-but-independent** (the default outcome for any measured overlap,
  e.g. `MSC24-C` / `STR31-C`): a `[references] related = ["RULE-ID", ...]`
  field in both rules' TOML, populated from task 625's measurement query and
  extended as new pairs are found. Informational only — does not change
  detection or aggregation. Whether this is hand-maintained or ingested from
  CERT's own "Related Guidelines" wiki cross-reference (task 625's
  unverified note — worth checking before hand-building the initial list)
  is task 626's call.
- **Declared exception** (rare, must clear the bar above): a distinct field,
  e.g. `[references] defers_to = "RULE-ID"` with a `rationale` string
  required alongside it, so `defers_to` without a rationale is a schema
  violation, not a silent default. The aggregation path only ever collapses
  findings for pairs with an explicit `defers_to` — never as a fallback for
  merely-related pairs.

## Rule-author workflow (pre-implementation check)

Before writing a new rule, alongside the existing `internal-capability-catalog.md`
and macro-expansion checks already required by this file's Rule
Implementation section:

1. Check whether the new rule's CWE mapping or defect concept already
   overlaps an enabled rule (search `rules_templates/rules-all.toml`
   descriptions and `docs/design/internal-capability-catalog.md`).
2. If it does, that is expected, not a reason to skip implementation or to
   silently suppress either rule. Default to letting both fire.
3. Only propose a `defers_to` exception if you can produce the evidence
   required above. If you can't, add the pair to the `related` list instead
   (or leave it for task 626/the next overlap measurement pass to record —
   don't block a new rule's landing on doing the bookkeeping yourself).

## Measurement appendix (task 625, 2026-08-27, bench node)

Real-world (sqc, latest run, all 8 oracles): 8,254 / 52,790 flagged locations
(15.6%) share a `(project, file, line)` with a different rule. Of the
20,366 ground-truth-labeled co-located pairs, 17,420 agree and 2,946 (14.5%)
disagree.

Juliet (fast-mode, full run): 1,558 / 23,068 (6.75%) co-located — lower than
real-world's 15.6%, consistent with fast mode only enabling CWE-relevant
rules per scan, which suppresses some overlap as a benchmark artifact rather
than a real-world signal.

Top overlapping pairs and top disagreement pairs are reproducible via the
canonical queries in task 625's own record (`todo-sqlite-cli show 625`) —
not duplicated here to avoid drifting out of sync with a live re-run.
