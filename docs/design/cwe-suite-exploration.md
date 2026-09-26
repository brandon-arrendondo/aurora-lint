# Should aurora-lint grow a non-CERT CWE rule suite? (exploration)

**Status:** recommendation for Brandon, 2026-09-25.
The ADR references are to the set accepted at aurora-lint `72b8f734`.
Exploration only: no rules, manifests or mappings are changed. If the
answer is anything but "no", it becomes an ADR on the scope of the rule set,
followed by individual rule tasks.

**The objection under test:** "cppcheck can detect X, and aurora-lint can't."
The cppcheck `-j 1` re-run in the competitor comparison series added mostly `unusedFunction` (CWE-561).
tcb's mapping marks that check as having no CERT rule, so it counts in
cppcheck's raw and CWE columns but not in the CERT comparison.

**Mechanism** is not the question. `src/rules/brules/` already shows that a
second suite can sit next to `cert_c/` with its own manifest and rule ids, so
a `cwe/` suite would be opt-in and reported under its own ids by
construction. The question is **scope**.

## Recommendation

**No new suite now.** The evidence for one is almost empty:

1. **The objection is a mapping error, not a scope gap.** Every high-volume
   competitor check tcb calls "no CERT" has an honest CERT home, usually a
   *recommendation* that aurora-lint already implements and enables:
   - `unusedFunction` → MSC07-C. The CERT page lists CWE-561, and so does
     cwe.mitre.org's CWE-561 taxonomy row.
   - `unusedStructMember` → MSC12-C.
   - Frama-C's `_Bool` trap representation → EXP33-C (CERT UB annex row 12).

   Of the 89 competitor checks that tcb marks `nocert` or leaves unmapped,
   75 have a CERT id (71 strong, 4 weak).
2. **The true residue is four defect-class items, with almost no volume:**

   | Item | Source | Findings |
   |---|---|---|
   | Partially overlapping lvalue assignment | Frama-C | 7, one corpus |
   | `funcArgOrderDifferent` (CWE-683) | cppcheck | 4 |
   | Unlock of a lock not held (CWE-832) | Juliet only | no competitor fires |
   | Reference-count update (CWE-911) | CWE-658 only | no competitor fires |

   The first even has an arguable CERT home, MSC15-C ("Do not depend on
   undefined behavior"): the CERT UB annex row for it names no guideline.
   That is not enough to justify a suite, its manifests, its hook support and
   its oracle.
3. **What the objection actually exposes are two CERT-side defects.** Fix
   those instead:
   - **A detection gap in MSC07-C.** On Juliet `CWE561_Dead_Code` (2 files),
     aurora-lint's MSC07-C catches the code after `return`. It does not flag
     the file whose flaw is a `static` function that is never called, and no
     enabled rule does (a full-rule run on that file reports only an
     unrelated DCL40-C finding). cppcheck's `unusedFunction` catches that one
     and misses the other. This is a CERT MSC07-C recall task, not a CWE
     suite.
   - **Mapping errors on both sides.** tcb's `nocert` calls are listed below,
     and so are aurora-lint's own `data/rule_cwe_map.json` gaps (§4). These
     change the comparison tables in both directions, so they come before
     the comparison paper's numbers.

If Brandon wants a door left open, §5 gives admission criteria, so that a
later proposal for a CWE rule is judged against a written bar rather than
re-argued.

## Inputs

- **Competitor findings:** the latest bundle per (tool, target) in tcb's
  `runs/`, as of the competitor comparison series (48 bundles).
  - cppcheck 2.10: the `-j 1` re-runs, all 12 real-world corpora plus full
    Juliet.
  - clang-tidy 21.1.8: 12 corpora plus Juliet. Several corpora have large
    per-TU failure counts in `meta.json`, so their clang-tidy counts are
    lower bounds.
  - Infer 1.2.0 and Frama-C 33.0: the first Infer/Frama-C bundles. Three corpora ran with no
    compile database (0 TUs), and Frama-C's entry coverage is partial
    elsewhere. **those runs are stopped for review**, so treat those two tools'
    counts as provisional.
  - The six-CWE Juliet subset runs are excluded, since they duplicate the full
    Juliet runs.
- **Mappings:** tcb `mapping/*.json`; aurora-lint `rules_templates/rules-all.toml`
  (311 ids tracked, 307 enabled); aurora-lint `data/rule_cwe_map.json` (built
  from each rule TOML's `[references].cwe`).
- **Honest-mapping evidence:** every CERT C guideline page (306), CERT's
  undefined-behavior annex and MITRE-CWE back-matter pages, cwe.mitre.org
  (v4.20) definition pages, and the Frama-C 33.0 libc ACSL specs. The
  per-check working table (evidence URL, strength, counts) is kept as
  working data, not committed. Every row below can be regenerated from the
  pages named.
- **Local measurements** (Juliet CWE-561/563) use a local 0.5.3 release build
  and local cppcheck 2.10. They are **working data, not project figures**
  (ADR-0004), and must not be cited.

## 1. Mapping pass (tcb `nocert` / unmapped → honest CERT id)

These are tcb follow-ups (cert-c-tool-comparison). They change which column
a finding falls in, so they must land before the comparison paper's tables.

| Check | tcb says | Honest CERT id | Evidence | Real-world / Juliet findings |
|---|---|---|---|---|
| cppcheck `unusedFunction` | nocert | MSC07-C | CERT MSC07-C lists CWE-561; cwe.mitre.org CWE-561 → MSC07-C | 2003 (10 corpora) / 23768 |
| cppcheck `unusedStructMember` | nocert | MSC12-C (weak) | judgement: unused declaration | 187 / 72 |
| Frama-C `trap representation of a _Bool lvalue` | nocert | EXP33-C | CERT UB annex row 12 → EXP33-C | 80 / 0 |
| clang `optin.portability.UnixAPI` | nocert | MEM04-C | judgement (zero-size allocation) | 17 / 0 |
| clang `unix.StdCLibraryFunctions` | nocert | EXP37-C, EXP34-C, ARR38-C | cwe.mitre.org CWE-628 → EXP37-C | 2 / 0 |
| clang `core.FixedAddressDereference` | nocert | INT36-C | INT36-C lists CWE-587 | 1 / 0 |
| cppcheck dead/no-effect family: `unreachableCode`, `duplicateBreak`, `constStatement`, `selfAssignment`, `redundant*`, `identical*Condition*`, `comparisonError`, `incorrectLogicOperator`, `multiCondition` | unmapped | MSC07-C / MSC12-C / MSC00-C | CWE-561/570/571 rows; judgement | 49 / 2 (12 checks) |
| cppcheck `arrayIndexThenCheck`, `invalidTestForOverflow`, `badBitmaskCheck`, `assertWithSideEffect`/`assignmentInAssert`, `clarifyCalculation`/`clarifyCondition`, `*Address*Integer*` | unmapped | ARR30-C, INT32-C, EXP46-C, PRE31-C, EXP00-C, INT36-C | judgement / CERT page text | 40 / 0 (9 checks) |
| clang `security.PointerSub`, `unix.Errno` | unmapped | ARR36-C, ERR30-C | CWE-469 → ARR36-C (Exact) | 8 / 0 |
| Frama-C `precondition of <libc fn>` (41 callees) | unmapped | STR32-C, ARR38-C, EXP34-C, FIO46-C, POS54-C… | the callee's ACSL `requires` clause | 106 / 324 |

Genuinely no CERT id, and not a defect in C: C++-only checks
(`virtualCallInConstructor`, `cstyleCast`, `noExplicitConstructor`,
`cert-msc54-cpp`, …), tool diagnostics (`syntaxError`, `unknownMacro`,
`preprocessorErrorDirective`, `internalAstError`), and two performance or
style checks (`optin.performance.Padding`, `useStandardLibrary`).

**Two tcb mechanism notes:**
- **Frama-C:** Frama-C's alarm text names the failing clause (`valid_stream`,
  `valid_fd`, `valid_read_string`, `buf_has_room`). Keying tcb's pattern on
  the clause instead of the callee would map the mixed-contract callees that
  tcb currently leaves unmapped for that reason.
- **Juliet's `unusedFunction` count is a harness artifact.** All 23,768 of
  cppcheck's Juliet `unusedFunction` findings are test-case entry functions
  (14,290 `good`, 9,478 `bad`). Juliet calls these only under `INCLUDEMAIN`,
  so they measure nothing. A table that counts them as detections, or as FPs,
  misstates cppcheck either way. Exclude them, or scope CWE-561 to the Juliet
  `CWE561_Dead_Code` directory.

## 2. Two-way coverage matrix (checkbox level)

| | CERT ids |
|---|---|
| aurora-lint enables | 307 (127 rules, 180 recommendations) |
| Fired by at least one competitor in the comparison bundles | 49 (36 rules, 13 recommendations) |
| Fired by a competitor but not enabled in aurora-lint | **0** |
| Enabled in aurora-lint, fired by no competitor | 258 (91 of the 127 rules) |

Competitor-fired recommendations: ARR01, CON05, DCL00, DCL01, DCL03, DCL16,
DCL19, INT02, INT09, MEM05, MSC12, MSC13, MSC24.

Per tool, fired CERT ids: cppcheck 25, clang-tidy 28, Frama-C 17, Infer 5. The
checkbox matrix therefore runs one way only. There is no CERT id a competitor
reports that aurora-lint lacks. §1's remaps add MSC07-C, EXP33-C, MEM04-C,
ARR36-C, ERR30-C, FIO46-C and POS54-C to the competitor side, and all of them
are enabled in aurora-lint.

**This is a checkbox, not a measurement.** Two cells matter for the
objection, and they need a detection rate next to them:

| Juliet dir (not in `juliet_cwes.txt`) | Tool | Files with a bad-block finding | Files with a good-block finding |
|---|---|---|---|
| CWE561_Dead_Code (2 files) | aurora-lint MSC07/12/13-C | 1 (code after return) | 0 |
| | cppcheck 2.10 (style + unusedFunction) | 1 (unused static function) | 0 |
| CWE563_Unused_Variable (366 files) | aurora-lint MSC07/12/13-C | 287 | 114 |
| | cppcheck 2.10 (style) | 297 | 215 |

Local runs, scored by Juliet's OMITBAD/OMITGOOD blocks, which is the guide's
function-level unit. Not citable. They show the two tools are complementary
on CWE-561 and comparable on CWE-563, which is the honest answer to "cppcheck
detects X". A citable version needs `CWE561_Dead_Code` and
`CWE563_Unused_Variable` added to tcb's Juliet list, since both are C-bearing
and one tool claims each.

**Proposed `tcb table` (safe under ADR-0007: aggregate counts only).** Rows
are CERT ids and CWE ids, and columns are tools. Each cell says one of:
- mapped and measured (Juliet flaw-hit %, real-world labeled precision where
  labels exist);
- mapped but not measured;
- not mapped.

## 3. Gap list, ranked by competitor firing

After §1, what fires and still has no CERT rule or recommendation:

| Rank | Item | Tool | Real-world | Juliet | Class |
|---|---|---|---|---|---|
| 1 | partially overlapping lvalue assignment | Frama-C | 7 (1 corpus) | 0 | defect (arguably MSC15-C) |
| 2 | `funcArgOrderDifferent` (CWE-683) | cppcheck | 4 (3 corpora) | 0 | defect (DCL40-C covers incompatible types, not swapped names) |
| — | `optin.performance.Padding` | clang-tidy | 3 | 0 | performance |
| — | `useStandardLibrary` | cppcheck | 1 | 0 | style |

**Juliet CWEs with no CERT guideline.**
- `juliet_cwes.txt` (the 17 CWEs every tool runs): every one has a CERT id.
- Across all 118 Juliet directories, 34 had no CERT id in aurora-lint's
  `rule_cwe_map`. On honest mapping:
  - 17 map to a CERT id aurora-lint enables. All 17 are `rule_cwe_map` gaps:
    CWE-196→INT31-C, 400→INT04-C/MEM11-C, 427→ENV03-C, 475→EXP43-C,
    478→MSC01-C, 483→EXP19-C, 484→MSC17-C, 588→EXP39-C, 606→INT04-C,
    617→MSC11-C/ERR06-C, 688→FIO47-C, 785→ARR38-C/STR31-C, 90→STR02-C, plus
    four weak ones (284, 390, 835, and 256, which maps to MSC18-C, one of the
    four disabled ids).
  - 15 are security-policy or design weaknesses that no C coding standard
    covers: plaintext password, trapdoor, logic bomb, info exposure,
    RSA-without-OAEP, multiple binds, and so on.
  - 2 remain: CWE-546 (suspicious comment, style) and **CWE-832** (unlock of a
    resource not locked, defect; POS48-C covers unlocking another thread's
    mutex, not a never-locked one).

**CWE Top 25 (2025) cross-check.** Honestly mapped, a CERT id exists for:
- 787 (#5) → ARR30-C/ARR38-C/STR31-C, *missing from `rule_cwe_map`*;
- 22 → FIO02-C;
- 416 → MEM30-C;
- 125 → ARR30-C;
- 78 → ENV33-C/STR02-C;
- 77 → STR02-C, by judgement;
- 120, 121, 122 → ARR38-C/STR31-C;
- 476 → EXP34-C;
- 20 → API00-C and others;
- 770 → MEM11-C.

The rest are web, authorization or design weaknesses that are not C-coding
defects: 79, 89 (see §4), 352, 862, 94, 434, 502, 863, 284, 200, 306, 918,
639. None of them is a candidate for a C static-analysis rule suite.

**CWE-658 ("Weaknesses in C") cross-check.** Of its 103 members, 63 have a
CERT id in `rule_cwe_map`. Of the other 40:
- 31 map honestly, including CWE-787, 788, 822, 823, 825, 910 → FIO46-C
  (cwe.mitre.org: *Exact*), 1335 → INT34-C and 1341 → MEM30-C.
- 8 are OO, design or Windows-driver weaknesses.
- 1 (CWE-911, reference counting) is residue.

## 4. aurora-lint's own `rule_cwe_map.json` needs a pass

This is a CERT-side finding. It affects Juliet CWE-matched scoring, which
uses this map to decide which rules count for a Juliet directory.

- **Missing references.** Honest CERT ids for 40 distinct CWEs are absent
  from the rules' TOML `[references].cwe`:
  - the 17 Juliet pairs above;
  - the 31 CWE-658 members (8 of them overlap with the Juliet 17);
  - notably CWE-787 on ARR30-C, ARR38-C and STR31-C.
- **Boilerplate entries that inflate coverage.** ERR07-C, MEM10-C and MSC24-C
  carry CWE-20/79/89/91/94/114/601. The references were copied faithfully:
  all three CERT pages list that same block. But:
  - none of the three guidelines is about injection;
  - cwe.mitre.org lists no CERT C mapping for 79, 89 or 94;
  - CERT's own MITRE-CWE back-matter page says the information "was provided
    by outside contributors and has not been verified by SEI CERT" (checked).

  As a result, those three rules' findings can be credited to injection CWEs.
- **Our own additions to label as ours.** STR02-C's CWE-89 is aurora-lint's
  addition, and a defensible one: the page lists only CWE-78/88, but its
  Automated Detection table names SQL-injection checkers. MSC24-C adds
  CWE-242/119 and omits CWE-114. MSC12-C lists CWE-398/561, while its page
  lists none. The map should distinguish CERT-listed from
  aurora-lint-judged references.
- **Proposed:** add a `related_cwe` field (CERT-listed but not a real mapping)
  next to `cwe`, and apply the honest pairs. That is a code change with a
  Juliet re-measurement, so it is its own task, sequenced like any change to
  scoring.

## 5. Admission criteria, if a `cwe/` suite is ever opened

A proposed CWE rule is admitted only if all of these hold:

1. **No CERT rule or recommendation covers it**, after an honest-mapping pass
   like §1. Neither CERT's pages nor cwe.mitre.org is complete: most C
   recommendations list no CWE, and cwe.mitre.org 4.20 names a CERT C id on
   only about 26 of about 160 C-relevant pages. So "no row" is not evidence
   of "no rule", and a judgement mapping needs a human reviewer.
2. **It is a code defect in C.** Not C++-only, not a tool diagnostic, not a
   style or performance preference, and not a security-policy or design
   weakness (CWE-259/510/780-style) that no source-level C rule can decide.
3. **Evidence from the gap list:** a competitor fires it on in-scope corpora,
   or it has a Juliet directory, with counts stated. For a defect class no
   competitor fires on, a hand-written fixture showing the construct.
4. **ADR-0013's shipping criterion applies unchanged.** ADR-0013 (accepted at
   `72b8f734`) says "the same criterion governs any new rule, CERT or not".
   A candidate needs a disposition (Deterministic, Deterministic with review,
   or Environment-gated), must be able to find a true violation, and must
   not be structurally FP-dominated. One that would land in "fails the
   criterion" is not implemented.
5. **Labels before any precision claim** (CLAUDE.md protocol 6), on the same
   `(project, commit, file, line, rule)` oracle, under the suite's own rule
   ids.
6. **Reporting stays separate by construction.** CERT conformance and
   CERT-comparison tables stay CERT-only. The suite gets its own table
   column, and its ids never appear in a CERT figure.
7. **Manifests.** `check-realworld-manifests` today knows only `cert_c`
   blocks. Before the first `cwe/` rule, extend the hook so every
   `conf/realworld/*-rules.toml` decides each suite rule explicitly. Until a
   rule has labels there, it starts **disabled** in the real-world manifests,
   which the hook would otherwise not allow. That is a suite-level exception
   that needs writing into `conf/realworld/README.md`.

**The four residue items against these criteria:**
- CWE-683 argument-order swap: passes 1–3 and is a plausible first candidate.
- CWE-832 unlock-not-locked: passes 1–2. For 3 there is a Juliet directory,
  with Windows-heavy cases.
- The overlapping-assignment UB: fails 1 if MSC15-C is accepted as its home,
  in which case it is a CERT MSC15-C extension instead.
- CWE-911 refcount: passes 1–2 and fails 3 (nothing fires).

None of them is worth a suite today.

## Follow-ups this exploration proposes (for the coordinator to file or not)

1. **tcb mapping:** apply §1, including the Frama-C clause-keyed patterns and
   excluding Juliet entry-function `unusedFunction`, before the comparison paper's tables
   (cert-c-tool-comparison).
2. **tcb Juliet list:** add `CWE561_Dead_Code` and `CWE563_Unused_Variable`.
3. **aurora-lint MSC07-C:** flag a never-called `static` function (the
   Juliet CWE-561 FN). This is a recall change with a Juliet re-run, and
   delta-adjudication before any precision claim.
4. **aurora-lint `rule_cwe_map`:** apply §4 (`related_cwe`, missing pairs,
   boilerplate), then re-measure Juliet CWE-matched scoring.
5. **No ADR for a `cwe/` suite now.** Keep §5 as the bar if the question
   returns.
