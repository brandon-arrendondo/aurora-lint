# ADR external alignment: what CERT, comparable tools and the literature do on the same questions

**Status:** research input for Brandon (aurora_lint 1574, part c), 2026-09-25; revision 2 against the ADRs accepted at `72b8f734`.
Nothing here changes an ADR. Every "amend" below is a proposal to rule on.
Parts (a) internal consistency and (b) clarifications are the coordinator's,
in `docs/design/adr-review-2026-09.md`. This doc is the external half they
cite.

**Scope.** The first pass (sections D, P and E) read ADR-0001..0011 as of
`f7b21113`, proposed ADR-0012 (branch `docs-finding-location-1572`, whose
research in `docs/design/finding-location.md` is reused and not repeated), and
the labeling rulings made since 2026-09-24 that no ADR recorded yet
("standing calls", paraphrased here as S-items). **Revision 2** (after the Summary)
re-reads the set as accepted at aurora-lint `72b8f734`. That set adds amended
0005/0006/0007/0010/0011 and the accepted 0012, 0013 and 0014. Revision 2
says which findings the amendments resolve and assesses the new decisions.
Where it and sections D/P/E disagree, Revision 2 is current.

**Method.** Three research passes, each over one cluster of decisions. Primary
sources were fetched and grepped where possible (CERT wiki pages, N1570,
vendor docs, NIST reports, papers). Before synthesis, about 40 of the quotes this
doc relies on were re-fetched and matched verbatim by a separate check. Any
claim that rests on a summarizing fetch or on memory is marked
**unverified**. MathWorks (Polyspace) pages block scripted fetches, so
Polyspace quotes come through a summarizing fetch. One of them (the
`-main-generator-calls` default) was re-checked the same way.

**Verdicts.**

| Verdict | Meaning |
|---|---|
| aligned | CERT, tools or literature do the same thing |
| stricter-and-defensible | we report or label more, and a citable basis exists |
| stricter-and-exposed | we report or label more, and a referee could reasonably attack it |
| looser | we accept something others would not |
| novel | no external precedent either way |

---

## Summary

| # | Decision | Verdict | Action |
|---|---|---|---|
| D1 | ADR-0001 report as written; suppression is configuration; golden rule | stricter-and-defensible | clarify: name the product class; a suppression is a CERT deviation and the row stays TP |
| D2 | ADR-0002 0% TP ≠ unneeded; 1523 shipping criterion | stricter-and-defensible | amend: make "always FP-dominated" operational; separate "shipped" from "on by default" |
| D3 | ADR-0005 misfire vs judgment FP | aligned | clarify: rename "judgment FP"; under CERT and SATE it is a TP |
| D4 | ADR-0006 resolve to declarations; silence if unresolved | aligned | clarify: name the soundiness trade-off; fix the sound/complete terminology |
| D5 | ADR-0008 no ERROR-ancestry gate | aligned | none (publish the measurement) |
| D6a | ADR-0010 every compilable arm is labeled | stricter-and-defensible | clarify: labels follow the all-configs model, denominators follow the build-capture model |
| D6b | ADR-0010 one stated primary configuration per oracle | aligned | (already required: declare it per corpus) |
| D7a | ADR-0007 extended detail gated until the fix lands | aligned | none |
| **D7b** | **ADR-0007 keys, verdicts and label-basis reasons published whatever the reporting status** | **looser** | **amend for security-class rules: notify first or embargo** |
| D8a | ADR-0004 Postgres single source of truth | aligned | amend: archive a public snapshot behind each published figure |
| **D8b** | **ADR-0009 only Added/Fixed/Removed** | **stricter-and-exposed** | **amend: restore Deprecated; Changed for breaking changes; Security for aurora-lint's own vulnerabilities** |
| D9 | ADR-0003 utility layer vs substrate | novel (internal) | none |
| P1 | ADR-0011 proof-basis ladder | stricter-and-defensible | clarify: scope config ≠ ABI proof; pin the ISO edition |
| **P2** | **ADR-0010 D5 / S: `NDEBUG` asserts are not guards** | **stricter-and-exposed** | **fix a miscitation; address EXP34-C's own compliant solution; report assert-dominated rows as a sub-class** |
| P3 | S: open caller sets (libraries, `-rdynamic`, "could be callable") | stricter-and-defensible | clarify: record per corpus which build exports what |
| P4 | ADR-0011: checks made by every caller count | aligned | clarify: which rules it applies to |
| **P5** | **ADR-0011: a proof chain must end in a real proof** | **stricter-and-exposed** | **amend: link the dependent callee row to its caller row, and score both ways** |
| P6 | S: callee postconditions; absent generated callers | aligned | clarify: longjmp/macro error paths; per-arm |
| P7 | S: `&p->field` with p unproven is TP | aligned | cite EXP34-C-EX1 by name |
| P8 | S: `(ptr, len)` is an informal contract | stricter-and-defensible | clarify: SAL / GCC `access` are basis 4 too |
| P9 | S: integer widths | stricter-and-defensible | clarify: `CHAR_BIT == 8` is not ISO |
| **P10** | **S: `_Noreturn` alone is no proof** | **stricter-and-exposed** | **amend: accept ISO `_Noreturn` for the caller and flag a callee that can return; keep `__attribute__((noreturn))` at basis 4** |
| P11 | S: report the first dereference | aligned | clarify: a redundant later check alone is not proof of nullability |
| P12 | S: correlated flags | aligned | clarify: struct-field / global correlation, aliasing through a call |
| P13 | S: `main`'s argv; static zero-init | aligned | none |
| E1 | proposed ADR-0012 finding sites | stricter-and-defensible (the opaque-callback consequence alone: stricter-and-exposed) | amend: define "use" for a pure pass-through, or report that sub-class both ways |
| **E2** | **S: labels describe the code; non-emitted keys not re-adjudicated** | **stricter-and-exposed** | **amend: re-adjudicate non-emitted TP/FN keys a new ruling touches; add a line-tolerance sensitivity score; split recall by FN provenance** |
| E3 | ADR-0010 D6–7 one oracle per configuration | aligned | clarify: rename to "primary platform profile"; say how off-platform *arms* in in-scope files are excluded |
| E4 | CLAUDE.md protocol 6: delta-adjudicate before citing | aligned | clarify: publish labeled coverage per rule; if sampled, random-stratified with a CI |
| **E5** | **labels produced mostly by LLM agents** | **looser** | **amend: a blinded human re-label sample with kappa/alpha; an independent second model; provenance on every label** |
| E6 | ADR-0002: Juliet for detection, real-world for noise | aligned | clarify: real-world is also a recall signal; state per-rule Juliet coverage and the scoring unit |

The shape of the result: **most decisions align, or are stricter for reasons CERT
itself gives.** The recurring gap is not the decisions but their
**presentation**. aurora-lint is a *conformance checker* measured with
bug-finder vocabulary (precision, FP), so every place where we are stricter
than Coverity, Infer or Clang SA reads as an FP-rate problem unless the ADR
says up front that the product class differs. Adding one paragraph to
ADR-0001 (D1) removes most of the "stricter-and-exposed" pressure. The eight
bold rows are where outside practice argues for a real amendment.

Two of them matter more than the rest because they reach every published
real-world figure, not one rule:

- **E5 (LLM labels).** No surveyed evaluation uses LLM verdicts as the oracle
  without a *measured* human-agreement figure.
- **E2 (the recall denominator).** It can carry labels made under rulings
  since overturned.

Both have cheap, standard fixes. Doing them before the paper is submitted
costs much less than answering them in review.

---

## Revision 2: the ADR set as accepted at `72b8f734`

### What the amendments did to the first-pass findings

| First-pass item | Now | Where |
|---|---|---|
| P1: separate "the configuration fixes the denominator" from "its ABI is not proof" | **resolved** | 0010 D8: the primary configuration "guides the benchmark; it never proves anything" |
| P3: "could be callable" is judged over every compilable config | **resolved** | 0010 D8 (reach uses every configuration); 0011 settled case "anything that could be publicly callable is an API" |
| P7: `&p->field` | **resolved** (still worth citing EXP34-C-EX1, whose exemption list is exactly `&*x` and `&x[y]`) | 0012 D6 |
| P11: first site of failure | **resolved** | 0012 D5 |
| P13, P6, P8, P9, P12: settled cases | **recorded** as written; the P6/P8/P9/P12 clarifications stay open | 0011 "Settled cases" |
| D4: silence when unresolved as a soundiness choice | **largely resolved**: silence is now scoped to *identity*; safety uncertainty reports | 0006 "Two kinds of uncertainty" |
| D2: operational shipping criterion; shipped vs on-by-default | **largely resolved** by dispositions (see R1 below); one clarification open | 0013 |
| E1: ADR-0012 | **accepted as drafted**; the opaque-context consequence (option A/B) is still open | 0012 Consequences |
| E2: labels describe the code | **vocabulary resolved**, and the incompleteness caveat is now required on every recall figure. The stale-ruling point is **still open, and now sharper** (R2) | 0014, 0007 |
| E6: Juliet scoring unit | **partly resolved**: 0005 says Juliet is section-scored. `bench/analyzer.py` scores by FLAW line ±1, so say which unit each figure uses | 0005 |
| P2: the ADR-0010 Context sentence "API00-C's own standard holds that an `assert()` is not a parameter guard" | **still open.** The CERT API00-C page mentions neither `assert` nor `NDEBUG` (re-checked), so the sentence reads as a CERT citation that isn't one. Reword it to "the project's API00-C labeling standard", or cite MSC11-C and C11 7.2p1 | 0010 Context |
| P2 assert sub-class; P5 double counting; P10 `_Noreturn`; D1 conformance-checker paragraph; D3 rename; D7b; D8a; D8b; E3; E4; E5 | **open**, unchanged by the amendments | — |

### New decisions in the accepted set

#### R1 — ADR-0013: which rules ship (nature, not counts; five dispositions)

- **Theirs:**
  - ISO/IEC TS 17961 states essentially 0013's criterion: "All rules are
    meant to be enforceable by static analysis. The criterion for selecting
    these rules is that analyzers that implement these rules must be able to
    effectively discover secure coding errors without generating excessive
    false positives" [CERT-17961] (checked).
  - MISRA C:2012 classifies every guideline as decidable or undecidable, and
    as a rule or a directive [MISRA-blog, vendor source]. That is the same
    idea as 0013's Deterministic / Deterministic-with-review split.
  - Removing a rule (not disabling it) and publishing why is unusual. Vendors
    publish which CERT rules they support, not reasons for the ones they
    don't.
- **Verdict: aligned** with TS 17961 and MISRA on the criterion. Publishing
  the unshipped rules with reasons is **novel**, and a strength for a paper.
- **Clarify:** the "Unenforceable" disposition says "CERT itself says the
  guideline can't be checked automatically". CERT's per-rule **Detectable**
  column does *not* mean that. It asks "Can a static analysis tool
  automatically determine if code violates this guideline **with high
  accuracy and precision**?" [CERT-org] (checked). Many rules aurora-lint
  already detects well carry "Detectable: No"; ARR38-C and API00-C are two.
  If Detectable = No were read as "unenforceable", it would drop working
  detectors, which 0013 D3 (Juliet-covered ships) and ADR-0002 forbid. State
  that the disposition rests on CERT's *text* saying the guideline is not
  automatable, or on a decidability argument, never on the Detectable column
  alone.

#### R2 — ADR-0014: the oracle is independent of the tool

- **Theirs:**
  - Tool-independent ground truth is the norm: Juliet's flaw manifests,
    OWASP's expected-results file, SATE's CVE locations [Juliet-UG;
    OWASP-BM; SATE-IV]. The *semantic* definition is **aligned**, and the
    TP/FP/FN/TN-per-pairing framing is standard confusion-matrix practice.
  - Stating the oracle's incompleteness on every recall figure matches SATE
    IV's own caveat that it "could not credit tools" with vulnerabilities it
    did not know about [SATE-IV].
- **Exposed: independence of meaning is not independence of construction.**
  0014 says the oracle "covers the lines runs have reported plus the known
  misses". The lines *chosen* for labeling were chosen by aurora-lint's runs.
  That costs nothing when scoring aurora-lint against itself over time. It
  matters for 0014's last consequence, "a second tool's run can be scored
  against the same oracle".
  - A competitor's findings on lines aurora-lint never reported are mostly
    unlabeled, so they fall out of its precision denominator.
  - Its true detections there cannot count as TPs.
  - Its recall is measured against violations aurora-lint found.

  This is the classic pooling bias from IR evaluation: judgments built only
  from some systems' outputs favor those systems (Zobel, SIGIR 1998; Buckley
  et al., Information Retrieval 2007; **unverified** here, full texts not
  fetched). A referee of the tool-comparison paper will raise it.
  - **Shore-up:** before cross-tool figures, adjudicate a random sample of
    each competitor's *unlabeled* findings (the pool-deepening remedy).
    Report the labeled fraction of each tool's output next to its precision.
- **Still open (E2, sharper now):** 0014 D4 says an oracle verdict is revised
  "for the code's sake (a ruling that changes what counts as a violation…)",
  and also that entries no run reports are re-examined "when a run reports
  the line again, not to keep up with new rulings". For recall these pull in
  opposite directions: a non-emitted *violation* entry whose basis a later
  ruling overturned stays in the recall denominator unexamined. Proposed
  reading, for Brandon to rule on:
  - non-emitted **not-a-violation** entries wait until a run reports them;
  - non-emitted **violation** entries (which drive recall) are re-examined
    when a ruling changes their stated basis.

#### R3 — ADR-0011 basis 1 now includes ISO C and POSIX library contracts

- **Theirs:** every surveyed analyzer models libc by its specification:
  - Frama-C's libc ACSL `requires` clauses [FC-assert];
  - Clang SA's `unix.StdCLibraryFunctions`;
  - Polyspace's standard-library stubs.

  CERT itself cites the standard's library clauses in its rules (EXP34-C's
  `memcpy` case) [EXP34-C].
- **Verdict: aligned.** The "stricter mode for minimal embedded libcs" note
  is a sensible, disclosed opt-out.
- **Clarify:** POSIX is a contract only where the code targets POSIX. Under
  ADR-0010 every compilable configuration counts, including Win32 arms and
  Windows-only files, and there a POSIX guarantee (for example about
  `read()`/`fd` semantics or `strdup`) is not basis 1. Say "ISO C always;
  POSIX for code in a POSIX configuration".

#### R4 — ADR-0011: a static function is closed only while its address stays in source; data invariants need every writer in source

- **Theirs:** this is the standard escape condition in whole-program
  analysis. An address-taken function is a call target for any indirect call
  the analysis cannot resolve (Frama-C `-lib-entry`'s open-world entry
  pointers are the same assumption) [FC-Eva]. The data-writer condition is
  the usual requirement for a global invariant to be sound.
- **Verdict: aligned, and it tightens an earlier gap** (P4's "no
  function-pointer route in" is now explicit).

#### R5 — ADR-0011: the caller-check proof needs at least one call site

- **Verdict: aligned.** It closes a vacuous-truth hole ("every caller checks"
  over the empty set), and it is consistent with "unused functions stay in
  scope". Infer Pulse makes the opposite *reporting* choice: no manifest call
  site means no report [Pulse]. That difference is already covered by D1's
  conformance-checker framing.

#### R6 — ADR-0006: identity uncertainty is silence, safety uncertainty is report

- **Verdict: aligned.** This is the soundiness position stated precisely:
  unsound only in identified, stated places (identity resolution), and sound
  (report unless proven) for the property checked [Soundiness]. It answers
  most of D4. What remains is measurement: count per rule how often identity
  resolution failed, so the recall cost of the silence is reported
  [Soundiness].

#### R7 — ADR-0005: right for the wrong reason; Juliet section scoring

- **Theirs:** the Juliet guide defines a hit as a report "in a function with
  the word 'bad' in its name" [Juliet-UG §8.1]. That confirms 0005's reading
  that a Juliet TP means "fired in the flawed section". Habib & Pradel
  manually filtered line-window matches because warnings "coincidentally
  match a faulty line" [H&P], which is the right-for-the-wrong-reason
  problem in another benchmark.
- **Verdict: aligned, and a strength:** few evaluations say this out loud.
- **Clarify:** `bench/analyzer.py` scores Juliet detections at a FLAW line
  ±1, and tcb's table reports both `in_bad` (section) and `flaw_lines_hit`.
  0005 says reported Juliet figures state section-level scoring. Name which
  figure is which unit.

### Amendment list, updated

Status of the 16 proposals at the end of this doc, against `72b8f734`:

- **Resolved or overtaken:**
  - 2 (by 0013; keep the Detectable clarification from R1);
  - 4, mostly (by the 0006 identity/safety split);
  - 13 (standing calls folded into 0011's settled cases and 0012).
  - Item 10's first bullet (by 0010 D8).
- **Open, unchanged:** 1, 3, 5, 6, 7, 8 (the miscitation is still there),
  9, 11, 12, 14, 15, 16.
- **New, from this revision:**
  - 17. ADR-0013: the Unenforceable disposition must not rest on CERT's
    Detectable column (R1).
  - 18. ADR-0014: cross-tool scoring needs a pool-deepening sample of each
    competitor's unlabeled findings, and each tool's labeled fraction
    reported (R2).
  - 19. ADR-0014 D4: re-examine non-emitted violation entries whose basis a
    ruling changes (R2 / E2).
  - 20. ADR-0011 basis 1: POSIX contracts apply to POSIX configurations only
    (R3).

---

## D. Detection policy and project process

### D1 — Report as written; suppression is configuration; the golden rule (ADR-0001)

- **Ours:** A rule reports every construct matching its CERT text.
  Codebase-specific judgment goes into hash-pinned inline suppressions or
  per-project manifests, and a suppression must be tool-provable, never an
  inferred heuristic.
- **CERT / TS 17961:**
  - Conformance means zero rule violations. A correct-but-flagged instance is
    a *true positive* handled by a deviation "documented in the source code"
    [CERT-conf].
  - TS 17961 makes diagnosis of each rule a conformance requirement for
    analyzers [CERT-17961].
  - CERT asks tools to "minimize false positives that do not violate the
    intent of the guideline", and calls this "a quality-of-implementation
    issue" [CERT-tools].
- **MISRA Compliance:2020:** violations are recorded as deviation records,
  and deviation permits cover recurring cases [MISRA-blog; primary PDF
  **unverified**, 403]. This is the same split as ours.
- **Bug finders go the other way, on purpose:**
  - Coverity aims for "below 20%" FP on stable checkers. It "could ignore
    code constructs that led to high rates of false-error messages", and its
    suppression analysis is "invisible" [Bessey].
  - Tricorder puts an analyzer on probation at ≥10% not-useful and may turn
    it off above 25% [Tricorder].
  - Infer Pulse withholds "latent" parameter-dependent issues [Pulse].
  - Clang SA tells users to suppress with an `assert` that it accepts as an
    assumption [CSA-FAQ].
- **Verdict: stricter-and-defensible.** For a conformance checker, "report,
  then record the deviation" is CERT's and MISRA's own model. The bug-finder
  FP budgets serve a different goal, developer adoption, which Bessey and
  Sadowski say openly.
- **Attack:** "CERT says minimize FPs." **Answer:** CERT means FPs that "do
  not violate the intent of the guideline". That is ADR-0005's misfire, not a
  correctly flagged construct.
- **Attack:** the open-API rulings. CERT's front matter says "unless
  otherwise noted, function arguments should be assumed to point to valid
  values" [CERT-org]. **Answer:** that sentence is scoped to how the
  *standard's own code examples* are written. It is the paragraph about
  wrapping examples in functions, and the next sentence sends real parameter
  validation to API00-C. SATE also labels "function has a weakness, but the
  function is always called with safe parameters" as **true** (quality), not
  false [SATE-IV]. Cite both, or a referee will quote the first sentence
  alone.
- **Clarify:**
  - Say in ADR-0001's first paragraph that aurora-lint is a *conformance*
    checker, not a bug finder, and cite [CERT-conf].
  - Say that a suppression records a CERT deviation: the oracle row stays TP.
    Otherwise a reader may assume suppressed instances are labeled FP.

### D2 — 0% real-world TP doesn't make a rule unneeded; the 1523 shipping criterion (ADR-0002)

- **Ours:** A 0% real-world TP rate is no reason to drop a rule. A rule is
  not shipped only if it could never find a TP or would always be
  FP-dominated. Juliet-covered rules stay.
- **CERT:** Risk-assessment priorities are "used to prioritize the repair of
  rule violations", and "new code will be developed to be compliant with the
  entire coding standard" [CERT-org]. That is ADR-0002's CI/CD rationale
  almost word for word.
- **Vendors:** Polyspace advertises support for "all rules in the CERT C
  standard" [PS-cov, via summarizing fetch]. Full rule coverage is the
  market norm for a CERT checker.
- **Bug-finder platforms retire noisy checks:**
  - Google retires checks that annoy developers [Tricorder; SWE-Google].
  - Christakis & Bird: "Program analysis should not have all rules on by
    default" [C&B].
  - SATE: synthetic-suite FP rates "may differ from results on production
    software" [SATE-IV].
- **Verdict: stricter-and-defensible.** Keeping every enforceable rule is
  what CERT expects of new code and what TS 17961 expects of an analyzer.
- **Attack:** "All rules on by default, against [C&B]." **Answer:** separate
  *shipped* (all rules) from *enabled by default* (a CI profile with a stated
  precision bar), if aurora-lint has or wants such profiles.
- **Attack:** "Always FP-dominated" has no operational test, so it reads as
  discretionary.
- **Amend:** write 1523 into ADR-0002 as a numbered criterion with an
  operational test. For example: "could never find a TP" means the defining
  construct cannot occur in conforming C, and "always FP-dominated" means the
  construct is always accompanied by a context that makes it conform.

### D3 — Misfire vs judgment false positive (ADR-0005)

- **Ours:** A misfire names a construct not present and is always a bug. A
  "judgment FP" describes the construct correctly, and someone decides it
  does not matter.
- **SATE IV** keeps "Not a weakness – false – an invalid conclusion about the
  code" (its example: "Tool confuses a function call with a variable name")
  apart from "true but insignificant" and "true quality weakness"
  [SATE-IV].
- **Tricorder** separates an analyzer FP from an *effective* FP, "any report
  that they did not want to see" [Tricorder].
- **Kang et al.** show heuristic "actionable" oracles disagree with human
  ones [Kang22], which supports an oracle kept on correctness.
- **CERT** calls the judgment case a true positive with a deviation
  [CERT-conf].
- **Verdict: aligned.**
- **Attack:** the *name*. Under CERT and SATE a "judgment FP" is a TP. If any
  oracle row is FP on a judgment basis, precision is understated.
- **Clarify:** rename it "unwanted true positive (deviation)". State that the
  oracle's FP label means SATE's "invalid conclusion about the code", or a
  construct proven conforming under ADR-0011, and nothing else.

### D4 — Resolve identifiers to declarations; silence when unresolved (ADR-0006)

- **Ours:** Facts about an identifier come from its declaration, never its
  spelling. The file's own definition beats the project-wide map, and an
  unresolved occurrence produces no finding.
- **Theirs:**
  - clang-tidy resolves through the compiler AST of a real translation unit
    [clang-tidy].
  - The lexical tools show the failure ADR-0006 bans. Flawfinder "primarily
    does simple text pattern matching" [Flawfinder]. Semgrep, which parses
    without preprocessing, says typedefs "are not known to Semgrep when
    parsing a file" [Semgrep-C].
  - SATE's "false" examples include spelling confusion [SATE-IV].
  - Silence-when-unresolved is a *soundy* choice, "mostly sound, with
    specific, well-identified unsound choices". The manifesto asks papers to
    "evaluate the implications for the benchmarks" [Soundiness].
- **Verdict: aligned.**
- **Clarify:**
  - Name the trade-off: recall is traded for precision. The paper should
    count per rule how often resolution failed and the rule stayed silent.
  - **Terminology trap.** CERT defines *sound* as "cannot issue
    false-positive results" and *complete* as no false negatives
    [CERT-tools]. That is the reverse of the PL convention used by the
    soundiness literature and by Ockham [Ockham]. The ADRs and the paper
    should pick one and say which.

### D5 — No preprocessor; ERROR ancestry is not a suppression signal (ADR-0008)

- **Ours:** tree-sitter parses unpreprocessed source. A finding is never gated
  on an `ERROR` ancestor, and misreads get fixed where they happen.
- **Theirs:**
  - **Same design:**
    - Semgrep "parses source code prior to macro expansion", uses
      "tree-sitter's error recovery", and "will typically analyze both
      branches" of conditional compilation [Semgrep-C].
    - Coccinelle works on unpreprocessed C and ignores only `#if 0` by
      default [Coccinelle].
    - Flawfinder "can analyze software that you can't build" [Flawfinder].
  - **Coverity does not drop damaged files:** "compiling no files means
    finding no bugs". Its most common repair "simply rips out the offending
    construct", and isolated parse errors "don't matter… Unfortunately,
    failure often isn't modular" [Bessey]. That is ADR-0008's whole-file
    framing finding in Coverity's words.
  - **The variability-aware literature** calls parse-as-is heuristic and
    offers rigorous alternatives (TypeChef, SuperC) that no production CERT
    checker uses [TypeChef; SuperC].
  - **Published error rates** for this design are scarce. Padioleau's ~96%
    parse figure is **unverified** (paywalled).
- **Verdict: aligned.**
- **Attack:** "A CERT conformance claim on code that was never preprocessed
  is not a claim about a translation unit" [CERT-17961: conformance is "with
  respect to source code that is visible to the analyzer"]. **Answer:** state
  that findings describe the source text across configurations (ADR-0010),
  and cite ADR-0008's measured misfire rates (~12% in large `ERROR` regions,
  ~39% in small ones). Those numbers are rarer in this literature than the
  design itself, so they are worth publishing.

### D6 — Every compilable configuration counts (ADR-0010)

**D6a. Labels in every compilable arm.**
- **Ours:** An arm is dead only if the file itself proves it. Mutually
  exclusive arms are separate flows.
- **Theirs:**
  - cppcheck by default "automatically test[s] different combinations of
    preprocessor defines" [cppcheck].
  - Semgrep analyzes both branches, and skips only statically dead ones like
    `#if 0` [Semgrep-C; Semgrep-rn, via summarizing fetch].
  - Coccinelle ignores only `#if 0` [Coccinelle].
  - Soundiness: "Every time there are multiple options (e.g., branches of a
    conditional statement…) the analysis models all of them" [Soundiness].
  - SuperC: Linux `allyesconfig` "enables less than 80% of the code blocks
    contained in conditionals" [SuperC]. A single configuration misses code
    by construction.
  - TS 17961 asks only that violations be diagnosed "for at least one C
    implementation" [CERT-17961].
- **Verdict: stricter-and-defensible.** We go past TS 17961's floor. What we
  do is cppcheck's, Semgrep's and Coccinelle's default.

**D6b. One stated primary configuration per oracle.**
- **Theirs:**
  - Coverity: "the most reliable way to check a system is to grab its code
    during the build process" [Bessey].
  - SuperC describes it as relying "on a single, maximal configuration"
    [SuperC].
  - cppcheck with a compile database checks "only 1 configuration"
    [cppcheck].
- **Verdict: aligned.**
- **Clarify (both halves):** say plainly that the *labels* follow the
  all-configurations model and the *denominators* follow the build-capture
  model. A referee comparing our precision with a build-capture tool's needs
  that sentence. Also note that TP labels on arms the host never compiles are
  construct-level only: no sanitizer confirmation is possible for them.

### D7 — Disclosure (ADR-0007 and its 2026-09-20/23 clarifications)

**D7a. Extended material gated until the fix lands.**
- **Theirs:** Project Zero publishes details 30 days after a patch, or at 90
  days regardless [P0-policy]. CERT/CC's CVD principle is harm reduction
  [CERT-CVD]. ISO/IEC 29147 and 30111 are the normative references
  (**unverified**, 403).
- **Verdict: aligned.** Our gate is more conservative than Project Zero's: it
  has no deadline.

**D7b. Keys, verdicts and label-basis reasons published whatever the reporting status.**
- **Theirs:**
  - Project Zero's transparency list publishes an open issue's *existence*
    (vendor, product, dates), with no file or line, and only after the
    vendor has been notified [P0-transparency].
  - USENIX Security expects researchers to "disclose vulnerabilities as soon
    as they are discovered". It warns that disclosing publicly "before they
    have been privately disclosed to the responsible parties… can therefore
    expose people to negative outcomes" [USENIX26].
  - SATE avoided the question by using CVE-bearing old versions next to their
    fixed versions [SATE-IV].
  - No precedent was found for publishing TP labels on unfixed, unreported
    code.
- **Verdict: looser.**
- **The attack:** the 2026-09-23 test, "could an independent person reach
  this with the pinned SHA and the public tool?", is weaker than it sounds.
  Triage is the expensive step. Effective-FP rates of tens of percent are
  normal [Tricorder; C&B], and picking actionable warnings out of raw output
  is a research problem in itself [Kang22]. A published TP row on a
  memory-safety rule is a *filtered* pointer at a real defect in shipping
  code, not a restatement of tool output. The 2026-09-20 clarification ("a
  label is not a vulnerability claim") addresses severity *language*, not
  *location*.
- **Amend (proposal, cheapest first):** for TP/FN rows on security-relevant
  rule classes (memory safety, integer overflow feeding a size, injection),
  publish once the maintainer has been notified, or after a fixed embargo,
  whichever comes first. Project Zero's 90 days is the recognizable
  precedent. Alternatively, publish those rows with a coarsened key until
  then. Style, declaration and recommendation-class rows keep the current
  policy, with one sentence on why: no plausible attacker advantage
  [CERT-CVD].
- This is the one place in the review where outside practice clearly
  disagrees with a ruling Brandon made recently. It also interacts with the
  paper venue: a security venue will apply [USENIX26] directly.

### D8 — Process

**D8a. Postgres is the single source of truth (ADR-0004).**
- **Theirs:** SATE published the tool reports and analysis themselves and
  forbade hand-editing tool reports [SATE-IV; SATE-2008]. Artifact-evaluation
  norms ask for a publicly archived artifact [ACM badging, **unverified**,
  403].
- **Verdict: aligned** on provenance.
- **Amend:** a private Postgres instance is authoritative but not public. Each
  published figure should ship with an archived snapshot of the run rows it
  was computed from, next to `benchmark_adjudication`'s labels, citing run ids
  and the tool SHA. The paper's SHA triple already points this way.

**D8b. The changelog has only Added, Fixed and Removed (ADR-0009).**
- **Theirs:** Keep a Changelog's own "if you do nothing else" line is "list
  deprecations, removals, and any breaking changes" [KaC]. It defines
  Changed, Deprecated and Security headings. SemVer ties MAJOR to
  incompatible changes [SemVer].
- **Verdict: stricter-and-exposed.** The purpose matches Keep a Changelog. The
  missing headings do not:
  - Without *Deprecated*, a user gets no warning before a Removal.
  - Without *Changed*, a breaking change that is neither a fix nor an
    addition (a flipped default, an output-schema change) has nowhere to go.
  - ADR-0009 drops *Security* on the grounds that ADR-0007 governs it. That
    conflates third-party disclosures with vulnerabilities in **aurora-lint
    itself**, such as a crash on crafted input, which users should hear about
    and which ADR-0007 does not govern.
- **Amend:** restore Deprecated; allow Changed for breaking changes only;
  restore Security for the tool's own vulnerabilities. The ADR-0007 safety
  screen stays as it is.

### D9 — Utility layer vs substrate (ADR-0003)

- **Verdict: novel (internal).** This is code organization with no bearing on
  results, and nothing external to align with. No action.

---

## P. What counts as proof (ADR-0011, ADR-0010 D5, standing calls)

### P1 — The basis ladder

- **Ours:**
  - Accepted: ISO guarantees, file-provable dead code, and proof in the
    scanned source.
  - Rejected: compiler, flag and platform behavior, and inference.
  - Anything uncovered is TP "even when almost certainly harmless".
- **CERT:**
  - A rule "does not rely on source code annotations or assumptions" [CERT-rvr].
  - INT00-C: "if your code depends on any assumptions not guaranteed by the
    standard, you should provide static assertions" [INT00-C]. That is
    ADR-0011's `static_assert` exception exactly.
  - INT35-C judges against "strictly conforming (that is, portable)
    programs" [INT35-C].
- **Sound tools:** they are all *target-parameterized*: Polyspace `-target`
  [PS-target], Frama-C `-machdep` [FC-user], Astrée ABI files [Astree]. On
  signed overflow they agree with us by default: Frama-C treats wrap-around as
  opt-in [FC-Eva], and Polyspace defaults to `forbid` [PS-overflow, via
  summarizing fetch].
- **Verdict: stricter-and-defensible.**
- **Attack:** "Every sound tool takes a target, and ADR-0010 D6 fixes one per
  corpus. Refusing that target's data model is inconsistent."
- **Clarify:**
  - Add one sentence: the primary configuration fixes the *denominator*
    (ADR-0010 D6), and its ABI is *not* a proof basis (ADR-0011 basis 4).
  - Pin the ISO edition that basis 1 means. WG14 N3322, proposed for C2y,
    makes `null + 0` and zero-length library calls on null defined [N3322;
    acceptance **unverified**]. That would change some basis-1 answers.

### P2 — Asserts (ADR-0010 D5; standing call)

- **Ours:** An `NDEBUG`-strippable `assert()` is not a guard. An assert macro
  with no build-flag arm is a guard. A runtime-off-by-default assert is
  neutral.
- **Theirs:**
  - Clang SA prunes "paths where the assertion condition is false" [CSA-ann].
  - Polyspace Code Prover: "following the assert, Polyspace considers that"
    the condition holds [PS-assert, via summarizing fetch].
  - Public Coverity model files map assert failure to a kill path [Cov-model;
    vendor default **unverified**].
  - Frama-C turns an assert into a proof *obligation*, and its libc `assert.h`
    has an `NDEBUG` arm [FC-assert]. It does not treat an unproven assert as
    proof.
  - MSC11-C: assertions are "not for runtime error checking" and are
    "generally turned off before code is deployed" [MSC11-C]. That supports
    us.
  - **But CERT's own EXP34-C compliant solution** "adds assertions to
    document that certain other pointers must not be null" [EXP34-C].
  - Juliet uses `assert` only in CWE-617 test cases, where the assert is the
    flaw. It has no guard usage either way [local Juliet 1.3].
- **Verdict: stricter-and-exposed.** Every surveyed analyzer treats a live
  assert as an assumption, and CERT's compliant code leans on one.
- **Fix (a factual error):** ADR-0010's Context says "API00-C's own standard
  holds that an `assert()` is not a parameter guard". The CERT API00-C page
  mentions neither `assert` nor `NDEBUG` (checked). "API00-C's standard" there
  means the project's internal adjudication standard, not CERT's text, and a
  referee who checks will find nothing. Reword it, and cite MSC11-C and C11
  7.2p1 instead.
- **Amend:**
  - Answer the EXP34-C `tun_chr_poll` example in the ADR. The defensible
    reading: its asserts document, and the fix is the moved `if (!tun)`.
  - **Tag assert-dominated rows as their own sub-class**, so precision can be
    reported under both readings. The strict reading then becomes a disclosed
    parameter instead of a hidden one.
  - Say that a macro with "no build-flag arm" counts only if its failure path
    provably does not return, by P10's standard. Otherwise P2 and P10
    disagree.

### P3 — Open caller sets (libraries, `-rdynamic`, "could be publicly callable")

- **Ours:** Every non-static function that some real, compilable build exports
  has an open caller set, and no caller-side proof counts for it. This covers
  a built/installed/example-linked library, a `-rdynamic` executable, and
  anything reachable through a dlopen plugin interface. Code no real build
  exports stays closed.
- **Theirs:**
  - **CERT API00-C** frames the risk around libraries: "the library itself
    may still be the vector by which the calling code's vulnerability is
    exploited" [API00-C].
  - **Frama-C `-lib-entry`** analyzes a function "outside of a calling
    context", with pointer arguments that may be NULL [FC-Eva]. That is the
    same open-world view as ours.
  - **GCC:** `-rdynamic` adds "all symbols, not only used ones, to the dynamic
    symbol table" [GCC-link]. The ruling's factual basis is correct.
  - **Looser, but documented and switchable, defaults:**
    - Polyspace's generated main "calls only those functions that are not
      called in the source code" (default `unused`) [PS-maingen, re-checked].
      That is exactly the in-tree-callers trap ADR-0011 names.
    - Polyspace also assumes environment pointers are non-null and in bounds
      unless told otherwise [PS-envptr, via summarizing fetch].
    - Pulse keeps parameter-dependent issues latent [Pulse], and
      `NULLPTR_DEREFERENCE_LATENT` is off by default [Infer-man].
    - CodeSonar's LANG.STRUCT.UPD ("parameter is dereferenced without an
      initial NULL check") exists but is "disabled by default" [CS-UPD].
- **Verdict: stricter-and-defensible.**
- **Clarify:**
  - Record per corpus *which* build target or config option establishes an
    export, so the converse ruling ("stays closed") can be audited.
  - Say that ADR-0010's compilable test governs "could be callable", and that
    a platform-impossible build is excluded.

### P4 — Checks made by every caller count

- **Theirs:** Context-sensitive tools do this routinely, and more loosely:
  - Pulse reports once "a call site at which all the conditions for the error
    are satisfied" exists [Pulse].
  - Polyspace analyzes callees in their callers' contexts [PS-maingen].
- **Verdict: aligned.** Our precondition is stricter: a closed caller set,
  every site provable.
- **Clarify:** name the rules it applies to. For API00-C, cite CERT's "the
  usual discipline in C and C++ is to require validation on only one side of
  each interface" [API00-C], so the ruling does not read as ignoring
  API00-C's text.

### P5 — A proof chain must end in a real proof

- **Ours:** A caller's earlier dereference is not a check. The caller's
  dereference is reported, *and* the callee's dereference stays TP.
- **Theirs:**
  - Engler: "a dereference of a pointer, p, implies a belief that p is
    non-null" [Engler].
  - Coverity REVERSE_INULL reasons from "already been dereferenced on all
    paths" [Cov-RI].
  - For NULL to reach the callee through that path, undefined behavior must
    already have occurred at the caller (C11 6.5.3.2).
- **Verdict: stricter-and-exposed.** The "report the caller" half is aligned.
  Also keeping the dominated callee site counts one missing check twice, and
  no surveyed tool does that.
- **Answer to give:** argue from the fix. The likely repair is at the caller
  (`if (p) p->x = 1; f(p);`), after which the callee *does* receive NULL. For
  API00-C, CERT wants the callee to validate anyway.
- **Amend:** record a dependency link from the callee row to its caller row,
  or score them as one defect cluster, so precision and recall can be
  reported with and without dependent sites. Say whether this applies to
  EXP34-C or only to API00-C.

### P6 — Callee postconditions; callers only in absent generated files

- **Theirs:** Summary-based tools derive callee facts from bodies: Klocwork
  NPD.FUNC.MUST [KW-NPD], Pulse specs [Pulse]. Frama-C WP `ensures` is the
  formal analogue (**unverified**).
- **Verdict: aligned.** The generated-file limb follows from basis 3: proof
  must be visible in the scanned source. A build-capturing tool would see more
  input, which is a different measurement.
- **Clarify:** "every return path" includes `longjmp` and error exits through
  macros, and is judged per configuration arm (ADR-0010 D4).

### P7 — `&p->field` / `&p->a[i]` with p unproven

- **Theirs:**
  - C11 6.5.2.3p4: `->` "designates a member of a structure or union
    object". Footnote 102 exempts `&*E` and `&(E1[E2])` only [N1570].
  - **CERT EXP34-C-EX1**: "expressions of the form &*x and &x[y] effectively
    cancel out … so they do not violate this rule even if x is a null
    pointer" [EXP34-C]. That is exactly our boundary.
  - Clang SA's `core.NullPointerArithm` covers null plus a nonzero offset
    [CSA-checkers].
- **Verdict: aligned.**
- **Clarify:** name EXP34-C-EX1 in the ruling. It is the strongest citation.

### P8 — `(ptr, len)` is an informal contract

- **Theirs:**
  - ARR38-C: "the given size should not be greater than the element count of
    the pointer" [ARR38-C].
  - Formal contracts exist only outside ISO C: MSVC SAL `_In_reads_(s)`
    [SAL] and GCC `access` [GCC-attr].
  - Polyspace assumes in-bounds environment pointers by default [PS-envptr],
    and Eva's `-lib-entry` assumes small arrays [FC-Eva].
- **Verdict: stricter-and-defensible.**
- **Clarify:** say that SAL and GCC `access`, like `nonnull`, are basis 4.
  Otherwise "a contract isn't formal in C" invites the reading that an
  attribute would suffice.

### P9 — Integer widths

- **Theirs:** C11 5.2.4.2.1 gives minimum magnitudes. 7.20.1.1 defines exact
  widths, and those types are optional [N1570]. INT00-C and INT35-C say the
  same as the ruling [INT00-C; INT35-C].
- **Verdict: stricter-and-defensible.** Stricter only than target-configured
  sound tools (P1).
- **Clarify:**
  - `CHAR_BIT == 8` is **not** an ISO guarantee, only `>= 8`, so apply the
    ruling to it consistently.
  - An `intN_t` proves its width in any build where the code compiles.

### P10 — noreturn

- **Ours:** `_Noreturn` or `__attribute__((noreturn))` alone is no proof. Only
  a verified body or the ISO stdlib set counts.
- **Theirs:**
  - C11 6.7.4p8: a `_Noreturn` function "shall not return to its caller".
    That is a "shall" outside a constraint, so returning is UB (4p2) [N1570].
  - GCC's `noreturn` lets the compiler "assume that fatal cannot return"
    [GCC-attr].
  - Clang SA trusts `noreturn` for path pruning [CSA-ann].
- **Verdict: stricter-and-exposed.** `_Noreturn` is ISO C (C23
  `[[noreturn]]`), not an extension. Code after the call is reached only
  after UB has already happened in the callee. Rejecting it sits awkwardly
  next to P5, which does use "UB already happened at the caller" as a reason.
  A referee would probe that asymmetry.
- **Amend:** accept ISO `_Noreturn` / `[[noreturn]]` as basis 1 *for the
  caller*, and report the callee if its body can return (6.7.4p9's
  recommended diagnostic). That puts the defect where it is, consistent with
  P5 and P11. Keep `__attribute__((noreturn))` at basis 4. If the ruling
  stays as it is, the ADR should say why the `nonnull` reasoning ("undefined
  rather than impossible") applies to an ISO specifier too.

### P11 — Report the first dereference after a later `if (p && …)`

- **Theirs:**
  - CERT EXP34-C's `tun_chr_poll` example is this exact shape, and it
    locates the violation at the early dereference [EXP34-C].
  - cppcheck `nullPointerRedundantCheck` reports at the dereference [cppcheck
    source].
  - Coverity REVERSE_INULL [Cov-RI] and Klocwork RNPD.DEREF [KW-RNPD] anchor
    at the *check* line instead.
  - Engler: "Either the check is impossible and should be deleted, or the code
    has a potential error" [Engler].
- **Verdict: aligned** with CERT. Coverity and Klocwork choose a different
  line, which matters for line-exact cross-tool matching (§E).
- **Clarify:** a later check alone does not prove p can be NULL. For a closed
  value that is provably non-null, the finding is FP by basis 3.

### P12 — Correlated flags

- **Theirs:**
  - ESP must "reason about branch correlations, which is usually necessary to
    control the number of false error reports" [ESP].
  - Bodik et al.: "from 9 to 40 % of conditionals" show compile-time
    detectable correlation [Bodik].
  - Path-sensitive tools handle the exact intraprocedural case (per-tool
    **unverified**).
- **Verdict: aligned.** "Every path, no reassignment" is the soundness
  condition for an infeasible-path argument.
- **Clarify:** say whether correlation through a struct field or a global
  counts, and that a call between the test and the use breaks "no
  reassignment" when it can alias.

### P13 — `main`'s argv; static zero-init

- **Theirs:**
  - C11 5.1.2.2.1 (`argv[argc]` is null; `argv[0]` is a string only if
    `argc > 0`) and 6.7.9p10 (static zero-init) [N1570].
  - EXP33-C is scoped to "Local, automatic variables" [EXP33-C].
  - Frama-C Eva's own default of `argv ∈ {NULL; …}` is, in its manual's words,
    "generally not what is wanted" [FC-Eva].
- **Verdict: aligned.**

---

## E. ADR-0012 and evaluation methodology

### E1 — Proposed ADR-0012: EXP34-C at the dereference, API00-C at the receiving function

- **Ours:** See ADR-0012's Decision. `finding-location.md` holds the full
  prior research. This pass re-fetched its key quotes and reused its tool
  table.
- **Re-verified:**
  - CERT API00-C's noncompliant `setfile` body is only `myFile = file;` (read
    from the raw page source; a summarizing fetch wrongly paraphrased it as a
    dereference). So CERT does place an API00-C violation at a function that
    never dereferences [API00-C].
  - EXP34-C's site at a `memcpy` call [EXP34-C].
  - Pulse's latent issues [Pulse].
  - Ockham: a tool may define its own site "as long as it is expressed". The
    site of missing checks is "still open". A report like "caution: this
    function does not check for a null" is "at best ignored (not counted)"
    [Ockham].
  - SATE IV accepts "Same weakness instance, different perspective" [SATE-IV].
- **Verdict: stricter-and-defensible.** The EXP34-C half is aligned with
  tools, Juliet and Ockham. The API00-C half rests on CERT's own example and
  on Ockham's stated-convention allowance.
- **Exposed consequence: opaque-context callbacks become TP.** CERT's fix for
  `setfile` checks a validity predicate (`file && !ferror(file) && ...`). An
  uninterpreted `void *ctx` whose domain includes NULL has no predicate the
  function could test, so the fix is empty. Ockham's "at best ignored"
  describes exactly this report shape. A referee can also argue that code
  which never interprets `ctx` does not *use* it.
  - **Option A:** define "use" to exclude forwarding an uninterpreted value
    into the same opaque slot.
  - **Option B:** keep the TP, tag the keys as a named sub-class, and report
    API00-C with and without it. Also report with and without all
    forwarding-only TPs (~13% of API00-C TPs, per `finding-location.md`).
- **Clarify:**
  - Cite Ockham in Decision item 4 as the basis for reporting separately with
    a stated site convention.
  - Say that API00-C figures are conditional on the open-caller-set rulings
    (P3) and are never merged into CWE-476 comparisons.
  - Report API00-C as distinct entry-point/parameter pairs. One leaf defect
    fanning out into several wrapper rows is what Tricorder and Bessey
    predict developers reject.

### E2 — Labels describe the code; non-emitted keys are a regression net

- **Ours:**
  - Labels are keyed `(project, commit, file, line, rule)`, and a run is its
    findings overlaid with labels.
  - Labels on keys no run emits are kept, and are re-adjudicated only if they
    reappear.
  - `bench/db.py` `score_realworld_run` (checked): recall is "over all known
    real-bug labels (verdict TP or FN) for the matching commit". Non-emitted
    TP/FN keys **are the recall denominator**.
- **Theirs:**
  - Tool-independent ground truth is the norm: Juliet's per-test-case flaws,
    OWASP Benchmark's `expectedresults` file, and SATE IV's CVE locations.
    The principle is **aligned**.
  - Every surveyed benchmark matches *coarser than a line*:
    - Juliet: a report "in a function with the word 'bad' in its name" [Juliet-UG §8.1].
    - SATE IV: "at least one warning location was in an appropriate block",
      and for CVEs "the starting line number and block length" [SATE-IV].
    - OWASP: per test case [OWASP-BM].
    - Habib & Pradel: a line window "of [-1,1]" [H&P] (checked).
- **Verdict: stricter-and-exposed.** Three attacks:
  1. **Stale rulings in the recall denominator.** Precision is protected,
     because an emitted key is re-judged when it reappears. Recall is not: a
     non-emitted TP or FN labeled under a ruling that has since changed (the
     `&p->f`, first-site, closed-caller-set and `-rdynamic` calls all changed
     bases this week) stays in the denominator unexamined.
     - **Amend:** stamp each label with the ruling set or date it was made
       under.
     - **Amend:** when a ruling changes a basis, re-adjudicate the
       non-emitted **TP/FN** keys whose recorded basis it touches. Non-emitted
       FP keys can stay dormant as ruled: they enter no denominator.
  2. **Exact-line fragility.** Commit pinning removes code drift, not *tool*
     drift. A rule change that moves a report by one line turns a TP into an
     unlabeled finding plus an FN, silently.
     - **Amend:** keep exact-line scoring primary, and add a tolerance-matched
       sensitivity score (same rule and same function, or ±N lines).
     - **Amend:** in delta-adjudication, flag new findings near a
       non-emitted TP of the same rule as probable relocations.
  3. **Oracle circularity.** Most TP labels come from adjudicating the tool's
     own output, so recall is largely "against what earlier versions found".
     SATE IV and the Juliet guide both name the unknown-flaws problem
     [SATE-IV; Juliet-UG §1.3.1].
     - **Amend:** `bench/db.py` already records FN provenance (`juliet:`,
       `cross:`, `cve:`, `uncorroborated`; checked). Publish recall split by
       provenance, call the total "recall relative to the oracle", and present
       the cross-tool and CVE-derived part as the independent recall figure.

### E3 — One oracle per stated primary configuration (ADR-0010 D6–D7)

- **Theirs:**
  - SATE IV shipped a VM "properly configured to compile the cases", had teams
    state "the environment (including the operating system and version of
    compiler)", and excluded Windows-only Juliet cases that "did not compile on
    Linux" [SATE-IV].
  - cppcheck checks one configuration by default [cppcheck].
  - scan-build captures the build by overriding `CC`/`CXX` [scan-build].
- **Verdict: aligned.**
- **Clarify:**
  - **The name is inaccurate.** Under D1 every feature-flag arm is in the
    denominator, so the "primary build configuration" is a *platform
    profile* with all feature arms counted, which no single `make` compiles.
    Rename it, for example "primary platform profile (all feature arms in
    scope)", and state it per corpus.
  - **Granularity.** `scope_include`/`scope_exclude` work per file, but D7
    also excludes off-platform *arms* inside shared files. Say how that is
    done. If it is not done, say so and count the labeled rows in off-platform
    arms of in-scope files.

### E4 — Delta-adjudicate before citing (CLAUDE.md protocol item 6)

- **Theirs:**
  - SATE IV sampled "a subset of 30 warnings from each tool report, based on
    weakness name and severity" [SATE-IV].
  - Lenarduzzi et al. used "a 95% statistically significant stratified sample
    with a 5% confidence interval" [Lenarduzzi] (checked).
  - Ockham judged Frama-C warnings class by class [Ockham].
  - Excluding unlabeled findings is unbiased only if the labeled set is a
    random sample of what the new version emits. Labels harvested from earlier
    runs are not, which is exactly what protocol 6 guards against.
- **Verdict: aligned.** A census kept current is stronger than SATE's
  sampling.
- **Clarify:**
  - Publish the per-rule labeled fraction next to each figure.
  - If a pass ever samples instead of labeling everything, make the sample
    random and stratified, not "the first batches", and report a
    Wilson/Clopper-Pearson interval.
  - Say in the paper that the scope predicate is fixed before batching, since
    post-hoc scoping is a known way to steer precision.

### E5 — Labels produced mostly by LLM agents under written rulings

- **Ours:** LLM agents apply the written rulings (ADR-0010/0011 and the
  standing calls). Adversarial second passes run, and Brandon rules on
  contested cases.
- **Theirs:**
  - **General LLM-as-judge work:**
    - MT-Bench: GPT-4 judges reach "over 80% agreement" with humans, and have
      "position, verbosity, and self-enhancement biases" [Zheng23].
    - Bavaresco et al.: LLMs "should be carefully validated against human
      judgments before being used as evaluators" [Bavaresco] (checked).
    - LLM-as-judge research in SE "is still in its early stages" [SE-judge].
  - **LLM triage of static-analysis warnings:**
    - LLift's authors built ground truth with "about 50 human hours
      inspecting all results", and measured the LLM *against* it [LLift].
    - LLM4FPM scores F1 > 99% on Juliet but 86% on D2A [LLM4FPM]. The
      synthetic/real gap applies to LLM judges too.
    - LLM4SA's figures are **unverified** (paywalled).
    - None of these papers uses LLM output *as* the oracle.
  - **Label noise in real-world vulnerability data:**
    - Croft et al.: "20-71% of vulnerability labels to be inaccurate"
      [Croft23] (checked).
    - PrimeVul designs its labeling around "low label accuracy" in prior
      datasets [PrimeVul].
    - Kang et al.: heuristic labels "do not agree with human oracles"
      [Kang22].
  - **Rater norms:** two independent human inspectors with Krippendorff's
    alpha 0.84 [Lenarduzzi]; Habib & Pradel discussed every non-obvious
    candidate between both authors [H&P].
- **Verdict: looser.** The written rulings improve *consistency*, but they do
  not *measure* it. An adversarial pass by the same model family, with the
  same rulings and context, is not an independent rater. ADR-0007's own
  2026-09-20 clarification records that adversarial review repeatedly
  overturns first-pass verdicts. A referee will ask what the error rate is on
  rows that got no such pass.
- **Amend (priority order):**
  1. **A blinded human re-label sample.** Random, stratified by rule class and
     project, sized for ±5% at 95% (~370, Lenarduzzi's design). Raters do not
     see the LLM's verdict or reason. Report Cohen's kappa or Krippendorff's
     alpha per rule class against a stated threshold (≥ 0.80).
  2. **An independent second model** (another vendor, fresh context) on a
     larger sample, reporting LLM–LLM agreement. It is cheap and shows how
     stable the labels are.
  3. **Label error folded into precision**, as a corrected estimate or a wider
     interval.
  4. **Provenance on every label:** model and version, ruling set or date,
     batch, and whether a human touched it.
  - Until (1) exists, describe real-world precision as "against LLM-adjudicated
    labels under published rulings".

### E6 — Juliet for detection logic, real-world for noise (ADR-0002)

- **Theirs:**
  - The Juliet guide says the test cases are "simpler than natural code", that
    this "may inflate results", and that FP rates "may be much different from
    the rates the tools would have on natural code" [Juliet-UG §1.3.2]
    (checked against the local copy).
  - SATE IV: Juliet has "an equal number of good and bad code blocks, whereas
    in practice, sites with weaknesses appear much less frequently"
    [SATE-IV].
  - Goseva-Popstojanova & Perhinschi (IST 2015) use the same two-part design
    [G-P&P].
  - Lipp et al. (ISSTA 2022): tools that do well on synthetic bugs "miss
    in-between 47% and 80% of the vulnerabilities" in real programs [Lipp22,
    abstract].
  - NIST notes that "many issues remain" in Juliet 1.3's own cases [Juliet-1.3].
- **Verdict: aligned.**
- **Clarify:**
  - Lipp's result makes "real-world measures noise, not detection" too narrow.
    Rephrase: Juliet is the *controlled* detection signal, and real-world
    corpora give the *ecological* FP and recall signal, against independent
    ground truth (E2).
  - State which rules Juliet covers at all. API00-C and CWE-20 have no Juliet
    ground truth, so for them "Juliet is primary" is empty.
  - State aurora-lint's Juliet matching unit and how it treats incidental
    flaws. Today `bench/analyzer.py` (`_hits_flaw_line`) counts a hit at a
    FLAW line ±1. That is finer than the guide's bad-function unit
    [Juliet-UG §8.1] and coarser than the exact-line real-world key (E2), so
    say which unit each published figure uses. Numbers under a different
    unit are not comparable with published Juliet results.

---

## Proposed amendments and new ADRs, for Brandon to rule on

Numbered for reference. None is applied.

1. **ADR-0001:** one opening paragraph naming aurora-lint a *conformance*
   checker [CERT-conf], and saying a suppression is a CERT deviation, so the
   oracle row stays TP. (D1, D3)
2. **ADR-0002:** write the 1523 shipping criterion in, with operational tests.
   Separate *shipped* from *enabled by default*. Widen "real-world measures
   noise" to include recall. (D2, E6)
3. **ADR-0005:** rename "judgment FP" to "unwanted true positive (deviation)".
   Define the oracle's FP label. (D3)
4. **ADR-0006 / methodology:** name the soundiness trade-off, and pick one
   meaning of "sound", since CERT's is inverted. (D4)
5. **ADR-0007:** notify-or-embargo for TP/FN rows on security-relevant rule
   classes. The rest are unchanged. (D7b)
6. **ADR-0004:** archive a public snapshot of the rows behind each published
   figure. (D8a)
7. **ADR-0009:** restore Deprecated; allow Changed for breaking changes; add
   Security for aurora-lint's own vulnerabilities. (D8b)
8. **ADR-0010:**
   - Fix the "API00-C's own standard" miscitation. (P2)
   - Rename "primary build configuration" to a platform profile. (E3)
   - State how off-platform arms are excluded. (E3)
9. **ADR-0010 D5 / assert ruling:**
   - Answer CERT's EXP34-C compliant-solution asserts.
   - Tag assert-dominated rows so precision is reported both ways.
   - Require a no-build-flag assert's failure path to be provably
     non-returning. (P2, P10)
10. **ADR-0011:**
    - Separate "the configuration fixes the denominator" from "its ABI is not
      proof". (P1)
    - Pin the ISO edition. (P1)
    - List SAL and GCC `access` as basis 4. (P8)
    - Note that `CHAR_BIT == 8` is not ISO. (P9)
11. **ADR-0011, proof chains:** link a dependent callee row to its caller row,
    and score both ways. (P5)
12. **noreturn:** accept ISO `_Noreturn` / `[[noreturn]]` for the caller and
    flag a callee that can return. Keep `__attribute__((noreturn))` at basis 4.
    (P10)
13. **Standing calls → ADR-0011:** record the open-caller-set, `(ptr, len)`,
    widths, `&p->f` (cite EXP34-C-EX1), first-site and correlated-flag rulings
    with the clarifications in P3–P12. Most of them currently exist only as
    rulings.
14. **ADR-0012:** choose option A or B for opaque-context pass-through. Cite
    Ockham for the separate-reporting convention. (E1)
15. **New ADR, oracle maintenance:**
    - Stamp each label with its ruling set.
    - Re-adjudicate non-emitted TP/FN keys that a new ruling touches.
    - Add a line-tolerance sensitivity score.
    - Split recall by FN provenance.
    - Publish labeled coverage per rule, and a CI for any sampled pass. (E2, E4)
16. **New ADR, label production:** state the LLM-agent process, and commit to
    a blinded human agreement sample with kappa/alpha, an independent second
    model, and per-label provenance. (E5)

---

## References

All URLs were fetched on 2026-09-25 unless marked. "Checked" marks quotes
that a second, independent fetch matched verbatim.

CERT / ISO
- [CERT-conf] https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/front-matter/introduction/conformance-testing (checked)
- [CERT-tools] …/front-matter/introduction/tool-selection-and-validation (checked)
- [CERT-rvr] …/front-matter/introduction/rules-versus-recommendations (checked)
- [CERT-org] …/front-matter/introduction/how-this-coding-standard-is-organized (checked, incl. the surrounding paragraph)
- [CERT-17961] …/front-matter/introduction/isoiec-ts-17961-c-secure-coding-rules (checked)
- [API00-C] …/recommendations/application-programming-interfaces-api/api00-c (checked; no `assert`/`NDEBUG` on the page)
- [EXP34-C] …/rules/expressions-exp/exp34-c (checked)
- [EXP33-C] …/rules/expressions-exp/exp33-c
- [ARR38-C] …/rules/arrays-arr/arr38-c
- [INT00-C] …/recommendations/integers-int/int00-c
- [INT35-C] …/rules/integers-int/int35-c
- [MSC11-C] …/recommendations/miscellaneous-msc/msc11-c (checked)
- [N1570] http://port70.net/~nsz/c/c11/n1570.html (5.1.2.2.1, 5.2.4.2.1, 6.5.2.3, 6.5.3.2 fn 102, 6.7.4, 6.7.9p10, 7.2p1, 7.20.1)
- [N3322] https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3322.pdf (proposal text; C2y acceptance unverified)

Tools
- [PS-target] https://www.mathworks.com/help/codeprover/ref/targetprocessortypetarget.html (summarizing fetch)
- [PS-overflow] https://www.mathworks.com/help/codeprover/ref/overflowmodeforsignedintegersignedintegeroverflows.html (summarizing fetch)
- [PS-assert] https://www.mathworks.com/help/codeprover/ref/userassertion.html (summarizing fetch)
- [PS-maingen] https://www.mathworks.com/help/codeprover/ref/functionstocallmaingeneratorcalls.html (re-checked via a second summarizing fetch)
- [PS-envptr] https://www.mathworks.com/help/codeprover/ref/considerenvironmentpointersasunsafestubbedpointersareunsafe.html (summarizing fetch)
- [PS-cov] https://www.mathworks.com/help/bugfinder/ug/polyspace_coverage_coding_standard.html (summarizing fetch)
- [FC-user] https://frama-c.com/download/frama-c-user-manual.pdf §5.6
- [FC-Eva] https://www.frama-c.com/download/frama-c-eva-manual.pdf §6.3
- [FC-assert] https://raw.githubusercontent.com/Frama-C/Frama-C-snapshot/master/share/libc/assert.h
- [Astree] https://www.absint.com/releasenotes/astree/19.04/index.htm
- [CSA-ann] https://clang.llvm.org/docs/analyzer/user-docs/Annotations.html
- [CSA-FAQ] https://clang.llvm.org/docs/analyzer/user-docs/FAQ.html
- [CSA-checkers] https://clang.llvm.org/docs/analyzer/checkers.html
- [clang-tidy] https://clang.llvm.org/extra/clang-tidy/
- [Pulse] https://fbinfer.com/docs/checker-pulse (checked)
- [Infer-man] https://github.com/facebook/infer/blob/main/infer/man/man1/infer-full.txt
- [CS-UPD] https://docs.adacore.com/live/wave/codesonar_manual/html/codesonar_manual/WarningClasses/LANG/LANG.STRUCT.UPD.html (checked)
- [KW-NPD] https://help.klocwork.com/2024/en-us/reference/npd.func.must.htm
- [KW-RNPD] https://help.klocwork.com/2025.3/en-us/reference/rnpd.deref.htm (checked)
- [Cov-RI] a public Coverity Scan trace in a GitHub issue (REVERSE_INULL wording); vendor docs not reached
- [Cov-model] public project-authored Coverity model files (ghc `utils/coverity/model.c`, cmocka `coverity/coverity_assert_model.c`)
- [cppcheck] https://cppcheck.sourceforge.io/manual.pdf; source: https://github.com/danmar/cppcheck/blob/main/lib/checknullpointer.cpp
- [Semgrep-C] https://semgrep.dev/blog/2024/modernizing-static-analysis-for-c/
- [Semgrep-rn] https://docs.semgrep.dev/release-notes/2026-07-13 (summarizing fetch)
- [Coccinelle] https://coccinelle.gitlabpages.inria.fr/website/docs/options.pdf
- [Flawfinder] https://dwheeler.com/flawfinder/
- [SAL] https://learn.microsoft.com/en-us/cpp/code-quality/annotating-function-parameters-and-return-values
- [GCC-attr] https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html
- [GCC-link] https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html (checked)
- [MISRA-blog] https://www.perforce.com/blog/qac/misra-rules-misra-guidelines (vendor blog: "while most MISRA rules are decidable, some of them are undecidable"; MISRA Compliance:2020 PDF returned 403)

Literature and practice
- [Bessey] Bessey et al., "A Few Billion Lines of Code Later", CACM 53(2), 2010. https://web.stanford.edu/~engler/BLOC-coverity.pdf (checked)
- [Tricorder] Sadowski et al., ICSE 2015. https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43322.pdf (checked)
- [SWE-Google] Software Engineering at Google, ch. 20. https://abseil.io/resources/swe-book/html/ch20.html
- [C&B] Christakis & Bird, ASE 2016. https://mariachris.github.io/Pubs/ASE-2016.pdf (checked)
- [Kang22] Kang, Aw, Lo, ICSE 2022. https://arxiv.org/pdf/2202.05982
- [SATE-IV] NIST SP 500-297. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-297.pdf (checked)
- [SATE-2008] NIST SP 500-279. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication500-279.pdf
- [Ockham] NIST IR 8113. https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8113.pdf (checked)
- [Soundiness] Livshits et al., "In Defense of Soundiness". https://yanniss.github.io/Soundiness-CACM.pdf
- [SuperC] Gazzillo & Grimm, PLDI 2012. https://paulgazzillo.com/papers/pldi12.pdf
- [TypeChef] Kästner et al., OOPSLA 2011. https://www.cs.cmu.edu/~ckaestne/pdf/oopsla11_typechef.pdf
- [Engler] Engler et al., SOSP 2001. https://web.stanford.edu/~engler/deviant-sosp-01.pdf
- [ESP] Das, Lerner, Seigle, PLDI 2002. https://www.cs.cornell.edu/courses/cs711/2005fa/papers/dls-pldi02.pdf
- [Bodik] Bodik, Gupta, Soffa, FSE 1997. https://www.cs.virginia.edu/~soffa/Soffa_Pubs_all/Conferences/Refining.Bodick.1997.pdf
- [P0-policy] https://projectzero.google/vulnerability-disclosure-policy.html
- [P0-transparency] https://projectzero.google/reporting-transparency.html
- [CERT-CVD] https://certcc.github.io/CERT-Guide-to-CVD/topics/principles/
- [USENIX26] https://www.usenix.org/conference/usenixsecurity26/call-for-papers (checked)
- [Juliet-UG] Juliet Test Suite v1.2 for C/C++ User Guide, https://samate.nist.gov/SARD/downloads/documents/Juliet_Test_Suite_v1.2_for_C_Cpp_-_User_Guide.pdf (§1.3.2 checked against the local copy)
- [Juliet-1.3] NIST TN 1995, https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=925632
- [OWASP-BM] https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv
- [H&P] Habib & Pradel, ASE 2018. https://software-lab.org/publications/ase2018_static_bug_detectors_study.pdf (checked)
- [Lipp22] Lipp et al., ISSTA 2022, abstract: https://portal.fis.tum.de/en/publications/an-empirical-study-on-the-effectiveness-of-static-c-code-analyzer/ (full text unverified)
- [G-P&P] Goseva-Popstojanova & Perhinschi, IST 2015. https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf
- [Lenarduzzi] https://arxiv.org/pdf/2101.08832 (checked)
- [scan-build] https://clang.llvm.org/docs/analyzer/user-docs/CommandLineUsage.html
- [Zheng23] https://arxiv.org/abs/2306.05685
- [Bavaresco] https://arxiv.org/abs/2406.18403 (checked)
- [SE-judge] https://arxiv.org/abs/2510.24367
- [LLift] https://www.cs.ucr.edu/~zhiyunq/pub/oopsla24_llift.pdf
- [LLM4FPM] https://arxiv.org/abs/2411.03079
- [Croft23] https://arxiv.org/abs/2301.05456 (checked)
- [PrimeVul] https://arxiv.org/abs/2403.18624
- [KaC] https://keepachangelog.com/en/1.1.0/
- [SemVer] https://semver.org/

**Could not verify** (not relied on for any verdict):
- ISO/IEC 29147 and 30111, the ACM badging page and the MISRA Compliance PDF
  (all returned 403).
- Heckman & Williams 2011, Muske & Serebrenik 2016, Abal et al. 2014 and
  Medeiros et al. (full texts not retrieved).
- Padioleau's 96% figure.
- Coverity vendor documentation.
- Infer's default assert modeling.
- Frama-C WP `ensures`.
- Whether Clang SA or UBSan `null` reports `&p->f` without a load.
- WG14's acceptance of N3322.
- Lipp et al.'s full text: only the abstract was read, so its matching
  granularity is not established.
- LLM4SA's figures.
- Coverity `cov-build` documentation.
