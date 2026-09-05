Testing Methodology
===================

SqC employs a three-tier testing strategy: unit tests for individual rule logic,
the NIST Juliet Test Suite for precision/recall measurement, and real-world
open-source codebases for scalability and noise validation.

Benchmark Strategy
------------------

SqC is benchmarked on two axes:

1. **Juliet Test Suite** (NIST) — 54,484 files with ground truth (OMITBAD/OMITGOOD
   sections). Measures TP rate, FP rate, and per-CWE coverage.

2. **Real-World Open-Source Projects** — 9 codebases (libcrc, sqlite, mosquitto,
   curl, hostap, lua, raylib, pure-ftpd, seL4); the original 7 are analyzed by
   sqc, cppcheck, and clang-tidy, the latter two (pure-ftpd, seL4) sqc-only so
   far. No ground truth from the tools themselves — measures violation counts,
   rule distribution, and cross-tool agreement (a separate adjudicated
   ground-truth oracle covers precision/recall; see below).

**Why both**:

- **Juliet** provides precision metrics (TP/FP) but is synthetic single-file code
- **Real-world** tests scalability, noise levels, and cross-file analysis on production code
- Rule improvements are validated on Juliet for TP/FP impact, then verified on
  real-world for noise reduction

**Benchmark cadence**:

- **After every significant rule change**: Juliet benchmark (``python -m bench juliet``, ~10 min)
- **After version milestones**: Full real-world benchmark (``python -m bench
  realworld-run``, all 9 codebases; sqc on all 9, cppcheck/clang-tidy on the
  original 7)
- **cppcheck/clang-tidy results are stable** across sqc changes — run once and cache

Unit Tests
----------

Each CERT C rule has dedicated test cases written as C source files organized
under ``src/rules/cert_c/<CATEGORY>/<RULE-ID>/tests/``:

::

    src/rules/cert_c/SIG/SIG01-C/tests/
      fail/                          # C files that SHOULD trigger violations
        testcases_signal_restart_assumption.c
        testcases_concurrent_signals.c
        ...
      pass/                          # C files that should NOT trigger violations
        testcases_proper_signal_handling.c
        ...

**Current coverage**: 3,582 C fixtures across 309 rules — 1,921 ``fail/``
(must-detect), 1,600 ``pass/`` (must-not-detect) and 61 ``expected_fail/``
(known limitations). These generate 4,050 Rust tests; all pass, 66 are
``#[ignore]``\ d (the ``expected_fail`` tier plus fixtures for rules that
are tracked but not implemented). Regenerate these counts with
``python3 scripts/fixture_provenance.py``.

Tests are auto-generated into Rust test functions from ``.c`` files — no embedded
``#[cfg(test)]`` modules in rule implementation files. Run tests with:

::

    # All tests
    cargo test

    # Tests for a specific rule
    cargo test --package sqc --lib -- rules::cert_c::sig01_c::tests

    # Tests for a category
    cargo test --package sqc --lib -- rules::cert_c::mem

Test cases are derived from patterns documented in the
`SEI CERT C Coding Standard <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard>`_
(formerly hosted on a Confluence wiki at wiki.sei.cmu.edu; the standard
migrated to a static site in 2026 -- ``scripts/scrape_cert_wiki.py`` reads
its page-data JSON API directly rather than scraping rendered HTML).
Each rule's page provides:

- **Non-compliant code examples**: patterns that violate the rule
- **Compliant solutions**: corrected versions of the same patterns
- **Risk assessment**: severity, likelihood, and remediation cost

Test cases map these directly:

- ``fail/`` cases encode non-compliant patterns (expected violations)
- ``pass/`` cases encode compliant solutions (expected clean)

Fixture Provenance
~~~~~~~~~~~~~~~~~~

Not every fixture carries the same evidentiary weight, and a raw pass/fail
count hides the difference. Each fixture declares its origin on a ``Source:``
line in its header comment:

.. list-table::
   :header-rows: 1

   * - Tier
     - Wiki-derived
     - Locally authored
     - Undeclared
     - Total
   * - ``fail/`` (must-detect)
     - 590
     - 1,254
     - 77
     - 1,921
   * - ``pass/`` (must-not-detect)
     - 730
     - 777
     - 93
     - 1,600
   * - ``expected_fail/``
     - 17
     - 39
     - 5
     - 61
   * - **All**
     - **1,337**
     - **2,070**
     - **175**
     - **3,582**

**Wiki-derived** fixtures come from the CERT C standard's own compliant and
non-compliant code examples. They are third-party evidence: SEI wrote them
against the rule text with no knowledge of SqC, so a rule agreeing with them
is a conformance result rather than a self-consistency check. 300 of the 309
rules with fixtures have at least one; the 9 without are regression-tested
only.

**Locally authored** fixtures were written in this repo, almost all of them
to pin a specific defect found in real code or to lock in a false-positive
fix. They are regression evidence and nothing more — we chose both the input
and the expected answer, so they cannot corroborate that SqC reads the
standard correctly.

**Undeclared** fixtures simply predate the header convention. Every one
inspected is locally authored (the ``BRULE-*`` JPL rules, which have no CERT
wiki page at all, and several ``WIN*`` rules), but they are counted
separately rather than assumed.

Regenerate with ``python3 scripts/fixture_provenance.py --containment``.

.. warning::

   The split above is what each fixture *declares*. A wiki example lightly
   edited to compile is still wiki-derived; one rewritten until it matched
   what the checker happens to look for is not, and no header can tell those
   apart. ``scripts/audit_wiki_fixture_staleness.py`` is the independent
   check: it re-fetches each rule's current page and measures what fraction
   of a wiki code block's lines still appear in the fixture claiming to
   derive from it. Of 1,316 wiki fixtures audited across 295 rules, 1,209
   (91.9%) reproduce the current wiki block line-for-line and 21 more are
   above 85% containment — so the tier is overwhelmingly genuine extraction,
   not paraphrase. The remaining 86 (30 substantially edited, 32 mostly
   rewritten, 24 with no overlap against the current page) are the ones
   where only a human can say whether the fixture drifted, the wiki page
   changed under it, or it was never a faithful extraction; 57 are flagged
   stale by that auditor's own threshold.

What the Fixture Corpus Does and Does Not Measure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The corpus is a **conformance and regression gate, not a benchmark.** It is
never reported alongside Juliet or the real-world oracle: those measure
precision against labels SqC did not choose, while most of this corpus is
labeled by the same people who wrote the analyzer.

Scoring the corpus settles how much drift that gate has actually absorbed.
``cargo test`` runs on every push (``.github/workflows/ci.yml``), so a rule
change that breaks any fixture — its own or another rule's — cannot merge:
**zero of the 309 rules fail their own fixtures**, and that is a property of
the gate, not evidence about the rules.

Two limits of the harness are worth stating, because the green result does
not cover them.

**Most fixtures are not tested under the context the analyzer really
builds.** Each test calls ``rule.check()`` directly. A fixture carrying a
``// sqc-test: prescan`` marker is given the scan's own context —
``prescan::prescan_single_file`` (the file-list prescan behind ``-d``,
applied to that fixture alone) and then ``analyze::build_file_analysis`` for
CFGs and value ranges, which is the call ``analyze_one_file`` makes. Only 83
of the 3,582 fixtures carry the marker. The rest are checked with no project
context, no CFGs and no value ranges at all — strictly weaker than any
invocation of the shipped tool.

How much that hides is measured, not estimated. Removing the gate so every
fixture gets the real context was checked fixture by fixture, and each
disagreement was confirmed against the shipped binary, which agrees with the
context-built result every time. The largest cluster had a single cause: the
provenance gate INT30-C, INT31-C and INT32-C share used to return "risky"
whenever ``function_summaries`` was empty, so 56 ``fail/`` fixtures were
reported without the provenance analysis ever running. That fail-open is
gone — the gate now runs in every configuration — and those 56 fixtures moved
to ``expected_fail/``, where their headers record which limitation each one
sits behind: 46 are the gate treating a function parameter as bounded local
state, 10 are a definite-overflow that no value-based channel currently
proves. Restoring detection for either group changes what three high-volume
rules report, so each is tracked as its own benchmarked work rather than
folded into a harness change.

What remains behind the marker gate is small: a handful of ``fail/`` fixtures
(ARR30-C ×2, EXP33-C, INT33-C, MEM30-C) detected only under the weaker
analysis, and one ``pass/`` fixture (MEM31-C's ``safe_wrapper_functions``)
that draws five findings once context exists.

A separate and earlier claim on this page — that scanning the corpus with
the shipped binary finds 17 violations on 11 must-not-detect fixtures — was
an artifact of invoking ``sqc`` with no ``-d``. A scan with no ``-d`` builds
no context for its own target: a single-file target sees sibling ``.h``
declarations only, a directory target sees nothing. Pass ``-d``, even a
directory holding just that one fixture, and all 17 go to zero. Every
benchmark invocation passes ``-d``, so no reported number was affected; the
exposure is a first-touch ``sqc foo.c`` run, tracked separately.

**Cross-rule interference is untested.** A fixture is only ever checked
against its owning rule, so a ``pass/`` fixture for one rule is never
evidence about any other. Running the full rule set over the ``pass/`` tier
produces 19,712 findings from other rules on 1,472 of the fixtures,
concentrated in broad recommendations (EXP12-C, DCL15-C, ERR33-C). **That
number is not a false-positive count**: a fixture written to be compliant
with EXP34-C has no obligation to be clean under DCL15-C, and most of these
are legitimate. It is reported only to show the tier's blind spot has real
volume behind it.

Scoring the ``pass/`` tier with the full rule set also surfaced a
performance defect the per-rule harness cannot see, since a fixture is only
ever run against its owning rule. MEM30-C's own 2,000-level ``pass/``
fixture finishes its MEM30-C unit test in milliseconds, but CON40-C,
EXP33-C and MSC13-C each cost cubic time in its block-nesting depth, and a
parallel full-rule-set scan of the directory holding it aborted outright on
a worker thread's stack. The cause of the cubic term is that
``Node::parent()`` recovers a parent by descending from the tree root, so an
ancestor query per node costs O(depth²); the three rules now prune, carry a
scope chain, or precompute byte ranges instead, and worker threads get an
explicit stack. That file went from 120 s+, 120 s+ and 93 s to 40 ms, 1.8 s
and 1.2 s, and the directory scan completes. Roughly twenty other rules
still sit in the 0.3–3 s band on it for the same reason, which is tracked
separately.

NIST Juliet Test Suite Benchmarking
-----------------------------------

The `NIST Juliet Test Suite v1.3
<https://samate.nist.gov/SARD/test-suites/112>`_ is a collection of 54,484 C/C++
files covering 118 CWE categories, each containing known-bad (``OMITGOOD``) and
known-good (``OMITBAD``) code sections. This provides ground truth for measuring
true positive and false positive rates.

How Juliet Benchmarking Works
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **CWE-matched manifests**: For each CWE, a TOML manifest enables only the
   CERT C rules that map to that CWE (e.g., CWE-476 enables EXP34-C). This
   eliminates noise from unrelated rules.

2. **Per-CWE analysis**: SqC scans each CWE's test cases with its matched manifest.
   Violations in ``bad`` functions are true positives; violations in ``good``
   functions are false positives.

3. **Parallel execution**: CWEs are processed in parallel via Python's
   ``ProcessPoolExecutor`` for fast turnaround (~8-10 min on 4-core, ~3-5 min
   on 24-core).

4. **Results stored in SQLite**: All results go to ``data/benchmarks.db`` with
   per-CWE metrics, per-rule breakdowns, and cross-version comparison support.

Running the benchmark:

::

    # Via CLI
    python -m bench juliet          # Fast mode (CWE-matched rules only)
    python -m bench juliet --full   # Full suite (all rules on all CWEs)

    # Query results
    python -m bench runs            # List all benchmark runs
    python -m bench status RUN_ID   # Check a running benchmark
    python -m bench compare v1 v2   # Compare two runs

Current Results (v0.4.116)
~~~~~~~~~~~~~~~~~~~~~~~~~~

===============================  ==========
Metric                           Value
===============================  ==========
**CWEs Scanned**                 74
**True Positives**               21,770
**False Positives**              4,220
**TP Rate (Precision)**          83.8%
**Per-file Detection Rate**      38.2%
**100% Precision CWEs**          48
**FP Reduction from Baseline**   -99.5%
===============================  ==========

SqC achieves 100% precision (zero false positives) on 48 CWEs including:

- CWE-78 (OS command injection)
- CWE-190 (Integer overflow)
- CWE-481 (Assigning instead of comparing)
- CWE-467 (sizeof on pointer type)
- CWE-252 (Unchecked return value)
- CWE-338 (Weak PRNG)
- CWE-590 (Free memory not on heap)
- CWE-761 (Free not at start of buffer)
- CWE-690 (NULL dereference from return)
- CWE-789 (Uncontrolled memory allocation)

High-precision (>80% TP rate) on several additional CWEs including CWE-191
(98.5%), CWE-127 (81.5%), and CWE-675 (93.0%).

See :doc:`juliet-history` for per-CWE tier breakdowns, or query
``data/benchmarks.db``/``sqc_bench`` Postgres (``get_cwe_detail``) for the
full current per-CWE data.

FP Reduction History
~~~~~~~~~~~~~~~~~~~~

Over 30+ rounds of targeted optimization, SqC has reduced false positives by
99.5% from baseline while improving the TP rate from 41.1% to 83.8%:

========  ==========================================  ==========  =========  =========
Round     Key Changes                                 FP          TP Rate    FP Delta
========  ==========================================  ==========  =========  =========
Baseline  Initial implementation                      839,341     41.1%      --
Round 3   Standard function database                  537,589     42.8%      -198,974
Round 6   Cross-file analysis (``-d``)                327,191     43.1%      -148,622
Round 9   Windows API whitelist                       243,849     43.8%      -52,566
Round 12  CFG + inter-procedural analysis             215,671     44.5%      -28,178
v0.2.23   Built-in C limit macros + const_eval        163,585     44.6%      -12,088
v0.3.37   Fast mode, taint tracking                   9,067       48.4%      --
v0.3.119  74 CWEs (6 new), precision improvements     11,702      67.5%      +2,635
v0.4.116  VRA, macro expansion, field-sensitive        4,220       83.8%      -7,482
          alias tracking, per-rule tuning
========  ==========================================  ==========  =========  =========

*Note: v0.3.37 and later use fast mode (CWE-matched rules only); earlier rounds
used full-suite scoring, so absolute FP counts are not directly comparable across
the two methodologies. TP rate is the consistent metric. The FP increase from
v0.3.37 to v0.3.119 reflects expanded CWE scope (68 → 74 CWEs) and more test files,
not regression — TP rate improved 19.1 percentage points over the same span. The
v0.3.119 → v0.4.116 span (dozens of intermediate releases; see
``docs/juliet-history.rst``) cut FP by more than half again while gaining a
further 16.3 points of TP rate.*

Real-World Code Analysis
------------------------

SqC is benchmarked against 7 real-world open-source C codebases alongside
cppcheck and clang-tidy:

===========  =========  =============  ============  ============  ============
Project      C Files    LOC            sqc           cppcheck      clang-tidy
===========  =========  =============  ============  ============  ============
libcrc       9          1,034          391           40            2
lua          33         31,637         3,068         49            107
raylib       17         56,107         5,213         1,060         469
mosquitto    120        39,368         11,225        277           44
curl         222        186,220        16,085        556           116
sqlite       125        218,733        31,319        503           137
hostap       430        589,724        37,432        1,761         1,710
**Total**    **956**    **1,122,823**  **104,733**   **4,246**     **2,585**
===========  =========  =============  ============  ============  ============

*Data from sqc v0.4.120, cppcheck 2.10, clang-tidy 21.1.6 (run #118).*

**Why sqc reports more violations**: SqC implements 311 CERT C rules, 307 enabled by default (both
advisory and mandatory) while cppcheck and clang-tidy implement ~20 checks each.
The difference reflects rule coverage breadth, not false positive rate.

**Measured precision/recall**: 6.2% precision / 91.7% recall against the
adjudicated ground-truth oracle (``python -m bench realworld-score 118``) —
the empirical floor across all 7 projects, not a raw violation-count
comparison, from a run superseded many times since. Current figures are in
README.md's Benchmark Highlights table; the full version history and
per-rule breakdowns live in ``sqc_bench`` Postgres, queryable via
``benchmarking_db``'s MCP servers or, on the benchmark host, its CLI (see
that repo's README) -- not in a hand-maintained file here
(``REALWORLD_RESULTS.md``, which carried this role until it was retired
2026-09-03). Oracle methodology, including the DCL31-C worked example of
why a per-rule 0.0% can be a corpus artifact rather than a rule defect, is
in README.md's "Rule-suite coverage" section.

Cross-Tool Comparison Methodology
----------------------------------

Apples-to-Apples Concerns
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Rule coverage**: cppcheck/clang-tidy implement ~20 checks each vs. sqc's
   307 enabled rules. Raw violation counts are not directly comparable.

2. **Translation unit scope**: Use consistent scope (cross-file ``-d`` flag or
   single-file) when comparing.

3. **Preprocessor handling**: cppcheck evaluates all ``#ifdef`` configs;
   clang-tidy sees one; sqc analyzes all visible branches. For Juliet, compile
   with ``-DOMITBAD``/``-DOMITGOOD`` when needed.

4. **Standard library awareness**: cppcheck/clang-tidy have built-in stdlib
   knowledge. sqc uses ``std_functions.rs`` database.

5. **Severity mapping**: cppcheck ``error/warning/style``, clang-tidy
   ``error/warning``, sqc ``Low/Medium/High/Critical``. Map conservatively.

Recommended Comparison Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Pick a representative codebase or CWE subset
2. Run all tools with consistent flags
3. Normalize to ``(file, line, rule/check-id)`` tuples
4. Classify as TP/FP using Juliet ground truth
5. Compute precision, recall, F1 per tool
6. Restrict to overlapping rules for fair comparison

Published CERT-C Results
~~~~~~~~~~~~~~~~~~~~~~~~

No published CERT-C violation rates per KLOC on production open-source code
exist (Goseva2015). Valid comparison strategies:

1. sqc vs. cppcheck vs. clang-tidy on same codebase (done for 5 projects)
2. sqc on JasPer with reference to SEI SCALe 2015 report (only named CERT-C audit)
3. sqc TP rate vs. TrustInSoft's synthetic CERT-C benchmark as upper bound

For academic context on tool effectiveness, FP rates, and the Juliet benchmark
methodology, see :doc:`bibliography`.

Test Infrastructure Details
---------------------------

Build-Time Test Generation
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Test files**: ``.c`` files in ``src/rules/cert_c/CATEGORY/RULE-ID/tests/{fail,pass}/``
2. **Build-time generation**: ``build.rs`` walks the test directories and generates
   Rust test functions in ``$OUT_DIR/integration_tests.rs``
3. **Test harness**: ``src/rules/cert_c/integration.rs`` includes the generated
   tests, records results, and produces ``docs/test-summary.md``
4. **Test logic**:

   - ``fail/`` tests: parse the C file, run the rule, assert violations > 0
   - ``pass/`` tests: parse the C file, run the rule, assert violations == 0

5. **Disabled rules**: if ``RULE-ID.toml`` has ``enabled = false``, tests are
   generated with ``#[ignore]``

Test File Naming Conventions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

=================  ==================  ======  ====================================
Prefix             Origin              Count   Description
=================  ==================  ======  ====================================
``wiki_*``         CERT wiki examples  ~1,120  Directly from CERT C Coding Standard
``testcases_*``    AI-generated        ~1,860  Broader pattern coverage
Other              Mixed               ~80     Various
=================  ==================  ======  ====================================

Test Distribution by Rule Size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

=================  ======  =========================================
Test Count Range   Rules   Examples
=================  ======  =========================================
1–2 tests          3       Remaining sparse rules
3–5 tests          167     Most wiki-sourced rules
6–10 tests         70      DCL06-C, ENV31-C, INT36-C, etc.
11–20 tests        12      INT31-C, DCL37-C, EXP43-C, etc.
21–50 tests        30      Most "large suite" rules
51–100 tests       8       ARR30-C, STR31-C, INT32-C, MEM31-C, etc.
=================  ======  =========================================

What Tests Do NOT Cover
~~~~~~~~~~~~~~~~~~~~~~~

- **Inter-procedural analysis**: No tests exercise ``-d`` directory scanning,
  prescan, or cross-file function resolution
- **Project context**: No tests exercise ``set_project_context()`` or
  ``set_function_cfgs()``
- **CFG/dataflow**: The CFG builder, null state analysis, value-range analysis,
  and init state analysis have embedded Rust unit tests but no integration-level
  C test coverage
- **CLI flags**: No tests for ``--diff``, ``--export``, ``--format``, ``--include-path``,
  ``--save-prescan``, ``--load-prescan``, ``--jobs``
- **Suppression**: No tests for ``.sqc-suppress.toml`` hash-based suppression

Coverage Gate
~~~~~~~~~~~~~

Line coverage is enforced at **75%** via ``scripts/coverage-gate.sh``, shared by
the pre-commit hook and GitHub Actions CI pipeline. The script:

- Runs tests via ``cargo llvm-cov``
- Produces ``lcov.info`` (publishable as CI artifact)
- Excludes from threshold: ``ui/`` (GUI), ``main.rs`` (CLI entry),
  ``integration.rs`` (test harness), ``progress.rs`` (terminal I/O),
  ``export/`` (SARIF/Excel output), ``files/`` (git/directory I/O),
  ``manifest/`` (TOML config loading)
- Fails with clear output showing current coverage and largest uncovered files

Embedded Rust Unit Tests
~~~~~~~~~~~~~~~~~~~~~~~~

Files in ``src/analyze/`` with ``#[cfg(test)]`` modules:

=========================  ======  ======
File                       Lines   Tests
=========================  ======  ======
prescan.rs                 2,741   31
const_eval.rs              2,071   43
value_range.rs             1,778   13
init_state.rs              1,729   6
null_state.rs              1,720   9
function_summary.rs        1,175   14
suppression.rs             1,070   34
dataflow.rs                988     19
cfg.rs                     761     7
mod.rs                     705     10
context.rs                 93      0
=========================  ======  ======

Rule implementation files with embedded tests (against project convention):
INT34-C, INT33-C, CON31-C, FIO01-C, EXP32-C, EXP30-C, EXP33-C, EXP08-C,
EXP42-C, DCL08-C, STR10-C.

Known Rule Implementation Gaps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following rule-level analysis limitations were discovered during test coverage
work. These are cases where valid C patterns should pass/fail but the rule
implementation cannot detect them correctly.

- **INT00-C**: ``find_type_in_source()`` only matches ``TYPE VAR;`` or
  ``TYPE VAR,``, not ``TYPE VAR = expr;``. Variables with initializers get type
  "unknown", so format specifier checks cannot validate ``%ld`` with
  ``long x = 42;``.

- **INT08-C**: Positive-only. A violation is reported only where ``const_eval``
  can bound every operand and prove the promoted result leaves ``int``; an
  operand it cannot resolve (a struct field, a subscript, a call result) yields
  no finding rather than an unproven one. Genuine narrow-type overflow behind
  an unresolvable operand is therefore missed.

- **INT34-C**: ``is_likely_unsigned()`` parameter declaration check doesn't
  traverse tree-sitter's function parameter hierarchy. Also,
  ``checks_shift_bounds()`` doesn't handle reversed comparison form
  ``N <= var`` (only ``var >= N``).

- **POS50-C**: ``is_declared_in_function()`` doesn't distinguish ``static`` from
  automatic storage. Static locals passed to ``pthread_create()`` produce FPs.

- **FLP00-C**: Only detects float equality in ``if``-conditions, not in return
  statements or assignments.

- **EXP40-C**: ``is_const_qualified()`` returns false for identifiers — cannot
  determine if a variable was declared ``const`` without a symbol table.

- **STR03-C**: ``strncpy()`` and ``snprintf()`` always trigger violations
  regardless of whether null-termination is manually added afterward.


Benchmark Caveats And Rule-Suite Coverage
-----------------------------------------

Moved out of ``README.md`` (2026-09-03), which should say how well SqC works
rather than how the measurement is constructed. These are the caveats a
maintainer or a reviewer needs; see :doc:`tool-comparison` for how SqC scores
against other analysers.

Numbers below are **not** auto-refreshed with README's highlights table, and
that is deliberate: a caveat whose job is to say what a figure does not cover
can do that without restating the figure. An earlier version of these notes
carried the run's version, its unlabeled percentage and the recall figure, and
when the table was refreshed onto the canonical basis those three did not move
with it — the table said 93.9% recall and 89.8% coverage while the prose eight
lines below still said 93.7% and 11.8%. Treat any number here as illustrative
of a *gap*, and ``python -m bench compare`` or ``sqc_bench`` Postgres as the
current measurement.

Published figures are pinned to the last validly-adjudicated run. Rule-logic
commits landed since that run are not reflected, and a current figure requires
delta-adjudicating the newer unlabeled findings first — the protocol for that
lives in the repository's agent instructions, not here, because it is a
maintainer workflow rather than a user-facing one.

Juliet TP rate is not the ceiling signal — the flaw-hit rate is
---------------------------------------------------------------

**Juliet TP Rate** above is the share of sqc's Juliet findings that are true
positives. It says how clean the output is, not how much of the suite's
planted defect set sqc actually locates. That second question is the
**flaw-hit rate** — the fraction of Juliet's known flaw lines sqc lands a
finding on — and it moves independently: as of v0.4.321 it was 12.9%
(17,100 of 132,406 flaw lines), essentially flat for weeks while the TP
rate above was moving. Quoting only the TP rate overstates the tool; this
paragraph is not auto-refreshed with the table above (deliberately, per the
lesson in the note above this section — see ``python -m bench compare`` or
``sqc_bench`` Postgres for the current figure), so treat the number here as
illustrative of the *gap*, not as a current measurement.

Per-file detection rate (in the table above) sits between the two: sqc
flags something in over a third of flawed files, but lands on the specific
planted flaw line in roughly an eighth of cases. When judging headroom, the
flaw-hit rate is the honest signal to watch for movement, not the TP rate.

Juliet also exercises only part of the rule suite — 127 rules have any
Juliet true positive, out of 311 implemented. See "Rule-suite coverage"
below for what that leaves unmeasured, and
[``docs/juliet-history.rst``](docs/juliet-history.rst) for the full
round-by-round version history behind the table above.

Rule-suite coverage
-------------------

Precision and recall above are aggregates over the rules that actually fire
on the benchmark corpora. They say nothing about the rest of the suite, and
the rest of the suite is substantial (measured 2026-09-02, run #226):

.. list-table::
   :header-rows: 1
   :widths: 62 38

   * -
     - Rules
   * - Implemented
     - **311** (307 enabled by default)
   * - Have true-positive evidence somewhere
     - **186** — 127 from Juliet, 144 from real-world TP/FN labels
   * - **No true-positive evidence anywhere**
     - **125 (40%)**
   * - · fire on the corpus, but have only ever produced FPs
     - 65
   * - · never fire on the nine projects at all
     - 60

A rule in that last group has never been shown to detect anything real —
but that is usually a statement about the corpora, not about the rule. The
nine real-world projects are mature, warning-clean C, which is the opposite
population from sqc's nominal use case (newer, in-progress, possibly
non-compiling code wired into CI/CD early — sqc needs no build system, which
is the whole point). A rule whose defect cannot survive review in released
software is structurally incapable of scoring a true positive there. The 60
never-firing rules include ``WIN02-C`` and ``WIN30-C`` — Windows rules against
Linux-only corpora, categorically inapplicable rather than broken (rule
applicability is the user's lever, by design: manifest scoping and
suppression exist so the user decides which rules apply to their code,
rather than detection logic silently deciding for them).

**Worked example of why a per-rule 0.0% is sometimes a corpus artifact, not
a rule defect** (task 692): ``DCL31-C`` shows 364 findings, 324 labeled, 0
TP — 0.0% precision. That figure measures sqc's header reachability, not
the rule's quality. ``mosquitto`` alone goes from 1,365 ``DCL31-C`` findings
with no ``-I`` to 0 with ``-I /usr/include``. The rule guards a genuine defect —
under C89 an implicit declaration makes the compiler assume ``int f()``, so
the return type is misread, no argument checking happens, and a returned
pointer is truncated on LP64; C99 removed implicit declarations and C23
makes them an error — on code this corpus does not contain. Quoting that
number as a rule-quality measure is a category error.

The material to close this gap already exists in the repo: **1,975
must-detect** fixtures (``src/rules/cert_c/*/*/tests/fail/*.c``) and **1,594
must-not-detect** fixtures (``src/rules/cert_c/*/*/tests/pass/*.c``), labeled
by construction — 309 distinct rules carry at least one. 121 of the 125
unvalidated rules already have a must-detect fixture — only ``FLP01-C``,
``MSC18-C``, ``MSC25-C`` and ``ENV04-C`` have none. Of those, only
``FLP01-C`` is implemented (``flp01_c.rs`` exists) and simply lacks a fail
fixture. ``MSC18-C``, ``MSC25-C`` and ``ENV04-C`` have no detection logic at
all — a must-detect fixture for them cannot pass, so a fixture is not the
missing piece; see the "Tracked but not implemented" section of
:doc:`configuration` for why they are unimplemented.
Today those fixtures run only as pass/fail unit tests and feed no measured
metric, so a rule can be fully exercised by tests and still read as having
no detection evidence.

Note what that does *not* license. The corpus is a conformance and
regression gate and is never reported alongside Juliet or the real-world
oracle — see `What the Fixture Corpus Does and Does Not Measure`_ for the
scoring result and for the two blind spots (harness context divergence and
cross-rule interference) that the green suite does not cover. Only the
wiki-derived tier is third-party evidence, and `Fixture Provenance`_ gives
that split.
