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

2. **Real-World Open-Source Projects** — 5 codebases (libcrc, sqlite, mosquitto,
   curl, hostap) analyzed by sqc, cppcheck, and clang-tidy. No ground truth —
   measures violation counts, rule distribution, and cross-tool agreement.

**Why both**:

- **Juliet** provides precision metrics (TP/FP) but is synthetic single-file code
- **Real-world** tests scalability, noise levels, and cross-file analysis on production code
- Rule improvements are validated on Juliet for TP/FP impact, then verified on
  real-world for noise reduction

**Benchmark cadence**:

- **After every significant rule change**: Juliet benchmark (MCP server, ~10 min)
- **After version milestones**: Full real-world benchmark (MCP server, all 5
  codebases × 3 tools)
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

**Current coverage**: 3,322 tests across 290 rules (~3,070 C test files,
~1,820 fail + ~1,250 pass). All tests pass; zero duplicates.

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
`SEI CERT C Coding Standard wiki <https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard>`_.
Each rule's wiki page provides:

- **Non-compliant code examples**: patterns that violate the rule
- **Compliant solutions**: corrected versions of the same patterns
- **Risk assessment**: severity, likelihood, and remediation cost

Test cases map these directly:

- ``fail/`` cases encode non-compliant patterns (expected violations)
- ``pass/`` cases encode compliant solutions (expected clean)

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

Current Results (v0.3.39)
~~~~~~~~~~~~~~~~~~~~~~~~~

===============================  ==========
Metric                           Value
===============================  ==========
**CWEs Scanned**                 68
**True Positives**               8,508
**False Positives**              9,067
**TP Rate (Precision)**          48.4%
**Per-file Detection Rate**      14.3%
**100% Precision CWEs**          16
**FP Reduction from Baseline**   -80.7%
===============================  ==========

SqC achieves 100% precision (zero false positives) on 16 CWEs including:

- CWE-481 (Assigning instead of comparing)
- CWE-467 (sizeof on pointer type)
- CWE-252 (Unchecked return value)
- CWE-338 (Weak PRNG)
- CWE-590 (Free memory not on heap)
- CWE-761 (Free not at start of buffer)

High-precision (>50% TP rate) on 11 additional CWEs including CWE-690 (94.4%),
CWE-197 (67.5%), and CWE-134 (59.9%).

See ``JULIET_RESULTS.md`` and ``JULIET_COVERAGE.md`` for full per-CWE breakdowns.

FP Reduction History
~~~~~~~~~~~~~~~~~~~~

Over 30+ rounds of targeted optimization, SqC has reduced false positives by
80.7% from baseline while improving the TP rate from 41.1% to 48.4%:

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
========  ==========================================  ==========  =========  =========

*Note: v0.3.37 numbers use fast mode (CWE-matched rules only) while earlier
rounds used full-suite scoring, so absolute FP counts are not directly comparable.
TP rate is the consistent metric across methodologies.*

Real-World Code Analysis
------------------------

SqC is benchmarked against 5 real-world open-source C codebases alongside
cppcheck and clang-tidy:

===========  =========  ========  ===========  ============  ============
Project      C Files    LOC       sqc          cppcheck      clang-tidy
===========  =========  ========  ===========  ============  ============
libcrc       16         2,130     306          43            2
mosquitto    384        88,717    15,800       747           44
curl         697        240,412   24,665       519           114
sqlite       310        402,321   52,978       1,181         135
hostap       505        541,441   59,407       2,118         2,279
**Total**    **1,912**  **1.3M**  **153,156**  **4,608**     **2,574**
===========  =========  ========  ===========  ============  ============

*Data from sqc v0.3.39, cppcheck 2.10, clang-tidy 21.1.6.*

**Why sqc reports more violations**: SqC implements 283 CERT C rules (both
advisory and mandatory) while cppcheck and clang-tidy implement ~20 checks each.
The difference reflects rule coverage breadth, not false positive rate.

**Trend**: SqC violations on real-world code have decreased steadily from
548,027 (v0.2.7) to 153,156 (v0.3.39) -- a 72% reduction through targeted
FP reduction, cross-file analysis, and improved type inference.

See ``REALWORLD_RESULTS.md`` for full version history and per-rule breakdowns.

Cross-Tool Comparison Methodology
----------------------------------

Apples-to-Apples Concerns
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Rule coverage**: cppcheck/clang-tidy implement ~20 checks each vs. sqc's
   283 rules. Raw violation counts are not directly comparable.

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
- **CLI flags**: No tests for ``--diff``, ``--export``, ``--format``, ``-I``,
  ``--save-prescan``, ``--load-prescan``
- **Suppression**: No tests for ``.sqc-suppress.toml`` hash-based suppression

Coverage Gate
~~~~~~~~~~~~~

Line coverage is enforced at **75%** via ``scripts/coverage-gate.sh``, shared by
the pre-commit hook and ADO CI pipeline. The script:

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

- **INT08-C**: Rule does not recognize ``SHRT_MAX`` / ``CHAR_MAX`` guard checks
  before narrow-type arithmetic.

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
