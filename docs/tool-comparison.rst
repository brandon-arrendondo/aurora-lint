=========================
Comparison To Other Tools
=========================

Where SqC sits against the other static analysers you would consider for C.
The short version is in ``README.md``'s **Alternatives** section; this page is
the measurement behind it.

Read the coverage table first. Per-CWE precision is only meaningful on the
CWEs a given tool actually covers, and those sets differ by a factor of five.

The Tools
=========

.. list-table::
   :header-rows: 1
   :widths: 14 20 12 14 40

   * - Tool
     - Version measured
     - Needs a build?
     - CERT C rules
     - Notes
   * - `SqC <https://github.com/brandon-arrendondo/tools_sqc>`_
     - 0.4.321 / 0.4.332
     - **No**
     - 311 implemented
     - tree-sitter, no preprocessor. Uses ``compile_commands.json`` and
       ``-I``/``-D`` when given; never requires them.
   * - `cppcheck <https://cppcheck.sourceforge.io/>`_
     - 2.10
     - No
     - ~20 via ``--addon=cert``
     - Runs unbuilt like SqC. The cert addon is **not** enabled in our runs,
       so its ids are native (``nullPointer``, ``uninitvar``).
   * - `clang-tidy <https://clang.llvm.org/extra/clang-tidy/>`_
     - LLVM 21.1
     - **Yes**
     - ~20 native ``cert-*`` checks
     - Wants a compilation database; without correct flags it fails or
       silently under-reports.
   * - `Frama-C <https://frama-c.com/>`_
     - 32.0 (Germanium)
     - **Yes**
     - n/a (abstract interpretation, not rule-indexed)
     - Requires preprocessed input *and* an entry point per analysis. Sound-by
       -design, so it reports more. 33.0 (Arsenic) is what
       ``install-static-analyzers.yml`` now provisions; the Juliet numbers
       here are 32.0's.
   * - `Infer <https://fbinfer.com/>`_
     - v1.2.0
     - **Yes**
     - n/a (bug-type indexed)
     - Captures a compilation, then analyses.

Coverage Is The Difference
==========================

.. list-table::
   :header-rows: 1
   :widths: 16 14 14 56

   * - Tool
     - Juliet CWEs
     - Real-world
     - 
   * - SqC
     - **79**
     - 9 projects
     - 311 CERT C rules across 17 categories
   * - clang-tidy
     - 16
     - 8 projects
     - ~20 ``cert-*`` checks
   * - cppcheck
     - 16
     - 8 projects
     - ~20 CERT mappings via an addon we do not enable
   * - Infer
     - 11
     - supported, not yet swept
     - Memory-safety and concurrency bug types
   * - Frama-C
     - 6
     - supported, not yet swept
     - Value analysis; not organised as rules

.. note::

   **PARTLY RESOLVED** — ``python -m bench realworld-run --tool infer`` and
   ``--tool frama-c`` now work against all nine corpora (tools_sqc task 767).
   Both are driven from each checkout's ``compile_commands.json``, which
   ``playbooks/setup-compile-commands.yml`` generates for all nine —
   including seL4, hostap and pure-ftpd, whose supposed unbuildability was
   the original blocker and is no longer true.

   What remains is the **sweep itself**, which is a multi-hour job and wants
   scheduling through ``benchmarking_db``'s queue rather than a local
   invocation. Until it runs, this table has no Frama-C or Infer real-world
   column, and neither does the Speed table below.

.. warning::

   When those columns do land, **both are partial scans and must be labelled
   as such.**

   *Infer* captures only what preprocesses.
   ``setup-compile-commands.yml`` restores each checkout to pristine after
   building it, which deletes generated headers the compile database still
   references — 2 of libcrc's 9 in-scope translation units cannot be
   captured for that reason.

   *Frama-C* is partial by construction: EVA analyses one entry point at a
   time and a real codebase has no single one, so the runner walks entry
   points round-robin across translation units under a wall-clock budget. A
   Frama-C finding count is a **floor**, precision is the only defensible
   cross-tool statistic to draw from it, and **recall is not expressible from
   it at all**. See ``docs/design/framac-realworld.md``.

   Every run records a ``coverage`` block — entry points reached, capture
   failures, whether the budget ran out — in its result file, its
   ``.meta.json``, and the ``realworld_results.coverage`` column. Any table
   carrying one of these columns should carry the coverage percentage beside
   it.

Juliet, On The Overlap
======================

Juliet is the only benchmark where every tool can be scored the same way: the
suite labels its own planted defects, so TP/FP needs no adjudication. This is
SqC v0.4.321 (run ``sqc-0.4.321-daff4cf0``) against each competitor on the
CWEs that competitor covers — precision, so higher is better.

.. list-table::
   :header-rows: 1
   :widths: 12 10 10 10 12 12 12 12

   * - CWE
     - SqC TP
     - SqC FP
     - SqC
     - clang-tidy
     - cppcheck
     - Frama-C
     - Infer
   * - 121
     - 2518
     - 848
     - 74.8%
     - **100.0%**
     - 40.6%
     - –
     - 38.8%
   * - 122
     - 1495
     - 291
     - 83.7%
     - **98.8%**
     - 45.0%
     - –
     - 37.8%
   * - 124
     - 652
     - 268
     - 70.9%
     - **97.0%**
     - 40.5%
     - –
     - 33.9%
   * - 127
     - 720
     - 100
     - 87.8%
     - **100.0%**
     - 42.7%
     - –
     - 33.9%
   * - 190
     - 1498
     - 0
     - **100.0%**
     - **100.0%**
     - 27.5%
     - 58.1%
     - –
   * - 191
     - 1211
     - 18
     - 98.5%
     - **100.0%**
     - 27.2%
     - 63.1%
     - –
   * - 197
     - 468
     - 0
     - **100.0%**
     - **100.0%**
     - 40.0%
     - **100.0%**
     - –
   * - 369
     - 544
     - 342
     - 61.4%
     - **100.0%**
     - 27.4%
     - 43.4%
     - –
   * - 401
     - 779
     - 391
     - 66.6%
     - **100.0%**
     - 25.7%
     - –
     - 54.7%
   * - 415
     - 468
     - 288
     - 61.9%
     - **84.2%**
     - 33.8%
     - –
     - 63.0%
   * - 416
     - 367
     - 36
     - **91.1%**
     - 60.3%
     - 29.8%
     - –
     - 2.0%
   * - 476
     - 370
     - 175
     - 67.9%
     - **100.0%**
     - 39.7%
     - 64.2%
     - 66.1%
   * - 680
     - 352
     - 0
     - **100.0%**
     - **100.0%**
     - 40.8%
     - 82.6%
     - –
   * - 690
     - 558
     - 0
     - **100.0%**
     - **100.0%**
     - 45.7%
     - –
     - 60.0%
   * - 761
     - 276
     - 0
     - **100.0%**
     - **100.0%**
     - 45.7%
     - –
     - 58.1%

**clang-tidy wins the overlap, and it is not close.** On the 16 CWEs it
covers: clang-tidy 13,952 TP / 116 FP (99.2%), SqC 12,276 TP / 2,757 FP
(81.7%). It is at 100% on eleven of them, and it finds *more* true positives
than SqC does on the same CWEs.

Two things soften that without overturning it. 1,170 of clang-tidy's findings
(8%) are ``unknown`` — neither matched to a planted flaw nor confidently
outside one — against 75 for cppcheck and 0 for Frama-C and Infer. And it
gets there by compiling the code, which is the trade described below.

SqC leads on CWE-416 (use-after-free, 91.1% vs 60.3%) and matches at 100% on
six CWEs. Everywhere else on the overlap it is behind, and that is the honest
read: **SqC's case is not that it is more precise than clang-tidy on the
sixteen CWEs clang-tidy checks. It is the other 63 CWEs, the other 290 rules,
and not needing your build.**

Speed
=====

Real-world suite, 8 projects, run 215:

.. list-table::
   :header-rows: 1
   :widths: 18 18 20 44

   * - Tool
     - Findings
     - Wall clock
     - 
   * - SqC
     - 69,354
     - ~1,190 s
     - See the TODO below — run 215 recorded 0.0 s for two projects.
   * - clang-tidy
     - 2,694
     - 501 s
     - Excludes the time to produce a compilation database.
   * - cppcheck
     - 4,258
     - **11,452 s**
     - Over 3 hours. mosquitto alone took 3,578 s.

.. note::

   **TODO** — run 215's SqC rows for ``hostap`` and ``sqlite`` both record
   ``duration_s = 0.0``, so its recorded SqC total is 490.9 s. The ~1,190 s
   above substitutes those two projects' run-229 figures (450.4 s and
   253.1 s), which mixes runs and is therefore not a citable number. Quoting
   the 490.9 s would be wrong in SqC's favour, which is worse. Tracked as
   benchmarking_db task 740.

Frama-C and Infer have no row here yet — see the note above. For an order of
magnitude on what the Frama-C row will cost: its 6-CWE Juliet run took
9,914 s over files averaging under 200 lines, which is why its real-world
mode is budget-bounded rather than exhaustive.

On Juliet, where CWE subsets differ: cppcheck 895 s over 16 CWEs, clang-tidy
5,944 s over 16, Infer 5,019 s over 11, Frama-C 9,914 s over 6.

Real-World Precision, Per Rule
==============================

.. note::

   **TODO** — this section cannot be written yet.

   ``realworld_violations`` holds 17.5M SqC rows and **zero** for cppcheck or
   clang-tidy. The runner's ``_parse_cppcheck_xml`` and
   ``_parse_clang_tidy_txt`` return a count per check id and discard file and
   line, so there is no coordinate to adjudicate — and a count cannot be
   labelled TP or FP by anyone. Competitor real-world precision is therefore
   unmeasured, and the Juliet table above is the only cross-tool precision
   figure that exists.

   cppcheck additionally needs a native-id-to-CERT-C mapping (or
   ``--addon=cert`` enabled) before a per-rule table is even expressible.

   Tracked as tools_sqc task 766 (capture) and benchmarking_db task 740
   (ingest, plus the ``ground_truth`` key collision that adjudicating a
   second tool at the same coordinate would create).

.. note::

   **TODO** — the competitor Juliet runs are from 2026-04-03/04 and the SqC
   run is from 2026-09-02. Competitor versions move slowly and five months of
   SqC improvement makes the comparison generous to SqC rather than to a
   rival, so the direction is safe — but a single-date table is what a
   reader deserves. Tracked as tools_sqc task 768.

What The Trade Actually Is
==========================

Every tool that beats SqC on precision above does it by compiling the code.
clang-tidy, Frama-C and Infer all need a working build and correct flags;
with a real preprocessor they know which branches exist, what a macro
expands to, and what a type is, and they are right more often as a result.

SqC parses source as written. That is why it runs on a partial checkout, a
tree you cannot build, or a file that was generated a moment ago — and it is
also why it has a macro-expansion engine, a suppression system, and a
false-positive backlog as substantial as its rule backlog. The precision gap
on those sixteen CWEs is the price of the property that makes it useful
elsewhere.

cppcheck is the honest control here: it also runs unbuilt, and on the same
sixteen CWEs it scores 36.4% to SqC's 81.7%, at roughly ten times the wall
clock.
