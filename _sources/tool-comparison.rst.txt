=========================
Comparison To Other Tools
=========================

Where aurora-lint sits against the other static analysers you would consider for C.
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
   * - `aurora-lint <https://github.com/brandon-arrendondo/tools_sqc>`_
     - 0.4.321 / 0.4.332
     - **No**
     - 311 implemented
     - tree-sitter, no preprocessor. Uses ``compile_commands.json`` and
       ``-I``/``-D`` when given; never requires them.
   * - `cppcheck <https://cppcheck.sourceforge.io/>`_
     - 2.13.0
     - No
     - ~20 via ``--addon=cert``
     - Runs unbuilt like aurora-lint. The cert addon is **not** enabled in our runs,
       so its ids are native (``nullPointer``, ``uninitvar``).
   * - `clang-tidy <https://clang.llvm.org/extra/clang-tidy/>`_
     - LLVM 21.1.8
     - **Yes**
     - ~20 native ``cert-*`` checks
     - Wants a compilation database; without correct flags it fails or
       silently under-reports.
   * - `Frama-C <https://frama-c.com/>`_
     - 33.0 (Arsenic)
     - **Yes**
     - n/a (abstract interpretation, not rule-indexed)
     - Requires preprocessed input *and* an entry point per analysis. Sound-by
       -design, so it reports more. 32.0 (Germanium) and 33.0 (Arsenic)
       produce identical Juliet numbers — see the re-measurement note below.
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
   * - aurora-lint
     - **75**
     - 9 projects
     - 311 CERT C rules across 17 categories
   * - clang-tidy
     - 15
     - 8 projects
     - ~20 ``cert-*`` checks
   * - cppcheck
     - 15
     - 8 projects
     - ~20 CERT mappings via an addon we do not enable
   * - Infer
     - 10
     - supported, not yet swept
     - Memory-safety and concurrency bug types
   * - Frama-C
     - 6
     - supported, not yet swept
     - Value analysis; not organised as rules

.. note::

   aurora-lint's 75 is CWEs **measured**, on the same rule as every other count here.
   The runner enumerates all 118 Juliet CWE directories and aurora-lint's list covers
   79 of them, but four — CWE-23, CWE-672, CWE-676 and CWE-762 — hold no
   ``.c`` files at all, so aurora-lint correctly scans none of them. Counting a
   directory it declined would credit it with coverage it does not have.
   Verified across 52 completed runs, which agree on exactly those four; it
   is a property of the Juliet corpus rather than of any run.

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
aurora-lint v0.4.321 (run ``sqc-0.4.321-daff4cf0``) against each competitor on the
CWEs that competitor covers — precision, so higher is better.

.. list-table::
   :header-rows: 1
   :widths: 12 10 10 10 12 12 12 12

   * - CWE
     - aurora-lint TP
     - aurora-lint FP
     - aurora-lint
     - clang-tidy
     - cppcheck
     - Frama-C
     - Infer
   * - 121
     - 2518
     - 848
     - 74.8%
     - **100.0%**
     - 40.9%
     - –
     - 38.8%
   * - 122
     - 1495
     - 291
     - 83.7%
     - **98.8%**
     - 44.2%
     - –
     - 37.8%
   * - 124
     - 652
     - 268
     - 70.9%
     - **97.0%**
     - 40.2%
     - –
     - 33.9%
   * - 127
     - 720
     - 100
     - 87.8%
     - **100.0%**
     - 40.8%
     - –
     - 33.9%
   * - 190
     - 1498
     - 0
     - **100.0%**
     - **100.0%**
     - 27.6%
     - 58.1%
     - –
   * - 191
     - 1211
     - 18
     - 98.5%
     - **100.0%**
     - 27.9%
     - 63.1%
     - –
   * - 197
     - 468
     - 0
     - **100.0%**
     - **100.0%**
     - 40.7%
     - **100.0%**
     - –
   * - 369
     - 544
     - 342
     - 61.4%
     - **100.0%**
     - 27.6%
     - 43.4%
     - –
   * - 401
     - 779
     - 391
     - 66.6%
     - **100.0%**
     - 29.1%
     - –
     - 54.7%
   * - 415
     - 468
     - 288
     - 61.9%
     - **84.2%**
     - 31.8%
     - –
     - 63.0%
   * - 416
     - 367
     - 36
     - **91.1%**
     - 60.3%
     - 32.0%
     - –
     - 2.0%
   * - 476
     - 370
     - 175
     - 67.9%
     - **100.0%**
     - 34.5%
     - 64.2%
     - 66.1%
   * - 680
     - 352
     - 0
     - **100.0%**
     - **100.0%**
     - 40.9%
     - 82.6%
     - –
   * - 690
     - 558
     - 0
     - **100.0%**
     - **100.0%**
     - 42.7%
     - –
     - 60.0%
   * - 761
     - 276
     - 0
     - **100.0%**
     - **100.0%**
     - 44.8%
     - –
     - 58.1%

**clang-tidy wins the overlap, and it is not close.** On the 15 CWEs it
covers: clang-tidy 13,952 TP / 116 FP (99.2%), aurora-lint 12,276 TP / 2,757 FP
(81.7%). It is at 100% on eleven of them, and it finds *more* true positives
than aurora-lint does on the same CWEs.

Two things soften that without overturning it. 1,170 of clang-tidy's findings
(8%) are ``unknown`` — neither matched to a planted flaw nor confidently
outside one — against 75 for cppcheck and 0 for Frama-C and Infer. And it
gets there by compiling the code, which is the trade described below.

aurora-lint leads on CWE-416 (use-after-free, 91.1% vs 60.3%) and matches at 100% on
six CWEs. Everywhere else on the overlap it is behind, and that is the honest
read: **aurora-lint's case is not that it is more precise than clang-tidy on the
fifteen CWEs clang-tidy checks. It is the other 60 CWEs, the other 290 rules,
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
   * - aurora-lint
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

   **TODO** — run 215's aurora-lint rows for ``hostap`` and ``sqlite`` both record
   ``duration_s = 0.0``, so its recorded aurora-lint total is 490.9 s. The ~1,190 s
   above substitutes those two projects' run-229 figures (450.4 s and
   253.1 s), which mixes runs and is therefore not a citable number. Quoting
   the 490.9 s would be wrong in aurora-lint's favour, which is worse. Tracked as
   benchmarking_db task 740.

Frama-C and Infer have no row here yet — see the note above. For an order of
magnitude on what the Frama-C row will cost: its 6-CWE Juliet run is the
slowest of the four by a factor of two, over files averaging under 200 lines,
which is why its real-world mode is budget-bounded rather than exhaustive.

Juliet, all four on one host (2026-09-04), CWE list sizes differing:

.. list-table::
   :header-rows: 1
   :widths: 20 16 16 48

   * - Tool
     - Wall clock
     - CWEs measured
     - 
   * - cppcheck
     - 350 s
     - 15
     - 
   * - clang-tidy
     - 1,393 s
     - 15
     - 
   * - Infer
     - 1,707 s
     - 10
     - 
   * - Frama-C
     - 3,443 s
     - 6
     - Slowest by 2×, on the smallest set.

.. warning::

   **These durations are comparable to each other and to nothing else.** All
   four ran on one host (dev-921, i5-12400) on one day. The April figures —
   895 s / 5,944 s / 5,019 s / 9,914 s — were taken on an r720, roughly ten
   years older and materially slower per core, so the two sets are separated
   by a hardware generation and no ratio between them means anything. They
   are not quoted side by side here for that reason.

   That the *findings* are unaffected is what makes the two sets usable at
   all: three of the four tools produced byte-identical results on both
   machines, so precision and coverage cross the boundary freely. Only wall
   clock does not.

   Speed is a real metric for aurora-lint, but evaluating it means running the
   comparison on like hardware — which is a separate exercise from this one.
   The runs still record no hostname of their own; attribution lives in
   ``data/competitor_results/run_hosts.json`` with its source stated per
   entry, and is surfaced in the exported CSV as ``hostname`` +
   ``hostname_source``.

.. note::

   Every count on this page is **CWEs measured**, not CWEs requested.

   aurora-lint implements CERT **C**, so this benchmark is C-only and the runner
   globs ``*.c`` deliberately. Nine Juliet directories hold no C at all, and
   one of them — CWE-762, mismatched memory management, 6,092 ``.cpp`` files
   and no ``.c`` — sat in the cppcheck, clang-tidy and Infer lists scoring
   0/0 in every run while counting toward their coverage. New/delete versus
   malloc/free is a C++ defect by construction, so it was never a valid entry
   here rather than a gap to close.

   It is removed from the lists, and ``run_tool`` now refuses any CWE that
   resolves to zero ``.c`` files instead of recording a 0/0 row that reads
   the same as "the tool found nothing". The runs above predate that fix and
   still carry the row; the exported CSV distinguishes them as ``cwe_count``
   (rows present) and ``cwes_measured``. Tracked as tools_sqc task 909; the
   same defect on aurora-lint's own count is task 910.

Real-World Precision, Per Rule
==============================

.. note::

   **TODO** — this section cannot be written yet.

   ``realworld_violations`` holds 17.5M aurora-lint rows and **zero** for cppcheck or
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

   **All four competitor columns were re-measured on 2026-09-04**, on one
   host (dev-921), at the versions in the table above.  The April runs were
   on a different and much older machine (r720), which affects wall clock
   only — see the warning under Speed.  Three of the four reproduced their
   April figures *exactly*:

   .. list-table::
      :header-rows: 1
      :widths: 16 30 22 32

      * - Tool
        - Version, April → September
        - Result
        - 
      * - Frama-C
        - 32.0 Germanium → 33.0 Arsenic
        - **identical**
        - A major EVA release moved no cell.
      * - Infer
        - v1.2.0 → v1.2.0
        - **identical**
        - Same version, different host, five months apart.
      * - clang-tidy
        - LLVM 21.1.6 → 21.1.8
        - **identical**
        - 13,952 TP / 116 FP / 1,170 unknown both times.
      * - cppcheck
        - 2.10 → 2.13.0
        - moved on all 15
        - Total barely shifts; individual CWEs move both ways.

   The cppcheck column above is the September measurement.  Its total is
   almost unchanged (36.4% → 36.7% precision) but individual CWEs move
   materially in both directions — CWE-401 25.7% → 29.1%, CWE-476
   39.7% → 34.5% — so it was refreshed rather than re-dated.

   The aurora-lint column is still from 2026-09-02, so the table is now within days
   of single-date rather than five months from it.  Tracked as tools_sqc
   task 768.

.. note::

   **clang-tidy is pinned to LLVM 21, deliberately.**  Ubuntu 24.04 ships
   18.1.3 and tops out at 20, so a freshly-provisioned node would measure an
   *older* clang-tidy than this table — and since clang-tidy is the tool that
   beats aurora-lint on the overlap, that would flatter aurora-lint by understating a rival.
   ``playbooks/install-static-analyzers.yml`` adds ``apt.llvm.org`` for this
   reason.  cppcheck is deliberately *not* pinned: it drifted forward, and
   the runner records whichever version it saw.

What The Trade Actually Is
==========================

Every tool that beats aurora-lint on precision above does it by compiling the code.
clang-tidy, Frama-C and Infer all need a working build and correct flags;
with a real preprocessor they know which branches exist, what a macro
expands to, and what a type is, and they are right more often as a result.

aurora-lint parses source as written. That is why it runs on a partial checkout, a
tree you cannot build, or a file that was generated a moment ago — and it is
also why it has a macro-expansion engine, a suppression system, and a
false-positive backlog as substantial as its rule backlog. The precision gap
on those fifteen CWEs is the price of the property that makes it useful
elsewhere.

cppcheck is the honest control here: it also runs unbuilt, and on the same
overlap it scores 36.7% to aurora-lint's 81.7%.

The wall-clock gap is on the *real-world* suite, not this one: cppcheck's
run-215 sweep of 8 projects took 11,452 s against aurora-lint's ~1,190 s, roughly ten
times. On Juliet the ordering reverses — cppcheck is the fastest of the four
competitors at 350 s. Both facts are about the same tool and neither is the
other's counterexample: cppcheck is quick on 5,900 small generated files and
slow on a real codebase.
