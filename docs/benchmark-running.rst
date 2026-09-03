Running Benchmarks (MCP Server)
===============================

The MCP benchmark servers provide a programmatic interface for running Juliet and
real-world benchmarks. All results are stored in ``data/benchmarks.db`` (SQLite,
WAL mode).

Benchmark Infrastructure
------------------------

::

    bench/
      __init__.py      Package marker
      __main__.py      CLI: python -m bench juliet [--full] [--jobs N]
                            [--keep-csv] [--compile-commands]
      config.py        Paths, constants, defaults
      db.py            SQLite schema, WAL mode, CRUD + query API
      analyzer.py      TP/FP classifier (Juliet ground truth)
      runner.py        Parallel CWE runner
      machine.py       Machine metadata (CPU, RAM, hostname)

SQLite Schema
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 60

   * - Table
     - Purpose
   * - ``runs``
     - One row per benchmark (version, SHA, mode, status, machine)
   * - ``cwe_scans``
     - One row per CWE per run (file count, violations, duration)
   * - ``violations``
     - Every individual sqc finding with TP/FP classification
   * - ``cwe_metrics``
     - Pre-computed aggregates per CWE (TP/FP rates)
   * - ``rule_cwe_breakdown``
     - Per-rule per-CWE counts
   * - ``realworld_runs``
     - Real-world benchmark runs (sqc version, machine)
   * - ``realworld_results``
     - Per-project per-tool violation counts (+ codebase_commit)
   * - ``realworld_violations``
     - Every individual real-world sqc finding (file, line, rule)
   * - ``ground_truth``
     - Adjudicated TP/FP oracle keyed on (project, commit, file, line, rule)

Historical data from ``JULIET_RESULTS.md`` and ``REALWORLD_RESULTS.md``
(both retired 2026-09-03 once this backfill made them redundant with
Postgres) has been backfilled into the database.

Benchmark Workflow Protocol
---------------------------

.. important::

    1. **Version bump + commit BEFORE benchmark**: Always bump the version in
       ``Cargo.toml``, rebuild (``cargo build --release``), and commit before
       starting. The run_id is ``sqc-{version}-{sha}``.

    2. **NEVER modify code while a benchmark is running**: The benchmark uses
       ``target/release/sqc``. Rebuilding while running corrupts results.

    3. **Wait for completion**: Fast-mode ~8-10 min (4-core), ~3-5 min (24-core).
       Full-suite ~40-50 min. Check status no more than once every 5 minutes.

    4. **Compare runs after completion**.

    5. **Sequence**: ``implement -> bump version -> commit -> build release ->
       run benchmark -> wait -> analyze``

Pre-Benchmark Checklist
~~~~~~~~~~~~~~~~~~~~~~~~

- All code changes committed
- Version bumped in ``Cargo.toml`` (for Juliet)
- ``cargo build --release`` successful
- No other benchmark currently running (it's your terminal -- you'll know)
- Previous results compared if needed (``python -m bench compare``)

Juliet Benchmark
-----------------

.. code-block:: bash

    python -m bench juliet [--full] [--jobs N] [--keep-csv] [--compile-commands]
    python -m bench status [RUN_ID]
    python -m bench compare BASE TARGET
    python -m bench runs
    python -m bench corpus-check [--json]   # real-world checkouts still pinned?

Run identifiers accepted by ``status``/``compare``:

- ``"latest"`` -- most recent run (default)
- Full run name: ``"sqc-0.3.20-abc1234"``
- Commit SHA: ``"abc1234"``
- Historical runs: ``"sqc-0.3.17-historical"``

**Notes**:

- ``python -m bench juliet`` blocks until the run finishes -- background it
  yourself (``nohup ... &``, a second terminal, ``tmux``) to keep working
  while it runs
- **Fast mode** (default): per-CWE manifests, CWE-matched rules only. ~10x faster
- **Full mode**: all 305 enabled rules against every CWE. Higher noise ratio
- Resume: interrupted runs skip already-completed CWEs on re-run
- Per-CWE/per-rule detail beyond what ``status``/``compare`` print is a direct
  ``sqlite3 data/benchmarks.db`` query away (``cwe_scans``, ``violations``,
  ``rule_cwe_breakdown``) -- there's no separate CLI subcommand for it

Compile-Database Runs
~~~~~~~~~~~~~~~~~~~~~

``--compile-commands`` makes a run pass sqc's ``--compile-commands`` flag,
adding the build's include search paths and
``-D`` macro state to the cross-file context. It is **off by default** -- a
plain run is unchanged.

The run_id is suffixed ``-cdb`` (and, for real-world runs, so is the results
directory), so a with/without pair on the *same* sqc build stays two distinct,
comparable runs. Without that suffix the second run would collide: Juliet's
resume logic skips a run_id already marked ``completed``, and the real-world
runner reuses the id for its results directory.

Databases are generated per-host (they embed absolute paths, so they are never
committed):

.. code-block:: bash

    # real-world: one compile_commands.json per checkout root
    ansible-playbook playbooks/setup-compile-commands.yml -i "localhost," -c local --ask-become-pass
    # Juliet: synthesized, no real build system to capture
    python3 scripts/generate_juliet_compile_commands.py

A run requested with ``--compile-commands`` **errors** if the database is
absent, rather than silently running without it -- a quietly-degraded run is
indistinguishable from a genuine "the compile DB made no difference" result.

.. warning::

   A compile-DB run is a **changed-rule delta, not a like-for-like
   comparison**. The flag can only *add* macro/header knowledge, so findings
   move to ``(file, line)`` pairs that were never adjudicated and fall outside
   the ``ground_truth`` precision/recall denominator in either direction.
   Follow the delta-adjudication protocol in ``CLAUDE.md`` before publishing
   any precision claim from such a run.

.. note::

   **Juliet gains nothing from this.** Measured on the synthesized database
   (54,486 entries): its only flag is ``-I<testcasesupport>``, which the runner
   already passes as ``-d testcasesupport``. A with/without pair on
   CWE457/s01 produced an identical 6,783 violations. The plumbing exists for
   symmetry and for future Juliet build changes; the real payoff is on the
   real-world corpora, whose databases carry genuine per-project include trees
   and ``-D`` state.

Real-World Benchmark
---------------------

Local and sequential, by design: one person running one benchmark in their
own terminal, against their own SQLite DB. See ``bench/realworld_runner.py``.

.. code-block:: bash

    python -m bench realworld-run [--tool sqc,cppcheck,clang-tidy] [--codebase C,C] [--compile-commands]
    python -m bench realworld [RUN] [--compare BASE]   # FP dashboard
    python -m bench realworld-runs                     # list runs
    python -m bench realworld-score [RUN]               # measured precision/recall

``realworld-run`` defaults to ``sqc`` against every codebase; narrow either
flag as needed. It blocks until every requested combo finishes, then ingests
the sqc results and scores them against the oracle -- no separate ingest
step, no polling.

Supported tools: ``sqc``, ``cppcheck``, ``clang-tidy``

Supported codebases: ``libcrc``, ``sqlite``, ``mosquitto``, ``curl``, ``hostap``,
``lua``, ``raylib``, ``pureftpd``, ``sel4`` (sqc-only for the latter two —
no cppcheck/clang-tidy baseline yet)

.. note::

   Remote-host execution (SSH) and background/concurrent run tracking
   existed in this module's MCP-server predecessor and were deliberately
   dropped when it became a plain synchronous script -- neither applies to
   one person running one benchmark locally. If you need to run against a
   fleet of remote hosts, that's the kind of thing the maintainer's
   ``benchmarking_db`` infrastructure is for, not this repo.

Per-Codebase Rule Configs
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each codebase may carry its own sqc rules manifest in ``conf/realworld/`` (the
real-world analog of a project shipping its own ``sqc-rules.toml``). The
runner reuses it for **every** run of that codebase via the
``CODEBASES[<name>]["sqc"]["manifest"]`` registry entry, so rules that do not
apply are ignored consistently. A codebase with no entry falls back to the
shared base ``rules_templates/rules-benchmark.toml``. The config is the
*categorical* filter (disable a whole rule only when it is inapplicable);
per-finding false positives among enabled rules are recorded in the
``ground_truth`` oracle instead, so analyzer misfires stay measured rather than
hidden. See ``conf/realworld/README.md`` for the per-codebase audit workflow.
``libcrc`` is fully audited (every enabled-rule finding labelled); the four
large codebases grow their labels incrementally.

Per-Codebase Scan Scope
~~~~~~~~~~~~~~~~~~~~~~~~

Each codebase's ``CODEBASES[<name>]["sqc"]["extra_args"]`` entry in
``bench/realworld_runner.py`` also carries ``--exclude`` globs that
scope the scan to the *shipped product*, not the whole checked-out repo —
test harnesses, build tooling, vendored/bundled code, and companion tools
(fuzzers, example plugins, separate CLI utilities) are excluded so they don't
inflate the violation count or dilute the precision/recall denominator.
These globs are derived from each codebase's ground-truth oracle scope
(``data/precision_audit/<codebase>/README.md``), which documents exactly
which directories were ruled in/out during that codebase's adjudication
sweep and why.

.. important::

    ``-d``/``--directories`` in a codebase's ``extra_args`` does **not**
    restrict the scan — it only adds cross-file pre-scan context (see
    :doc:`cli-usage`). A codebase's primary scan root is the whole repo
    whenever ``scan_path`` is ``None``, regardless of any ``-d`` entries in
    ``extra_args``. To actually narrow scope, use ``--exclude`` globs (or set
    ``scan_path`` to a single subdirectory, as ``raylib`` does for
    ``{path}/src``).

When adding a new real-world codebase or revisiting an existing one's
ground-truth audit, check whether its scope notes call for new
``--exclude`` entries here — a mismatch between the oracle's labeled scope
and the live scan's actual scope means dashboard numbers include findings
that were never meant to be measured (or, more subtly, that the ground-truth
denominator no longer matches what's being scanned).

.. warning::

    **That mismatch is not hypothetical, and it is measured.** Scope is
    declared in *three* places per codebase and nothing keeps them in sync:
    the ``--exclude`` globs here (what sqc reads), ``scope_include`` /
    ``scope_exclude`` in ``data/benchmark_repos.json`` (what the oracle may
    adjudicate), and the ``## Scope`` section of
    ``data/precision_audit/<codebase>/README.md`` (the rationale the other
    two claim to derive from).

    Audited across all nine codebases, six agree and three do not — always
    in the same direction, with the scan wider than the scope, so sqc emits
    findings that can never be labelled: **sqlite 992, mosquitto 168, curl
    144**. That is 1,304 findings, roughly a fifth of that run's whole
    unlabelled pool, unadjudicable by construction. They depress label
    coverage permanently, with work nobody is allowed to do.

    The sharpest case is one category of file treated two ways in the same
    suite: curl excludes ``include/**`` here, so its installed public
    headers are never scanned, while mosquitto does not, so its public
    headers *are* scanned and then declared out of scope by the oracle.

    So when you touch either list, change both — and prefer making this one
    derive from ``benchmark_repos.json``, which is already the declared
    single source of truth for the pins and is already read by
    ``setup-benchmark-repos.yml`` and ``corpus-check``. ``benchmarking_db``
    asserts both directions of drift on every run
    (``_check_scope_within_scan`` and ``_check_scan_within_scope``); the
    per-codebase reasoning and the audit results live in that repo's
    ``docs/corpus-scope.md``, since it owns the scope predicate.

.. note::

    ``benchmark_repos.json``'s globs are **path-aware**: ``*`` stops at
    ``/`` and ``**`` crosses it, so ``src/**`` and ``src/*.c`` are different
    things. The ``--exclude`` globs here are sqc's own and follow sqc's
    rules; do not assume the two spellings are interchangeable when copying
    a pattern between the files.

Auto-Scoring
~~~~~~~~~~~~~

When ``realworld-run`` finishes, it ingests the sqc results and **auto-scores**
them against the oracle: it writes a ``<run-dir>.score.json`` sidecar and
prints a one-line measured precision/recall. Scoring only joins findings to
*existing* labels — it never adjudicates new findings. Re-run any time with
``python -m bench realworld-score <RUN>``.

Typical real-world workflow:

.. code-block:: bash

    python -m bench realworld-run --tool sqc          # blocks until every codebase is done
    python -m bench realworld latest                   # view results
    python -m bench realworld latest --compare 0.2.6   # compare against a prior run

Real-World Ground-Truth Oracle (measured precision/recall)
----------------------------------------------------------

Volume deltas and CWE-aware Juliet rates do not predict real-world precision
(the v0.4.22 audit measured ~2--34% precision for the noisiest rules). The
``ground_truth`` table is a growing, manually/AI-adjudicated TP/FP oracle for
the real-world codebases --- the real-world analog of Juliet's
OMITGOOD/OMITBAD. Because each benchmark checkout is pinned to a fixed git
SHA, a label keyed on ``(project, codebase_commit, file_path, line, rule_id)``
stays valid across sqc versions: only the tool changes, never the code. Labels
are appended over time, never tied to a single run.

CLI::

    python -m bench corpus-check                       # checkouts still pinned?
    python -m bench ground-truth                       # label inventory
    python -m bench realworld-score [RUN]              # measured precision/recall
    python -m bench realworld-unlabeled [RUN] --rule R --project P --limit N --seed S
    python -m bench realworld-import-labels CSV --run RUN [--source TAG] [--update]

``realworld-score`` joins a run's findings to labels for **each project's own
``codebase_commit``** and reports, per rule and overall:

- **precision** = labeled-TP / (labeled-TP + labeled-FP), over the labeled
  subset of the run's findings (a sampled estimate; "Label coverage" shows how
  much of the run is labeled);
- **recall** = known-TPs flagged / known-TPs --- a known true bug that stops
  being flagged drops recall, seeding regression detection;
- **unlabeled_count** / **unlabeled_fraction** (overall and per rule) ---
  ``run_findings - labeled_total``, i.e. how much of this run's findings
  never got adjudicated. Precision/recall are only computed over the labeled
  slice, so a rule with a high unlabeled fraction can have a precision number
  that looks stable while its *raw* finding count swings heavily underneath
  it. The CLI text view flags any rule above 50% unlabeled; ``compare_runs``
  surfaces the same fields (``target_labeled_total`` /
  ``target_unlabeled_count`` / ``target_unlabeled_fraction``) per rule delta
  so a raw-count regression that outpaces adjudication is visible without
  manually cross-referencing ``ground_truth``.

A run whose ``codebase_commit`` has no labels is warned about, not scored.

Incremental adjudication loop (need not be one-shot):

1. ``realworld-unlabeled RUN --rule X --seed S --limit N`` --- pull findings
   with no label yet (reproducible sample);
2. adjudicate them (Claude or manual) into a CSV
   (``rule,idx,project,file,line,verdict,reason``);
3. ``realworld-import-labels CSV --run RUN`` --- append (existing labels are
   skipped unless ``--update`` re-adjudicates them).

The first 200 labels were seeded from ``data/precision_audit/adjudication_0.4.22.csv``.

Delta-Adjudication Gate
~~~~~~~~~~~~~~~~~~~~~~~~

.. important::

    Before citing a precision/recall claim ("precision held", "FP reduced",
    a published table row) for a rule whose detection logic just changed, **run
    a delta-adjudication pass on that rule's new findings first.**

``ground_truth`` labels are snapshotted at `(project, commit, file, line,
rule)`. When a rule's logic changes (any commit touching
``src/rules/cert_c/**/*.rs`` that alters what it flags, not a pure refactor),
its new findings land on ``(file, line)`` pairs that were never adjudicated —
they're silently excluded from the precision/recall denominator regardless
of direction. A flat precision number computed only over the pre-existing
labeled sample, or a raw finding-count comparison via ``compare_runs``, can
both look clean while the real picture underneath is unmeasured. This is not
hypothetical: a 21-rule sweep in this project once nearly got reported as a
clean net-positive on aggregate raw-count deltas alone before someone
actually adjudicated the new findings.

Procedure:

1. Pull the rule's new unlabeled findings (repeat per project, or split
   after)::

       python -m bench realworld-unlabeled RUN --rule RULE_ID --project P --json

2. **Derive each project's in-scope file predicate from its own**
   ``data/precision_audit/<project>/README.md`` **before batching, not
   after.** One delta-adjudication pass found 2,548 of 4,026 (63%) raw
   unlabeled findings were out-of-scope noise (test harnesses, vendored
   deps, language bindings) — mosquitto alone was 73% contamination.
   Scoping after batches are already generated means redoing completed
   adjudication work.
3. Batch (~110-150 findings/batch), adjudicate, and import with
   ``realworld-import-labels`` — the same workflow as building a fresh
   oracle.
4. Only after ``ground_truth`` reflects the new lines is a precision/recall
   claim about the changed rule safe to publish.

See ``data/precision_audit/DELTA_MEM31_TASK420.md`` for a fully worked
example: 6 projects, 14 batches, 1,478 findings, 0.7% delta precision — a
very different number than the aggregate raw-count comparison suggested.

Comparing Across Runs
---------------------

Juliet
~~~~~~

.. code-block:: bash

    python -m bench compare sqc-0.3.17-historical latest

Positive FP delta = regression. Negative = improvement.

Real-World
~~~~~~~~~~

.. code-block:: bash

    python -m bench realworld 0.2.7 --compare 0.2.6

Competitor Benchmarks (Infer / Frama-C)
----------------------------------------

The ``bench/competitors.py`` module runs Facebook Infer and Frama-C EVA on
Juliet test cases and classifies findings as TP/FP using the same ground truth
as the sqc benchmark (``OMITBAD``/``OMITGOOD`` guards and procedure names).

Results are written to ``data/competitor_results/<tool>_<timestamp>.json``.

Infrastructure
~~~~~~~~~~~~~~

::

    bench/
      competitors.py   Infer + Frama-C runners, TP/FP classification, comparison

Default CWE sets:

===========  ==================================================================
Tool         CWEs
===========  ==================================================================
Infer        476, 690, 416, 401, 415, 761, 762, 121, 122, 124, 127
Frama-C      190, 191, 476, 369, 197, 680
===========  ==================================================================

Running
~~~~~~~

.. code-block:: bash

    # Run Infer on default CWEs (~80 min on 24-core)
    python3 -m bench.competitors infer --jobs 8

    # Run Frama-C on default CWEs (~7-9 hours)
    eval $(opam env) && python3 -m bench.competitors framac --jobs 8

    # Run a specific subset
    python3 -m bench.competitors infer --cwes CWE476,CWE690

    # Compare results
    python3 -m bench.competitors compare \
      data/competitor_results/infer_*.json \
      data/competitor_results/framac_*.json

Timing Estimates
~~~~~~~~~~~~~~~~

===========  ============  ===============  =============
Tool         CWEs          Files            Estimated Time
===========  ============  ===============  =============
Infer        11            17,232           ~80 min
Frama-C      6             11,628           ~7--9 hours
===========  ============  ===============  =============

Infer uses incremental capture (``infer capture --continue``) per file then a
single ``infer analyze`` pass per CWE.  Frama-C runs EVA per-function per-file
(``-main <func>``), which is the main bottleneck.

Classification Logic
~~~~~~~~~~~~~~~~~~~~

**Infer**: Findings include a ``procedure`` field (e.g.
``CWE476_..._01_bad``).  If the procedure contains ``_bad`` or ``Bad`` it is
classified as TP; if it contains ``good`` it is FP.  Unresolved findings fall
back to line-level classification using ``parse_c_file_sections()``.

**Frama-C**: Each file is analyzed once per entry point (``_bad`` function and
``_good``/``goodN`` functions).  Alarms found when the entry point is a bad
function are TP; alarms under a good entry point are FP.

Key Frama-C flags:

- ``-machdep gcc_x86_64`` — enables GCC extensions (required for Juliet headers)
- ``-lib-entry`` — incomplete application analysis (no ``main``)
- ``-warn-signed-overflow -warn-signed-downcast`` — needed for CWE-190/191
- ``-eva-precision 1`` — reasonable precision/speed tradeoff

Troubleshooting
---------------

=======================================  =============================================
Issue                                    Solution
=======================================  =============================================
"Benchmark already running"              It's synchronous and runs in your terminal --
                                          Ctrl-C the process if you meant to stop it
Old results consuming disk               ``rm -rf results/realworld/<version_dir>``
Results show wrong version               Ensure version bump + commit before build
SQLite locked                            WAL handles concurrent reads; check for a
                                          leftover process still holding the file open
Historical run not found                 Data predates SQLite migration; not available
=======================================  =============================================

Resolved Issues
~~~~~~~~~~~~~~~

- **DCL02-C Stack Overflow** (Fixed 2026-01-07): Unbounded recursive AST traversal
  in DCL02-C caused stack overflow on large files (SQLite). Converted to iterative
  with depth limit.

- **STR31-C ``detect_manual_string_loop`` Runaway** (Fixed 2026-02-25): Caused
  36--49% of all violations on 3 of 5 real-world projects. Root cause: the
  final fallback iterated every line in the source file looking for
  ``memcpy`` + ``strlen``/``string``, so one match anywhere caused every loop
  to generate a violation -- ``jimsh0.c`` alone produced 180,297 violations.
  Fix: deleted the file-wide fallback, restricted matching to the loop
  condition and body, improved ``is_string_memcpy``. After the fix,
  ``jimsh0.c``'s STR31-C count dropped from 180,297 to 10. (Migrated here
  2026-09-03 from ``REALWORLD_RESULTS.md``, retired that day.)

- **Output Buffer Saturation**: SqC emits one status line per rule per file
  (~100 rules × N files). Always suppress or redirect output during scans::

      ./target/release/sqc directory/ --export results.csv 2>/dev/null
