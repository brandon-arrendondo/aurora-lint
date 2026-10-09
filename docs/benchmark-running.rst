Running Benchmarks
==================

``python -m bench`` runs Juliet and real-world benchmarks synchronously in your
terminal and writes to this checkout's ``data/benchmarks.db`` (SQLite, WAL
mode). Those results describe your runs; official numbers come only from the
``sqc_bench`` Postgres instance through ``benchmarking_db``
(``docs/adr/0004-postgres-is-the-single-source-of-truth.md``).

Benchmark Infrastructure
------------------------

The harness is the ``bench/`` package; ``python -m bench --help`` lists every
subcommand. The Juliet and real-world commands are described below.

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
     - Every individual aurora-lint finding with TP/FP classification
   * - ``cwe_metrics``
     - Pre-computed aggregates per CWE (TP/FP rates)
   * - ``rule_cwe_breakdown``
     - Per-rule per-CWE counts
   * - ``realworld_runs``
     - Real-world benchmark runs (aurora-lint version, machine)
   * - ``realworld_results``
     - Per-project per-tool violation counts (+ codebase_commit)
   * - ``realworld_violations``
     - Every individual real-world aurora-lint finding (file, line, rule)
   * - ``ground_truth``
     - Adjudicated TP/FP oracle keyed on (project, commit, file, line, rule)
   * - ``calibration_labels``
     - Second, independent verdicts on already-labeled findings
       (``calibration-*`` subcommands)
   * - ``audited_files``
     - Files exhaustively audited (``audit-complete``, ``audit-score``)
   * - ``audit_corpus_meta``
     - In-scope file count per project and commit (``audit-coverage``)
   * - ``oracle_versions``
     - Frozen, citable oracle snapshots (``oracle-freeze``, ``oracle-versions``)

Historical data from ``JULIET_RESULTS.md`` and ``REALWORLD_RESULTS.md``
(both retired 2026-09-03 once this backfill made them redundant with
Postgres) has been backfilled into ``sqc_bench`` Postgres through
``benchmarking_db``; a fresh clone's ``data/benchmarks.db`` holds only its
own runs.

Benchmark Workflow Protocol
---------------------------

.. important::

    1. **Commit BEFORE benchmark, do not bump the version**: rebuild
       (``cargo build --release``) and commit before starting. The run_id is
       ``sqc-{version}-{sha}[-full][-cdb]-{preset}-{hash12}[-cwe...]``
       (see *Policy and Environment Settings*), and the **SHA** is what discriminates runs;
       the version string is a release artifact, bumped only when a release
       is cut (see ``CLAUDE.md``).

    2. **NEVER modify code while a benchmark is running**: The benchmark uses
       ``target/release/aurora-lint``. Rebuilding while running corrupts results.

    3. **Wait for completion**: a dated Juliet run time is in
       :doc:`reproducing-published-numbers` (*Hardware, time and memory*).
       Check status no more than once every 5 minutes.

    4. **Compare runs after completion**.

    5. **Sequence**: ``implement -> commit -> build release -> run benchmark
       -> wait -> analyze``

Pre-Benchmark Checklist
~~~~~~~~~~~~~~~~~~~~~~~~

- All code changes committed
- ``cargo build --release`` successful
- ``python -m bench corpus-check`` clean (real-world)
- No other benchmark currently running (it's your terminal -- you'll know)
- Previous results compared if needed (``python -m bench compare``)

Juliet Benchmark
-----------------

.. code-block:: bash

    python -m bench juliet [--full] [--jobs N] [--keep-reports] [--compile-commands] [--cwe CWE[,CWE]] [--profile P]
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
- **Full mode**: all |rules_enabled| enabled rules against every CWE. Higher noise ratio
- Resume: interrupted runs skip already-completed CWEs on re-run
- ``--cwe 78`` (or ``CWE78,CWE476``) scans only those CWEs: a quick check
  that a Juliet install and the build work end to end, not a benchmark. The
  run gets its own run_id (``...-cwe78``) and mode (``fast +cwe=CWE-78``), so
  it never stands in for the build's full run, and an unknown CWE is an error
- Per-CWE/per-rule detail beyond what ``status``/``compare`` print is a direct
  ``sqlite3 data/benchmarks.db`` query away (``cwe_scans``, ``violations``,
  ``rule_cwe_breakdown``) -- there's no separate CLI subcommand for it

Policy and Environment Settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every scan passes aurora-lint's ``--profile`` (``default`` unless
``--profile`` says otherwise), and each run records the settings it scanned
under -- the resolved values from ``aurora-lint --list-options json`` -- in
the ``settings`` column of ``runs`` and ``realworld_runs``, so a figure can
always name its setting (:doc:`options`). Runs recorded before settings
existed have ``settings`` NULL: they ran under neither preset exactly.

Every new run_id names its preset and settings hash:
``sqc-{version}-{sha}[-full][-cdb]-{preset}-{hash12}[-cwe...]``, where
``{preset}`` is ``default`` or ``strict`` when the settings are exactly that
preset and ``preset`` otherwise, and ``{hash12}`` is the first 12 characters
of the settings hash (the binary computes it; the full hash is in the
``settings`` column and the SARIF report). The label names the preset, not
each declared fact: the hash identifies every fact and the ``settings`` column
records them all, so a figure names its settings from there, not from the
run_id. (Juliet runs keep their ``+closed`` token, e.g. ``default+closed``,
so existing run ids stay valid; no further facts are added to labels.)
Real-world runs carry the same
suffix in their ``variant`` (``default-{hash12}``, ``cdb-strict-{hash12}``).
Runs recorded before settings existed keep their bare ids ("pre-settings");
nothing is renamed. A bare SHA resolves to the default-preset run of that
build.

Each benchmark declares the data model of the configuration it measures,
since aurora-lint credits no integer width beyond ISO C's minimums without
one: every real-world manifest has ``[environment] data_model`` (``lp64``
for the Linux corpora), and Juliet runs with ``--set data_model=lp64``, the
Linux x86_64 GCC build its testcases come from. The reasons per corpus are in
``docs/design/realworld-corpus-scope.md``. The declaration is part of each
run's settings and hash.

``compare`` and ``realworld --compare`` print the option-by-option settings
difference between the two runs, and flag two runs that share a preset name
but not a hash: that preset's own options changed between the builds.

Compile-Database Runs
~~~~~~~~~~~~~~~~~~~~~

``--compile-commands`` makes a run pass aurora-lint's ``--compile-commands`` flag,
adding the build's include search paths and
``-D`` macro state to the cross-file context. It is **off by default** -- a
plain run is unchanged.

The run_id is suffixed ``-cdb`` (and, for real-world runs, so is the results
directory), so a with/without pair on the *same* aurora-lint build stays two distinct,
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

   **Juliet gains nothing from this.** The synthesized database's only flag
   is ``-I<testcasesupport>``, which the runner already passes as
   ``-d testcasesupport``. A with/without pair on CWE457/s01 produced
   identical violations. The plumbing exists for
   symmetry and for future Juliet build changes; the real payoff is on the
   real-world corpora, whose databases carry genuine per-project include trees
   and ``-D`` state.

Real-World Benchmark
---------------------

Local and sequential, by design: one person running one benchmark in their
own terminal, against their own SQLite DB. See ``bench/realworld_runner.py``.

.. code-block:: bash

    python -m bench realworld-run [--tool sqc,cppcheck,clang-tidy] [--codebase C,C] [--compile-commands] [--profile P] [--dirs-out PATH] [--header-tree ID]
    python -m bench realworld [RUN] [--compare BASE]   # FP dashboard
    python -m bench realworld-runs                     # list runs
    python -m bench realworld-score [RUN]               # measured precision/recall

``realworld-run`` defaults to ``sqc`` -- the aurora-lint binary; the tool id
is ``sqc`` on purpose, see :doc:`reproducing-published-numbers` -- against
every codebase; narrow either flag as needed. It blocks until every requested combo finishes, then ingests
the aurora-lint results and scores them against the oracle -- no separate ingest
step, no polling.

Supported tools: ``sqc`` (aurora-lint), ``cppcheck``, ``clang-tidy``, ``infer``,
``frama-c``

Supported codebases: ``libcrc``, ``sqlite``, ``mosquitto``, ``curl``, ``hostap``,
``lua``, ``raylib``, ``pureftpd``, ``sel4``, ``mbedtls``, ``valkey``, ``ventoy``
(aurora-lint-only for ``pureftpd``, ``sel4``, ``mbedtls`` and ``valkey`` — no
cppcheck/clang-tidy baseline yet; ``ventoy`` is the Win32 oracle,
``Ventoy2Disk/Ventoy2Disk/`` only; aurora-lint scans it against the pinned
Windows SDK/CRT header tree, which must be provisioned first -- see
:doc:`benchmark-setup` -- while cppcheck and clang-tidy still run without
``<windows.h>``; ``curl``, ``hostap``, ``mosquitto``, ``sqlite`` and
``valkey`` are scanned against the host's own ``/usr/include`` unless
``--header-tree`` opts in to a pinned Debian 12 tree, below)

.. note::

   Remote-host execution (SSH) and background/concurrent run tracking
   existed in this module's MCP-server predecessor and were deliberately
   dropped when it became a plain synchronous script -- neither applies to
   one person running one benchmark locally. If you need to run against a
   fleet of remote hosts, that's the kind of thing the maintainer's
   ``benchmarking_db`` infrastructure is for, not this repo.

Per-Codebase Rule Configs
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each codebase carries its own aurora-lint rules manifest in ``conf/realworld/`` (the
real-world analog of a project shipping its own ``aurora-lint-rules.toml``). The
runner reuses it for **every** run of that codebase via the
``CODEBASES[<name>]["sqc"]["manifest"]`` registry entry, so rules that do not
apply are ignored consistently. There is no shared fallback base: a codebase
with no ``manifest`` entry is an error, because a manifest replaces the base
outright and so decides which rules can reach the oracle at all. The config is the
*categorical* filter (disable a whole rule only when it is inapplicable);
per-finding false positives among enabled rules are recorded in the
``ground_truth`` oracle instead, so analyzer misfires stay measured rather than
hidden. See ``conf/realworld/README.md`` for the per-codebase audit workflow.

Because a manifest is standalone and a scan iterates only its *enabled* rules, a
rule with no entry at all never runs on that codebase and nothing reports the
gap — an omission is indistinguishable from an oversight, which is a defect that
has actually shipped. ``scripts/check_realworld_manifests.py`` (pre-commit hook
``check-realworld-manifests``) asserts every manifest decides every rule, and
that every ``enabled = false`` carries a comment naming its reason.
``libcrc`` is fully audited (every enabled-rule finding labeled); the other
eleven codebases grow their labels incrementally.

Per-Codebase Scan Scope
~~~~~~~~~~~~~~~~~~~~~~~~

Each codebase's ``CODEBASES[<name>]["sqc"]["extra_args"]`` entry in
``bench/realworld_runner.py`` also carries exclude globs that
scope the scan to the *shipped product*, not the whole checked-out repo —
test harnesses, build tooling, vendored/bundled code, and companion tools
(fuzzers, example plugins, separate CLI utilities) are excluded so they don't
inflate the violation count or dilute the precision/recall denominator.
Test, demo and tooling trees are ``--exclude-all`` globs: out of the report
and out of the cross-file facts. Trees still read for cross-file facts but
not reported are ``--report-exclude`` globs. Each choice is recorded in
``docs/design/realworld-corpus-scope.md``.
These globs are derived from each codebase's ground-truth oracle scope,
documented per project in ``docs/design/realworld-corpus-scope.md`` — exactly
which directories were ruled in/out during that codebase's adjudication
sweep and why. (That rationale used to live in
``data/precision_audit/<codebase>/README.md``; ``data/precision_audit/`` is
now local working data, gitignored per
``docs/adr/0007-responsible-disclosure-gates-publication.md``, and holds
only what your own adjudication pass produces.)

.. important::

    ``-d``/``--directories`` in a codebase's ``extra_args`` does **not**
    restrict the scan — it only adds cross-file pre-scan context (see
    :doc:`cli-usage`). A codebase's primary scan root is the whole repo
    whenever ``scan_path`` is ``None``, regardless of any ``-d`` entries in
    ``extra_args``. To actually narrow scope, use ``--exclude-all`` or
    ``--report-exclude`` globs (or set
    ``scan_path`` to a single subdirectory, as ``raylib`` does for
    ``{path}/src``).

When adding a new real-world codebase or revisiting an existing one's
ground-truth audit, check whether its scope notes call for new
exclude entries here — a mismatch between the oracle's labeled scope
and the live scan's actual scope means dashboard numbers include findings
that were never meant to be measured (or, more subtly, that the ground-truth
denominator no longer matches what's being scanned).

.. warning::

    **That mismatch is not hypothetical, and it is measured.** Scope is
    declared in *three* places per codebase and nothing keeps them in sync:
    the exclude globs here (what aurora-lint reports), ``scope_include`` /
    ``scope_exclude`` in ``data/benchmark_repos.json`` (what the oracle may
    adjudicate), and the codebase's *Scope* section in
    ``docs/design/realworld-corpus-scope.md`` (the rationale the other
    two claim to derive from).

    An audit on 2026-09-03, across the nine codebases of that time, found
    six agreeing and three not — always
    in the same direction, with the scan wider than the scope, so aurora-lint emitted
    findings that could never be labeled: **sqlite 992, mosquitto 168, curl
    144** in the run it audited. That was 1,304 findings, roughly a fifth of
    that run's whole unlabeled pool, unadjudicable by construction. Findings
    like these depress label coverage permanently, with work nobody is
    allowed to do. The scan scope has changed since (see above), and this
    audit has not been repeated here.

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
    things. The ``--report-exclude`` globs here are aurora-lint's own and follow aurora-lint's
    rules; do not assume the two spellings are interchangeable when copying
    a pattern between the files.

Auto-Scoring
~~~~~~~~~~~~~

When ``realworld-run`` finishes, it ingests the aurora-lint results and **auto-scores**
them against the oracle: it writes a ``<run-dir>.score.json`` sidecar and
prints a one-line measured precision/recall. Scoring only joins findings to
*existing* labels — it never adjudicates new findings. Re-run any time with
``python -m bench realworld-score <RUN>``.

The scans and the ingest fail independently. Every tool writes its JSON export
as it goes, so a scan that printed ``ok`` is on disk under
``results/realworld/<version-sha>/`` whatever happens next; if the ingest then
fails, ``realworld-run`` says so on an ``INGEST FAILED`` line and exits
nonzero, and the run is simply absent (or partial) in ``bench realworld`` and
``bench realworld-score`` until the ingest is repeated. Two runs can still be
compared straight from their JSON exports, finding for finding, without the
database.

``realworld-run``'s exit status says how far the run got:

===== ==========================================================================
Exit  Meaning
===== ==========================================================================
0     every requested scan completed (and the ingest, if any, succeeded)
1     the scans completed but the ingest failed
2     no scan completed, or the command line was refused (an unknown tool or
      codebase, an unusable ``--dirs-out``, an unknown commit)
4     some scans completed and some did not; the completed ones are ingested
      (if that ingest also fails, the exit stays 4 and ``INGEST FAILED`` is
      printed)
===== ==========================================================================

A scan that failed to start (a missing compile-database cache, say) counts as
not completed, as does one whose run reported ``FAILED`` or one aurora-lint
reported incomplete (its exit 3). A final ``FAILED:``
line names each by ``tool:codebase``. Exit 3 is aurora-lint's own "scan
incomplete" code and is never returned by ``realworld-run`` itself.

One invocation can write more than one export directory: a codebase's compile
database or a settings option in its ``extra_args`` can change the settings it
is scanned under, and each set of settings is its own directory and its own
run. ``--dirs-out PATH`` writes a JSON list of the directories the aurora-lint
scans produced -- each with its name (which is also its ``run_id``), path,
settings and settings hash, and the codebases scanned into it -- before the
ingest starts, so a caller that ingests the exports somewhere else reads the
names instead of predicting them. Write it outside ``results/realworld/``: an
export directory's ``*.json`` files are read as scan results.

By default the corpora that read system headers (curl, hostap, mosquitto,
sqlite, valkey) are scanned against this host's own ``/usr/include``, and
each scan records ``host`` as its header tree. That is right for an A/B on
one machine, where both arms share the host; a local run's figures are its
own, and official ones come from the benchmark node alone
(``docs/adr/0004-postgres-is-the-single-source-of-truth.md``).
``--header-tree ID`` opts in to scanning those corpora against a pinned tree
from ``header_trees`` in ``data/benchmark_repos.json`` instead, to reproduce
another machine's header environment or take the host out of a comparison.
The tree must be provisioned (``python3 -m bench.header_tree fetch ID``), and
the scans land under a run id of their own (``...-hdr-ID``), never under the
default run's. ``--header-tree host`` is the default spelled out. A
comparison between two header environments measures the whole change: the
package set and the include search path differ at once (see
:doc:`benchmark-setup`).

Typical real-world workflow:

.. code-block:: bash

    python -m bench realworld-run --tool sqc                  # blocks until every codebase is done
    python -m bench realworld latest                   # view results
    python -m bench realworld latest --compare 12      # compare against run 12 (ids from realworld-runs)

Real-World Ground-Truth Oracle (measured precision/recall)
----------------------------------------------------------

Volume deltas and CWE-aware Juliet rates do not predict real-world precision
(a historical audit at v0.4.22 measured ~2--34% precision for the noisiest
rules). The
``ground_truth`` table is a growing, manually/AI-adjudicated TP/FP oracle for
the real-world codebases --- the real-world analog of Juliet's
OMITGOOD/OMITBAD. Because each benchmark checkout is pinned to a fixed git
SHA, a label keyed on ``(project, codebase_commit, file_path, line, rule_id)``
stays valid across aurora-lint versions: only the tool changes, never the code. Labels
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

The first 200 labels were seeded from an early adjudication pass at v0.4.22;
that CSV is historical and is not in this repo.

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

2. **Derive each project's in-scope file predicate from its section of**
   ``docs/design/realworld-corpus-scope.md`` **before batching, not
   after.** One delta-adjudication pass found that most of its raw
   unlabeled findings were out-of-scope noise (test harnesses, vendored
   deps, language bindings), and mosquitto's share was higher still.
   Scoping after batches are already generated means redoing completed
   adjudication work.
3. Batch (~110-150 findings/batch), adjudicate, and import with
   ``realworld-import-labels`` — the same workflow as building a fresh
   oracle.
4. Only after ``ground_truth`` reflects the new lines is a precision/recall
   claim about the changed rule safe to publish.

A worked example from this pattern, across six projects, measured a delta
precision near zero, a very different number than the aggregate raw-count
comparison suggested.

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

    python -m bench realworld 14 --compare 12   # integer run ids, from realworld-runs

Competitor Benchmarks
---------------------

The ``bench/competitors.py`` module runs Facebook Infer, Frama-C EVA, cppcheck
and clang-tidy on Juliet test cases and classifies findings as TP/FP using the same ground truth
as the aurora-lint benchmark (``OMITBAD``/``OMITGOOD`` guards and procedure names).

Results are written to ``data/competitor_results/<tool>_<timestamp>.json``.

Infrastructure
~~~~~~~~~~~~~~

::

    bench/
      competitors.py   Infer, Frama-C, cppcheck and clang-tidy runners,
                       TP/FP classification, comparison

Default CWE sets:

===========  ==================================================================
Tool         CWEs
===========  ==================================================================
Infer        476, 690, 416, 401, 415, 761, 121, 122, 124, 127
Frama-C      190, 191, 476, 369, 197, 680
cppcheck     the union of the two sets above
clang-tidy   the union of the two sets above
===========  ==================================================================

Running
~~~~~~~

.. code-block:: bash

    # Run Infer on default CWEs
    python3 -m bench.competitors infer --jobs 8

    # Run Frama-C on default CWEs
    eval $(opam env) && python3 -m bench.competitors framac --jobs 8

    # Run cppcheck, clang-tidy, or all four tools
    python3 -m bench.competitors {cppcheck,clangtidy,all} --jobs 8

    # Run a specific subset
    python3 -m bench.competitors infer --cwes CWE476,CWE690

    # Compare results
    python3 -m bench.competitors compare \
      data/competitor_results/infer_*.json \
      data/competitor_results/framac_*.json

Timing
~~~~~~

Dated wall-clock figures for all four tools, measured on one host, are in
:doc:`tool-comparison` (*Speed*).

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
Results show wrong version               Ensure commit before build; the SHA is the id
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

- **Output Buffer Saturation**: aurora-lint prints a progress bar and every
  finding to standard output (``-v`` adds per-rule progress lines), which is
  large on a big corpus. When only the export is wanted, redirect it::

      ./target/release/aurora-lint directory/ --export results.sarif > /dev/null
