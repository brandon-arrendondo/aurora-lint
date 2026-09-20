Reproducing the Published Numbers
=================================

Every real-world precision / recall / coverage figure this project publishes
(README's *Benchmark Highlights*, the paper) is a function of three inputs,
each named by a git SHA. With those three SHAs, a checkout of this repo and
no other access, you can regenerate the figure yourself and compare it at
the level of individual findings. This page is the procedure. It assumes
:doc:`benchmark-setup` has been followed once on the machine (corpus
checkouts, Juliet, headers); it repeats nothing from there.

.. contents::
   :local:
   :depth: 2

What "reproduces" means
-----------------------

A published number is reproduced when a fresh run of the named aurora-lint
build, on the named corpus commits, scored against the named label set,
yields **the same set of findings at the key level** -- the same
``(project, file, line, rule_id)`` tuples -- and therefore the same scored
figures. Keys are the unit of comparison because that is what a label is
attached to; the *message text* of a finding is not part of the comparison
and can legitimately differ between builds (MEM31-C, for one, spells the
allocator name from whatever it resolved first). Compare keys, never
messages.

The three inputs are:

.. list-table::
   :header-rows: 1
   :widths: 22 38 40

   * - Input
     - Named by
     - Where the name is recorded
   * - the analyzer
     - an aurora-lint release tag, and the commit it was cut from
     - the paper; the README highlights table (as the recorded build
       version and run id); ``git tag`` in this repo
   * - the labels
     - a commit of the public `benchmark_adjudication
       <https://github.com/brandon-arrendondo/benchmark_adjudication>`_
       repository
     - the paper's pinned measurement facts (its ``data/`` carries the
       exact SHA the oracle was level with); release notes
   * - the corpus
     - one pinned commit per real-world codebase, plus the Juliet suite
       version
     - ``data/benchmark_repos.json`` in this repo, at the analyzer's commit

Official published numbers are computed by the maintainers' private
pipeline from exactly these public inputs; a local run describes *that run*
and is never itself a project figure (ADR-0004,
``docs/adr/0004-postgres-is-the-single-source-of-truth.md``). What a reproducer gains is the ability to check the
published figure, key for key, and to say precisely where a disagreement
lies if there is one.

Input 1: the analyzer -- tag, SHA and version string
----------------------------------------------------

A release is a git tag (``vX.Y.Z``) on a commit whose only change over its
parent is the ``Cargo.toml`` version bump. The benchmark runs behind a
release are made from the commit the tag was **cut from**, not from the
tagged commit itself, so a run's recorded build version reads the
*previous* version string. Nothing about the analyzer differs between the
two commits; the SHA is what identifies the build, and the version string
adds readability only. (For v0.5.1 a single docs-only commit, ``d7a4f22f``,
sits between the benchmarked commit ``e405089a`` and the version bump
``3c245249``; it changes nothing the analyzer reads.)

Concretely, for v0.5.0:

.. list-table::
   :widths: 30 70

   * - tag ``v0.5.0``
     - ``717783a9`` (``chore: bump version to 0.5.0``)
   * - cut from
     - ``f48effe3`` -- the commit that produced the runs
   * - version string those runs record
     - ``0.4.336`` (the ``Cargo.toml`` value at ``f48effe3``)
   * - real-world run id
     - ``sqc-0.4.336-f48effe3``; the maintainers' run number for it is
       ``#265``, which is what the README highlights cite

Run ids are ``sqc-{version}-{sha}`` and the tool id inside the benchmark
tooling is ``sqc`` (``--tool sqc``, ``results/realworld/sqc-…``). The crate
and binary were renamed to ``aurora-lint``; the identifier in run ids, tool
ids and label provenance deliberately was not, because every historical
label and run is keyed on it. Do not translate it.

To build the analyzer that produced a published run, check out the
**cut-from commit** (or the tag: same code) and build release:

.. code-block:: bash

   cd $AURORA_LINT_SRC_ROOT/aurora-lint
   git fetch --tags
   git checkout --detach f48effe3          # or: git checkout --detach v0.5.0
   cargo build --release
   ./target/release/aurora-lint --version   # prints the Cargo.toml version at that commit

Determinism boundary
~~~~~~~~~~~~~~~~~~~~

From commit ``fc9164fd`` (*analyze: order findings on a total key so two
runs export identical bytes*) onward, one binary on one checkout writes a
**byte-identical** ``--export`` file every time. Before it, the *set* of
findings is the same but their order in the file can vary between runs, so
two exports must be compared as sets of keys, not with ``diff``.

Up to and including ``v0.5.1``, "one checkout" is literal. The set of
findings depends on the order in which the cross-file prescan walks the
tree, and that order is the filesystem's directory order, which differs
between filesystems and is not preserved by ``cp``, ``rsync`` or a fresh
clone (see *What another machine reproduces*). The same directory scanned
twice is byte-identical; a copy of it need not be.

From commit ``4ac5710f`` (*analyze: sort the file walk so the finding set
depends on the tree's content, not its directory order*) onward, every walk
that feeds the prescan and the scan list is sorted by file name, so the set
is a function of the tree's **content**: a copy, an ``rsync`` or a fresh
clone of the same commit gives the same bytes. Measured on the same machine
with the same binary: seL4 and hostap each copied to tmpfs twice, once with
files created in sorted order and once in reverse, ``cmp`` identical from
``4ac5710f`` on; on the ``v0.5.1`` binary the same two copies differ by 5
keys (seL4, all PRE31-C) and 116 keys (hostap, 23 removed / 93 added). To
repeat that check on any codebase, make two copies whose directories list
in different orders and scan both with the same command line, from the same
path (the export carries absolute paths):

.. code-block:: bash

   # tmpfs lists a directory in creation order, so the order files are
   # copied in is the order the walk would have seen them before 4ac5710f.
   for order in sorted reverse; do
       rm -rf /dev/shm/x
       (cd "$SRC" && git ls-files) | sort > /tmp/files
       [ "$order" = reverse ] && tac /tmp/files > /tmp/files.r && mv /tmp/files.r /tmp/files
       while IFS= read -r f; do
           mkdir -p "/dev/shm/x/$(dirname "$f")" && cp -p "$SRC/$f" "/dev/shm/x/$f"
       done < /tmp/files
       aurora-lint /dev/shm/x -d /dev/shm/x --manifest "$MANIFEST" --export "/tmp/$order.json"
   done
   cmp /tmp/sorted.json /tmp/reverse.json && echo "order-independent"

``v0.5.0`` (``717783a9``) predates ``fc9164fd``: reproduce it at the key
level. ``v0.5.1`` is the first tag that contains the ordering commit, and the
first for which a reproducer should expect ``diff`` on two exports of the
same codebase to be empty. ``v0.5.2`` is the first tag for which that holds
across copies of the checkout as well.

.. list-table::
   :header-rows: 1
   :widths: 14 20 20 22 24

   * - Tag
     - Tagged commit
     - Cut from
     - Runs record version
     - Byte-identical export
   * - ``v0.5.0``
     - ``717783a9``
     - ``f48effe3``
     - ``0.4.336``
     - no (key-level only)
   * - ``v0.5.1``
     - ``3c245249``
     - ``e405089a``
     - ``0.5.0``
     - per checkout, on one machine (see below)
   * - ``v0.5.2``
     - *<filled at tagging>*
     - *<filled at tagging>*
     - ``0.5.1``
     - per checkout content, on one machine (from ``4ac5710f``)

Input 2: the labels -- ``benchmark_adjudication`` at a SHA
----------------------------------------------------------

The adjudicated labels are a standalone public dataset: one row per
labeled finding, ``data/<project>/adjudication.csv``, keyed on
``(project, codebase_commit, file_path, line, rule_id)`` with a ``verdict``
of ``TP``, ``FP``, ``uncertain`` or ``FN``, plus who labeled it, when, and
why. Its README documents the columns and the review process; nothing in it
needs a database or a credential to read.

The dataset grows continuously, so a published figure is scored against the
labels **as of one commit** of that repo. The paper pins that commit in its
measurement facts (``benchmark_adjudication_commit``); for v0.5.0 the
maintainers' oracle was level with ``3ab3f41d``. Clone the repo beside this
one and keep the SHA -- the scorer reads the labels at that commit through
``git show``, so the checkout itself can sit on any branch:

.. code-block:: bash

   cd $AURORA_LINT_SRC_ROOT
   git clone https://github.com/brandon-arrendondo/benchmark_adjudication
   git -C benchmark_adjudication cat-file -e 3ab3f41d^{commit} && echo "label SHA present"

The same repo carries the reference scorer, ``scripts/score.py``, and a
golden test (``tests/test_score_golden.py``) that pins the scorer to run
``#265``: run 265's finding keys are stored under ``tests/golden/run-265/``,
and the test asserts that scoring them against the labels at ``3ab3f41d``
with the scope from this repo at ``f48effe3`` reproduces the paper's
per-project and overall figures exactly. ``python3 -m unittest discover -s
tests`` in that repo runs it; it is the demonstration that the published
figure *is* a function of the three SHAs and nothing else.

Input 3: the corpus -- pinned checkouts and Juliet
--------------------------------------------------

Real-world codebases
~~~~~~~~~~~~~~~~~~~~

``data/benchmark_repos.json`` pins every real-world codebase to one commit
and declares, per codebase, which files count toward the oracle
(``scope_include`` / ``scope_exclude``). Read it **at the analyzer's
commit** -- the pins and scope are part of what the run means, and the
scorer takes this file as its scope input:

.. code-block:: bash

   git show f48effe3:data/benchmark_repos.json > /tmp/benchmark_repos.f48effe3.json

The checkouts live under ``$SQC_BENCH_ROOT`` (default ``~/toolchain``), one
directory per codebase named exactly as in the JSON; the runner attributes
findings to a project by that directory name, and the scorer normalizes
scan paths by it. Provision them with the playbook in :doc:`benchmark-setup`
and then, **before every run**, verify they are still at their pins:

.. code-block:: bash

   python -m bench corpus-check      # exit 0 and every row OK, or stop here

Provisioning pins a checkout once and nothing holds it there: a ``git pull``
on a tracking branch moves it, and the runner records whatever commit it
finds rather than asserting the pin. Findings from a drifted tree land at
``(file, line)`` pairs the labels never saw and fall silently out of both
precision and recall. ``corpus-check`` also flags **untracked and gitignored
``*.c``/``*.h`` files**: aurora-lint dispatches on file extension and never
consults git, so a build run inside a checkout contaminates every later
scan while ``git status`` stays clean -- sqlite's generated ``sqlite3.c``
amalgamation is the standing example, worth a quarter of a million lines.
Keep the checkouts pristine and build nothing inside ``$SQC_BENCH_ROOT``.

Juliet
~~~~~~

The synthetic corpus is the NIST SARD `Juliet Test Suite for C/C++ v1.3
<https://samate.nist.gov/SARD/test-suites/112>`_ (SARD suite 112),
obtained manually because SARD has no stable download URL, and placed at
``$SQC_BENCH_ROOT/benchmarks/juliet-test-suite-c`` (:doc:`benchmark-setup`).
It is versioned by NIST, not pinned by this repo; v1.3 is the only version
these numbers have ever been run on.

Procedure
---------

Real-world half
~~~~~~~~~~~~~~~

1. Build the analyzer at the cut-from commit (above) and confirm
   ``python -m bench corpus-check`` is clean.

2. Scan every codebase with the benchmark runner. It invokes the release
   binary per codebase with that codebase's manifest from
   ``conf/realworld/`` and its include paths, and writes one ``--export``
   JSON per codebase; the local SQLite ingest and score that follow are for
   your own use and are not part of the reproduction.

   .. code-block:: bash

      python -m bench realworld-run --tool sqc              # all 12 codebases
      python -m bench realworld-run --tool sqc --codebase libcrc,lua   # a subset

   Exports land under ``results/realworld/sqc-<version>-<sha>/`` as
   ``sqc-<project>-<version>-<sha>.json``, a JSON list of
   ``{"rule_id", "file", "line", "message", …}`` objects. ``file`` is the
   path as scanned (absolute, under ``$SQC_BENCH_ROOT/<project>/``); the
   scorer strips it to the project-relative form the labels use. The run
   ends with ``No oracle labels cover this run's commit(s) yet -- nothing
   scored``: that is the *local* SQLite scorer finding no labels in a fresh
   clone, and it is expected -- the labels live in ``benchmark_adjudication``
   and the next step scores against them.

3. Score the exports with the reference scorer, naming the label SHA and the
   scope file from step 0:

   .. code-block:: bash

      cd $AURORA_LINT_SRC_ROOT/benchmark_adjudication
      R=$AURORA_LINT_SRC_ROOT/aurora-lint/results/realworld/sqc-0.4.336-f48effe3
      python3 scripts/score.py \
          --scope /tmp/benchmark_repos.f48effe3.json --scope-ref aurora-lint@f48effe3 \
          --labels-ref 3ab3f41d \
          $(for p in curl hostap libcrc lua mbedtls mosquitto pureftpd raylib sel4 sqlite valkey ventoy; do
              echo --export $p=$R/sqc-$p-0.4.336-f48effe3.json; done)

   It prints a per-project table and an overall row -- precision, recall
   against known true positives, label coverage -- with a basis line naming
   the definition version and every input. ``--json`` gives the same as a
   document whose keys match the maintainers' pipeline output, so it can be
   diffed against the paper's pinned facts directly.

4. Compare. The expected figures are not restated here on purpose (a number
   copied into prose goes stale silently): they are the README highlights
   table for the current release, and for the paper its pinned measurement
   facts, both of which name the run and the SHAs they came from. The
   scorer's own golden test holds the run-265 expectation as data.

Juliet half
~~~~~~~~~~~

Juliet is scored by this repo's own runner, against the suite's built-in
ground truth (``OMITBAD``/``OMITGOOD``), so there is no external label set
to pin -- the analyzer commit and the suite version are the whole triple:

.. code-block:: bash

   python -m bench juliet                # fast mode: per-CWE manifests, CWE-matched rules
   python -m bench status latest         # precision, per-CWE detail, run id

Published Juliet figures are fast-mode figures. The run id is
``sqc-<version>-<sha>``; ``status`` and ``compare`` accept a SHA.

Hardware, time and memory
~~~~~~~~~~~~~~~~~~~~~~~~~

Measured on one 12-core / 32 GB node running the procedure above at
``v0.5.0`` (2026-09-19); scale wall time by core count.

- ``cargo build --release`` from clean: 1 min 10 s (7.7 CPU-minutes).
- Real-world, ``--tool sqc``, all 12 codebases: **11 min 40 s** wall
  (62 CPU-minutes; 11 min 31 s at ``e405089a``). The long ones are hostap (3.5 min), sqlite (2.8 min),
  raylib (2.2 min) and valkey (1.5 min); everything else finishes in under
  40 s. Peak resident memory was about 6 GB, on hostap.
  **sqlite with every rule enabled needs real memory** -- a 3.8 GB node
  runs out and is killed; keep 8 GB or more free, or scan it last on its
  own with ``--codebase sqlite``.
- Juliet, fast mode: about 32--40 minutes, largely CPU-bound and parallel
  (``--jobs N``).
- Neither run needs the network, a database, or anything in
  ``benchmark_adjudication`` beyond the scorer and the CSVs.

Do not rebuild the binary while a run is in progress: the runner invokes
``target/release/aurora-lint`` per codebase and a mid-run rebuild mixes two
builds into one run id.

What another machine reproduces, measured
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The procedure above has been run in full on a machine that is not the one
that produced the maintainers' run, twice: at ``v0.5.0`` (``f48effe3``)
and, as a dry run for ``v0.5.1``, at ``e405089a`` (Ubuntu 24.04, glibc
2.39, against the benchmark node's Debian 12, glibc 2.36; same pins, same
label SHA, same scope). Both times, scored by ``score.py``:

- five of twelve projects reproduced **key for key** (libcrc, lua,
  pure-ftpd, raylib, Ventoy) -- the same five both times;
- overall precision reproduced to the published decimal both times; at
  ``v0.5.0`` recall against known TPs matched and label coverage came out
  0.1 point lower, at ``e405089a`` coverage matched and recall came out
  0.1 point lower (five known TPs of 64,392 detected on one machine and
  not the other);
- about 150 keys (0.1 %) differed at ``v0.5.0`` and 183 (105 only on the
  reproducing machine, 78 only on the benchmark node) at ``e405089a``, out
  of some 151,000 in scope, spread over the other seven projects. Of the
  183, 83 were labeled keys (9 TP, 74 FP), which is why the rates held.

The differing keys have two causes, and the second is the one a
reproducer will not guess:

1. **The host's installed headers**, which the scan reads through
   ``-I /usr/include`` and the per-project include paths. A missing
   third-party header produces DCL31-C *called without prior declaration*
   findings (curl's ``lib/vauth/gsasl.c`` without ``libgsasl``; mosquitto's
   MySQL example plugin without ``libmysqlclient``; curl's mbedTLS backend
   against an older ``libmbedtls``), and a different glibc declares
   ``gettimeofday``, ``waitpid``, ``asprintf`` and ``fileno`` behind
   different feature macros, which moved 52 valkey DCL31-C keys in
   opposite directions. A different glibc, OpenSSL or ``sqlite3.h`` also
   moves a handful of cross-file EXP34-C / EXP36-C / API00-C / DCL15-C
   decisions that depend on how a system typedef or prototype resolved.

2. **Directory iteration order.** The cross-file prescan walks the tree in
   the order the filesystem returns entries, and when a name is defined in
   more than one file -- hostap defines ``crypto_bignum_deinit`` once per
   crypto backend, seL4 defines the ``IDX_TO_IRQT`` macro once per
   architecture -- the definition the walk reaches last is the one every
   caller is analyzed against. Whether that definition checks its
   argument for NULL, or evaluates its macro argument twice, decides
   whether EXP34-C or PRE31-C fires at each call site. Measured at
   ``e405089a``: copying the seL4 checkout so that its directories list in
   a different order, on the same machine with the same binary, added
   exactly the five PRE31-C keys the benchmark node had and the reproducing
   machine lacked; the same for hostap moved 121 keys, 36 of them the
   cross-machine differences. Directory order is a property of the
   filesystem (ext4 orders a large directory by a per-filesystem hash
   seed; tmpfs by creation order), so it differs between machines and
   between two copies of a checkout on one machine, and no ``git`` state
   records it.

   **Removed at** ``4ac5710f``: the walk is sorted by file name from that
   commit on, so which definition wins is decided by the tree's content
   (the alphabetically last file for a function summary or a struct's
   field types, the first for a function-like macro), the same on every
   machine. Deterministic is not the same as right -- the winner is still
   an arbitrary one of the definitions, and a name defined once per
   backend or per architecture still resolves to a single body -- but it
   is now the *same* arbitrary choice everywhere. Measured against
   ``e405089a`` on the twelve pinned checkouts on one machine, the sort
   moved 140 keys (30 removed, 110 added): 121 on hostap, 10 on sqlite,
   5 on seL4, 3 on mbedtls and 1 on raylib, each read and attributed to a
   multiply-defined name in the commit message; the other seven codebases
   were key-identical. The cross-machine diff has not yet been re-measured
   at ``4ac5710f`` on the benchmark node; when it is, only cause 1 should
   remain.

The same binary on the same checkout, run twice, gives byte-identical
exports on every codebase checked (from ``fc9164fd`` on), with one
exception that ``v0.5.2`` still carries: MSC13-C on mbedtls's
``library/bignum.c:1301`` (``quotient``, declared in both branches of an
``#if``, sharing its first declaration with ``dividend``) appears in
roughly a third of runs of one binary on one checkout, even single-file at
``--jobs 1`` -- a per-process ``HashMap`` order inside the rule, not a
walk-order effect, fixed in the first commit after the ``v0.5.2``
baseline (task 1386) and worth one key. Otherwise the variation is
between checkouts, not between runs. So the inputs a SHA does not name are
the header environment -- :doc:`benchmark-setup` lists the packages the
benchmark node carries -- and, before ``4ac5710f``, for codebases with
multiply-defined names, the checkout's directory order. A published
figure's precision and recall do not hinge on either; a claim about an
exact finding count does, and a key-level diff against a maintainer run at
``v0.5.1`` or earlier on hostap or seL4 should be read with cause 2 in mind
before any label is questioned.

Reading a mismatch
------------------

If every per-project row of the scorer's output equals the published one,
the figure is reproduced. If not, the scorer's inputs localize the cause:

- **A project's finding count differs but its labeled counts do not.** The
  extra or missing keys are unlabeled, so precision and recall hold and only
  coverage moves. Usual causes: the host's headers (above -- look for
  DCL31-C keys naming a library function), a different build (check
  ``--version`` and the SHA), a drifted or contaminated checkout
  (``corpus-check``), or a different manifest under ``conf/realworld/`` than
  the one at the analyzer commit.
- **A project is reported unscored.** Its ``codebase_commit`` has no labels
  at the label SHA, which means the checkout is not at its pin -- the
  scorer takes the commit from ``benchmark_repos.json``, so this points at
  a scope file from the wrong analyzer commit.
- **Labeled counts differ by more than the handful above.** Findings
  moved to or from labeled keys: the binary is not the named one. Compare
  the two export files as key sets to see which rules moved.
- **A project's EXP34-C, PRE31-C or API00-C keys differ at call sites of
  a function or macro the codebase defines more than once** (hostap's
  per-backend ``crypto_*``, seL4's per-architecture macros). On a build
  before ``4ac5710f``, directory order chose a different definition on the
  two machines (cause 2 above); the keys are real output of the named
  build on the named corpus either way and say nothing about the labels.
  From ``4ac5710f`` on this cannot happen: the same definition wins on
  every machine, and such a diff points at the headers or the binary.
- **Only the order of an export differs** from a maintainer-provided one.
  Expected before ``fc9164fd``; not expected from ``v0.5.1`` on.

Whatever the cause, the reproduction is a statement about your run against
the published inputs. A disagreement worth reporting is one you can name at
the key level -- which project, which rule, which ``(file, line)`` pairs --
because that is the form in which the label set itself can be corrected.
