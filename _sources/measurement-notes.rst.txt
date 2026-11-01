Measurement Notes
=================

What a reader needs to compare figures across releases: why the v0.5.0
baseline is a trend break rather than a gain, how the ERR33-C labels moved
between oracle snapshots, what changed in how v0.6.0 and v0.7.0 are measured,
and how the precision intervals are computed. The paper states the finding and cites this page at a pinned
version for the detail.

.. contents::
   :local:
   :depth: 2

.. note::

   **No figure on this page is typed, and none is official yet.** Each
   figure has a place between a pair of ``.. BENCH:NAME:START`` /
   ``.. BENCH:NAME:END`` comments, and those blocks are placeholders: no
   renderer fills them yet (``bench/render_docs.py`` renders only README's
   highlights table). Until one does, they read *pending*, and no figure on
   this page is official. The prose outside the blocks is hand-written and
   does not state a figure.

A precision figure is a property of a triple
--------------------------------------------

A real-world precision or recall figure depends on three things: the detector
(an aurora-lint build), the rule set (the per-project manifests under
``conf/realworld/``) and the oracle (the ``benchmark_adjudication`` label set at
a commit). If any one of them changes, the figure changes, even when the other
two are unchanged. These are the same inputs
:doc:`reproducing-published-numbers` pins as analyzer, labels and corpus: the
rule set comes with the analyzer commit, whose tree holds the manifests, and
the corpus is held fixed by the pinned project commits. So a published figure
states all three, and a comparison between figures
is valid only when the difference is explained by the component that was meant
to change.

The v0.5.0 trend break
----------------------

What changed
~~~~~~~~~~~~

The published real-world precision rose sharply between the last v0.4
baseline and v0.5.0 (the trend-break table gives the figures). The rise is a
result of the measurement changing, not of detection improving. Between the two
baselines two of the three components moved.

**The rule set.** Commit ``10745a46`` ("config(realworld): stop hiding rules
from the oracle in nine manifests") re-enabled a block of rules on every
real-world manifest: DCL04-C, DCL06-C, DCL08-C, EXP02-C, EXP10-C, EXP12-C,
EXP14-C, EXP19-C, INT01-C, INT02-C, INT16-C, INT17-C and PRE31-C. A build-time
constant had disabled them as "too noisy on real codebases" in the generated
base manifest, and most per-project manifests copied that as explicit
disables. The premise had been tested only on the projects where the block
remained enabled, and there it did not hold for much of the block. On the other
corpora the rules could not fire where the oracle could grade them. Once
enabled, the block contributed a large share of the next run's findings at high
precision, most of it from EXP19-C, a brace-style rule.

**The oracle.** The known-true-positive set grew. Most of the new labels are at
``(file, line, rule)`` keys the earlier run never emitted, because the block was
off when it ran. Re-scoring the earlier run against the newer oracle lowers its
recall without any change to the run itself. A recall figure measured against
a tool-derived oracle describes the oracle's history as much as the tool.

**The corpus.** Projects were added in the same interval. Next to the other two
changes, their effect on the aggregate is second-order.

.. BENCH:TREND_BREAK:START

*Pending: the trend-break table (run, rule set and oracle date, precision,
recall, coverage, findings) for the published baseline, that baseline
re-scored on the newer oracle, the v0.5.0 run, and the like-for-like rows
below. Filled by the host-side refresh.*

.. BENCH:TREND_BREAK:END

The like-for-like view
~~~~~~~~~~~~~~~~~~~~~~

Fixing two components isolates the third. The like-for-like rows score
both runs against **one oracle date**, with **the changed rules removed from
both sides**:

- **Across the break**, the fixed oracle is the one the v0.5.0 pin was taken
  on, and the excluded rules are the re-enabled block. Both runs are then
  scored on the rule set the earlier baseline actually measured. On that view,
  detector work over the interval barely moved precision, while the finding
  count rose with the added projects.
- **Across the v0.5.0 to v0.5.2 step**, which kept the corpus and the rule set
  fixed, the excluded rules are the ones whose source changed between the two
  commits, and the oracle is the v0.5.2 baseline's. Here the labeled false-positive count fell mostly because the
  labeled set and the in-scope finding count both shrank, not because verdicts
  changed. Precision is unchanged within the v0.5.2 run's
  file-clustered interval.

The like-for-like view does not have an interval yet. Its interval has to be
computed over the same subset as its point estimate, the findings left after
the changed rules are excluded, and the published figures do not yet include
that computation. Until they do, the like-for-like rows are point estimates
without an interval.

Reading a figure across the break
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Do not claim an improvement across the break from the headline series. Its
  rows are not comparable with one another.
- Compare only on like-for-like rows, and quote a real-world precision figure
  with its rule set and oracle snapshot attached.
- The paper's output-volume series (total findings per release), which
  predates the oracle, cannot be extended past ``10745a46`` on the same axis.
  The rule set that produced it no longer exists.

ERR33-C relabeled to the rule as written
----------------------------------------

The denominator can also move without any change to the rule set. Between
states of the public label repository, the ERR33-C label set shifted toward
true positives. The composition table is of the **labels** at each
ref, not a run's precision. A run's figure also depends on which labeled keys
it reports. But the labels are the denominator of every real-world figure, so an
ERR33-C number pinned before the shift cannot be compared with one pinned after
it unless the reader knows the shift happened.

.. BENCH:ERR33C_COMPOSITION:START

*Pending: ERR33-C label composition (TP, FP, FN, TP share) at each
``benchmark_adjudication`` ref, regenerable with that repository's
label-churn script between any two refs.*

.. BENCH:ERR33C_COMPOSITION:END

There were two mechanisms, and they happened in this order.

**A. New labels written to the rule as written.** The bulk is the valkey
ERR33-C oracle build. It was labeled from the start to this reading: a call
ERR33-C covers whose result is ignored outright, or assigned and never tested,
is a violation as written. ERR33-C-EX1 lists the functions whose results a caller
may ignore, and it does not exempt any others. A whole-daemon pass on pure-ftpd
and the ``fclose`` delta with its review added more labels on the same reading,
and that review flipped some existing FP labels to TP. This mechanism added
labels and removed none.

**B. The retroactive relabel.** Once valkey had been labeled to that bar, the
older projects were the odd ones out. Their ERR33-C rows had been written to a
looser reading, which tolerated a bare unchecked ``fflush`` or ``time``. Rather
than carry two bars, the older labels were brought to the rule as written in a
single batch. The batch only flipped rows from FP to TP; it changed nothing
else.

.. BENCH:ERR33C_FAMILIES:START

*Pending: the relabel's FP-to-TP flips per callee family, beside the valkey
build's TP, FP and TP share for the same families, and the number of projects
the relabel left unchanged.*

.. BENCH:ERR33C_FAMILIES:END

The per-family view is the consistency check. The relabel moved only some
families of callees, the ones where an unchecked result is itself the
violation: formatted output, stream I/O and ``time``. Those are the families
the independently built valkey oracle labels mostly TP. The **memory and
environment families barely moved**, because their ERR33-C false positives are
results that are tested, in the same condition that assigns them. The strict
bar calls those false positives too. The projects whose ERR33-C false positives
are all of that kind did not move at all.

That is the labeling principle the oracle follows throughout (see the
`adjudication rules
<https://github.com/brandon-arrendondo/aurora-lint/blob/main/docs/adjudication-rules.md>`_). A label records whether the construct violates the
rule *as written*. Whether a project acts on every such violation is a
question for suppression and configuration (:doc:`suppression`,
:doc:`configuration`). It is not settled by softening what counts as a true
positive.

Reading an ERR33-C figure
~~~~~~~~~~~~~~~~~~~~~~~~~

- ERR33-C's share of true positives rises between an oracle pinned before the
  relabel and one pinned after it, with no change to what the rule detects. The
  pooled real-world precision rises with it. This is the same denominator
  effect as the trend break, coming from the label side instead of the manifest
  side. It is why a published figure states its ``benchmark_adjudication`` SHA beside
  its aurora-lint one.
- The detector moved as well. Since commit ``09336c31``, ERR33-C treats a result
  tested in the same condition it is assigned in as checked. That
  withdraws the findings at those keys; it does not relabel them.
- A v0.5.2 ERR33-C figure therefore carries three movements at once: new
  labels, relabeled labels and withdrawn findings. Read it through the
  like-for-like view that excludes the rule, or through a per-rule delta that
  separates the three, not as a single number.

What changed in how v0.6.0 is measured
--------------------------------------

Between v0.5.3 and v0.6.0 every movement in the benchmark figures was traced
to the commit that caused it, before the release was cut. Most are changes in
what the rules detect, and the changelog lists them. The ones below change
*how* a figure is measured, so they are trend breaks: compare a v0.6.0 figure
with a v0.5.x one only after accounting for them. The figures themselves come
from the release's citation runs, not from this page.

Juliet
~~~~~~

- **Which rules run on each CWE.** Fast mode runs, for each Juliet CWE, the
  rules that map to it. Since this release a rule's mapping holds only the
  CWEs its own Juliet cases verify; the rest moved to a list of related CWEs.
  Whole blocks of a rule's findings on a CWE therefore appear or vanish, and
  the per-file denominator changes with them. Some true positives that
  disappeared from a CWE (for example STR31-C on CWE-124 and CWE-127) are
  mapping removals, not detection losses.
- **What a flaw line is.** A flaw line is now the code a ``FLAW`` comment
  annotates, counted once. This changes the flaw-line figures and nothing else.
- **Caller sets.** Under ADR-0011 a check made by every visible caller proves
  a parameter only when the caller set is closed: the function is ``static``
  and its address stays inside the scanned source. Juliet's functions have
  external linkage, so they count as open, and the rules now report inside
  good functions whose callers pass only safe values. Most of those are the
  hardcoded-value good functions NIST describes as Juliet's most widespread
  issue. The Juliet runs declare ``closed_program``, but in this release that
  option applies only to EXP33-C (:doc:`options`). Juliet's false positives
  rise accordingly. After v0.6.0 the declaration also closes caller sets for
  the proofs about the value a caller passes, which clears part of them: a
  value range, a buffer size or a non-null pointer every caller passes now
  proves the parameter of a non-static function too, and INT30-C to INT32-C
  count the value range every caller passes. ENV03-C, ENV33-C and STR02-C,
  which accept a caller because its body reads no untrusted input, still
  credit only ``static`` functions. So does the INT30-C to INT32-C test of
  whether a parameter can receive untrusted or full-range input, which in
  v0.7.0 judges each caller by what it passes at that position rather than by
  whether any caller reads input. That share of the false positives remains.
  On real-world code the same change is the intended reading,
  because exported and library functions do have callers the scan cannot see.

Real-world
~~~~~~~~~~

- **What counts as the corpus.** The benchmark runner now excludes each
  project's test, demo and tooling trees from the scan entirely, including
  from the cross-file facts other files are checked against, as declared in
  ``docs/design/realworld-corpus-scope.md``. Findings in those trees leave the
  figures.
- **Declared facts.** Each real-world manifest now declares its data model and,
  where the project frees memory through its own functions, its deallocators
  (``conf/realworld/``). Since frees count only by proof, a declaration can
  remove leak reports a project's wrapper used to cause, or let a rule see a
  free it missed and report where it was silent.
- **Analysis time.** Real-world analysis is markedly slower than in v0.5.3,
  mostly because of one new null-state proof whose cost grows with the square
  of a function's length, and partly because previously unparsable code now
  parses. Juliet's short functions show little of it. Compare analysis times
  only between runs of the same release on the same node.

What changed in how v0.7.0 is measured
---------------------------------------

The changes below alter *how* a figure is measured, so compare a v0.7.0
figure with a v0.6.0 one only after accounting for them. The counts in this
section come from the release's default-profile citation runs and v0.6.0's,
scored on the same labels and the same corpus scope. Every codebase is
pinned to the same commit in both.

Real-world
~~~~~~~~~~

- **The scan runs in the pinned benchmark environment.** v0.7.0's runs of
  record scan inside the declared container image, each codebase against its
  own pinned header set (*The Benchmark Environment* in
  :doc:`benchmark-setup`; ``docs/adr/0018``), and each run records that
  environment and header tree. v0.6.0's ran natively on the benchmark node,
  against its installed headers, and record neither. Findings that hinge on a
  header move with that change: Ventoy, for one, is now scanned against a
  Win32 header set.
- **The manifests declare the target.** Every real-world manifest
  (``conf/realworld/``) now declares ``libc`` and ``posix_version``, and
  every one but Ventoy's also ``c_standard`` and ``char_signed``. Ventoy
  declares ``posix_version = "none"``, since it is a Win32 program. In
  v0.6.0 none of the four was declared, so these runs read under each
  preset's assumption instead.
- **Strict-profile runs of record.** v0.7.0 is the first release whose
  citation runs include the strict profile, for both Juliet and real-world.
  v0.6.0's are default-profile only, so a strict figure has no v0.6.0
  counterpart to compare with.

Juliet
~~~~~~

- **The dependency set is on the include path.** Juliet scans now pass
  Juliet's pinned dependency set as ``-I`` and record it in the run's
  environment. Juliet's settings also declare ``libc``, ``c_standard``,
  ``posix_version`` and ``char_signed``. v0.6.0's Juliet runs did neither.

The oracle
~~~~~~~~~~

- **Removed and withheld rules count as misses.** The oracle covers every
  CERT C guideline, so a rule removed or withheld in this release leaves its
  labeled findings in the oracle, where no finding of the rule can match
  them. On the default citation runs, the four removed rules with labeled
  true positives (PRE12-C, INT14-C, STR03-C and FIO03-C) account for 364
  labeled true-positive keys that v0.6.0 found and v0.7.0 does not. The
  withheld rules and the checks moved to the CWE ruleset account for none.
- **Moved reports fall off their labels.** A label is keyed on the line of
  the finding. EXP19-C now reports an unbraced body where the body starts,
  not at its keyword, and PRE01-C reports at each use of a macro parameter,
  not at the ``#define``, so the same detections land on new, unlabeled
  lines. Of the 34,938 labeled true-positive keys v0.6.0 found and v0.7.0
  does not, 32,004 have a finding of the same rule one to three lines below,
  on a line no label covers: 31,956 for EXP19-C, 47 for PRE01-C and 1 for
  DCL37-C. Until those lines are labeled, these count as misses, and the
  findings that replace them as unlabeled. In the other direction, v0.7.0
  finds 254 labeled true-positive keys that v0.6.0 did not.

Settings
~~~~~~~~

One change moves every run's identity at once, so it is a trend break in the
run ids even where the findings do not move.

- **Every settings hash changes once.** The settings now carry a hash of the
  policy's column of the per-rule preset table (:doc:`rule-presets`), so a
  changed cell, or a rule removed from the table, moves the hash of the runs
  that read with it. A default-preset
  scan with no data model declared now records the LP64 model the preset
  assumes, and where it came from. Each preset's hash, and every run id that
  carries one, therefore differs from v0.6.x with nothing else changed.
  Compare a run across the break by its commit and resolved settings, not by
  its hash. With nothing declared (``aurora-lint --list-options json
  --profile P``), the hashes move as follows; a run that declares facts has
  its own hash, which moves at the same point:

  ========  ============================  ============================
  Preset    Before (first 12 digits)      After (first 12 digits)
  ========  ============================  ============================
  default   ``6a42bd4cf1e0``              ``8823c3e89a7b``
  strict    ``f017c4b47de7``              ``7fcd86f7da96``
  pedantic  ``7d5d09905362``              ``31c6c8ce626e``
  ========  ============================  ============================
- **Declined rules do not run.** A rule a preset declines while another
  preset enforces it (``not_enforced`` in :doc:`rule-presets`) no longer
  runs under that preset, and the run's settings name it. Its findings leave
  that preset's runs instead of being reported and scored as an abstention.
  A rule every preset declines still runs until it is removed, and preset
  scoring still treats it as an abstention.
- **The data model the default preset assumes.** Undeclared, the default
  preset now credits LP64 widths where it used to credit only ISO C's. The
  benchmarks declare their data model (each real-world manifest in
  ``conf/realworld/``, and Juliet's settings), so their findings do not move
  with it.

Precision intervals
-------------------

A pooled precision figure is one number over projects whose labeled
populations differ by orders of magnitude. It mostly describes the largest
project and a few high-volume rules. So the same run is reported several ways,
each with an interval.

.. BENCH:PRECISION_INTERVALS:START

*Pending: the pooled precision with its Wilson interval and file- and
project-clustered bootstrap intervals; the macro-average with file- and
project-clustered bootstrap intervals; the precision without the top one and
top three rules, each with its Wilson interval, macro-average and
file-clustered bootstrap interval; the coverage bounds; and the resample
count, seed, cluster order and CI definition version.*

.. BENCH:PRECISION_INTERVALS:END

The views
~~~~~~~~~

**Pooled Wilson.** The pooled figure is labeled TP over labeled TP plus FP,
with a Wilson score interval. Wilson assumes findings are independent, so it
runs too narrow. Findings cluster: one defect pattern in one function yields a
run of same-verdict findings in one file.

**Clustered bootstrap.** A percentile bootstrap resamples whole clusters, not
single findings. The **file** bootstrap resamples ``(project, file)`` clusters.
The **project** bootstrap resamples whole projects. Its width is the one that
applies to a claim about C codebases in general rather than about this corpus,
and it is wide and lumpy by nature.

**Macro-average.** Each project's precision carries equal weight, so the
figure stops tracking corpus size. It is reported beside the pooled figure,
not in place of it. The gap between the two is itself a finding.

**Rule-stratified.** The same run is scored with the top one rule, and then the
top three rules, by labeled volume removed. These rows say what the rest of the
rule set does.

**The coverage bracket.** The views above are computed over the *labeled*
findings. That silently assumes the unlabeled remainder resembles the labeled
part, and nothing has shown it does. The only bounds that do not rest on that assumption
are the bracket. One end is the precision if every unlabeled in-scope finding
were a true positive; the other is the precision if every one were a false
positive. The pooled figure is one point inside the bracket, and it is
quoted with the bracket beside it.

.. BENCH:PROJECT_INTERVALS:START

*Pending: for each project the render lists, its TP, FP and uncertain
counts, precision and Wilson interval.*

.. BENCH:PROJECT_INTERVALS:END

Regenerating an interval exactly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A seeded bootstrap draws the *indices* of clusters. Its interval is therefore a
function of the seed, the replicate count, **and the order in which the
clusters are listed**. The same clusters in another order give different
replicates. The current definition (CI definition version 2) lists them in
code-point order of their key: ``(project, file_path)`` for the file bootstrap,
``(project,)`` for the project bootstrap. Under that order an interval depends
on the labeled findings alone and is the same on every machine.

The earlier definition (version 1) drew clusters in the order the database
returned its labels. That order was sorted under the database's en_US.UTF-8
collation, and glibc has changed that collation between releases. It is kept only to
reproduce intervals printed under it. Where the two orders disagree, they
disagree only at the last decimal. That decimal is the Monte Carlo noise floor
at the default replicate count, so no endpoint is given, or should be read, to
more than one decimal.

The public reimplementation is ``benchmark_adjudication``'s
``scripts/precision_ci.py``. It takes the same three inputs as that repository's
``scripts/score.py`` (findings, labels at a commit, and aurora-lint's scope
declaration), and it records the seed, replicate count, order and definition
version in every result. So anyone can recompute an interval from public inputs
and check that they used the same definition.
