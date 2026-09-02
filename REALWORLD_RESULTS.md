# SqC — Real-World Benchmark Results

**Last Updated**: 2026-09-02

Automated benchmark results across 9 real-world C codebases using sqc, plus
cppcheck and clang-tidy on the original 7.

> **Canonical source**: as of the SQLite migration, `data/benchmarks.db`
> (`realworld_runs` + `realworld_results`) is the source of truth for all
> real-world numbers. This file is a curated narrative snapshot; query the DB
> (or the realworld MCP tools) for the full per-version history.

---

## Latest Raw Counts (sqc v0.4.249 / v0.4.258)

Run #186, commit `107be7f0`, scanned 2026-08-23 — sqc only (cppcheck 2.10 /
clang-tidy 21.1.6 not re-run since v0.4.120 for the original 7 projects;
`pure-ftpd`'s competitor columns were added in the very next run, #187/
v0.4.258, which has identical sqc violation counts to #186 below). `pure-ftpd`
and `seL4` are two newly onboarded oracles. Note `sqlite`'s scan scope
narrowed (125→81 files, 218,733→181,604 LOC) since v0.4.120 — the project's
in-scope file predicate changed, not a regression.

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 9 | 1,034 | 395 | 40 | 2 |
| **lua** | 33 | 31,470 | 3,047 | 49 | 107 |
| **raylib** | 17 | 56,107 | 4,749 | 1,060 | 469 |
| **mosquitto** | 120 | 39,368 | 2,970 | 277 | 44 |
| **curl** | 222 | 186,220 | 8,582 | 556 | 116 |
| **sqlite** | 81 | 181,604 | 18,922 | 503 | 137 |
| **hostap** | 430 | 589,724 | 30,752 | 1,761 | 1,710 |
| **pure-ftpd** | 53 | 33,301 | 5,855 | 12 | 109 |
| **seL4** | 184 | 87,223 | 4,959 | — | — |

**Now scored** — see "Previous Adjudicated Results (sqc v0.4.258)" below.
Task 532's delta-adjudication (completed 2026-08-25) closed the gap between
this raw run and the last validly-measured v0.4.120 baseline; `seL4` still
has thin label coverage (81 labels from initial onboarding, later expanded
to a 10% sample under task 552) and `pure-ftpd`'s 10% sample is task 551.

---

## Latest Adjudicated Results (sqc v0.4.325)

Run #226, commit `0c889c2d`, scanned 2026-09-02. Precision/recall moved from
the v0.4.313 baseline below via continued rule-logic FP-reduction across the
~12 intervening releases. Every finding that moved relative to run #224 is
labeled, which is why this run — rather than simply the newest — is the one
cited (see CLAUDE.md's delta-adjudication protocol). `seL4`'s scan scope
narrowed (184→183 files, 87,223→49,957 LOC, first reflected at v0.4.260) the
same way `sqlite`'s did earlier — an in-scope file predicate change, not a
regression.

**Read the precision figure with the corpus in mind** — see
"[What this corpus can and cannot measure](#what-this-corpus-can-and-cannot-measure)"
below before quoting any per-rule number from it.

<!-- BENCH:REALWORLD_LATEST:START -->
### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **curl** | 222 | 186,220 | 7,201 | 556 | 116 |
| **hostap** | 430 | 589,724 | 27,255 | 1,761 | 1,710 |
| **libcrc** | 9 | 1,034 | 364 | 40 | 2 |
| **lua** | 33 | 31,470 | 2,616 | 49 | 107 |
| **mosquitto** | 120 | 39,368 | 2,588 | 277 | 44 |
| **pure-ftpd** | 53 | 33,301 | 5,339 | 12 | 109 |
| **raylib** | 17 | 56,107 | 4,353 | 1,060 | 469 |
| **seL4** | 183 | 49,957 | 2,619 | — | — |
| **sqlite** | 81 | 181,604 | 15,718 | 503 | 137 |
| **Total** | **1,148** | **1,168,785** | **68,053** | **4,258** | **2,694** |

Aggregate measured precision (adjudicated oracle, `bench realworld-score 226`): **24.3%** (TP 13,294 / 54,691 labeled of 62,028 findings), **recall 93.7%** (13,294 / 14,184 known TPs flagged); label coverage 54,691 / 62,028 findings (88.2%; 39 matched labels are "uncertain" and excluded from precision).
<!-- BENCH:REALWORLD_LATEST:END -->

Regenerate the table + precision/recall paragraph above with
`python -m bench render-docs --realworld-run RUN` (see `bench/render_docs.py`);
the header, "Run #N..." sentence and the note below stay hand-written since
they cite which tasks did the adjudicating.

**Week-over-week, against the same oracle** (run #193, v0.4.273, scanned
2026-08-26 → run #226): precision 22.1% → 24.3%, findings 69,532 → 62,028,
recall essentially flat (94.2% → 93.7%). That is ~7,500 findings removed in
seven days with recall held — real FP reduction landing on real code, not
reduced scanning.

Scan time over a comparable window fell from 23.5 min to 16.8 min across the
nine projects (run #212, v0.4.305 → run #220, v0.4.320; both recorded a
complete 9-of-9 set of per-project durations). Run #226 itself recorded no
durations — see task 715 — so it cannot be cited for timing, and neither can
runs #216–218 or #221–226.

> The bulk of the remaining 7,337 unlabeled findings (11.8%) is still the
> deliberately-unsampled majority of `pure-ftpd` (4,218 unlabeled, task 578)
> and `seL4` (1,949 unlabeled, task 579), plus a long tail spread across
> `sqlite` (781), `curl` (183), `mosquitto` (104), `hostap` (88) and smaller
> — not a gap in this measurement's validity for the rules/projects it does
> cover. Scope-enforced (task 636) and de-duplicated on
> `(file, line, rule)`, that debt is much smaller than the raw count
> suggests: 2,602 distinct in-scope unlabeled findings, of which `seL4`
> alone is 2,126 (82%) and `pure-ftpd` only 211.

**Clearing that debt will most likely lower the headline number, not raise
it.** Both remaining sampling tasks cover projects that label out well below
the corpus average — `seL4` at 9.5% and `sqlite` at 11.1% sample precision
against 24.3% aggregate — so finishing 578 and 579 should dilute measured
precision by roughly 1–2 points. That is adjudication debt being paid, not a
regression, and it should not be read as one when it lands.

### What this corpus can and cannot measure

The nine projects are mature, actively maintained, warning-clean C. That
makes them a demanding FP test and a credible source of real bug reports —
several findings here became upstream fixes. It also makes them the
*opposite* population from sqc's nominal use case.

sqc needs no build system and tolerates source that does not compile. That
is its differentiator, and it means the code it is designed for is newer,
less mature, in-progress work wired into CI/CD early — not released
software. Finding real defects in sqlite, curl and hostap demonstrates the
tool's reach and belongs in the record as exactly that: a demonstration, not
the representative case.

Two consequences that this file's aggregate numbers otherwise obscure:

1. **A per-rule real-world precision of 0% is often a statement about the
   corpus, not the rule.** Any rule whose defect cannot survive review in a
   codebase like these is structurally incapable of producing a true
   positive here. `DCL31-C` is the worked example: 364 findings, 324
   labeled, 0 TP — which reads as 0.0% precision. That figure measures
   sqc's header reachability, not the rule's quality. `mosquitto` alone goes
   from 1,365 `DCL31-C` findings with no `-I` to 0 with `-I /usr/include`.
   The rule guards a genuine defect — under C89 an implicit declaration
   makes the compiler assume `int f()`, so the return type is misread, no
   argument checking happens, and a returned pointer is truncated on LP64;
   C99 removed implicit declarations and C23 makes them an error — on code
   this corpus does not contain. Quoting that number as a rule-quality
   measure is a category error (task 692).
2. **Rule applicability is the user's lever, by design.** Manifest scoping
   and suppression exist so the user decides which rules apply to their
   code; detection logic deliberately does not make that call (the
   surface-don't-silence principle). A Linux-only corpus should not run the
   `WIN*` rules, for the same reason — a zero there is correct, not a gap.

See the rule-coverage section in [README.md](README.md#rule-suite-coverage)
for how much of the rule suite these two effects leave unvalidated.

---

## Previous Adjudicated Results (sqc v0.4.313) — superseded by v0.4.325 above

Run #217, commit `c4dad129`, scanned 2026-09-01. Precision/recall moved from
the v0.4.258 baseline below via incremental ground-truth adjudication and
rule-logic FP-reduction work across the ~55 intervening releases (see the
`ground_truth` table / task history for per-commit detail). `seL4`'s scan
scope narrowed (184→183 files, 87,223→49,957 LOC, first reflected at
v0.4.260) the same way `sqlite`'s did earlier — an in-scope file predicate
change, not a regression.

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **curl** | 222 | 186,220 | 7,243 | 556 | 116 |
| **hostap** | 430 | 589,724 | 27,460 | 1,761 | 1,710 |
| **libcrc** | 9 | 1,034 | 364 | 40 | 2 |
| **lua** | 33 | 31,470 | 2,655 | 49 | 107 |
| **mosquitto** | 120 | 39,368 | 2,602 | 277 | 44 |
| **pure-ftpd** | 53 | 33,301 | 5,385 | 12 | 109 |
| **raylib** | 17 | 56,107 | 4,421 | 1,060 | 469 |
| **seL4** | 183 | 49,957 | 2,647 | — | — |
| **sqlite** | 81 | 181,604 | 16,152 | 503 | 137 |
| **Total** | **1,148** | **1,168,785** | **68,929** | **4,258** | **2,694** |

Aggregate measured precision (adjudicated oracle, `bench realworld-score 217`): **24.1%** (TP 13,353 / 55,528 labeled of 62,886 findings), **recall 94.2%** (13,353 / 14,182 known TPs flagged); label coverage 55,528 / 62,886 findings (88.3%; 39 matched labels are "uncertain" and excluded from precision).

---

## Previous Adjudicated Results (sqc v0.4.258) — superseded by v0.4.313 above

Run #187, commit `8cb0c4ba`, scanned 2026-08-24. Delta-adjudicated against
the v0.4.120 baseline below per CLAUDE.md's delta-adjudication protocol
(task 532, completed 2026-08-25): ~30 intervening rule-logic commits'
findings were batched and adjudicated per-rule (tasks 534–550), plus initial
10%-sample coverage audits for the two newly-onboarded projects, `pure-ftpd`
(task 551) and `seL4` (task 552). Same violation counts as run #186 above,
now with `pure-ftpd`'s cppcheck/clang-tidy columns filled in (12 / 109).

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 9 | 1,034 | 395 | 40 | 2 |
| **lua** | 33 | 31,470 | 3,047 | 49 | 107 |
| **raylib** | 17 | 56,107 | 4,749 | 1,060 | 469 |
| **mosquitto** | 120 | 39,368 | 2,970 | 277 | 44 |
| **curl** | 222 | 186,220 | 8,582 | 556 | 116 |
| **sqlite** | 81 | 181,604 | 18,922 | 503 | 137 |
| **hostap** | 430 | 589,724 | 30,752 | 1,761 | 1,710 |
| **pure-ftpd** | 53 | 33,301 | 5,855 | 12 | 109 |
| **seL4** | 184 | 87,223 | 4,959 | — | — |
| **Total** | **1,149** | **1,206,051** | **80,231** | **4,258** | **2,694** |

Aggregate measured precision (adjudicated oracle, `bench realworld-score 187`):
**16.6%** (TP 10,576 / 63,674 labeled of 73,718 findings), **recall 97.4%**
(10,576 / 10,863 known TPs flagged); label coverage 63,674 / 73,718 findings
(86.4%; 41 matched labels are "uncertain" and excluded from precision).
Total sqc finding volume is down 28% from the v0.4.120 baseline's 104,733
(despite more rules enabled) — real FP-reduction landing on real-world code,
not just less scanning.

> The bulk of the remaining 10,044 unlabeled findings (13.6%) is the
> deliberately-unsampled 90% of `pure-ftpd` (task 578) and `seL4` (task 579),
> plus pre-existing long-tail rule gaps outside task 532's scope — not a gap
> in this measurement's validity for the rules/projects it does cover.

---

## Previous Adjudicated Results (sqc v0.4.120) — superseded by v0.4.258 above

Full sweep on per-project pinned commits (cppcheck 2.10, clang-tidy 21.1.6,
sqc v0.4.120), run #118, scanned 2026-07-22. Same 7-project set (`libcrc`,
`lua`, `raylib`, `mosquitto`, `curl`, `sqlite`, `hostap`) as the v0.4.83
snapshot below.

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 9 | 1,034 | 391 | 40 | 2 |
| **lua** | 33 | 31,637 | 3,068 | 49 | 107 |
| **raylib** | 17 | 56,107 | 5,213 | 1,060 | 469 |
| **mosquitto** | 120 | 39,368 | 11,225 | 277 | 44 |
| **curl** | 222 | 186,220 | 16,085 | 556 | 116 |
| **sqlite** | 125 | 218,733 | 31,319 | 503 | 137 |
| **hostap** | 430 | 589,724 | 37,432 | 1,761 | 1,710 |
| **Total** | **956** | **1,122,823** | **104,733** | **4,246** | **2,585** |

Aggregate measured precision (adjudicated oracle, `bench realworld-score 118`):
**6.2%** (TP 2,025 / 32,868 labeled of 92,915 findings), **recall 91.7%**
(2,025 / 2,209 known TPs flagged); label coverage 32,908 / 92,915 findings (40
matched labels are "uncertain" and excluded from precision).

This figure is the empirical precision floor across a diverse, adjudicated
multi-project sample, not a single-codebase spot check — cite it scoped (project
count, oracle methodology, recall alongside precision), not as a raw headline
number.

> The four MEM31-C ownership-model iterations targeting this run (task 2,
> v0.4.117–v0.4.120) moved the needle only slightly (-8 MEM31-C violations,
> all in `hostap`; `mosquitto` — the primary target — unchanged). The
> dominant real-world MEM31-C false-positive pattern turned out to be
> parameter-owned struct fields, a distinct root cause tracked separately
> (todo #306), not the same-function ownership-transfer pattern these
> iterations fixed.

---

## Previous Results (sqc v0.4.83)

Full sweep on commit `2220dc55` (cppcheck 2.10, clang-tidy 21.1.6, sqc v0.4.83),
run #91, scanned 2026-07-06. Adds `lua` and `raylib` as a 5th and 6th
ground-truth oracle alongside the original 5 projects (see
[Structural-C99 / Lua oracle context] below).

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 9 | 1,034 | 391 | 40 | 2 |
| **lua** | 33 | 31,637 | 3,090 | 49 | 107 |
| **raylib** | 17 | 56,107 | 5,248 | 1,060 | 469 |
| **mosquitto** | 120 | 39,368 | 11,299 | 277 | 44 |
| **curl** | 222 | 186,220 | 16,181 | 556 | 116 |
| **sqlite** | 125 | 218,733 | 31,314 | 503 | 137 |
| **hostap** | 430 | 589,724 | 37,910 | 1,761 | 1,710 |
| **Total** | **956** | **1,122,823** | **105,433** | **4,246** | **2,585** |

Aggregate measured precision (adjudicated oracle, `bench realworld-score 91`):
**6.2%** (TP 2,073 / 33,359 labeled of 93,411 findings), **recall 93.8%**
(2,073 / 2,209 known TPs flagged); label coverage 33,399 / 93,411 findings (40
matched labels are "uncertain" and excluded from precision).

---

## Results (sqc v0.4.57)

Full sweep on commit `1bbbbf14` (cppcheck 2.10, clang-tidy 21.1.6, sqc v0.4.57). 83/83 runs, 0 failed. 5-project set, before `lua`/`raylib` were added.

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 9 | 1,034 | 391 | 40 | 2 |
| **sqlite** | 125 | 218,733 | 32,358 | 503 | 137 |
| **mosquitto** | 120 | 39,368 | 11,317 | 277 | 44 |
| **curl** | 222 | 186,220 | 16,637 | 556 | 116 |
| **hostap** | 430 | 589,724 | 39,898 | 1,761 | 1,710 |
| **Total** | **906** | **1,035,079** | **100,601** | **3,137** | **2,009** |

Aggregate measured precision (adjudicated oracle): **7.2%** (TP 1,941 / 26,922 labeled of 88,615 findings), **recall 94.7%** (1,941 / 2,049).

### sqc Change vs v0.4.56

| Project | v0.4.56 | v0.4.57 | Delta |
|---------|--------:|--------:|------:|
| **libcrc** | 391 | 391 | 0 |
| **sqlite** | 32,382 | 32,358 | −24 |
| **mosquitto** | 11,317 | 11,317 | 0 |
| **curl** | 16,638 | 16,637 | −1 |
| **hostap** | 39,918 | 39,898 | −20 |
| **Total** | **100,646** | **100,601** | **−45** |

**v0.4.57 changes (task 214 — EXP34-C error-path null-vote suppression)**: prescan
no longer records an error/cleanup `x = 0; goto/return …;` null assignment as a
variable's null state, since that value never falls through to downstream call
sites. Previously the flow-insensitive last-write cast a spurious null call-site
vote that poisoned callee parameters every reachable caller passes non-null
(e.g. sqlite `whereOmitNoopJoin(pWInfo)`, `growOp3(p)`; hostap
`nl80211_bss_msg → bss->drv`), producing spurious EXP34-C param derefs.

- **EXP34-C** −43 of the −45 total: sqlite −23, hostap −19, curl −1 — all
  reductions, 0 additions. On sqlite all 19 adjudicated removals are
  oracle-confirmed FP (0 of 7 oracle TPs lost); curl's single removal is not an
  oracle TP. The malloc-then-deref null-deref FN is untouched (no trailing
  jump), and Juliet stayed 100% flat (TP 22,615 / FP 4,607 / 83.1% across all 74
  CWEs), so null-deref recall is unaffected.

---

## Results (sqc v0.3.5)

MCP-based benchmark infrastructure across 3 hosts (cppcheck 2.10, clang-tidy 21.1.6, sqc v0.3.5 commit `8b8e1eec`).

### Violation Counts — All Three Tools

| Project | C Files | LOC | sqc | cppcheck | clang-tidy |
|---------|--------:|----:|----:|--------:|-----------:|
| **libcrc** | 16 | 2,130 | 734 | 43 | 2 |
| **sqlite** | 310 | 402,321 | 129,035 | 1,181 | 135 |
| **mosquitto** | 384 | 88,717 | 29,824 | 747 | 44 |
| **curl** | 697 | 240,412 | 63,207 | 519 | 114 |
| **hostap** | 505 | 541,441 | 179,833 | 2,118 | 2,279 |
| **Total** | **1,912** | **1,275,021** | **402,633** | **4,608** | **2,574** |

**Interpretation**: sqc covers 283 CERT-C rules (advisory + mandatory) while cppcheck and clang-tidy implement ~20 checks each. The 100x difference in raw counts reflects rule coverage breadth, not false positive rate.

### Scan Timing — sqc v0.3.13 (4-core laptop, single process)

| Project | C Files | LOC | sqc Time | Violations |
|---------|--------:|----:|----------|-----------:|
| **libcrc** | 16 | 2,130 | 6s | 734 |
| **mosquitto** | 384 | 88,717 | 4m 10s | 26,735 |
| **curl** | 697 | 240,412 | TBD | 63,207 |
| **sqlite** | 310 | 402,321 | TBD | 129,035 |
| **hostap** | 505 | 541,441 | TBD | 179,833 |

**Environment**: 4-core laptop (AMD/Intel mobile), single sqc process, `-d` cross-file analysis enabled, warm filesystem cache. Timing measured with `time` command (wall-clock).

**Notes**:
- Scan time correlates with LOC more than file count. sqlite's amalgamated `sqlite3.c` (~250K lines) dominates its scan time despite having fewer files than curl
- When comparing across machines, record CPU model and core count
- First-run (cold cache) adds ~50-60% overhead vs warm cache
- **mosquitto** is used as the CI/CD benchmark target. Expected CI time: ~8-12 min on a standard CI agent

### sqc Version History

| Project | v0.2.7 | v0.2.13 | v0.2.16 | v0.2.21 | v0.2.22 | v0.3.5 | Delta (0.2.21→0.3.5) |
|---------|-------:|--------:|--------:|--------:|--------:|-------:|----------------------:|
| **libcrc** | 842 | 811 | 790 | 777 | 777 | 734 | -43 (-5.5%) |
| **mosquitto** | 39,177 | 33,638 | 33,200 | 29,997 | 29,989 | 29,824 | -173 (-0.6%) |
| **sqlite** | 180,011 | 147,091 | 144,581 | 130,774 | 130,802 | 129,035 | -1,739 (-1.3%) |
| **curl** | 93,576 | 73,816 | 73,239 | 64,393 | 64,389 | 63,207 | -1,186 (-1.8%) |
| **hostap** | 234,421 | 206,906 | 204,560 | 184,952 | 185,197 | 179,833 | -5,119 (-2.8%) |
| **Total** | **548,027** | **462,262** | **456,370** | **410,893** | **411,154** | **402,633** | **-8,260 (-2.0%)** |

**v0.3.5 changes**: DCL13-C alias tracking fix, DCL30-C function parameter skip, EXP33-C uninitialized variable improvements, struct field type resolution for INT32-C/INT30-C, ARR32-C array bounds fixes, POS49-C thread function fixes, STR04-C/STR34-C string type fixes.

**Top rule changes (4 comparable codebases, v0.2.21→v0.3.5)**:
- ARR32-C −2,178 (array declarator improvements)
- EXP33-C −2,118 (init tracking for function calls, conditional branches)
- POS49-C −1,787 (thread function recognition)
- STR04-C −229 (string literal type checks)
- EXP05-C −146 (const qualifier detection)
- INT34-C −100 (shift operand type fixes)
- INT32-C −93 (net: struct field resolution added new findings, bounds-check detection removed FPs)
- INT30-C +287 (struct field resolution now correctly identifies unsigned struct fields → more findings)

**v0.2.22 changes**: INT30-C if-statement upper-bound guard detection. Extends `is_bounded_by_loop_condition()` to suppress `++`/`+= 1`/`var + 1` inside `if (var < limit)` true branch. INT30-C deltas: curl -9, hostap -7, mosquitto -8 (total -24).

**v0.2.16→v0.2.21 changes**: const_eval value-range analysis (INT32-C/INT30-C macro constant folding), API00-C static function skip, INT01-C dedup fix, EXP34-C stack array NotNull, DCL13-C alias tracking, INT31-C pointer cast skip, ARR36-C type filter, INT30-C guard expansion, ARR02-C string-literal arrays, POS02-C socket/setsockopt, PRE31-C literal stripping, MEM05-C ALL_CAPS VLA.

**Top rule changes (curl, v0.2.16→v0.2.21)**: API00-C −6,102, DCL13-C −470, INT32-C −350, MEM05-C −323, EXP34-C −287, INT30-C −171, INT01-C −142, ARR02-C −98, EXP37-C −81, POS02-C −61.

**v0.2.13→v0.2.16 changes**: Call-site null propagation (EXP34-C Phase 2). Prescan collects argument null states at call sites; callee params seeded with joined caller states instead of blanket PossiblyNull. Call-site flagging re-enabled for DefinitelyNull args passed to functions that don't null-check.

**v0.2.7→v0.2.13 changes**: Cross-file analysis (`-d` directories), Windows API whitelist, bounds-check detection (INT32-C/INT30-C), CFG-based null state dataflow (EXP34-C Phase 1), multiple FP reduction rounds. Total: -85,765 (-15.6%).

### Improvement from Baseline (sqlite: v0.2.4 → v0.3.5)

| Metric | v0.2.4 | v0.2.7 | v0.2.16 | v0.2.21 | v0.3.5 | Delta (0.2.4→0.3.5) |
|--------|-------:|-------:|--------:|--------:|-------:|---------------------:|
| Total violations | 427,377 | 180,011 | 144,581 | 130,774 | 129,035 | **-298,342 (-69.8%)** |
| STR31-C | 206,651 | 222 | ~200 | ~200 | -206,451 (rewrite) |
| EXP34-C | 41,886 | 8,734 | ~8,500 | ~8,200 | -33,686 (CFG dataflow + call-site propagation) |
| ARR36-C | 3,034 | 600 | ~600 | ~550 | -2,484 |
| EXP30-C | 2,623 | 300 | ~300 | ~300 | -2,323 |
| API02-C | 1,542 | 166 | ~166 | ~166 | -1,376 |

### Key Observations

- **Steady decline across all projects**: Every codebase shows consistent reduction from v0.2.7 through v0.3.5
- **v0.2.16→v0.2.21 is the largest inter-version drop**: -10.0% overall, driven by API00-C static skip (dominant), const_eval, and multiple targeted FP fixes
- **v0.2.21→v0.3.5 continues trend**: -2.0% overall, driven by EXP33-C init tracking, ARR32-C array bounds, and POS49-C thread fixes
- **Struct field resolution validated**: INT30-C +287 increase is correct behavior — struct fields now properly classified as unsigned, generating new true findings
- **Advisory rules dominate**: DCL07-C, DCL31-C, DCL08-C, DCL13-C, EXP19-C, API00-C are code-style/quality rules. Severity filtering would significantly reduce noise
- **mosquitto is cleanest**: 30K violations (vs. 180K for hostap)
- **Cumulative reduction from v0.2.7**: -145,394 violations (-26.5%) across all 5 codebases (4 comparable)

---

## Cross-Tool Capability Analysis

### Comparable Checks

| Bug Class | sqc Rule | clang-tidy Check | cppcheck Check | Notes |
|-----------|----------|------------------|----------------|-------|
| Unchecked return value | ERR33-C | `cert-err33-c` | — | sqc 5x count (broader function list) |
| Unsafe numeric conversion | ERR34-C | `cert-err34-c` | — | sqc finds MORE (126 vs 33 on mosquitto) |
| Null pointer dereference | EXP34-C | `NullDereference` | `nullPointer` | sqc 4,300:1 ratio (see below) |
| Uninitialized variable | EXP33-C | — | `uninitvar` | Different sub-patterns of CWE-457 |
| String/buffer safety | STR rules | `DeprecatedOrUnsafe...` | — | Different scope |

### EXP34-C: Known High FP Rate on Real Code

| Project | sqc EXP34-C | cppcheck nullPointer (error) | cppcheck nullPointerRedundantCheck |
|---------|------------:|-----------------------------:|-----------------------------------:|
| mosquitto | 8,657 | 2 | 0 |
| curl | 22,350 | 0 | 177 |

sqc uses CFG-based null state dataflow with inter-procedural call-site propagation (Phase 2 complete as of v0.2.16). cppcheck uses data-flow analysis and only fires when it can prove a null-dereference path. The gap is narrowing but sqc still flags more conservatively.

### What sqc Uniquely Covers

- **POS49-C** (POSIX misuse): 4,534 on curl — no competitor equivalent
- **INT32-C / INT30-C** (signed/unsigned overflow): significant counts — competitors skip
- **MEM30-C / MEM31-C** (use-after-free, memory management)
- **API00-C / API02-C**: no competitor equivalent
- **270+ additional rules** across integer, floating-point, environment, concurrency, POSIX

---

## Historical Results (v0.2.7)

First MCP-based benchmark run (cppcheck 2.10, clang-tidy 21.1.6, sqc v0.2.7 commit `54819432`).

| Project | sqc | cppcheck | clang-tidy |
|---------|----:|--------:|-----------:|
| **libcrc** | 842 | 40 | 4 |
| **sqlite** | 180,011 | 517 | 204 |
| **mosquitto** | 39,177 | 364 | 160 |
| **curl** | 93,576 | 297 | 1,314 |
| **hostap** | 234,421 | 1,675 | 2,957 |
| **Total** | **548,027** | **2,893** | **4,639** |

---

## Baseline References (v0.2.3)

Earlier results for comparison (before STR31-C rewrite and major FP reductions).

### libcrc (v0.2.3)

| Tool | Total | Top Rules/Checks |
|------|------:|-----------------|
| **sqc** | 954 | EXP14-C (106), ERR33-C (68), EXP12-C (62), INT30-C (60) |
| **cppcheck** | 40 | variableScope (36), unusedFunction (2) |
| **clang-tidy** | 52 | cert-err33-c (26), DeprecatedOrUnsafe... (24) |

### sqlite (v0.2.3)

| Tool | Total | Notes |
|------|------:|-------|
| **sqc** | 424,842 | STR31-C (206,651) = 49% — `detect_manual_string_loop` bug |
| **cppcheck** | 1,182 | variableScope (505), toomanyconfigs (189) |
| **clang-tidy** | 2,291 | cert-err33-c (1,025), DeprecatedOrUnsafe... (453) |

### curl (v0.2.3)

| Tool | Total | Notes |
|------|------:|-------|
| **sqc** | 207,476 | STR31-C (93,140) = 45% — same runaway bug |
| **cppcheck** | 551 | toomanyconfigs (253), variableScope (95) |
| **clang-tidy** | 1,653 | clang-diagnostic-error (1,024), cert-err33-c (366) |

### mosquitto (v0.2.3)

| Tool | Total | Notes |
|------|------:|-------|
| **sqc** | 47,417 | EXP34-C (7,631) dominates (STR31-C NOT triggered here) |
| **cppcheck** | 598 | 50 `uninitvar` at error severity — highest-confidence real defects |
| **clang-tidy** | 907 | cert-err33-c (477), cert-err34-c (111) |

### hostap (v0.2.3)

| Tool | Total | Notes |
|------|------:|-------|
| **sqc** | 473,862 | STR31-C (170,586) = 36% |
| **cppcheck** | 1,066 | 89 `uninitvar` at error severity |
| **clang-tidy** | 1,083 | cert-err34-c (377) dominates |

---

## STR31-C `detect_manual_string_loop` Bug (FIXED)

**Severity**: High — caused 36–49% of all sqc violations on 3 of 5 projects.

**Root cause**: Final fallback iterated ALL lines in source file looking for `memcpy` + `strlen`/`string`. One match anywhere caused every loop to generate a violation. `jimsh0.c` alone produced 180,297 violations.

**Fix**: Deleted file-wide fallback; condition-only matching; body-only write detection; improved `is_string_memcpy`.

**After fix**: `jimsh0.c` STR31-C dropped from 180,297 to 10.
