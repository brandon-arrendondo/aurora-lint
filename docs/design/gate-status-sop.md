# SOP: Weekly Gate Status Check

**Cadence:** weekly, end of week (Friday). Ask Claude Code, in this repo,
to "run the gate status SOP" (`docs/design/gate-status-sop.md`).

**Purpose:** answer, with evidence rather than gut feel, how close sqc is
to two gates, and whether the tool's underlying capability is actually
improving week to week:

1. **Steady-state / maintenance mode** — `todo-sqlite-cli` task **#463**
2. **Publishable paper** — `todo-sqlite-cli` task **#9**, which has a hard
   dependency on #463 in the `deps` table (paper finalization cannot start
   before maintenance mode is reached)
3. **Capability trend** (not a gate — an ongoing health read) across five
   metrics: precision/recall, CERT-C rule coverage, Juliet/real-world
   benchmark breadth, the paper's claims vs. other tools, and runtime —
   see "Capability Trend Check" below.

Both are modeled as `GATE:`-prefixed tasks (the `is_gate` column /
`--gate` flag from `PLAN_gate_tasks.md` is the eventual first-class
version of this convention — check `SELECT is_gate FROM tasks WHERE
id IN (9,463)` and prefer that once it ships instead of matching on title
prefix). A gate task is not "work" — nobody `start`s it. It sits open
until the world satisfies the condition in its `details`, then gets
closed with `todo-sqlite-cli done`.

## Repos this SOP spans (as of 2026-09-03)

The three checks below no longer live in one tree:

| What | Where |
|------|-------|
| tool version, rule counts, this SOP, tasks #9/#463 | `tools_sqc` (run the SOP here) |
| paper source, its pinned version claims | `../sqc_paper` |
| every benchmark/oracle number, and the tasks behind them | `../benchmarking_db` (its own task DB since 2026-09-03) |

So a `todo-sqlite-cli` query in this file answers about the TOOL's backlog
only. Benchmark and adjudication tasks moved to `benchmarking_db`'s DB, and
display ids now collide between the two -- say which repo when citing one.

## Reliability note: query the DB directly, don't rely on `todo-sqlite-cli`'s CLI version

The CLI binary version and the `todo-sqlite-cli.db` schema version can be
out of sync across machines (observed 2026-08-26: work-machine CLI only
supported schema 2, the DB was already at schema 4, `cfd`/`gate`-aware
commands failed outright). Run raw `sqlite3` against `todo-sqlite-cli.db`
so this SOP works regardless of which machine or CLI version is current.
If `todo-sqlite-cli cfd --bucket week` / `todo-sqlite-cli show --gate`
happen to work on the machine you're on, they're a fine faster substitute
for 1a below — just don't block the check on them being available.

---

## Gate 1: Steady-state / maintenance mode (task #463)

Task #463's own wording defines three criteria, evidenced by trend, not a
single-day snapshot. All three must hold.

### 1a. Active backlog trend is flat or shrinking for several consecutive weeks

```bash
sqlite3 -header -column todo-sqlite-cli.db "
WITH weeks AS (SELECT strftime('%Y-%W', created_at) wk, count(*) created FROM tasks GROUP BY wk),
comp  AS (SELECT strftime('%Y-%W', completed_at) wk, count(*) completed FROM tasks WHERE completed_at IS NOT NULL GROUP BY wk),
merged AS (SELECT weeks.wk wk, created, COALESCE(completed,0) completed FROM weeks LEFT JOIN comp USING(wk))
SELECT wk, created, completed,
  SUM(created) OVER (ORDER BY wk) - SUM(completed) OVER (ORDER BY wk) AS running_backlog
FROM merged ORDER BY wk DESC LIMIT 8;"
```

Read the `running_backlog` column, most recent rows first.

- **Suggested heuristic** (adjust by feel, not gospel — #463 deliberately
  says "evidenced by," not "when X < N"): PASS if net weekly delta
  (`created - completed`) is ≤ 0 for at least 3 of the last 4 weeks, or
  `running_backlog` is within ~10% of its value 4 weeks prior.
- Baseline as of 2026-08-26: backlog has grown from 94 (week 16) to 156
  (week 34); the last 3 weeks (32/33/34) are all net-positive. **NOT YET.**

### 1b. No open P1/P2 tasks representing systemic FP/FN drivers

```bash
sqlite3 -header -column todo-sqlite-cli.db "
SELECT t.id, t.priority, t.title
FROM tasks t JOIN tags g ON t.uuid = g.task_uuid
WHERE t.status IN ('pending','partial','in-progress')
  AND t.priority <= 2
  AND g.tag IN ('fp-reduction','rule-bug','coverage-gap')
GROUP BY t.id ORDER BY t.priority;"
```

- PASS = empty result set.
- Judge against **delta-adjudicated** `ground_truth` findings, not raw
  finding counts — see CLAUDE.md's delta-adjudication protocol. A rule
  with a scary raw-count jump can be fine post-adjudication and vice
  versa; don't let a raw count alone flip this criterion.
- Baseline as of 2026-08-26: empty. **PASS.**

### 1c. Real-world precision/recall has plateaued across the last several ground_truth-scored runs

Requires `data/benchmarks.db` to be populated — this only happens on the
home benchmark machine (see project memory
[[project_benchmark_location]]); the work-machine copy is a 0-byte
placeholder and this criterion is simply **unavailable** there. Report it
as "unavailable, last checked `<date>`" rather than silently skipping it
or guessing.

```bash
python -m bench realworld-score RUN   # per scored run, or:
sqlite3 -header -column data/benchmarks.db ".schema ground_truth"
sqlite3 -header -column data/benchmarks.db "SELECT * FROM realworld_results ORDER BY run_id DESC LIMIT 20;"
```

(Confirm exact column names against the live schema before trusting a
canned query here — not verified from the work machine as of 2026-08-26.)

- **Suggested heuristic**: PASS if precision and recall both move by less
  than ~2 percentage points run-over-run across the last 3+
  ground_truth-scored runs (i.e., no rule change is still visibly moving
  the needle). Still climbing steeply = NOT YET regardless of direction.

### Gate 1 verdict

PASS only if 1a + 1b + 1c all PASS. Otherwise state which criteria are
outstanding and roughly by how much (don't just say "not yet" — give the
number that would need to flip).

---

## Gate 2: Publishable paper (task #9)

1. **Gate 1 must already be PASS.** Task #9 depends on #463 in the `deps`
   table — if Gate 1 isn't closed, Gate 2 is automatically NOT YET
   regardless of the rest. Don't evaluate 2–4 as if they could compensate.
2. **No open `paper`-tagged tasks:**
   ```bash
   sqlite3 -header -column todo-sqlite-cli.db "
   SELECT t.id, t.title, t.status, t.priority
   FROM tasks t JOIN tags g ON t.uuid = g.task_uuid
   WHERE g.tag = 'paper' AND t.status NOT IN ('done','rejected')
   ORDER BY t.priority;"
   ```
   Baseline as of 2026-08-26: one open item, #378 (P4) — Juliet trend-line
   caveat for the 21 newly-tracked rules from task 326, itself blocked on
   those rules actually being implemented (tasks 329–349).
3. **Version/number drift check** — the paper's tables are frozen to the
   `run_id` that produced them; catch drift before submission rather than
   at review time:
   - Cited Juliet/real-world version(s) in the paper repo's `sqc.tex`
     (`grep -n 'v0\.4\.[0-9]*' ../sqc_paper/sqc.tex`) vs. current `Cargo.toml`
     version. Baseline 2026-08-26: paper cites v0.4.249 (Juliet) /
     v0.4.258 (real-world); repo is at v0.4.267. A version gap isn't
     automatically disqualifying — confirm no rule/detection-logic change
     landed in that gap that would move the cited numbers, don't just
     leave the gap unexamined.
   - Cited rule count vs. `grep -c "enabled = true" rules_templates/rules-all.toml`
     (305 as of 2026-08-26).
4. **Spot-check a couple of paper citations against a live run_id**
   (`python -m bench runs`, `get_cwe_detail()`) rather than trusting prose
   — cheap insurance against a stale number surviving into submission.

### Gate 2 verdict

PASS only when 1–4 all clear. State specifically what's outstanding.

---

## Capability Trend Check (five metrics)

Distinct from the pass/fail gates above: this section tracks whether the
*tool itself* is getting better week to week, independent of whether
either gate has flipped. A gate can be PASS while capability is flat, or
NOT YET while capability is visibly still improving (the two are not the
same question — a still-climbing precision curve is good news for the
tool and simultaneously bad news for "has it plateaued," gate 1c). Report
all five every week, even when a metric is unavailable — say so rather
than omitting it silently.

### 5.1 Precision / recall (real-world, delta-adjudicated)

Same source and same caveat as gate 1c (`data/benchmarks.db`, home-machine
only). Pull the two most recent **delta-adjudicated** figures — not raw
counts — and diff them:

```bash
sqlite3 -header -column data/benchmarks.db "
SELECT run_id, sqc_version, finished_at FROM runs ORDER BY finished_at DESC LIMIT 5;"
python -m bench realworld-score RUN --json   # per candidate run_id, once ground_truth covers it
```

Baseline 2026-08-25 (task #532, run 187/v0.4.258 vs. v0.4.120 baseline):
precision 6.2% → **16.6%**, recall 91.7% → **97.4%**, real-world raw
finding volume down 28% (104,733 → 80,231) despite more rules enabled —
genuine FP reduction, not just less scanning. Also track Juliet TP rate
from the paper refresh cadence: 83.8% (v0.4.116) → **87.7%** (v0.4.249),
still climbing, not flat.

### 5.2 CERT-C rule coverage

No `benchmarks.db` dependency — works from any machine via git history:

```bash
grep -c "enabled = true" rules_templates/rules-all.toml   # current enabled count
git log --format="%ad %h" --date=short -- src/rules/cert_c/rules-all.toml | head -1  # last time it changed at all
```

Baseline 2026-08-26: **305 enabled / 311 implemented**, unchanged since
**2026-07-26** (task 326's re-ingest) — a full month flat. Report both the
count and how long it's been flat; a flat count for one week is normal
noise, a flat count for a month is a real signal that coverage work has
paused in favor of precision/recall work (as it has this cycle).

### 5.3 Juliet / real-world benchmark basis (breadth + freshness of testing)

Track two things, both git/doc-derivable without `benchmarks.db`:

- Real-world project-set size: `grep -c '^\| [a-z]' REALWORLD_RESULTS.md`
  or just read the project list. Baseline 2026-08-26: **9 projects**
  (pure-ftpd, seL4 added this cycle, up from 7).
- Days since the cited Juliet/real-world run's actual execution date vs.
  today — a run can be *cited* in the paper well after it was *executed*
  (e.g. run 186 executed ~2026-08-23, adjudicated and published 2026-08-25
  — a 2-day citation lag, healthy; watch for this lag growing to weeks).

### 5.4 Paper's claims vs. other tools

The 5-tool comparison table (cppcheck, clang-tidy, Infer, Frama-C) is
pinned to whatever `sqc_version` its narrative cites — check:

```bash
grep -n "SqC v0\.4\.[0-9]*" ../sqc_paper/sqc.tex   # pinned comparison-table version
grep -m1 "^version" Cargo.toml             # current version
```

Baseline 2026-08-26 (pre-refresh): comparison table pinned to **v0.4.116**,
current repo **v0.4.267** — a ~150-version gap, and *not* touched by the
routine paper refreshes (task #533 explicitly left it out of scope:
re-running it requires re-executing all 4 external tools, not a number
swap). Report the gap every week; it will only close via a deliberate
re-run task, not incidentally. Flag if this becomes the long-pole item
before submission.

**Updated 2026-08-26 (same day, commit 98be5e2f):** re-ran Juliet at
current HEAD (v0.4.271, `sqc-0.4.271-bf75fcaa`, 79/79 CWEs) and refreshed
SqC's column + overall stats + prose in `tab:competitor`. cppcheck/
clang-tidy/Infer/Frama-C columns still held fixed (unchanged from the
original study, per the table's own footnote — that part of the gap is
permanent by design, not drift). SqC's overall TP rate on the 15
overlapping CWEs moved 79.5% → 82.6%; no row's winner flipped. Next
refresh should re-check the version gap again from v0.4.271, not
v0.4.116.

### 5.5 Runtime / performance

Expected to drift **upward** over time as rule count and per-rule analysis
depth grow — the question isn't "did it go up" but "is it going up faster
than the rule count, or has it crossed a usability threshold" (interactive
use, CI budget). Requires `data/benchmarks.db` (home-machine only); always
compare runs on matching hardware (`hostname`/`cpu_model`/`cpu_cores` —
the schema captures these specifically so cross-machine comparisons don't
get made by accident):

```bash
sqlite3 -header -column data/benchmarks.db "
SELECT run_id, sqc_version, hostname, jobs,
  (julianday(finished_at) - julianday(started_at)) * 86400 AS total_wall_s
FROM runs WHERE status='finished' ORDER BY finished_at DESC LIMIT 8;"

sqlite3 -header -column data/benchmarks.db "
SELECT rr.id AS run_id, rr.sqc_version, res.project, res.duration_s
FROM realworld_results res JOIN realworld_runs rr ON res.run_id = rr.id
WHERE res.tool = 'sqc' ORDER BY rr.id DESC LIMIT 20;"
```

Not measured from the work machine as of 2026-08-26 — `benchmarks.db` is
empty here. Note also that the paper's own timing table has been
self-flagged stale since v0.4.55 (`fig:scan-time` is used as a proxy
trend chart instead) — a deliberate, tracked gap, not new information,
but this SOP's weekly runtime read is exactly the input that would let
someone decide to finally re-measure it properly before submission
(controlled serial single-process rerun, per task #533's notes — not a
docs-only fix).

- **Suggested heuristic**: track wall-clock per enabled rule
  (`total_wall_s / enabled_rule_count`) alongside the raw total. Flat or
  slowly-rising per-rule cost with a rule-count-driven total increase is
  healthy scaling. A per-rule cost that's itself rising is the real
  warning sign — it means something got slower independent of coverage
  growth, not just "more work to do."

---

## Output format

Close every run with a short status block, e.g.:

```
Gate 1 (maintenance mode): NOT YET
  1a backlog trend      — growing (+19 over last 3 weeks)
  1b open P1/P2 FP/FN   — PASS (none open)
  1c real-world P/R     — unavailable (data/benchmarks.db empty on this machine, last checked 2026-08-26)

Gate 2 (publishable paper): BLOCKED on Gate 1
  also: 1 open paper task (#378, P4); version drift v0.4.249->v0.4.267 unreconciled

Capability trend:
  5.1 precision/recall     — improving (real-world 6.2%/91.7% -> 16.6%/97.4%; Juliet TP 83.8% -> 87.7%, still climbing)
  5.2 rule coverage         — flat (305 enabled / 311 implemented, unchanged 1 month since 2026-07-26)
  5.3 benchmark breadth     — improving (real-world set 7 -> 9 projects; run-to-citation lag 2 days, healthy)
  5.4 vs-other-tools claims — refreshed 2026-08-26 (v0.4.116 -> v0.4.271; overall TP rate 79.5% -> 82.6%, no row flipped; competitor columns still held fixed by design)
  5.5 runtime               — unavailable (data/benchmarks.db empty on this machine, last checked 2026-08-26)
```

## Notes

- No fixed numeric thresholds are hard-coded for "flat" (1a) or
  "plateaued" (1c) — task #463 deliberately phrases this as "evidenced
  by" trend, not a hard cutoff. The heuristics above are a starting point
  for judgment, not a formula to satisfy mechanically; override them with
  reasoning when the trend is ambiguous (e.g. one large batch task
  inflating a single week's `created` count).
- When Gate 1 flips to PASS, close #463 via `todo-sqlite-cli done 463`
  (unblocks #9) and update this doc's baselines. When Gate 2 flips to
  PASS, close #9.
- Two memory names — `maintenance-mode-backlog-signal` and
  `ceiling-decision-alias-vs-realworld` — are referenced from #463's
  `details` field as containing "fuller reasoning" but do not currently
  exist in the auto-memory store as of 2026-08-26. Either write them (if
  the reasoning is still needed beyond what's captured in this SOP) or
  drop the dangling reference from #463.
