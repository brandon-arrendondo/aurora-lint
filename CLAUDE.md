# Claude Code Project Instructions

## Benchmark Workflow (CRITICAL)

See `docs/index.rst` (Benchmark Setup / Running Benchmarks sections) for the full CLI reference and troubleshooting.

### Where benchmark data actually lives (READ THIS FIRST)

**Every OFFICIAL number comes from the `sqc_bench` Postgres instance.** Full
stop. "Official" means anything published as this project's own measurement —
`README.md`, the paper, a release note, a claim made to anyone outside. It
is the only source of truth for both (a) historical benchmark data and (b)
adjudication data.

The gateway to it is the separate **`benchmarking_db`** repo: all benchmarking
capability was deliberately pulled out of this repo into that one to make the
distinction unambiguous. Worker nodes reach the historical record through
`benchmarking_db`'s MCP servers; Claude instances running on the benchmark host
itself have broader access because they operate on that data directly. If a run
is meant to count as ours, it is queued through `benchmarking_db` and lands in
Postgres.

**Running your own benchmarks locally is fully supported and nothing here
discourages it.** Anyone cloning this repo gets a working benchmark setup with
nothing beyond `cargo build --release` and the codebase checkouts in
`docs/benchmark-setup.rst`, and is free to run whatever they like and capture
it however they like — `data/benchmarks.db`, a CSV, a JSON dump, all equally
fine. That path is first-class for its purpose.

What it is not is a source of *official* numbers. `data/benchmarks.db` has no
special standing over any other local format: it is this checkout's own record
of its own runs. A figure computed from it describes those runs, not the
project's measurements, so it must never be transcribed into a published
document or cited as a project result.

**Why it moved (the part that keeps this from looking arbitrary).** Local
SQLite was a sound paradigm when this was mostly a single worker node — the
data sat where the work happened. The infrastructure is now multiple nodes
doing parallel work, and that broke the model: worker nodes need access to
benchmark data, that data keeps growing, and workers are cheap and expendable.
A node cannot afford to carry a duplicate of the entire benchmark corpus just
to do its job. Centralizing in Postgres and reaching it over MCP is what makes
a worker disposable. For scale, this checkout's own local DB is **6.5 GB** —
26M violation rows — and it is a strict subset of the shared instance. That is
the per-node cost the split removes.

**The second reason is the clone experience, and it is the one to apply when
judging a proposal.** Someone who clones sqc should not have to wade through
scaffolding that exists to make *this* maintainer's parallel-node setup
efficient. They will not have that machinery — or, just as likely, they are
more capable than it and would be slowed down by its assumptions. Either way it
is a barrier to them improving sqc, which is the point of the repo.

Benchmarking is primarily a **maintainer artifact**: it tells the story of the
tool's capability and how it progressed over time. Most users care about the
current state, and mostly about the codebase they are actually pointing sqc at
— not about its score on an arbitrary corpus. So `bench/` exists here so a user
*can* benchmark their own code; it does not exist to hand them the maintainer's
measurement pipeline.

The practical test for any new benchmarking/measurement code: **would a
stranger cloning this repo need it to evaluate sqc on their own codebase?** If
no, it belongs in `benchmarking_db`. Two corollaries follow:

- Do not "helpfully" reintroduce a local mirror, cache, or sync of benchmark
  data for speed or offline use. That is the paradigm deliberately abandoned,
  and it brings back the per-node duplication cost plus a second thing that can
  go stale or disagree.
- Do not add maintainer-workflow machinery here to save a hop. Multi-node
  coordination, shared-instance credentials, queue plumbing and cross-machine
  reconciliation are `benchmarking_db`'s, however convenient it would be to
  reach for them from this side.

**On the adjudication dataset specifically:** the TP/FP/FN labels are genuinely
valuable beyond sqc — other tools and research could use them. That is an
argument for *sharing* them, not for keeping them in git. Large datasets are
distributed the way ML/research datasets already are (object storage, a hosted
dataset, a distributed DB), and exporting from Postgres to such a target should
stay trivial. Keep it that way; do not let the dataset's future portability
become a reason to hold it in-repo now, where it would be a barrier to the
2-10 node parallel system needed to work the backlog down to maintenance mode.

**This repo stays Postgres-blind**: no DSN, no connection code, no awareness of
the shared instance in anything you add here. Postgres being the source of
truth and this repo not knowing how to reach it are both true at once, and the
seam is what keeps `bench/` usable by a fresh clone. See
`benchmarking_db/docs/ownership.md` for what that repo owns (historical runs,
every metric about them, and the whole adjudication oracle including the corpus
scope predicate).

### Local SQLite storage (the local-run path)

A local run writes to **`data/benchmarks.db`** (SQLite, WAL mode) — gitignored,
so it is per-checkout and no clone inherits anyone else's.

**Key tables**: `runs` (one row per benchmark), `cwe_scans` (one per CWE per run),
`violations` (every individual finding), `cwe_metrics` (pre-computed TP/FP/rates),
`rule_cwe_breakdown` (per-rule per-CWE counts), `realworld_runs` + `realworld_results`,
`ground_truth` (local adjudication store — **not** the oracle; the oracle is
`benchmarking_db`'s. `realworld-import-labels` requires `--local-oracle` so that
writing here is a thing you state rather than a default you fall into).

### Running Benchmarks

Everything runs synchronously in your own terminal — no server process, no
async polling. `python -m bench juliet`:
- Uses **fast mode by default** (per-CWE manifests, CWE-matched rules only)
- Runs CWEs in parallel via `ProcessPoolExecutor`
- Writes results directly to SQLite (no intermediate text files)
- Supports resume: re-running skips already-completed CWEs

```bash
python -m bench juliet [--full] [--jobs N]
python -m bench status [RUN_ID]
python -m bench compare BASE TARGET
python -m bench runs
python -m bench corpus-check   # are the real-world checkouts still pinned?

# Real-world (sqc + cppcheck + clang-tidy against real C codebases; local,
# sequential — see bench/realworld_runner.py). Defaults to sqc against every
# codebase; narrow with --tool/--codebase.
python -m bench realworld-run [--tool sqc,cppcheck,clang-tidy] [--codebase C,C]
python -m bench realworld [RUN]        # FP dashboard
python -m bench realworld-score [RUN]  # measured precision/recall vs oracle
```

**Run `python -m bench corpus-check` before any real-world run or precision
claim** (task 619). The pins live in `data/benchmark_repos.json` (single
source of truth, shared with `playbooks/setup-benchmark-repos.yml`), but
provisioning pins a checkout *once* and nothing keeps it there — a `git pull`
on a tracking-branch checkout drifts it silently, and the real-world runner
records whatever SHA it finds rather than asserting the expected one. Since
`ground_truth` is keyed on `(project, commit, file, line, rule)`, findings
from a drifted tree fall outside the precision/recall denominator in either
direction with no error. The check exits nonzero and prints the
`git checkout --detach` fix per row. It also flags untracked *and gitignored*
`*.c`/`*.h` files, which sqc *will* scan and attribute to the pinned commit —
sqc dispatches on file extension and never consults git, so a build run inside
a checkout (e.g. sqlite's generated `sqlite3.c` amalgamation) contaminates a
scan while staying invisible to `git status`.

### Protocol

1. **Version bump + commit BEFORE benchmark**: Always bump the version in `Cargo.toml`,
   rebuild (`cargo build --release`), and commit before starting a benchmark run.
   The run_id is derived from version + commit SHA (e.g., `sqc-0.3.20-abc1234`).

2. **NEVER modify code while a benchmark is running**: The benchmark uses
   `target/release/sqc`. If you rebuild while it's running, you corrupt results
   mid-run. Make ALL code changes and commits BEFORE starting the benchmark.

3. **Wait for completion**: Fast-mode Juliet benchmarks take ~32-40 minutes.
   Real-world sqc-only takes ~10-15 minutes. Full Juliet suite
   takes ~40-50 minutes. Check status with `python -m bench status` no more
   than once every 5 minutes (or just watch it -- it runs in your terminal).

4. **Compare runs**: After a benchmark completes, use `python -m bench compare`
   to compare against previous runs. `python -m bench status RUN_ID` for a
   per-run summary.
   Historical runs are available with suffix `-historical` (e.g., `sqc-0.3.17-historical`).

5. **Workflow sequence**:
   ```
   implement changes → bump version → commit → build release → run benchmark → wait → analyze
   ```

6. **Delta-adjudicate before citing precision/recall for a changed rule (CRITICAL)**:
   `ground_truth` is keyed on exact `(project, commit, file, line, rule)` tuples,
   adjudicated at a specific past audit's snapshot. When a rule's detection logic
   changes (any commit touching `src/rules/cert_c/**/*.rs` that alters what it
   flags — not a pure refactor), its new findings land at `(file, line)` pairs
   that were **never adjudicated**, so they're silently excluded from the
   precision/recall denominator in either direction. A raw-count jump or a
   flat "precision held" number computed only over the labeled sample can
   both look clean while the real picture is unmeasured underneath. Before
   writing "precision improved/held" or "FP reduced" into a commit message,
   task note, or the paper for a changed rule:
   - **Gate the delta-adjudication task on any known-but-unfixed FP driver for
     that rule before filing/starting it.** Adjudicating a raw dump when a
     cheap follow-up fix would still eliminate a large slice of it wastes
     investigatory effort re-reading findings that are about to disappear —
     task 553/582 saw MSC17-C real-world findings drop 2,024 → 376 (−81%)
     from one structural fix; adjudicating the 2,024 first would have thrown
     most of that work away. Before filing a delta-adjudication task,
     `todo-sqlite-cli list` (or search) for open FP-reduction tasks against
     the same rule; if any exist, add them via `--depends-on` so `next`
     skips the adjudication until the cheaper fixes land, then re-measure
     before adjudicating what's left.
   - Pull the new unlabeled findings for that rule only:
     `bench realworld-unlabeled RUN --rule RULE_ID --project P --json`
     (repeat per affected project, or omit `--project` and split after).
   - **Derive each project's in-scope file predicate from its own
     `data/precision_audit/<project>/README.md` BEFORE batching** — not
     after. Task 420's delta-adjudication found 2,548 of 4,026 (63%) raw
     unlabeled findings were out-of-scope noise (test harnesses, vendored
     deps, language bindings) that should never have been batched; mosquitto
     alone was 73% contamination. Scoping after the fact means redoing
     already-completed adjudication batches.
   - Batch (~110-150 findings/batch), adjudicate, and import via
     `bench realworld-import-labels` — same workflow as a fresh oracle build.
     See `data/precision_audit/DELTA_MEM31_TASK420.md` for a fully worked
     example (6 projects, 14 batches, 1,478 findings, 0.7% delta precision —
     a very different number than the aggregate raw-count comparison
     suggested).
   - Only after that pass is ground_truth updated for the new lines should a
     precision/recall claim about the changed rule be published.

### Querying Results

The `bench` CLI (`status`, `compare`, `runs`, `realworld`, `realworld-score`)
reads **local SQLite only**, falling back to legacy text files for old runs. It
cannot see the shared record and never will — so its output describes the runs
this checkout has done, which is exactly what you want when working locally and
never what you want when citing a project figure.

To query the actual history, use `benchmarking_db`'s MCP servers
(`sqc-benchmark-query`: `list_runs`, `get_run_status`, `compare_runs`,
`get_realworld_results`, `get_cwe_detail`) or, on the benchmark host, that
repo's own CLI. Deliberately no run counts quoted here: a number in this file
goes stale silently, which is the failure mode task 701 exists to kill. Ask the
source.

### Refreshing Published Doc Numbers

If asked to "refresh the benchmark numbers" (README.md's Benchmark
Highlights table): `python -m bench render-docs --realworld-run RUN
[--juliet-run RUN] [--check]` regenerates that table from whichever `db` it
is handed, bounded by the `<!-- BENCH:HIGHLIGHTS:START/END -->` marker pair
— everything outside it (narrative, task citations, history) is
hand-written and untouched. `--realworld-run` has no default on purpose:
pass a run you know is validly adjudicated (see the delta-adjudication
protocol above), not just whatever's newest.

(`REALWORLD_RESULTS.md` and `JULIET_RESULTS.md` were both retired
2026-09-03: each duplicated Postgres as a hand-maintained snapshot, which is
what this repo's README/docs and the paper now query directly instead.
`--realworld-run` stays required because `render-docs` still cites that run
in README's one-line highlight, alongside the Juliet run.)

**Published numbers come from Postgres, via `benchmarking_db`'s
`bin/refresh_tools_sqc_docs.py`** (that sibling repo — see its README). Not
"the better source" — the only correct one. It calls this repo's own
`bench/render_docs.py` rendering functions pointed at Postgres, so the output
is identical in shape and nothing here gains Postgres awareness.

Pointing `render-docs` at local `data/benchmarks.db` is a perfectly good way
for a collaborator to write up their *own* runs. What it must not do is
produce a table that gets committed to this project's README/RESULTS files or
the paper: those numbers would describe one checkout's runs while presenting
as the project's measurements. It will look plausible and be wrong.

Either path: review the diff before committing. The tool only ever
rewrites the marker-bounded block; a real refresh can still mean updating
hand-written prose near it that references the old figures (see the note
above the Benchmark Highlights table for why that prose is now written to
name no specific number, precisely so a refresh can't leave it stale) —
that's a judgment call the tool deliberately leaves alone.

---

## Task tracking

This repo uses `todo-sqlite-cli` for TODOs. The DB path is resolved via the
`.todo-sqlite-cli` marker at the repo root.

**This DB holds the TOOL's backlog only.** Until 2026-09-03 both repos'
markers pointed at this one file, so `benchmarking_db`'s oracle, metrics and
benchmark-host work sat in here — which meant `next` handed you a P1 whose
actionable half lived in another repo, and a stranger cloning sqc inherited
the whole maintainer backlog along with it (the DB is committed). 22 active
tasks moved to `benchmarking_db/todo-sqlite-cli.db`; display ids and UUIDs
were preserved, because ids like 701 are cited in commit messages, code
comments and this file. Completed history was not duplicated — it stays here.

So: adjudication, ground_truth quality, corpus acquisition/scope, derived
metrics and Postgres/backup infra are asked over there, and rule behaviour,
FP/FN work, docs and packaging are asked here. Same clone-experience test as
everywhere else in this file — would a stranger cloning this repo need it to
evaluate sqc on their own codebase? A dependency edge that would have crossed
the split is recorded in the task's own details as prose, since two DBs
cannot enforce one (tasks 9, 723 and 700 are the three).

**Display ids now collide across the two repos.** Each DB allocates from its
own sequence, so a bare "task 731" is ambiguous: 731 is the ARR38-C
delta-adjudication in `benchmarking_db`, and the next task added here will
also be 731. Demonstrated immediately — a stray `add` in this repo took 731
within minutes of the split. When citing a task in a commit message, code
comment or cross-repo message, say which repo unless it is obviously local.
Task UUIDs remain globally unique and are still the real identity; ids 1-730
predate the split and are unambiguous.

**Before planning or coding, ask the DB:**

- `todo-sqlite-cli next` — the single task to work on right now.
- `todo-sqlite-cli list` — all active (in-progress + partial + pending),
  in-progress first, then partial, then pending; within each, by priority.
- `todo-sqlite-cli show <id>` — full task detail (`--verbose` for humans).
- Every command supports `--json`.

**When picking up work:** `todo-sqlite-cli start <id>` before coding,
`todo-sqlite-cli done <id>` when committed. `start` auto-pauses any prior
in-progress task to `partial`, preserving its `started_at`, so a task left
`partial` was interrupted rather than abandoned — resume it with `start`.
`stop <id>` pauses deliberately; `revert <id>` undoes a start that turned out
to be wrong (back to pending, clears `started_at`).

**Adding a progress note to an existing task:**
`todo-sqlite-cli edit <id> --append-details "note"` — appends with a newline,
preserving prior context. `edit <id> --details "..."` REPLACES the entire
details body instead (discards what was there) — only use it when you mean
to overwrite, not to log progress. `--add-tag`/`--rm-tag`,
`--add-dep`/`--rm-dep`, `--add-related`/`--rm-related`,
`--location`/`--clear-location`, `--gate`/`--no-gate`, `--title`,
`--priority` are also available on `edit`.

**When a new task surfaces:**
`todo-sqlite-cli add "title" --details "..." --tag <area> --priority <1-5>`
(1 = highest). `--depends-on <id>` links prerequisites; tasks with unmet
deps are skipped by `next` and shown `[blocked]` in `list`.

**Use `--related` instead of naming a task id in prose (v3.2.0).** A
`--related <id>` link is mutual, appears on both tasks' `show` as
`Related: ...`, and is stored by UUID — so it FOLLOWS a `renumber` (verified:
a link displayed as `Related: 2` re-displayed as `Related: 99` after the
target was renumbered). That is the fix for the failure this file used to
document by hand: task 731's details still say "read every '728' above as
730" because a hand-written id went stale when two nodes collided on a
display id. Prose ids do not survive renumbering; `--related` does. An
unknown id is REJECTED (`error: related task N: task N not found`), so a link
is never left dangling.

Use `--depends-on` when the other task must land FIRST (it gates `next`);
use `--related` for "these are the same defect / same cohort / read these
together", which is most cross-references. Neither works across the two
repos — an id must exist in the same DB — so a cross-repo edge is still
recorded as prose, and that is now the ONLY case where prose is correct.

**CREATE THE FOLLOW-UP TASK FIRST, THEN LINK IT. Never write an
id you have not allocated yet into a task body, a commit message or a code
comment.** This is the one failure `--related` cannot repair, and with two
nodes working the backlog concurrently it is not hypothetical — it happened
TWICE on 2026-09-03 within a few hours:

- Task 665 says "Filed as its own follow-up, task 736" twice. The follow-up
  actually landed as **750**; 736 had been allocated in the interim by a
  session on the other node, so 665's prose now points at an unrelated
  EXP36-C task.
- Task 742 says "Filed as task 751". The follow-up is **759**; 751 had
  likewise been taken, by an MSC13-C task.

Both were written before the referenced task existed, so the number was a
guess about the future — and each node allocates from its own sequence with
no reservation, so the guess is simply wrong whenever the other node adds a
task first. `doctor` stays clean through all of this: nothing is duplicated
or corrupt, the prose just points somewhere else, which makes it invisible
until someone follows the link and lands on an unrelated task.

The working habit, in order: `add` the follow-up, take the id `add` prints,
then `edit <parent> --add-related <newid>`. Say "the follow-up task" in the
prose and let the `Related:` line carry the identity. If you genuinely must
name a number in text, allocate it first and paste the real one.

Note this is a DIFFERENT failure from the stale-id-after-renumber case
`--related` does fix. Renumber-staleness is a link that was once right;
this is a link that was never right. Only sequencing prevents it.

**`--location <text>` flags work that can only be done on a specific node**,
shown as an `@location` suffix in `list`. The established value is
`benchmark-node` (role, deliberately not the hostname `dev-41`/`r720`, so it
survives the hardware being replaced), meaning the task needs a Postgres
write against `sqc_bench` or a corpus checkout. It replaces the
"Benchmark node only" line that tasks 733/735 carried in their details.
Note it is DISPLAY-ONLY today — `list` has no `--location` filter and `next`
does not skip on it — so keep it high-signal: in `benchmarking_db`
benchmark-node is close to the default, and the useful information is which
tasks there are portable (they stay unmarked).

`--gate` marks a checkpoint on an external condition rather than work to be
done; gates are skipped by `next` and never flagged stale by `aging`, and
`list --kind gate` gives a readiness dashboard of open ones.

Original task IDs (prior to the 2026-04-20 import) are preserved
as `plan-id:NN` tags.

**Task identity is a UUID; the integer `<id>` is only a display alias**
(todo-sqlite-cli v3.0.0). Consequences worth knowing:

- **Run `todo-sqlite-cli doctor` after every `git merge`/`pull` that touches
  `todo-sqlite-cli.db`.** It checks for duplicate display ids, unresolved
  `merge-conflict` tags, orphaned tag/dep rows, self-deps and dependency
  cycles, and exits 1 so it can gate a script. Verified 2026-08-27 against a
  reconstruction of the v2.1.0 corruption: the merge itself is now sound
  (tags and deps are keyed on `task_uuid`, so details can't concatenate and
  tags can't union, and a dep keeps pointing at the task it meant), but two
  nodes that independently allocated the same display id still merge to **two
  rows sharing that id** — data intact, display ambiguous. `doctor` is what
  surfaces that; the driver's "0 conflicts" line no longer implies it.
- `rm` does not reserve the display id — a later `add` may reuse it.
- If `show <id>` prints two tasks, pass the full UUID to disambiguate.

Because identity is a UUID, the old defensive dance of deleting a
locally-created task before merging to dodge an id collision is obsolete.
Just merge, then run `doctor`.

**Release history** also lives in the DB — each CHANGELOG entry is a
`release`-tagged done task with `completed_at` set to the release date.
Rebuild a changelog with `todo-sqlite-cli export-completed` (bound by
`--since`/`--until`), or slice by section with
`todo-sqlite-cli list --status done --tag changed`
(also: `benchmark`, `added`, `fixed`, `task`).

---

## Documentation

| File | Contents |
|------|----------|
| `README.md` | Tool overview, installation, usage, CLI reference |
| `docs/index.rst` | Developer guide: advanced usage, CI/CD, benchmarks, testing, contributing |
| `docs/design/*.md` | Scoping docs for in-progress/completed capabilities (e.g. macro-expansion, project-relevance-gating). Not in the Sphinx toctree — read directly. **Their "Status" header goes stale once the work ships**; check `todo-sqlite-cli show <task>` for the real status before trusting the header, and check whether the feature needs a mention in `docs/cli-usage.rst`/`docs/architecture.rst` once it ships. |
| `../sqc_paper/` | **The paper, in its own repo since 2026-09-03** (moved with `git subtree split`, so its 40 commits came along). Same reason benchmarking moved out: a stranger cloning sqc to evaluate it on their own code does not need a paper draft. Numbers in it must trace to Postgres via `benchmarking_db` — see that repo's README. Its figure generator moved to `benchmarking_db/bin/` and is broken pending a port (their task 732). The paper's own tasks (#9, #378, #463, #723) stayed in this repo's DB. |
| `docs/design/gate-status-sop.md` | Weekly read on how close sqc is to the maintenance-mode gate (#463) and a publishable paper (#9). Run it *here* — it spans all three repos and its "Repos this SOP spans" table says which check lives where. |
| `docs/design/internal-capability-catalog.md` | Browsable-by-concept catalog of every reusable primitive in `src/utility/cert_c/*.rs`/`src/analyze/*.rs` (macro detection, declarator resolution, lvalue/aliasing, VRA, CFG, function summaries, suppression, cross-file `ProjectContext`). Read this before writing any new AST/text heuristic — see Code Navigation below. |

---

## Project Structure

- `src/rules/cert_c/` - CERT C rule implementations
- `src/analyze/` - Analysis infrastructure (CFG, null state, VRA, prescan)
- `bench/` - Benchmark infrastructure (runner, analyzer, SQLite DB, CLI)
- `data/` - Benchmark database (benchmarks.db), prescan caches
- `scripts/` - Workflow helpers, coverage gate
- `docs/` - Developer guide (index.rst), bibliography

## Code Navigation (clew)

This repo is indexed by [`clew`](https://github.com/tvanfossen/clew), registered as
the `clew` MCP server in `.mcp.json` (gitignored -- each machine runs `clew init`
once to write it; see the clew repo's README). `clew init` only registers the MCP
server -- it does not itself install anything, so each machine also needs the
`clew-trace` package installed (e.g. into the shared dev venv from
`playbooks/setup-dev-environment.yml`) for the `clew-mcp` command the config
points at to actually resolve.
It builds a queryable symbol database (call graph, threads, locks, requirements,
file docs) from rustdoc + tree-sitter, served over four tools: `dossier` (everything
about one named symbol — signature, body, callers/callees, locks held, in one call),
`search` (find a name, or a whole layer like `corpus='locks'`/`corpus='threads'`),
`index` (admin: `status`/`refresh`), `propose_declaration`.

**No manual indexing step is required.** The database lives outside the repo, under
`~/.local/state/clew/targets/<name>-<hash>/`, and the MCP tools build it themselves
on first use if it doesn't exist yet -- so a freshly-provisioned node with no
`~/.local/state/clew` is expected, not broken, until an agent there actually calls
`dossier`/`search`/`index` for the first time. To build it eagerly instead of
waiting for that first call (e.g. to warm it before a benchmark run), run
`clew --repo-root .` from the venv clew is installed in. **Omit `--output`**:
with it omitted clew writes to the same path the MCP server derives for
`--repo-root`, so a CLI build is what `dossier`/`search` then read. Passing
`--output clew.db` instead writes into the *current directory*, which the
server never looks at -- you get a stray `clew.db` in the repo root and a
first `dossier` call that still pays for a cold build.

**Prefer `dossier`/`search` over `grep`/`Read` for "what calls X", "where is Y
defined", "what locks does this function hold" style questions** — one call
instead of several, and it already has the call graph resolved. Fall back to
reading source directly for anything the index can only point at (exact comment
text, line-by-line logic).

Rebuild after non-trivial changes: `clew --repo-root . --rebuild` (again, no
`--output` -- same reason).
The MCP tools also offer to build/refresh on first use if no index exists yet.

**Before implementing any new AST/text heuristic, check
`docs/design/internal-capability-catalog.md` first** (task 479, filed after
task 475 nearly re-implemented DCL40-C's `is_defined_macro_name`/
`ProjectContext::defined_macro_names` cross-file macro-detection as a fresh
ALL_CAPS-name heuristic — a plain keyword grep for "macro detection" missed
it on the first pass). That catalog exists precisely because `search` does
literal token-conjunction matching: it finds `is_defined_macro_name`
instantly when queried with words close to its own doc comment, but returns
nothing useful for a vague concept phrase that doesn't appear verbatim
anywhere. If the catalog doesn't cover it, try `dossier`/`search` with
vocabulary close to an actual function/doc-comment wording, then grep
`src/utility/cert_c/` and `src/analyze/` directly by what the primitive
*does* — this has caught real scoping bugs before (ARR39-C task 146,
CON34-C task 385).

## Build & Test

```bash
cargo build
cargo test --package sqc --lib -- rules::cert_c::RULE_ID::tests  # inline unit tests
cargo test --package sqc --lib -- RULE_ID  # all tests (inline + generated from .c files)
cargo fmt
```

## Rule Implementation

**NEVER add embedded unit tests in rule implementation files:**
- ❌ NO `#[cfg(test)]` modules in `src/rules/cert_c/*/*/*.rs` files
- ❌ NO inline test functions with hardcoded C code snippets
- ✅ Test cases come from `.c` files in `tests/` directory (auto-generated into Rust tests)
- ✅ If no test cases exist for a rule, implement WITHOUT tests (this is acceptable)

For each new rule:
1. Create `src/rules/cert_c/CATEGORY/RULE_ID/rule_id_c.rs`
2. Register in `mod.rs` and enable in the TOML
3. Build and test

**Before writing a fix for a macro-related false positive/negative**, check
whether `src/analyze/macro_expand.rs` already solves it — do NOT reach for a
name-heuristic workaround first. sqc has a real, name-independent
macro-expansion engine (`collect_function_macros`, `macro_nulls_param_indices`
for "safe free" macros that free+null their arg, `macro_output_param_indices`
for output-param macros), already wired into MEM30-C, MEM31-C, EXP33-C, and
DCL31-C. See `docs/design/macro-expansion.md` for the full design rationale
and a per-rule disposition table (which rules are already on the engine,
which are legitimately definition-side and should stay off it). Its
"Status" line at the top is stale (says "no implementation yet" from the
original scoping date) — trust the phase stock-takes further down the file,
not that header.

**Before writing a new rule, check whether its defect concept already
overlaps an enabled rule** (search `rules_templates/rules-all.toml`
descriptions and `docs/design/internal-capability-catalog.md`). Overlap is
expected, not a bug — CERT-C's own two-layer structure (rules vs. broader
recommendations) means the same defect is frequently covered from two
angles. **Default to letting both rules fire.** Only suppress one in favor
of the other if you can show *total* subsumption across every
ground-truth-labeled instance, not just frequent co-location — see
`docs/design/cross-rule-overlap.md` for the full policy and a concrete
counterexample (`MSC24-C` categorically bans `strcpy`/`sprintf` regardless
of provable safety; `STR31-C` proves specific calls safe; a hard precedence
either direction is measurably wrong on real-world data).

## Git Commit Rules (CRITICAL)

**EXPLICITLY DENIED:**
- `git commit --no-verify` - NEVER use this flag. Pre-commit hooks MUST pass. Only humans can skip hooks.
- `Co-Authored-By: Claude` - NEVER add Claude as co-author. This is a corporate repository.
- Any hook-skipping flags (`--no-gpg-sign`, etc.)

**REQUIRED:**
- All pre-commit hooks must pass before commit succeeds
- If hooks fail, FIX the underlying issue (don't bypass)
- Standard commit message format without AI attribution

**PULLING FROM UPSTREAM (`todo-sqlite-cli.db`):**

`.gitattributes` maps `todo-sqlite-cli.db merge=todo-sqlite-cli`, but the
driver itself lives in **repo-local git config**, which is not committed — a
fresh clone (or a new machine) has the attribute and no driver, and git then
falls back to the binary default and leaves the DB in conflict on every
`pull`/`merge`/`rebase` that touched it. Before pulling upstream:

```bash
git config --get merge.todo-sqlite-cli.driver \
  || todo-sqlite-cli install-merge-driver    # one-time, per clone
git pull                                     # DB auto-merges by task UUID
todo-sqlite-cli doctor                       # REQUIRED after every merge/pull
```

`playbooks/setup-dev-environment.yml` now registers this driver (and the
pack settings below) on any node it provisions, so the one-time step above is
only needed on a clone that predates it or was set up by hand.

`install-merge-driver` appends the `.gitattributes` line unconditionally — if
that line is already there (it is, in this repo), register the driver by hand
instead so the file doesn't gain a duplicate:

```bash
git config merge.todo-sqlite-cli.name "todo-sqlite-cli 3-way merge driver"
git config merge.todo-sqlite-cli.driver "todo-sqlite-cli git-merge-driver %O %A %B"
```

The merge is a real 3-way union keyed on task UUID (`%O %A %B`), so nothing is
lost and dependency edges keep resolving. What it *cannot* fix is two sides
independently allocating the same display id: both rows survive, sharing that
id. `doctor` exits 1 on that (and on unresolved `merge-conflict` tags, orphaned
tag/dep rows, self-deps, cycles); fix a duplicate id with
`todo-sqlite-cli renumber <uuid> <new-id>`. Never resolve a DB conflict with
`git checkout --ours/--theirs` — that discards the other side's tasks entirely.

**PACK SIZE (`todo-sqlite-cli.db`):** the DB is ~2.3 MiB and is committed on
nearly every task change (692 of 3,571 commits as of 2026-09-03). Git's default
`pack.window` of 10 cannot find a good delta base among ~680 versions of it, so
recent versions get stored close to whole — 664 KiB of pack per DB commit
against a 39 KiB historical average. `setup-dev-environment.yml` sets
`pack.window 250` / `pack.depth 100` (repo-local, so uncommitted and per-clone),
which brings that to 38 KiB.

Those settings only affect *future* repacks. A clone provisioned before they
existed keeps its bloated pack until repacked once by hand:

```bash
git repack -a -d --window=250 --depth=100   # 58 MB -> 41 MB on this checkout
```

That is a pure storage-layout rewrite — it never changes commit SHAs or
history — so it is safe on any clone at any time. Committing the DB is fine;
the cost was a config default, not the practice.
