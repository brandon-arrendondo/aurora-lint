# Claude Code Project Instructions

Full CLI reference and troubleshooting live in `docs/index.rst` (Benchmark
Setup / Running Benchmarks). This file holds only what changes what you *do*.

---

## Benchmark Workflow (CRITICAL)

### Where benchmark data lives

**Every OFFICIAL number comes from the `sqc_bench` Postgres instance**, reached
through the separate **`benchmarking_db`** repo. "Official" means anything
published as this project's measurement — README, the paper, a release note,
any claim made outside. It is the sole source of truth for both historical
benchmark data and adjudication data. If a run is meant to count as ours, it is
queued through `benchmarking_db` and lands in Postgres.

**Running benchmarks locally is fully supported.** A fresh clone gets a working
setup from `cargo build --release` plus the checkouts in
`docs/benchmark-setup.rst`, and may capture results however it likes.
`data/benchmarks.db` has no special standing over a CSV — it is this checkout's
record of its own runs. So a figure computed from it describes *those runs*,
not the project's measurements, and must never be transcribed into a published
document or cited as a project result.

**The test for any new benchmarking/measurement code: would a stranger cloning
this repo need it to evaluate aurora-lint on their own codebase?** If no, it
belongs in
`benchmarking_db`. Two corollaries:

- Do not reintroduce a local mirror, cache, or sync of benchmark data for speed
  or offline use. That paradigm was deliberately abandoned: it restores a
  per-node copy of a corpus this checkout alone already fills 6.5 GB with, and
  adds a second thing that can go stale or disagree. Centralizing in Postgres
  is what makes a worker node disposable.
- Do not add maintainer-workflow machinery here to save a hop. Multi-node
  coordination, shared-instance credentials, queue plumbing and cross-machine
  reconciliation are `benchmarking_db`'s.

**This repo stays Postgres-blind**: no DSN, no connection code, no awareness of
the shared instance in anything you add. That seam is what keeps `bench/`
usable by a fresh clone. See `benchmarking_db/docs/ownership.md` for what that
repo owns.

**The adjudication dataset** (TP/FP/FN labels) is valuable beyond aurora-lint,
which is
an argument for *sharing* it the way research datasets are shared — object
storage, a hosted dataset — not for holding it in git. Keep export from
Postgres trivial; do not let its portability become a reason to put it in-repo.

### Local SQLite storage (the local-run path)

A local run writes to **`data/benchmarks.db`** (SQLite, WAL) — gitignored, so
no clone inherits anyone else's.

**Tables**: `runs` (one per benchmark), `cwe_scans` (one per CWE per run),
`violations` (every finding), `cwe_metrics` (precomputed TP/FP/rates),
`rule_cwe_breakdown`, `realworld_runs` + `realworld_results`, `ground_truth`
(local adjudication store — **not** the oracle; the oracle is
`benchmarking_db`'s, which is why `realworld-import-labels` requires
`--local-oracle`: writing here is something you state, not fall into).

### Running benchmarks

Everything runs synchronously in your terminal — no server, no polling.
`python -m bench juliet` uses fast mode by default (per-CWE manifests,
CWE-matched rules), runs CWEs in parallel, writes straight to SQLite, and
resumes by skipping completed CWEs.

```bash
python -m bench juliet [--full] [--jobs N]
python -m bench status [RUN_ID]
python -m bench compare BASE TARGET
python -m bench runs
python -m bench corpus-check   # are the real-world checkouts still pinned?

# Real-world: sqc + cppcheck + clang-tidy against real C codebases, local and
# sequential (bench/realworld_runner.py). Defaults to sqc against every
# codebase; narrow with --tool/--codebase.
python -m bench realworld-run [--tool sqc,cppcheck,clang-tidy] [--codebase C,C]
python -m bench realworld [RUN]        # FP dashboard
python -m bench realworld-score [RUN]  # measured precision/recall vs oracle
```

**Run `corpus-check` before any real-world run or precision claim.** Pins live
in `data/benchmark_repos.json` (shared with
`playbooks/setup-benchmark-repos.yml`), but provisioning pins a checkout once
and nothing holds it there — a `git pull` on a tracking branch drifts it
silently, and the runner records whatever SHA it finds rather than asserting
the expected one. Since `ground_truth` is keyed on
`(project, commit, file, line, rule)`, findings from a drifted tree fall out of
the precision/recall denominator with no error. The check exits nonzero and
prints the `git checkout --detach` fix per row. It also flags untracked **and
gitignored** `*.c`/`*.h` files: aurora-lint dispatches on file extension and
never
consults git, so a build run inside a checkout (e.g. sqlite's generated
`sqlite3.c` amalgamation) contaminates a scan while staying invisible to
`git status`.

### Protocol

1. **Commit BEFORE benchmarking. Do NOT bump the version** unless Brandon asks.
   Rebuild (`cargo build --release`) and commit — and push, if the run goes
   through `benchmarking_db`'s queue, which fetches from origin and never from
   your working tree.

   Why no bump: `run_id` is `sqc-{version}-{sha}`, so the **SHA** is what
   discriminates runs; the version added readability only. With ~5 nodes
   committing in parallel a per-task bump collides constantly and **silently** —
   both sides write the same string, so git reports no conflict and `doctor`
   only checks display ids. Version numbers are a **release** artifact.

   **The binary is `aurora-lint`; the benchmark tool id is still `sqc`.** The
   crate and binary were renamed, but `realworld_results.tool`, the
   `runs.sqc_version` column and the `sqc-{version}-{sha}` run_id prefix all
   stay `sqc`, because Postgres rows and `ground_truth`'s
   `(project, commit, file, line, rule)` keys are written that way. Renaming
   the identifier forks the namespace and silently drops every historical row
   out of comparison. Do not "fix" the `"sqc"` literals in `bench/`.

   **Consequence to accept:** address a real-world run by its integer id and a
   Juliet run by its full run_id or SHA. A bare version string is now
   ambiguous and quoting one without a SHA is meaningless — say
   `0.4.336-27785c4a`, or just the SHA.

2. **NEVER modify code while a benchmark is running.** It uses
   `target/release/aurora-lint`; rebuilding mid-run corrupts results. Make all
   changes and commits first.

3. **Wait for completion.** Fast-mode Juliet ~32-40 min, full Juliet ~40-50 min,
   real-world sqc-only ~10-15 min. Check `python -m bench status` at most every
   5 minutes, or just watch it.

4. **Compare runs** with `python -m bench compare`; `status RUN_ID` for a
   per-run summary. Historical runs carry a `-historical` suffix.

5. **Sequence**: implement → commit (+ push, if queueing) → build release →
   run benchmark → wait → analyze.

6. **Delta-adjudicate before citing precision/recall for a changed rule
   (CRITICAL).** `ground_truth` is keyed on exact
   `(project, commit, file, line, rule)` tuples adjudicated at a past
   snapshot. When a rule's detection logic changes (any commit under
   `src/rules/cert_c/**/*.rs` that alters what it flags — not a pure
   refactor), its new findings land at `(file, line)` pairs that were **never
   adjudicated**, so they fall outside the denominator in either direction. A
   raw-count jump and a flat "precision held" over the labeled sample can both
   look clean while the real picture is unmeasured. Before writing "precision
   improved/held" or "FP reduced" into a commit message, task note, or the
   paper:

   - **Gate the delta-adjudication task on any known-but-unfixed FP driver for
     that rule.** Adjudicating a dump that a cheap follow-up fix is about to
     shrink wastes the work — one MSC17-C structural fix took real-world
     findings 2,024 → 376 (−81%). Search the backlog for open FP-reduction
     tasks against the same rule and add them with `--depends-on` so `next`
     skips the adjudication until they land; then re-measure.
   - Pull only that rule's new unlabeled findings:
     `bench realworld-unlabeled RUN --rule RULE_ID --project P --json`.
   - **Derive each project's in-scope file predicate from its own
     `data/precision_audit/<project>/README.md` BEFORE batching.** One delta
     pass found 63% of raw unlabeled findings were out-of-scope noise (test
     harnesses, vendored deps, bindings); mosquitto alone was 73%. Scoping
     afterwards means redoing completed batches.
   - Batch ~110-150 findings, adjudicate, import with
     `bench realworld-import-labels`. Worked example:
     `data/precision_audit/DELTA_MEM31_TASK420.md`.
   - Only once `ground_truth` covers the new lines may a precision/recall
     claim about that rule be published.

### Querying results

The `bench` CLI (`status`, `compare`, `runs`, `realworld`, `realworld-score`)
reads **local SQLite only**. It cannot see the shared record and never will —
right for local work, never right for citing a project figure.

For real history use `benchmarking_db`'s MCP servers (`sqc-benchmark-query`:
`list_runs`, `get_run_status`, `compare_runs`, `get_realworld_results`,
`get_cwe_detail`), or that repo's CLI on the benchmark host. **No run counts or
metrics are quoted in this file on purpose** — a number here goes stale
silently. Ask the source.

### Refreshing published doc numbers

`python -m bench render-docs --realworld-run RUN [--juliet-run RUN] [--check]`
regenerates README's Benchmark Highlights table from whichever db it is handed,
bounded by the `<!-- BENCH:HIGHLIGHTS:START/END -->` markers; everything
outside them is hand-written and untouched. `--realworld-run` has no default on
purpose — pass a run you know is validly adjudicated, not the newest.

**Published numbers come from Postgres via `benchmarking_db`'s
`bin/refresh_tools_sqc_docs.py`** — not the better source, the only correct
one. It calls this repo's own `bench/render_docs.py` functions pointed at
Postgres, so output shape is identical and nothing here gains Postgres
awareness.

Pointing `render-docs` at local `data/benchmarks.db` is fine for writing up
your *own* runs. It must never produce a table committed to this project's
README or the paper: those numbers would describe one checkout while presenting
as the project's measurements. Plausible and wrong.

Either path, review the diff. The tool rewrites only the marker-bounded block;
prose near it is a judgment call it deliberately leaves alone.

---

## Task tracking

`todo-sqlite-cli`, with the DB resolved via the `.todo-sqlite-cli` marker at the
repo root.

**There are three task DBs, and this one holds the TOOL's backlog only.**

| Repo | Owns |
|---|---|
| here | rule behaviour, FP/FN work, docs, packaging |
| `benchmarking_db` | adjudication, ground_truth quality, corpus scope, derived metrics, Postgres/backup infra |
| `sqc_paper` | paper drafting, figures, wording, submission |

Do not `add` or reopen another repo's work here. Completed history was not
duplicated when the backlogs split, so old done tasks of every kind remain in
this DB. Same clone-experience test as everywhere else: would a stranger
cloning this repo need it to evaluate aurora-lint on their own codebase?

**Cross-repo dependency edges cannot be enforced.** Separate DBs mean no `next`
in either repo will honour one, so record it as prose in the task's details —
the only case where prose is correct — and **carry the urgency in the priority
number**, which is the only signal the other node actually sees. A blocker
parked at P5 reads as the least urgent thing in the backlog.

**Display ids collide across repos and across nodes.** Each DB allocates from
its own sequence with no reservation, so a bare "task 731" is three-ways
ambiguous, and two nodes adding tasks the same hour routinely claim the same
id. Consequences:

- **Say which repo** whenever you cite a task in a commit message, code comment
  or cross-repo message. "Obviously local" stopped being safe at three DBs.
  (Ids 1-730 predate the splits and are unambiguous.)
- **Prefer not to cite a number at all.** Write "the follow-up task" and let the
  UUID-backed `Related:` line carry identity — it survives every `renumber`.
- **Create the follow-up task FIRST, then link it.** Never write an id you have
  not allocated into a task body, commit message or code comment: the number is
  a guess about the future and is simply wrong whenever another node adds a task
  first. `doctor` stays clean through this — the prose just quietly points at
  something unrelated. Order: `add`, take the id it prints, then
  `edit <parent> --add-related <newid>`.
- Fix a duplicate id with `todo-sqlite-cli renumber <uuid> <new-id>`, then
  repair whatever prose named the old number.

**Before planning or coding, ask the DB:**

- `todo-sqlite-cli next` — the one task to work on now.
- `todo-sqlite-cli list` — all active, in-progress then partial then pending.
- `todo-sqlite-cli show <id>` — full detail (`--verbose` for humans).
- Every command supports `--json`.

**Working a task:** `start <id>` before coding, `done <id>` when committed.
`start` auto-pauses any prior in-progress task to `partial` and preserves its
`started_at`, so `partial` means interrupted, not abandoned — resume with
`start`. `stop <id>` pauses deliberately; `revert <id>` undoes a wrong start.

**Logging progress:** `edit <id> --append-details "note"` appends.
`edit <id> --details "..."` **REPLACES** the whole body — only when you mean to
overwrite. Also on `edit`: `--add-tag`/`--rm-tag`, `--add-dep`/`--rm-dep`,
`--add-related`/`--rm-related`, `--location`/`--clear-location`,
`--gate`/`--no-gate`, `--title`, `--priority`.

**New task:**
`add "title" --details "..." --tag <area> --priority <1-5>` (1 = highest).

**`--depends-on` vs `--related`:** use `--depends-on` when the other task must
land FIRST (it gates `next` and shows `[blocked]` in `list`); use `--related`
for "same defect / same cohort / read these together", which is most
cross-references. Both are stored by UUID, so they follow a `renumber`; an
unknown id is rejected rather than left dangling. Neither works across repos.

**`--location <text>`** flags work that can only be done on a specific node,
shown as `@location` in `list`. The established value is `benchmark-node` — a
role, deliberately not a hostname, so it survives the hardware being replaced —
meaning the task needs a Postgres write against `sqc_bench` or a corpus
checkout. It is **display-only**: `list` has no filter and `next` does not skip
on it, so keep it high-signal.

**`--gate`** marks a checkpoint on an external condition rather than work to be
done. Gates are skipped by `next`, never flagged by `aging`, and
`list --kind gate` is a readiness dashboard.

**Identity is a UUID; the integer id is a display alias.**

- **Run `todo-sqlite-cli doctor` after every merge/pull that touches
  `todo-sqlite-cli.db`.** It catches duplicate display ids, unresolved
  `merge-conflict` tags, orphaned tag/dep rows, self-deps and cycles, and exits
  1 so it can gate a script. The merge itself is sound (tags and deps key on
  `task_uuid`), but two nodes that independently allocated the same display id
  still merge to two rows sharing it — data intact, display ambiguous. The
  driver's "0 conflicts" line does not imply otherwise.
- `rm` does not reserve the id; a later `add` may reuse it.
- If `show <id>` prints two tasks, pass the full UUID.
- Because identity is a UUID, deleting a local task before merging to dodge a
  collision is obsolete. Merge, then run `doctor`.

**Release history** lives in the DB: each CHANGELOG entry is a `release`-tagged
done task with `completed_at` set to the release date. Rebuild with
`export-completed` (`--since`/`--until`), or slice with
`list --status done --tag changed` (also `benchmark`, `added`, `fixed`, `task`).

Pre-2026-04-20 task IDs survive as `plan-id:NN` tags.

---

## Documentation

| File | Contents |
|------|----------|
| `README.md` | Tool overview, installation, usage, CLI reference |
| `docs/index.rst` | Developer guide: advanced usage, CI/CD, benchmarks, testing, contributing |
| `docs/design/*.md` | Scoping docs, not in the Sphinx toctree — read directly. **Their "Status" headers go stale once work ships**; trust `todo-sqlite-cli show <task>` instead, and check whether the feature needs a mention in `docs/cli-usage.rst`/`docs/architecture.rst`. |
| `docs/design/internal-capability-catalog.md` | Catalog of every reusable primitive in `src/utility/cert_c/*.rs` and `src/analyze/*.rs`. **Read before writing any new AST/text heuristic.** |
| `docs/design/gate-status-sop.md` | Weekly read on distance to the maintenance-mode gate and a publishable paper. Run it *here* — its table says which check lives in which repo. |
| `../sqc_paper/` | The paper, in its own repo. Numbers in it must trace to Postgres via `benchmarking_db`. Its backlog and figure generator went with it. |

## Project Structure

- `src/rules/cert_c/` — CERT C rule implementations
- `src/analyze/` — analysis infrastructure (CFG, null state, VRA, prescan)
- `bench/` — benchmark infrastructure (runner, analyzer, SQLite DB, CLI)
- `data/` — benchmark database, prescan caches
- `scripts/` — workflow helpers, coverage gate
- `docs/` — developer guide, bibliography

## Code Navigation (clew)

Indexed by [`clew`](https://github.com/tvanfossen/clew), registered as the
`clew` MCP server in `.mcp.json` (gitignored — each machine runs `clew init`
once; it registers the server but installs nothing, so the machine also needs
the `clew-trace` package for `clew-mcp` to resolve). It serves a symbol
database — call graph, threads, locks, file docs — over `dossier` (everything
about one symbol in one call), `search` (a name, or a layer like
`corpus='locks'`), `index`, and `propose_declaration`.

**Prefer `dossier`/`search` over `grep`/`Read`** for "what calls X", "where is Y
defined", "what locks does this hold" — one call, call graph already resolved.
Read source directly only for what the index can point at but not contain
(exact comment text, line-by-line logic).

No manual indexing step is required: the DB lives outside the repo under
`~/.local/state/clew/targets/`, and the MCP tools build it on first use — a
fresh node with no `~/.local/state/clew` is expected, not broken. To build
eagerly (e.g. warming before a benchmark), run `clew --repo-root .`, and
`clew --repo-root . --rebuild` after non-trivial changes. **Omit `--output`
both times**: with it omitted clew writes where the MCP server reads; passing
`--output clew.db` writes into the current directory, which the server never
looks at, leaving a stray file and still paying for a cold build.

**Before implementing any new AST/text heuristic, check
`docs/design/internal-capability-catalog.md` first.** That catalog exists
because `search` matches literal token conjunctions: it finds a function
instantly when queried in words close to its own doc comment, and returns
nothing for a vague concept phrase. A rule once nearly re-implemented existing
cross-file macro detection from scratch because a keyword grep for "macro
detection" missed it. If the catalog does not cover it, try `dossier`/`search`
with vocabulary close to an actual doc comment, then grep
`src/utility/cert_c/` and `src/analyze/` by what the primitive *does*.

## Build & Test

```bash
cargo build
cargo test --package aurora-lint --lib -- rules::cert_c::RULE_ID::tests  # inline unit tests
cargo test --package aurora-lint --lib -- RULE_ID  # all tests (inline + generated from .c files)
cargo fmt
```

## Rule Implementation

**NEVER add embedded unit tests in rule implementation files:**
- ❌ NO `#[cfg(test)]` modules in `src/rules/cert_c/*/*/*.rs`
- ❌ NO inline test functions with hardcoded C snippets
- ✅ Test cases come from `.c` files in `tests/` (auto-generated into Rust tests)
- ✅ If a rule has no test cases, implement it WITHOUT tests — that is fine

For each new rule: create `src/rules/cert_c/CATEGORY/RULE_ID/rule_id_c.rs`,
register in `mod.rs`, enable in the TOML, then build and test.

**Before fixing a macro-related FP/FN**, check whether
`src/analyze/macro_expand.rs` already solves it — do **not** reach for a
name-heuristic workaround. aurora-lint has a real, name-independent
macro-expansion
engine (`collect_function_macros`, `macro_nulls_param_indices` for free+null
"safe free" macros, `macro_output_param_indices` for output-param macros),
already wired into MEM30-C, MEM31-C, EXP33-C and DCL31-C.
`docs/design/macro-expansion.md` has the rationale and a per-rule disposition
table; its "Status" header is stale, so trust the phase stock-takes below it.

**Before writing a new rule, check whether its defect concept already overlaps
an enabled rule** (search `rules_templates/rules-all.toml` descriptions and the
capability catalog). Overlap is expected — CERT-C's own rules/recommendations
split covers the same defect from two angles. **Default to letting both rules
fire.** Suppress one only on demonstrated *total* subsumption across every
ground-truth-labeled instance, not frequent co-location. See
`docs/design/cross-rule-overlap.md` for the policy and a counterexample where
hard precedence in either direction is measurably wrong.

## Git Commit Rules (CRITICAL)

**EXPLICITLY DENIED:**
- `git commit --no-verify` — never. Pre-commit hooks MUST pass; only humans skip
  hooks. Same for any other hook-skipping flag (`--no-gpg-sign`, etc.).
- `Co-Authored-By: Claude` — never add Claude as co-author.

  **The reason is placement, not prohibition.** Claude's contribution is
  acknowledged deliberately, in README.md's "AI Assistance" section. The trailer
  would repeat that fact in every one of thousands of commits, crowding out the
  message and telling a reader nothing the README has not already said clearly
  once. So do not read this as attribution being a compliance problem, and do
  not remove the README section for consistency. Acknowledge once, visibly.
  (`sqc_paper` deliberately differs and keeps the trailer — the PDF is its
  deliverable and nobody else works in its history.)

  **Enforced by a `commit-msg` hook** (`scripts/check_commit_message.py`), because
  prose alone did not hold: the trailer reached 172 commits before anyone
  noticed. A human co-author named normally still passes. `commit-msg` is a
  *second* hook type, so a clone that ran `pre-commit install` before the hook
  existed has the config and no hook, silently — same shape as the merge-driver
  trap below. One manual pass fixes it:

  ```bash
  pre-commit install --hook-type commit-msg
  ```

  `default_install_hook_types` in `.pre-commit-config.yaml` covers every fresh
  install, so this is only for older clones.

**REQUIRED:** hooks pass before a commit succeeds; if they fail, fix the cause;
standard commit message format without AI attribution.

**Pulling upstream (`todo-sqlite-cli.db`):** `.gitattributes` maps the DB to a
merge driver, but the driver lives in **repo-local git config**, which is not
committed — so a fresh clone has the attribute, no driver, and lands in
conflict on every pull that touched the DB.

```bash
git config --get merge.todo-sqlite-cli.driver \
  || todo-sqlite-cli install-merge-driver    # one-time, per clone
git pull                                     # DB auto-merges by task UUID
todo-sqlite-cli doctor                       # REQUIRED after every merge/pull
```

`setup-dev-environment.yml` registers the driver (and `pull.rebase` and the
pack settings below) on any node it provisions, so the one-time step is only
for older or hand-built clones. Note `install-merge-driver` appends the
`.gitattributes` line unconditionally, and this repo already has it — so
register by hand instead to avoid a duplicate:

```bash
git config merge.todo-sqlite-cli.name "todo-sqlite-cli 3-way merge driver"
git config merge.todo-sqlite-cli.driver "todo-sqlite-cli git-merge-driver %O %A %B"
git config pull.rebase false   # merge through the driver; see below
```

`pull.rebase false` is what makes the driver do its job when a pull races
another node. Merging invokes it once on the two DB tips and unions them by
task UUID; rebasing replays each local DB commit onto the new base instead,
running the driver once per commit against a moving target for no benefit.
Without the setting git 2.27+ just stops with *"need to specify how to
reconcile divergent branches"*.

The merge is a real 3-way union keyed on task UUID, so nothing is lost and
dependency edges keep resolving. **Never resolve a DB conflict with
`git checkout --ours/--theirs`** — that discards the other side's tasks
entirely.

**Pack size:** the DB is committed on nearly every task change, and git's
default `pack.window` of 10 cannot find a good delta base among hundreds of
versions of it, storing each close to whole. `setup-dev-environment.yml` sets
`pack.window 250` / `pack.depth 100` (repo-local, per-clone), which cuts a DB
commit from ~664 KiB of pack to ~38 KiB. Those affect only *future* repacks, so
a clone provisioned earlier needs one manual pass:

```bash
git repack -a -d --window=250 --depth=100
```

That is a pure storage-layout rewrite — it never changes SHAs or history — and
is safe on any clone at any time. Committing the DB is fine; the cost was a
config default, not the practice.

---

## Maintaining this file

This file is prepended to **every** session's context, on every node. A line
earns its place only by changing what an agent does. Before adding anything,
apply these:

- **Rules and rationale, not history.** Keep the decision rule and enough *why*
  that an agent will not "helpfully" undo it or misjudge a novel case. Cut the
  incident narrative that produced it — dated postmortems, which task collided
  with which, what a specific run measured. If an example is what makes a rule
  persuasive, compress it to one clause.
- **No live numbers, ids, or statuses.** Anything that changes on its own —
  run counts, metrics, "task N is pending at P5", active-task lists — goes
  stale silently and is worse than absent, because it reads as current. Name
  the source to ask instead.
- **State a thing once.** If it is already in `README.md`, `docs/index.rst` or
  a design doc, link it rather than restating it.
- **Prefer the imperative.** "Run X before Y" beats a paragraph explaining that
  running X before Y is generally advisable.
- **Put durable per-session facts in memory, not here.** Fleet topology, node
  capabilities and personal working preferences belong in the memory directory;
  this file is for the repo's own rules.
- When a section stops being true, delete it in the same commit that makes it
  untrue.
