# Pulling `benchmarks.db` Between Nodes

Workflow for parallelising sqc work across several machines. `data/benchmarks.db`
is the single source of truth for all Juliet and real-world benchmark results,
and it is **gitignored** (`.gitignore:28`) — a fresh clone has the code and none
of the data. This document covers moving it from a node that has it to a node
that needs it.

At the time of writing the DB is ~6.5 GB; `realworld_violations` (3.9 GB) and
`violations` (1.5 GB) are essentially all of it, while `ground_truth` — the
adjudicated oracle — is only 20 MB.

---

## 1. Copy the database

**Do not `scp` or `rsync` the `.db` file directly.** It runs in WAL mode, so a
plain file copy taken while anything is writing yields a torn database, and
copying `.db` without its `-wal` sibling silently drops recent commits. Take a
consistent snapshot instead.

On the **source** node:

```bash
sqlite3 file:$SRC_REPO/data/benchmarks.db?mode=ro \
  "VACUUM INTO '/tmp/sqc_benchmarks_snapshot.db';"
```

`VACUUM INTO` produces a transactionally consistent, compacted copy while
readers and writers continue against the live DB. It needs free space on the
source equal to the DB size, and took ~35 s for 6.5 GB.

On the **destination** node:

```bash
rsync -P -e ssh --compress-choice=zstd --compress-level=1 \
  SOURCE_HOST:/tmp/sqc_benchmarks_snapshot.db \
  /path/to/tools_sqc/data/benchmarks.db
```

**Destination-initiated is not a stylistic choice — it is the only direction
that works.** pf blocks `vlan30 → vlan1` SSH outright, and dev-921's `ufw`
independently omits r720 from its port-22 allow-list, so **r720 cannot open a
connection to dev-921 or surface**. Both steps above therefore run *from* the
destination: the `VACUUM INTO` via `ssh SOURCE_HOST 'sqlite3 …'`, then the
`rsync` pull, then the cleanup. There is no push variant to reach for, and this
matches the pull-based drop doctrine used for the quarantine-kit workers
(`SECURITY_CONCERNS` §10). See `PARALLEL_NODES_ISSUES.md` for the full matrix.

One consequence for automation: an unattended pull still needs the destination's
SSH agent live. The `r720-*` aliases pin `IdentityAgent` at the TPM or gpg agent,
and gotcha #10 in `SECURITY_CONCERNS` documents gpg-agent failing
`agent refused operation` with no TTY/DISPLAY — so a cron pull works only while
the desktop session is up and the agent is warm.

zstd compression is worth it: a 63.8 MB/s raw link carried this at ~320 MB/s
effective (6.4 GB in 20 s). Then clean up the source:

```bash
ssh SOURCE_HOST 'rm -f /tmp/sqc_benchmarks_snapshot.db'
```

## 2. Verify before trusting it

```bash
sqlite3 data/benchmarks.db "pragma quick_check;"          # expect: ok
sqlite3 data/benchmarks.db "
  select 'runs', count(*) from runs
  union all select 'ground_truth', count(*) from ground_truth
  union all select 'realworld_runs', count(*) from realworld_runs;"
```

Compare the counts against the same query on the source. A snapshot that
transferred cleanly matches exactly.

---

## 3. Provision the corpus separately

The database records findings; it does not contain the code they point at. Any
work needing source context — adjudication, delta-adjudication, an LLM triage
pass — also needs the pinned checkouts:

```bash
ansible-playbook playbooks/setup-benchmark-repos.yml   # clones into ~/toolchain
python -m bench corpus-check                           # must exit 0
```

`data/benchmark_repos.json` is the single source of truth for the pins.
`corpus-check` exits nonzero and prints a `git checkout --detach` fix per drifted
row; run it before any real-world run or precision claim (task 619).

If you only need one project, cloning it directly is much cheaper than the full
playbook:

```bash
git clone https://github.com/sqlite/sqlite.git ~/toolchain/sqlite
git -C ~/toolchain/sqlite checkout --detach <pinned-sha-from-benchmark_repos.json>
```

---

## Gotchas

These each cost real time; none of them announce themselves.

**A missing DB path silently becomes an empty database.** `sqlite3
data/benchmarks.db "..."` on a node that has not pulled yet *creates* a 0-byte
file rather than erroring. It then shadows a later `rsync` target and every
query returns empty with no error. Check `ls -la data/benchmarks.db` before
concluding a table is missing, and delete any 0-byte file before pulling.

**`file_path` is stored in two different formats.** `ground_truth.file_path` is
repo-relative (`src/vdbeaux.c`) while `realworld_violations.file_path` is
absolute (`/home/brandon/toolchain/sqlite/src/vdbeaux.c`). Joining them naively
returns **zero rows** — which reads exactly like "the current run shares no
findings with the oracle" rather than like a bug. Normalise first:

```sql
replace(v.file_path, '/home/brandon/toolchain/' || rr.project || '/', '')
```

**…and the absolute rows use *two* different roots, so that `replace` alone is
not enough across full history** (verified on dev-921, 2026-08-28, 15,936,907
`realworld_violations` rows). `realworld_runs.hostname` + `scanned_at` show a
clean era boundary:

| Root | Rows | Producers | Scanned |
|---|---:|---|---|
| `/home/brandon/toolchain/…` | 11,820,911 | `dev-41` (r720), `dev-workstation` | 2026-06-10 → 2026-08-28 |
| `/home/brandon/data/…` | 4,104,797 | `dev-41`, `10.0.0.63` (dev-107), `local` | 2026-03-20 → 2026-04-19 |
| repo-relative (already) | 11,199 | `audit-ingest` | 2026-06-16 |

The single-`replace` recipe above is **correct for current-era runs** (anything
from 2026-06-10 on) and is the right thing to use for a fresh delta-adjudication.
But run against the whole table it silently leaves the 4.1 M pre-2026-04-19 rows
absolute, so they still fail to join and drop out of the denominator — 26 % of
the table vanishing in exactly the way this gotcha warns about, one layer down.
When a query spans history, strip either root:

```sql
replace(replace(v.file_path,
  '/home/brandon/toolchain/' || rr.project || '/', ''),
  '/home/brandon/data/'      || rr.project || '/', '')
```

Or scope the query to `rr.scanned_at >= '2026-06-10'` and keep the simple form.
Check before assuming — `select distinct substr(file_path,1,24) …` costs nothing
and the failure is silent.

**Absolute paths encode the *producing* node's checkout root.** Because
`realworld_violations` stores absolute paths, rows carry whatever `BENCH_ROOT`
the scanning node used. Keeping every node on the default `~/toolchain/<project>`
(same username, or an equivalent path) keeps that normalisation a single
`replace`. Overriding `bench_root` on one node makes cross-node joins
node-dependent.

**Gitignored and untracked `.c`/`.h` files contaminate a scan.** sqc dispatches
on file extension and never consults git, so a build run inside a checkout —
sqlite's generated `sqlite3.c` amalgamation is the usual culprit — gets scanned
and attributed to the pinned commit while staying invisible to `git status`.
`corpus-check` flags these.

**A benchmark DB pulled mid-run is a snapshot, not a subscription.** Runs
completing on the source node afterwards are not reflected. Re-pull, or run the
benchmark locally and treat the two nodes' `runs` tables as divergent.

---

## Which node should do what

The database is large and the corpus is larger, but the *oracle* is small. A
useful split:

- **Nodes with the corpus and a built `target/release/sqc`** run benchmarks and
  produce new `runs` / `violations` rows.
- **Nodes with only the DB** can do analysis that needs labels but not source —
  per-rule precision, run comparison, `bench realworld-score`.
- **Nodes with a GPU** can run local-model work against the oracle (task 166);
  that needs the DB *and* the corpus, since prompts carry source context.

Only one node should write a given benchmark run. `run_id` is derived from
version plus commit SHA, so two nodes at the same commit produce colliding run
ids.

---

## Related

- `CLAUDE.md` — Benchmark Workflow (protocol, delta-adjudication rules)
- `docs/index.rst` — Benchmark Setup / Running Benchmarks
- `playbooks/setup-benchmark-repos.yml`, `data/benchmark_repos.json` — corpus pins
