# Parallel Nodes: Open Issues for a Network-Topology-Aware Plan

## Goal

Bring 2 additional machines online to churn through `todo-sqlite-cli list`
in parallel with this one. Motivation: most tasks' reasoning/implementation/
build/test loop is fully parallelizable; only the benchmark step is
expensive (32-50 min Juliet, 10-15 min real-world) and currently tied to
one machine's local state.

This doc was written by a node that does **not** know the actual network
topology (LAN/VPN/Tailscale/public IPs/firewalls, which machines can reach
which, whether MCP can be exposed remotely, etc.). Everything below is
either verified from the repo itself or is an open question that needs
topology knowledge to answer. A node that has that knowledge should read
this and turn it into an actual plan.

## What's already verified from the repo (safe to build on)

- **`todo-sqlite-cli.db` is designed for multi-machine use.** It has a real
  git 3-way merge driver: `.gitattributes` has
  `todo-sqlite-cli.db merge=todo-sqlite-cli`, and `.git/config` has
  `[merge "todo-sqlite-cli"]` wired to `todo-sqlite-cli git-merge-driver`.
  Task identity is a UUID (display `<id>` is just an alias, see CLAUDE.md),
  so independent machines creating/completing tasks and merging later is a
  supported case, not an afterthought. Run `todo-sqlite-cli doctor` after
  every merge/pull that touches this file (already documented in CLAUDE.md)
  — it catches duplicate display-ids and dependency-graph corruption, which
  is the one thing the merge driver *doesn't* fully resolve.
- **`data/benchmarks.db` is NOT shared.** It's gitignored (along with
  `-wal`/`-shm`), local-only, SQLite in WAL mode, single persistent DB per
  CLAUDE.md. There is no merge driver, no sync mechanism, and no multi-writer
  story for it today. Each machine that runs a benchmark today produces
  results only it can see via the MCP tools (`get_results`, `compare_runs`,
  `get_cwe_detail`, `list_runs`) or the `bench` CLI.
- **The DB access layer is centralized but SQLite-specific.**
  `bench/db.py` is 2081 lines of raw `sqlite3` (WAL pragma, `sqlite3.Row`,
  etc.) and is the sole layer both `mcp_servers/server.py` (via
  `bench.db.BenchDB`) and `mcp_servers/realworld_server.py` go through. A
  full RDBMS migration (e.g. Postgres) would mean porting this whole layer
  plus the 46 historical Juliet runs + 21 real-world runs already backfilled
  into it. Evaluated and **not recommended** for the current ask — the
  actual problem is network reachability (workers can't reach a file that
  lives on one machine's disk), not write concurrency (it's one writer,
  occasional readers, which SQLite/WAL already handles). Revisit only if
  the topology genuinely requires multiple machines to *write* benchmark
  results concurrently, not just read them.
- **Benchmark protocol constraints (CLAUDE.md, must hold under any plan):**
  - Version bump (`Cargo.toml`) + commit happens *before* a benchmark
    starts; the run_id is `sqc-<version>-<commit-sha>`.
  - Code must never change while a benchmark is running (it invokes
    `target/release/sqc`, built from a specific commit).
  - Real-world runs require `python -m bench corpus-check` first — the
    pinned checkouts (`data/benchmark_repos.json`) can drift per-machine
    (a `git pull` on a tracking branch, or stray build artifacts like
    sqlite's `sqlite3.c` amalgamation) with no error, silently corrupting
    the precision/recall denominator. Any new machine's checkouts need this
    verified before its results are trusted.
  - `ground_truth` is keyed on `(project, commit, file, line, rule)` — see
    CLAUDE.md's delta-adjudication protocol. A rule-detection-logic change
    needs its new findings delta-adjudicated before precision/recall claims
    are published; this is a per-rule, per-node workflow concern (does the
    plan need to prevent two nodes from touching overlapping rule
    detection logic + adjudication at the same time?).
- **git remote:** `origin` is
  `git@github-enterprise:brandon-arrendondo/tools_sqc` (both fetch and push).
  **Corrected 2026-08-28 from dev-921** — an earlier draft of this doc said
  `git@github.com:brandon-arrendondo/tools_sqc.git`, which is wrong in the
  way that matters: `github-enterprise` is an **`~/.ssh/config` Host alias**,
  not a real hostname. It resolves only on a machine whose ssh config
  defines it (with the right `HostName`/`IdentityFile`). That config is
  machine-local and **not in the repo**, so a worker node cannot clone or
  push until it is reproduced by hand. See "Node bring-up" below.
  No branch protection checked from this session.

## Open questions that need topology knowledge

1. **Reachability.** Can the two new worker machines open a connection to
   whichever machine is designated the "benchmark node"? Same LAN? VPN
   (Tailscale/WireGuard/etc.)? NAT'd with no inbound access? This decides
   whether a remote-MCP or live-replication approach is even possible, vs.
   needing a push-based sync (worker/benchmark node initiates outbound
   only) or an intermediary (S3 bucket, shared drive, etc.).
2. **MCP transport.** Is the MCP server (`mcp_servers/server.py`) currently
   spawned locally per-session (stdio), or does this setup support a
   network-reachable MCP endpoint worker machines could point at directly?
   If stdio-only, "expose the benchmark node's MCP server to workers" is
   off the table and the answer is some form of file sync instead.
3. **Shared filesystem or sync tooling already in place.** Is there an
   existing NFS mount, Syncthing, Dropbox-style sync, or similar between
   these machines that a periodic `sqlite3 data/benchmarks.db ".backup"`
   snapshot could ride on, or does this need to be built from scratch
   (rsync over SSH, cron, etc.)?
4. **Auth/security model.** Even read-only benchmark results — does
   anything network-facing here need real auth, or is this a fully trusted
   private network where a bare TCP/SSH exposure is fine?
5. **git push access.** Do all three machines have SSH keys/credentials
   configured for `origin`? Is there any expectation of branch protection
   or PR-based merging to `main` vs. direct pushes (current CLAUDE.md
   protocol assumes direct commits to `main` before benchmarking)?
6. **Task-claiming coordination.** `todo-sqlite-cli` has no distributed
   lock — two machines calling `next`/`start` before syncing the db could
   both pick the same task (not corruption, thanks to the merge driver,
   but wasted duplicate work). Does the topology make "push/pull the todo
   db immediately after `start`" fast enough to rely on, or does this need
   an explicit claim/assignment convention?
7. **Version-bump coordination.** Two machines both doing "bump patch
   version, build release, commit" against a stale local `main`
   concurrently will pick the same next version and collide on push. Does
   the plan restrict version bumps + benchmark runs to the one designated
   benchmark node (worker nodes land pre-bump commits for it to pick up),
   or does every node need a pull-immediately-before-bump discipline?
8. **Real-world corpus provisioning on new machines.** `playbooks/setup-
   benchmark-repos.yml` provisions the pinned checkouts once; are the new
   machines able to run that playbook against whatever's reachable (GitHub
   directly, a mirror, etc.), and is there anything topology-specific
   about how those checkouts get provisioned/kept in sync with
   `data/benchmark_repos.json`'s pins?

## Recommendation already on the table (from prior discussion, not yet decided)

Keep exactly one machine as the canonical benchmark node — it owns
`data/benchmarks.db`, does the version-bump+commit+benchmark ritual, and is
the source of truth for `compare_runs`/precision claims. The other two
machines do implementation + `cargo build`/`cargo test`/`clippy` +
todo-db updates in parallel on independent tasks, then hand off (push
commits, or open PRs) for the benchmark node to land and benchmark. This
sidesteps both the benchmarks.db split-brain problem and the version-bump
collision problem without needing any new infrastructure — but it does mean
worker nodes are blocked on the benchmark node's queue for anything that
needs a benchmark result before it can be called done. Whether that
blocking is acceptable, or whether workers need direct read access to
benchmark results (and via what mechanism, per the open questions above),
is the actual decision this doc exists to unblock.

---

## Findings from dev-921 (2026-08-28)

Node identity: hostname `dev-921`, `10.0.0.11` (RFC1918), 12 cores / 31 GB.
Everything in this section was verified on this machine this session. It
closes two of the open questions above and adds a bring-up checklist the
original draft didn't have. It does **not** describe the network topology —
this node doesn't know it either. The `surface` node holds the detailed
topology notes; this section is written to be merged with those.

### Q2 (MCP transport) — ANSWERED: stdio only

`mcp_servers/server.py:2086` is a bare `mcp.run()`. That is FastMCP's
default transport, i.e. **stdio** — the server is spawned as a child
process by whatever client launches it, over pipes. There is no listening
socket and no address to point a remote client at.

Consequence for the plan: **"expose the benchmark node's MCP server to the
workers" is off the table as currently written.** FastMCP does support
`mcp.run(transport="sse")` (or streamable-http), so this is a small code
change rather than a rewrite — but it is a real change, and it drags in
Q4 (auth) the moment it binds to anything but loopback. Until someone makes
that change, any cross-node access to benchmark results has to be
**file-level sync of `data/benchmarks.db`**, not MCP.

`.mcp.json` is gitignored (`.gitignore:75`), so each node configures its own
MCP server list regardless — same as the existing `clew init` per-machine
step documented in CLAUDE.md. Nothing about MCP config travels with the repo.

### Q3 (existing sync tooling) — ANSWERED for this node: none

Checked on dev-921: no Tailscale (no binary), no Syncthing (no binary), no
NFS or CIFS mounts (`mount` shows neither). There is no existing
file-sync channel on this machine to piggyback a
`sqlite3 data/benchmarks.db ".backup"` snapshot onto. If the plan wants
workers to read benchmark results, that transport gets built from scratch
(rsync-over-ssh on a timer being the obvious minimum).

This is a per-node fact, not a global one — the other nodes were not
checked from here. Confirm the same three checks on each node before
concluding the network has nothing.

### Node bring-up: the non-obvious prerequisites

These are the steps a fresh worker needs that are **not** discoverable from
the repo, because each one lives in machine-local state:

1. **`~/.ssh/config` must define the `github-enterprise` Host alias** (with
   its `HostName` and `IdentityFile`), or `git clone`/`git push` fails with
   an unresolvable host. The repo records the alias in the remote URL but
   nothing that resolves it. This is the single most likely first-run
   failure on a new node.
2. **The merge driver must be registered per clone.** `.gitattributes` maps
   `todo-sqlite-cli.db merge=todo-sqlite-cli`, but the driver itself lives
   in repo-local git config, which is not committed. Without it every pull
   that touches the todo DB leaves it in binary conflict. CLAUDE.md has the
   two `git config merge.todo-sqlite-cli.*` commands — use those rather
   than `install-merge-driver`, which would append a duplicate
   `.gitattributes` line since the line already exists here.
3. **`clew init --repo-root <path>` once per machine** — `.mcp.json` is
   gitignored, so the code index is per-node.
4. **Real-world corpus provisioning** via `playbooks/setup-benchmark-repos.yml`
   into `BENCH_ROOT` (default `~/toolchain`, kept in sync with
   `SQC_BENCH_ROOT` in `.env`). Note: **`playbooks/` has no committed
   inventory file** — there is no `hosts.yml`/`inventory` anywhere in the
   repo, so multi-node ansible runs need one written first. That is a
   genuine gap for this plan, not an oversight to route around.
   Juliet is *not* covered by the playbook (NIST SARD is a click-through
   portal); that stays a manual copy to each node that needs to benchmark.
5. **`python -m bench corpus-check` on the new node before trusting any
   real-world number from it** — per CLAUDE.md, pins drift silently and
   `ground_truth` is keyed on the commit.

Only step 4's Juliet half and step 5 are needed on a node that will *not*
benchmark. A pure worker node (impl + `cargo build`/`test`/`clippy` +
todo-db updates) needs steps 1–3 only, which is a meaningful argument in
favor of the single-benchmark-node recommendation above: it keeps the
expensive provisioning on one machine.

### Still open / needs the topology notes

Unchanged and still blocking: Q1 (reachability), Q4 (auth), Q5 (push
access on the other two machines), Q6 (task claiming), Q7 (version-bump
collision), Q8 (corpus provisioning reachability). Q6 and Q7 are the two
that bite soonest in practice, and neither needs new infrastructure to
decide — they're conventions, and could be settled independently of the
network answers.

### Slot: pulling `benchmarks.db` from r720-enterprise

**TO BE FILLED IN by the r720-enterprise node.** There are findings on that
machine about pulling the benchmark DB down from it that are not reproduced
here — this node has no record of them (no memory entries, nothing in the
repo, nothing in the task DB, nothing in git history mentioning r720).
They matter because they are the concrete precedent for the
"read-only snapshot sync to workers" option, which is otherwise
hypothetical in this doc. Anything known about WAL-mode safety while a
benchmark is mid-run, `.backup` vs. raw `cp`, transfer time for the DB's
current size, and how stale a worker's copy is allowed to get before
`compare_runs` misleads, belongs here.
