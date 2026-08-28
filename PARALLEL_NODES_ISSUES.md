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


---

## Topology resolved (dev-921, 2026-08-28)

Source: `~/environment/notes/pages/home_network.md` and
`~/environment/notes/pages/SECURITY_CONCERNS.md` (pulled from NAS to
dev-921). Those notes are the authority; this section records only what
bears on the parallel-nodes plan, and cites sections rather than copying
credential material. **Read `SECURITY_CONCERNS` §2, §3 and §6 before
acting on any of this** — they are the constraint, not background.

### The headline: the fleet is not three co-equal nodes

This doc was drafted assuming N symmetric machines that each implement,
build, and push. The actual fleet is **hub-and-spoke**, and two independent
mechanisms enforce it.

**1. Reachability is deliberately one-way.** pf's inter-VLAN policy allows
`vlan1 → vlan30` SSH only from the `<vlan30_ssh_allowed>` table
(firewall, dev-921, X270 eth/wifi, surface), and blocks `vlan30 → vlan1`
outright with an RST. r720 is the only host on vlan30. Independently,
dev-921's own `ufw` allow-lists port 22 to surface and X270 **only** —
r720 is not on that list. So:

| From → To | SSH |
|---|---|
| dev-921 → r720 | yes (LAN `10.0.30.10`, or WG `10.77.0.10`) |
| surface → r720 | yes (LAN, or WG when travelling) |
| r720 → dev-921 | **no** — blocked twice (pf, and dev-921's ufw) |
| r720 → surface | **no** — same |
| dev-107 / dev-106 → r720 | **no** — not in `<vlan30_ssh_allowed>` |

**Every byte that leaves r720 must be pulled by dev-921 or surface.**
r720 cannot initiate. This is the same asymmetry already imposed on the
quarantine-kit research workers (`SECURITY_CONCERNS` §10: "surface
initiates `scp`/`rsync`; the worker never pushes home"), so the pattern
is established doctrine here, not something to invent.

**2. r720 is permanently keyless, by policy.** `SECURITY_CONCERNS` §6:
r720 holds no SSH keys, ever — not soft, not TPM-bound. It sees only a
forwarded agent socket, chosen per-session by intent via the Option B
aliases (`r720-personal` forwards the TPM/szarta agent; `r720-enterprise`
forwards gpg-agent holding soft dev-330). The socket dies when the SSH
session ends.

### This directly contradicts the plan's premise — resolve it deliberately

The doc's model has worker nodes committing and **pushing to `origin`** for
the benchmark node to pick up. On r720 that is not merely unconfigured, it
is **designed to be impossible**:

> `SECURITY_CONCERNS` §3 — "A Claude session inside detached tmux still has
> the *old* `$SSH_AUTH_SOCK` pointing at the dead socket. Any `git push`
> attempt hangs on a dead socket and fails. **Result:** Claude in detached
> tmux literally cannot push."

That is listed as a *security property to preserve*, and it is exactly the
property an autonomous overnight worker would need to break. The notes
already name this gap and leave it open — `SECURITY_CONCERNS`
"Open questions", **"Long-lived bot tokens for CI / scheduled jobs"**:

> "If r720 runs anything that needs to push to GitHub without a human
> (e.g., nightly auto-commits), this whole 'credentials live with the
> human' model breaks for that workflow. Solve case-by-case — usually a
> scoped, write-only PAT for the specific repo, treated as
> compromised-by-default."

**So the real decision this doc exists to unblock is not a network
question at all.** It is: *does an autonomous parallel worker get a
standing credential, and if so what shape?* Three honest options:

- **(A) No standing credential — parallelism is bounded by attachment.**
  Worker sessions run on r720 under a live forwarded agent while Brandon
  is attached; they commit locally and push only during that window.
  Detached sessions keep building and testing but land nothing. Preserves
  §3 intact. Costs: no overnight autonomy, which is most of the motivation.
- **(B) A scoped write-only PAT for `tools_sqc` only**, treated as
  compromised-by-default, living on the worker. This is the case the notes
  pre-authorize ("solve case-by-case"), and it is bounded the way the
  `dev-106`/`dev-107` worker keys are bounded (§"Open questions"): one
  repo, one node, revocable in one line, not the TPM identity, shares no
  fingerprint with a real credential. Note it punches through §3 for that
  one repo — the detached session *can* push `tools_sqc` — so branch
  protection on `main` (§1) becomes load-bearing rather than optional.
- **(C) Worker never pushes; dev-921 pulls commits over SSH.** dev-921 can
  reach r720 but not vice versa, so dev-921 runs
  `git fetch <r720-path> <branch>` against the worker's clone and lands the
  work itself. No new credential anywhere; the asymmetry does the work.
  This is the direct analogue of the §10 pull-based drop, and it composes
  with the planned dev-921 git mirror (§4). **Recommended** — it buys most
  of (B)'s autonomy without creating a standing push credential.

Under (C) the worker's output is untrusted-until-pulled, which is the
existing doctrine, and nothing in §2/§3/§6 has to bend.

### Which machine should be the benchmark node

**r720**, on hardware: 12 cores / 24 threads and 192 GB, versus dev-921's
12 threads / 31 GB. Juliet fans out over `ProcessPoolExecutor`, so the
32–50 min fast-mode run is the part that actually benefits. r720 is also
the designated primary build host and sits on home fiber.

Caveats to check before committing to it:

- **Disk.** Root LVM is 456 GiB at ~61% used (~178 GiB free) — needs to
  cover the Juliet tree, nine real-world corpora, and `target/release`.
  `sdb` (250 GB, ext4 at `/media/drive-01`) is empty and is the obvious
  home for `BENCH_ROOT` if root gets tight.
- **Juliet is a manual copy.** The playbook deliberately doesn't fetch it
  (NIST SARD is click-through). It has to be transferred to r720 by hand,
  and given the direction of travel that means pushed *from* dev-921 or
  surface.
- **r720 has no compute GPU** (Matrox BMC only). Irrelevant for sqc, but it
  rules r720 out for any local-model adjudication work — that stays on
  dev-921 (RTX 3060 12 GB) or `brandons-mini`. Worth knowing given task 166.

### Pulling `benchmarks.db` off r720

**Superseded — see `BENCHMARK_PULLING.md`**, which documents the r720 → dev-921
pull that actually ran on 2026-08-28 (6.44 GB landed on dev-921 at 08:13) with
measured timings. It is the operational reference; this section keeps only the
two points that belong to *this* doc.

**Direction is forced, not chosen.** Per the matrix above, r720 cannot initiate
to dev-921 or surface, so the destination node drives every step — the
`VACUUM INTO` over SSH, the `rsync` pull, and the source cleanup. The completed
pull is empirical confirmation of the asymmetry.

**One correction to my earlier draft of this section:** it recommended
`sqlite3 ".backup"`. `VACUUM INTO` (what `BENCHMARK_PULLING.md` specifies and
what was actually used) is the better call — equally consistent against
concurrent writers, and it compacts, which matters at 6.4 GB. Both beat a file
copy; the WAL hazard I described was right, the remedy was second-best.

### Corrections to the earlier draft of this doc

- **`harrison` and `cecilia` are not candidate worker nodes** — they are
  the kids' gaming PCs, firewalled to accept SSH from dev-921 only. An
  earlier round of this discussion floated them; rule them out.
- **The real spare-capacity worker nodes already exist**: `dev-107`
  (Fedora, `10.0.0.63`, standing worker key from surface, NOPASSWD sudo)
  and `dev-106` (`10.0.0.69`, slated for headless-Debian reinstall). Both
  are already provisioned as disposable Claude worker nodes. **Neither can
  reach r720** — they are not in `<vlan30_ssh_allowed>`. Adding them means
  editing pf's table *and* r720's nftables mirror, which the notes flag as
  a must-keep-in-sync pair.

  **They do not need to reach r720 in order to benchmark, and dev-107 already
  has.** `realworld_runs.hostname` shows `10.0.0.63` producing 1,083,918
  `realworld_violations` rows over 2026-03-20/21 — so an earlier round of this
  already worked, with the node scanning its own corpus locally and the results
  merged into the DB later. That is a working precedent for a worker node that
  benchmarks without any path to r720, and it weakens the "one canonical
  benchmark node" framing: the binding constraint is `run_id` collision (version
  + commit SHA), not reachability. An earlier draft of this section claimed these
  boxes "suit implement/build/test, not benchmarking" — the DB says otherwise.
- **The seven-repo `github-enterprise` rewrite list in `SECURITY_CONCERNS`
  §2 is stale** — it names funky, todo-sqlite-cli, winhelp2rst, knots,
  windchill-connector, ingot, adotestplan-to-pytestbdd. `tools_sqc` is an
  eighth, cloned on dev-921, whose remote is already
  `git@github-enterprise:...`. §2's remark that "surface and dev-921 don't
  carry these aliases" is likewise superseded by the 2026-05-20 entry
  further down §6 (both machines got both aliases; 24 remotes rewritten).
  Worth a fix in the notes, not here.

### Revised open questions

| # | Was | Now |
|---|---|---|
| 1 | Reachability | **Answered** — one-way, dev-921/surface → r720 only |
| 2 | MCP transport | **Answered** — stdio only; file sync, not MCP |
| 3 | Existing sync tooling | **Answered** — none; use dev-921-initiated `.backup` + rsync |
| 4 | Auth model | **Reframed** — the question is the standing-credential decision (A/B/C above), not network auth |
| 5 | git push access | **Answered** — only credential-holding nodes (dev-921, surface) can push; r720 never can |
| 6 | Task claiming | **Still open** — convention, decide freely |
| 7 | Version-bump collision | **Mostly dissolved** — if only dev-921/surface push, there is effectively one writer; still needs a pull-before-bump habit |
| 8 | Corpus provisioning | **Partly answered** — r720 has fiber and can run the playbook; Juliet must be hand-copied *to* it |

The one genuinely blocking decision left is **A / B / C** above. Q6 is a
convention that can be settled in five minutes once that lands.
