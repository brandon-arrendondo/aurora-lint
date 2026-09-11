# valkey onboarding — 11th real-world oracle (in-memory database server, pthread CON* fit)

Onboarded 2026-09-11 (aurora_lint task: "Onboard valkey (src/) as real-world
benchmark codebase"). Numbers below are this checkout's own local runs at the
onboarding commit, never a project measurement (repo `CLAUDE.md`). Nothing is
adjudicated yet.

## Why this codebase

A security-conscious server with genuine pthread concurrency —
`pthread_create` in `src/iothread.c` (I/O threads) and the legacy
`src/threads_mngr.c`, the `ae.c` event loop, `redisAtomic` macros in
`src/atomicvar.h` — so the existing pthread-vocabulary CON* rules apply with
no prerequisite (unlike zephyr, whose `k_thread_*` idiom needs a table entry
first). First scan: CON34-C 411, CON33-C 198, CON03-C 50, CON40-C 37 — the
CON family has real volume here, which no earlier oracle except hostap gave it.

Chosen over Redis for upstream responsiveness, because this project files real
findings upstream and has already paused re-filing against unresponsive
maintainers. Measured 2026-09-09 over the 100 most recent open issues: Valkey
labels ~79% (bug / test-failure / enhancement), Redis ~9%; Redis carries issues
open since 2011 and PRs stale since 2024-03, Valkey's oldest artefacts date to
its 2024-03 founding. License was not the deciding factor. Worth resampling if
a filed Valkey issue goes quiet the way mosquitto's did.

## Candidate

[valkey-io/valkey](https://github.com/valkey-io/valkey) `9.1.2` →
`7f1dffedff6de73058b2c2a389422b6ecd56c8fb` (tag resolved locally to the same
SHA; BSD-3-Clause). Checkout directory `valkey`.

**A stale assumption, corrected before implementing:** the task body warned
that `src/version.h`, `src/commands.def` and `src/fmtargs.h` are
build-generated and absent from a bare clone. At this pin all three are
**tracked** (`git ls-files` lists them), so the bare clone scans without a
build step, no `#include` degrades, and `git ls-files --others --ignored`
finds no `.c`/`.h` for `corpus-check` to flag. Do not build inside the
checkout anyway; there is no need.

`zmalloc`/`zfree`/`zcalloc`/`zrealloc` (`src/zmalloc.h`) are plain functions,
not macros — confirmed; no `macro_expand.rs` work for the allocation rules.

## Scope: the shipped server under `src/`

Machine-readable mirror in `data/benchmark_repos.json`:

    "scope_include": ["src/*.c", "src/*.h", "src/trace/**", "src/modules/lua/**"],
    "scope_exclude": ["src/modules/*.c", "src/unit/**"]

234 in-scope files. The task counted `src/` as 210 files; that is the
top-level `src/*.c` + `src/*.h`. Two first-party subtrees the server build
links are included on top of it:

- `src/trace/` — LTTng tracepoints (`src/Makefile` compiles `trace/*.o` into
  the server; 155 lines).
- `src/modules/lua/` — the EVAL/FCALL Lua scripting engine. It lives under
  `modules/` because Valkey 9 ships it as a built-in module
  (`libvalkeylua.so`, `-DLUA_ENABLED` in `src/Makefile`), but it is the
  scripting attack surface of the server, not a sample: 10 files, 4,055
  lines.

Excluded inside `src/`: `modules/hello*.c` (eight sample modules shipped for
module authors — `helloworld.c`, `helloacl.c`, … — not the server) and
`unit/` (C++ unit tests; never dispatched anyway). `src/commands/` is 426
`.json` codegen specs, nothing to scan. `deps/` (vendored libvalkey,
jemalloc, lua, linenoise, hdr_histogram, fast_float, fpconv, gtest-parallel)
is outside the scan root by construction — same rationale as sqlite excluding
its Tcl bindings — with its headers on `-I` so the types resolve. `tests/` is
Tcl.

Runner entry (`bench/realworld_runner.py`): `scan_path {path}/src`,
`-d {path}/src`, `-I /usr/include` (openssl) + `src` + the six `deps/`
header dirs, `--exclude modules/hello*.c --exclude unit/**`. **`--exclude`
globs resolve relative to the scan root** — verified by probe: with
`--rules API00-C,DCL06-C`, `modules/hello*.c` accounts for 125 findings
without the exclude and 0 with it, `modules/lua` unchanged at 87.

## Manifest: `conf/realworld/valkey-rules.toml`

Full base plus the four suite-wide dead-config disables, and **one
categorical disable: WIN00-05/WIN30-C**, category 1 — Valkey has no Windows
port (`src/Makefile` selects Linux / FreeBSD / Darwin / SunOS / DragonFly; no
file includes `windows.h`/`winsock2.h`). This was not a pre-emptive call: the
exploratory scan with WIN* enabled produced **WIN03-C 36** ("fopen() called
without 'N' flag in mode string") on every POSIX `fopen()` and **WIN04-C 5**
(function pointer stored without `EncodePointer()`), which is a Windows-only
rule describing a defect that cannot occur here, the README's own example of
category 1. Same disposition as libcrc's WIN* block.

`aurora-lint --detect-relevance` reported `threading=true` (genuine) and
`windows=true`, and the latter is a **detector false positive**: its
`WINDOWS_IDENTIFIER_MARKERS` contains `HANDLE`, which matched the comment
`DESIGNED TO HANDLE USER INPUT` at `src/call_reply.c:586`. Filed as a
follow-up (match identifiers, not comment text). Had the detector been right,
`--write-manifest` would have produced this exact disable set itself.

## First-scan shape (unadjudicated)

Exploratory run under the pre-disable manifest, local run #224: **35,106
findings, 217 of 234 files, 186,822 LOC, 86.6 s**. Removing the 41 WIN*
findings gives the shape the committed manifest produces (re-scan at the same
tree: 35,065).

**Recorded first run at the onboarding commit (e51752fa), local run #225:
35,065 findings, 217 of 234 files, 75.1 s, WIN* 0.** Everything below is
unchanged by the WIN* disable.

Top rules: EXP19-C 6,551 · API00-C 3,372 · EXP34-C 3,341 · MEM31-C 1,710 ·
DCL15-C 1,662 · DCL13-C 1,050 · EXP12-C 1,009 · DCL19-C 988 · DCL06-C 824 ·
DCL05-C 789. EXP19-C (braces) is 18.7% of this codebase — Valkey's style
permits single-statement `if (x) return;` bodies pervasively, so the rule is
measuring a style disagreement at volume; that is the oracle's to record,
not this file's to hide (README category 3 is about swamping the *suite*,
and this is ~4% of it).

### MEM31-C: 1,710, dominated by `rdb.c`'s load paths

The largest single family is "Memory leak: 'X' allocated with
'rdbGenericLoadStringObject' is not freed" (~200 across `data`, `encoded`,
`nodekey`, `lp`, `cgname`), plus `hashtableCreate` 50, `streamCreateCG` 26,
`streamCreateNACK` 23. `rdbGenericLoadStringObject` is correctly inferred as
an allocator (it returns a fresh `sds`/`robj`/plain buffer depending on
flags). The one site read at source, `src/rdb.c:2323`:

    unsigned char *data = rdbGenericLoadStringObject(rdb, RDB_LOAD_PLAIN, &encoded_len);
    ...
        lp = data;
        if (!lpValidateIntegrity(lp, ...)) { decrRefCount(o); zfree(lp); return NULL; }   // <- reported here

The buffer is freed through the alias `lp`, and on the success path handed
to a container (`quicklistAppendPlainNode(objectGetVal(o), data, ...)`,
ownership transfer). Expect that family to adjudicate FP on alias-then-free
and container-transfer grounds; both are known MEM31-C ownership shapes, and
whether this pin's volume is one root cause or several is what the
adjudication pass should establish before anyone fixes by count.

## Adjudication status

None yet. The whole-codebase first pass belongs to `benchmarking_db`. Gate it
on the MEM31-C shape above if a cheap ownership fix is identified first —
adjudicating 200 findings a single alias fix removes is wasted work (repo
`CLAUDE.md`, delta-adjudication protocol).
